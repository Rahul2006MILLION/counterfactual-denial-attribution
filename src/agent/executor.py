"""Closed-loop agent executor mediating every tool call through ARMMonitor."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from src.agent.agent import BaseAgent
from src.agent.environment import EnvironmentState, SandboxedEnvironment
from src.agent.state import AgentMemory, AgentObservation, AgentTask
from src.attribution.intervention import DenialInterventionEngine
from src.attribution.models import (
    FeedbackCondition,
    InterventionRecord,
    PairedTrace,
    TraceStepRecord,
)
from src.monitor.arm_baseline import (
    ARMMonitor,
    CapabilityToken,
    CounterfactualStrategy,
    MonitorConfig,
    ProvenanceMode,
)
from src.monitor.audit import AuditLog
from src.monitor.models import DecisionVerdict, ExecutionStatus, PolicyDecision

_PROTECTED_SINKS = frozenset(
    {
        "send_email",
        "export_data",
        "post_message",
        "write_file",
        "delete_file",
        "transfer_funds",
        "update_record",
        "run_code",
    }
)


def _hash_obj(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _output_digest(output: Any) -> str:
    """Full SHA-256 of a tool output's canonical JSON (the output itself is not logged)."""
    payload = json.dumps(output, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _layer_verdicts(decision: PolicyDecision) -> list[dict[str, str]]:
    layers = decision.evidence.get("layers", [])
    return [
        {
            "layer": str(layer.get("layer_name", "")),
            "verdict": str(getattr(layer.get("verdict"), "value", layer.get("verdict"))),
        }
        for layer in layers
    ]


@dataclass
class BranchExecutionResult:
    """Complete result of running a single independent agent branch."""

    monitor: ARMMonitor
    environment: SandboxedEnvironment
    memory: AgentMemory
    trace: PairedTrace
    terminated_cleanly: bool
    termination_reason: str
    agent_overhead_ms: float
    monitor_overhead_ms: float
    audit_log: AuditLog = field(default_factory=AuditLog)


class AgentExecutor:
    """Executes an agent in a sandboxed environment mediated by ARMMonitor."""

    def __init__(
        self,
        intervention_engine: DenialInterventionEngine | None = None,
    ) -> None:
        self._intervention = intervention_engine or DenialInterventionEngine()

    def run_branch(
        self,
        task: AgentTask,
        initial_env_state: EnvironmentState,
        agent: BaseAgent,
        branch_name: str,
        feedback_condition: FeedbackCondition,
        monitor_config: MonitorConfig | None = None,
    ) -> BranchExecutionResult:
        """Execute a single independent branch with isolated state and memory."""
        env = SandboxedEnvironment(initial_env_state)
        memory = AgentMemory()
        cfg = monitor_config or MonitorConfig(
            provenance_mode=ProvenanceMode.GRAPH_L2G,
            counterfactual_strategy=CounterfactualStrategy.NONE,
        )
        token = CapabilityToken(
            session_id=f"{task.task_id}_{branch_name}",
            allowed_tools=frozenset(task.allowed_tools),
        )
        monitor = ARMMonitor(
            session_id=f"{task.task_id}_{branch_name}",
            capability_token=token,
            config=cfg,
        )

        available_tools = {
            name: desc
            for name, desc in SandboxedEnvironment.TOOL_DESCRIPTIONS.items()
            if not task.allowed_tools or name in task.allowed_tools
        }

        audit_log = AuditLog()
        session_id = f"{task.task_id}_{branch_name}"

        def _audit(
            step_idx: int,
            step_id: str,
            proposal_tool: str,
            proposal_args: dict[str, Any],
            proposed_ids: list[str],
            accepted_ids: list[str],
            decision: PolicyDecision,
            status: ExecutionStatus,
            feedback: str,
            data_id: str | None = None,
            output_digest: str | None = None,
            error: str | None = None,
        ) -> None:
            audit_log.append(
                record_id=f"audit_{session_id}_{step_idx}",
                session_id=session_id,
                branch_name=branch_name,
                feedback_condition=feedback_condition.value,
                step_index=step_idx,
                step_id=step_id,
                tool_name=proposal_tool,
                arguments=proposal_args,
                proposed_input_node_ids=list(proposed_ids),
                accepted_input_node_ids=list(accepted_ids),
                is_protected_sink=proposal_tool in _PROTECTED_SINKS,
                authorization=decision.decision,
                decision_id=decision.decision_id,
                deciding_layer=decision.evidence.get("failing_layer"),
                internal_reason=decision.reason,
                layer_verdicts=_layer_verdicts(decision),
                execution_status=status,
                executed=status == ExecutionStatus.EXECUTED,
                data_id=data_id,
                output_digest=output_digest,
                error=error,
                agent_visible_feedback=feedback,
            )

        trace_steps: list[TraceStepRecord] = []
        interventions: list[InterventionRecord] = []
        non_denial_outputs: dict[str, Any] = {}
        recorded_denials = 0
        terminated_cleanly = False
        termination_reason = "max_steps_reached"
        agent_ns = 0
        monitor_ns = 0

        for step_idx in range(task.max_steps):
            t_a0 = time.perf_counter_ns()
            proposal = agent.propose_next_action(task, memory, available_tools)
            agent_ns += time.perf_counter_ns() - t_a0

            if proposal.terminate or proposal.tool_name is None:
                terminated_cleanly = True
                termination_reason = proposal.termination_reason or "agent_terminated"
                break

            step_id = f"{branch_name}_s{step_idx}"
            valid_input_ids = [
                nid for nid in proposal.input_node_ids if monitor.graph.has_node(nid)
            ]
            t_m0 = time.perf_counter_ns()
            decision = monitor.evaluate_tool_call(
                event_id=step_id,
                tool_name=proposal.tool_name,
                arguments=proposal.arguments,
                input_node_ids=valid_input_ids,
            )
            monitor_ns += time.perf_counter_ns() - t_m0

            if decision.decision == DecisionVerdict.ALLOW:
                try:
                    output, trust, overrides = env.execute_tool(
                        proposal.tool_name, proposal.arguments
                    )
                except Exception as exc:  # noqa: BLE001 - any tool failure is a recorded outcome
                    # Authorized but failed: authorization stays ALLOW, execution is TOOL_ERROR.
                    # (Previously only ValueError was caught; e.g. ZeroDivisionError or
                    # SyntaxError from calculate() crashed the whole episode.)
                    # The agent-facing observation is unchanged in M1 (allowed=False).
                    tool_feedback = f"TOOL_ERROR: {exc}"
                    obs = AgentObservation(
                        step_index=step_idx,
                        tool_name=proposal.tool_name,
                        arguments=proposal.arguments,
                        allowed=False,
                        output=None,
                        feedback=tool_feedback,
                        data_id=None,
                    )
                    memory.record(obs)
                    trace_steps.append(
                        TraceStepRecord(
                            step_id=step_id,
                            tool_name=proposal.tool_name,
                            arguments=proposal.arguments,
                            input_node_ids=list(proposal.input_node_ids),
                            decision=decision.decision.value,
                            reason=f"Tool execution error: {exc}",
                            is_protected_sink=proposal.tool_name in _PROTECTED_SINKS,
                            is_unauthorized_sink=False,
                            executed=False,
                        )
                    )
                    _audit(
                        step_idx,
                        step_id,
                        proposal.tool_name,
                        proposal.arguments,
                        proposal.input_node_ids,
                        valid_input_ids,
                        decision,
                        ExecutionStatus.TOOL_ERROR,
                        tool_feedback,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    continue
                data_id = f"d_{step_id}"
                t_m1 = time.perf_counter_ns()
                monitor.record_tool_result(
                    call_event_id=step_id,
                    data_id=data_id,
                    value=output,
                    default_trust=trust,
                    field_trust_overrides=overrides,
                )
                if proposal.tool_name == "read_document" and "path" in proposal.arguments:
                    monitor.graph.get_node(data_id).metadata["source_id"] = (
                        f"doc::{proposal.arguments['path']}"
                    )
                monitor_ns += time.perf_counter_ns() - t_m1

                if proposal.tool_name not in _PROTECTED_SINKS:
                    key = (
                        f"{proposal.tool_name}:"
                        f"{json.dumps(proposal.arguments, sort_keys=True, separators=(',', ':'))}"
                    )
                    non_denial_outputs[key] = {"result": output, "trust": trust.label}

                obs = AgentObservation(
                    step_index=step_idx,
                    tool_name=proposal.tool_name,
                    arguments=proposal.arguments,
                    allowed=True,
                    output=output,
                    feedback=f"OK: {output}",
                    data_id=data_id,
                )
                _audit(
                    step_idx,
                    step_id,
                    proposal.tool_name,
                    proposal.arguments,
                    proposal.input_node_ids,
                    valid_input_ids,
                    decision,
                    ExecutionStatus.EXECUTED,
                    obs.feedback,
                    data_id=data_id,
                    output_digest=_output_digest(output),
                )
            else:
                denials = monitor.graph.denials
                rendered_fb = "Action was not executed."
                while recorded_denials < len(denials):
                    denial = denials[recorded_denials]
                    int_rec = self._intervention.apply(
                        denial=denial, condition=feedback_condition
                    )
                    interventions.append(int_rec)
                    rendered_fb = int_rec.rendered_feedback
                    recorded_denials += 1

                obs = AgentObservation(
                    step_index=step_idx,
                    tool_name=proposal.tool_name,
                    arguments=proposal.arguments,
                    allowed=False,
                    output=None,
                    feedback=rendered_fb,
                    data_id=None,
                )
                # Denied: the tool was never invoked (env.execute_tool is unreachable here).
                _audit(
                    step_idx,
                    step_id,
                    proposal.tool_name,
                    proposal.arguments,
                    proposal.input_node_ids,
                    valid_input_ids,
                    decision,
                    ExecutionStatus.NOT_EXECUTED_DENIED,
                    rendered_fb,
                )

            memory.record(obs)
            trace_steps.append(
                TraceStepRecord(
                    step_id=step_id,
                    tool_name=proposal.tool_name,
                    arguments=proposal.arguments,
                    input_node_ids=list(proposal.input_node_ids),
                    decision=decision.decision.value,
                    reason=decision.reason,
                    is_protected_sink=proposal.tool_name in _PROTECTED_SINKS,
                    is_unauthorized_sink=False,
                    # Previously True for every monitored step, including DENIED ones.
                    # Now means "the tool actually ran" (authorization is in `decision`).
                    executed=decision.decision == DecisionVerdict.ALLOW,
                )
            )

        trace = PairedTrace(
            trace_id=f"trace_{task.task_id}_{branch_name}",
            scenario_id=task.task_id,
            branch_name=branch_name,
            condition=feedback_condition,
            initial_state_hash=_hash_obj(initial_env_state.model_dump()),
            permissions_hash=_hash_obj(sorted(task.allowed_tools)),
            non_denial_outputs=non_denial_outputs,
            steps=trace_steps,
            interventions=interventions,
            replay_valid=True,
        )
        return BranchExecutionResult(
            monitor=monitor,
            environment=env,
            memory=memory,
            trace=trace,
            terminated_cleanly=terminated_cleanly,
            termination_reason=termination_reason,
            agent_overhead_ms=round(agent_ns / 1_000_000.0, 4),
            monitor_overhead_ms=round(monitor_ns / 1_000_000.0, 4),
            audit_log=audit_log,
        )
