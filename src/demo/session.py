"""Runs demo tasks through the real executor, monitor, environment and audit log."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.agent.agent import ReactivePolicyAgent
from src.agent.executor import AgentExecutor, BranchExecutionResult
from src.agent.state import AgentTask
from src.attribution.models import FeedbackCondition
from src.demo.interpreter import Interpretation, interpret
from src.demo.sandbox import DEMO_TOOLS, build_env_state
from src.monitor.models import ActionAuditRecord, ExecutionStatus

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTECTED_DIRS: tuple[Path, ...] = (REPO_ROOT / "results", REPO_ROOT / "configs")

# Historical v1 feedback conditions the demo may use. Neither is C0/C1/C2.
DEMO_FEEDBACK_CONDITIONS: tuple[FeedbackCondition, ...] = (
    FeedbackCondition.ACTUAL,
    FeedbackCondition.NEUTRALIZED,
)

MAX_STEPS = 6
BRANCH_NAME = "demo"


class UnsafeAuditDirectoryError(ValueError):
    """Raised when audit persistence would write into results/ or configs/."""


def validate_save_dir(path: str | Path) -> Path:
    """Return a resolved directory for optional audit persistence, or raise."""
    resolved = Path(path).expanduser().resolve()
    for protected in PROTECTED_DIRS:
        p = protected.resolve()
        if resolved == p or p in resolved.parents:
            raise UnsafeAuditDirectoryError(
                f"Refusing to save demo audit logs under {p}: historical results and "
                "configurations must not be modified."
            )
    return resolved


@dataclass
class StepView:
    """One displayed step. Every security field is copied from an ActionAuditRecord."""

    index: int
    tool: str
    arguments: dict[str, Any]
    decision: str
    deciding_layer: str | None
    deny_rule: str | None
    reason_category: str | None
    internal_reason: str
    execution_status: str
    executed: bool
    error: str | None
    agent_saw: str
    next_action: str


@dataclass
class TaskOutcome:
    task_number: int
    interpretation: Interpretation
    result: BranchExecutionResult
    records: list[ActionAuditRecord]
    steps: list[StepView]
    chain_errors: list[str]
    saved_path: Path | None = None
    side_effects: dict[str, int] = field(default_factory=dict)


def _fmt_call(tool: str, args: dict[str, Any]) -> str:
    inner = ", ".join(f"{k}={v!r}" for k, v in args.items())
    return f"{tool}({inner})"


def build_step_views(result: BranchExecutionResult) -> list[StepView]:
    """Derive the display rows from the audit log and the agent's memory.

    Raises if the agent-visible feedback in memory and in the audit record disagree,
    so the demo can never show something the audit trail does not support.
    """
    records = result.audit_log.records
    observations = result.memory.observations
    if len(records) != len(observations):
        raise RuntimeError("audit records and agent observations are out of step")
    views: list[StepView] = []
    for i, (rec, obs) in enumerate(zip(records, observations)):
        if rec.agent_visible_feedback != obs.feedback or rec.tool_name != obs.tool_name:
            raise RuntimeError(f"step {i}: audit record does not match agent observation")
        if i + 1 < len(records):
            nxt = records[i + 1]
            next_action = "proposes " + _fmt_call(nxt.tool_name, nxt.arguments)
        elif result.terminated_cleanly:
            next_action = f"terminates ({result.termination_reason})"
        else:
            next_action = f"stopped by executor ({result.termination_reason})"
        views.append(
            StepView(
                index=rec.step_index,
                tool=rec.tool_name,
                arguments=dict(rec.arguments),
                decision=rec.authorization.value,
                deciding_layer=rec.deciding_layer,
                deny_rule=rec.deny_rule,
                reason_category=rec.reason_category,
                internal_reason=rec.internal_reason,
                execution_status=rec.execution_status.value,
                executed=rec.executed,
                error=rec.error,
                agent_saw=obs.feedback,
                next_action=next_action,
            )
        )
    return views


class DemoSession:
    """Interactive-session state. Each task gets a fresh environment, monitor and memory."""

    def __init__(
        self,
        feedback_condition: FeedbackCondition = FeedbackCondition.ACTUAL,
        save_dir: str | Path | None = None,
    ) -> None:
        if feedback_condition not in DEMO_FEEDBACK_CONDITIONS:
            raise ValueError(f"Unsupported demo feedback condition: {feedback_condition}")
        self.feedback_condition = feedback_condition
        self.save_dir = validate_save_dir(save_dir) if save_dir is not None else None
        self.task_count = 0

    def _run(self, task_id: str, goal: str, directives: list[dict[str, Any]]) -> BranchExecutionResult:
        task = AgentTask(
            task_id=task_id,
            goal=goal,
            instructions={"directives": directives},
            allowed_tools=list(DEMO_TOOLS),
            max_steps=MAX_STEPS,
        )
        # Fresh executor, agent, environment state; run_branch builds a fresh
        # SandboxedEnvironment, AgentMemory, ARMMonitor and AuditLog internally.
        return AgentExecutor().run_branch(
            task, build_env_state(), ReactivePolicyAgent(), BRANCH_NAME, self.feedback_condition
        )

    def probe_monitor(self) -> dict[str, Any]:
        """Run one harmless real step to report the monitor's actual configuration and layers."""
        result = self._run("demo_probe", "probe", [{"op": "call", "tool": "get_time", "args": {}}])
        rec = result.audit_log.records[0]
        cfg = result.monitor.config
        return {
            "layers": [v["layer"] for v in rec.layer_verdicts],
            "provenance_mode": cfg.provenance_mode.value,
            "counterfactual_strategy": cfg.counterfactual_strategy.value,
            "trust_threshold": cfg.trust_threshold.name,
            "sensitive_path_patterns": list(cfg.sensitive_path_patterns),
            "protected_sinks": list(cfg.protected_sinks),
            "resource_policy_enabled": result.monitor.resource_policy is not None,
            "probe_decision": rec.authorization.value,
        }

    def run_task(self, text: str) -> TaskOutcome:
        self.task_count += 1
        interpretation = interpret(text)
        result = self._run(
            f"demo_task_{self.task_count}", interpretation.text or "(empty)", interpretation.directives
        )
        records = result.audit_log.records
        outcome = TaskOutcome(
            task_number=self.task_count,
            interpretation=interpretation,
            result=result,
            records=records,
            steps=build_step_views(result),
            chain_errors=result.audit_log.verify(),
            side_effects={
                "simulated_emails": len(result.environment.sent_emails),
                "simulated_exports": len(result.environment.exported_records),
                "tool_executions": sum(r.execution_status == ExecutionStatus.EXECUTED for r in records),
            },
        )
        if self.save_dir is not None and records:
            self.save_dir.mkdir(parents=True, exist_ok=True)
            path = self.save_dir / f"demo_audit_task{self.task_count:03d}_{uuid.uuid4().hex[:8]}.jsonl"
            result.audit_log.write_jsonl(path)  # exclusive create ("x"): never overwrites
            outcome.saved_path = path
        return outcome
