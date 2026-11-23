"""Security gateway: every proposed tool call passes through here before execution.

Order of checks (the first failure blocks the call):
  1. Live policy  - argument schema validation and task-scope checks (doc ids must
                    belong to this task; filenames confined to the task output folder).
  2. ARMMonitor   - the project's existing, unmodified monitor: L1 hard boundaries
                    (payload size, sensitive paths, credential patterns), L2G graph
                    provenance (untrusted data cannot reach a protected sink), L3
                    schema-derived rules and L4 capability token (tool allowlist and
                    per-tool budgets).
  3. Approval     - tools marked sensitive (writing files, external disclosure such as
                    send_email) pause for a human decision bound to the exact action.

Every outcome is appended to the existing hash-chained AuditLog (ActionAuditRecord).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import ValidationError

from src.monitor.arm_baseline import (
    ARMMonitor,
    CapabilityToken,
    CounterfactualStrategy,
    MonitorConfig,
    ProvenanceMode,
)
from src.monitor.audit import AuditLog
from src.monitor.models import DecisionVerdict, ExecutionStatus, PolicyDecision, TrustLevel
from src.monitor.reason_catalogue import CATALOGUE_VERSION, category_for_rule, deny_rule_id
from src.live.tools import REGISTRY, DOC_ID


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class GateDecision:
    verdict: Verdict
    layer: str
    rule: str | None
    reason: str
    args: Any = None  # validated pydantic args when not blocked by the live policy
    monitor_decision: PolicyDecision | None = None
    layer_verdicts: list[dict[str, str]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "layer": self.layer,
            "rule": self.rule,
            "reason": self.reason,
            "layers": self.layer_verdicts,
        }


def _digest(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


class SecurityGateway:
    def __init__(self, task_id: str, doc_ids: set[str]) -> None:
        self.task_id = task_id
        self.doc_ids = doc_ids
        self.session_id = f"live_{task_id}"
        token = CapabilityToken(
            session_id=self.session_id,
            allowed_tools=frozenset(REGISTRY),
            tool_budgets={name: spec.max_calls for name, spec in REGISTRY.items()},
        )
        config = MonitorConfig(
            provenance_mode=ProvenanceMode.GRAPH_L2G,
            counterfactual_strategy=CounterfactualStrategy.NONE,
            protected_sinks=MonitorConfig().protected_sinks
            + tuple(n for n, s in REGISTRY.items() if s.protected_sink),
        )
        self.monitor = ARMMonitor(session_id=self.session_id, capability_token=token, config=config)
        self.audit = AuditLog()

    # ---------------------------------------------------------------
    def evaluate(self, step_id: str, tool: str, raw_args: dict[str, Any], input_node_ids: list[str] | None = None, user_authorized: bool = True) -> GateDecision:
        spec = REGISTRY.get(tool)
        validated = None
        if spec is not None:
            # 1. Live policy: schema + scope
            try:
                validated = spec.args_model(**(raw_args or {}))
            except ValidationError as exc:
                errs = "; ".join(f"{'.'.join(map(str, e['loc'])) or 'arguments'}: {e['msg']}" for e in exc.errors()[:3])
                return GateDecision(Verdict.BLOCK, "LIVE:Policy", "LIVE-SCHEMA", f"Arguments rejected: {errs}")
            doc_id = getattr(validated, "doc_id", None)
            if doc_id is not None and doc_id not in self.doc_ids:
                return GateDecision(Verdict.BLOCK, "LIVE:Policy", "LIVE-SCOPE", f"{doc_id} is not a document of this task.")
            args_for_monitor = validated.model_dump(exclude_none=True)
        else:
            # Unknown tool: still sent to the monitor, whose L4 capability token denies it.
            args_for_monitor = {k: v for k, v in (raw_args or {}).items() if isinstance(v, (str, int, float, bool))}

        # 2. Existing ARMMonitor (unchanged)
        valid_inputs = [n for n in (input_node_ids or []) if self.monitor.graph.has_node(n)]
        decision = self.monitor.evaluate_tool_call(
            event_id=step_id, tool_name=tool, arguments=args_for_monitor, input_node_ids=valid_inputs
        )
        layers = [
            {"layer": str(l.get("layer_name")), "verdict": str(getattr(l.get("verdict"), "value", l.get("verdict")))}
            for l in decision.evidence.get("layers", [])
        ]
        if decision.decision == DecisionVerdict.DENY:
            return GateDecision(
                Verdict.BLOCK,
                decision.evidence.get("failing_layer", "ARMMonitor"),
                deny_rule_id(decision),
                decision.reason,
                validated,
                decision,
                layers,
            )

        # 3. User authorization check for protected sinks
        if tool in ("write_report", "send_email") and not user_authorized:
            return GateDecision(
                Verdict.BLOCK,
                "LIVE:Policy",
                "LIVE-AUTH",
                f"Action '{tool}' was not affirmatively authorized by the user.",
                validated,
                decision,
                layers,
            )

        # 4. Human approval for sensitive tools
        if spec is not None and spec.requires_approval:
            return GateDecision(
                Verdict.REQUIRE_APPROVAL,
                "LIVE:HumanApproval",
                None,
                spec.approval_reason or f"'{tool}' writes a file and requires explicit human approval. The monitor allowed it.",
                validated,
                decision,
                layers,
            )
        return GateDecision(Verdict.ALLOW, "ARMMonitor", None, decision.reason, validated, decision, layers)

    # ---------------------------------------------------------------
    def record_output(self, step_id: str, data_id: str, value: Any, trust: TrustLevel) -> None:
        self.monitor.record_tool_result(call_event_id=step_id, data_id=data_id, value=value, default_trust=trust)

    def audit_record(
        self,
        step_index: int,
        step_id: str,
        tool: str,
        args: dict[str, Any],
        gate: GateDecision,
        status: ExecutionStatus,
        feedback: str,
        *,
        input_ids: list[str] | None = None,
        data_id: str | None = None,
        output: Any = None,
        error: str | None = None,
        override_deny: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        """Append one hash-chained record. `override_deny` = (layer, reason) for a call the
        monitor allowed but a later gate (human rejection) stopped."""
        md = gate.monitor_decision
        authorization = DecisionVerdict.ALLOW if status != ExecutionStatus.NOT_EXECUTED_DENIED else DecisionVerdict.DENY
        rule = category = version = None
        deciding_layer = None
        reason = gate.reason
        if authorization == DecisionVerdict.DENY:
            if override_deny:
                deciding_layer, reason = override_deny
            else:
                deciding_layer = gate.layer
                if md is not None and md.decision == DecisionVerdict.DENY:
                    rule = deny_rule_id(md)
                    if rule is not None:
                        category, version = category_for_rule(rule).value, CATALOGUE_VERSION
        rec = self.audit.append(
            record_id=f"audit_{self.session_id}_{step_index}",
            session_id=self.session_id,
            branch_name="live",
            feedback_condition="LIVE",
            step_index=step_index,
            step_id=step_id,
            tool_name=tool,
            arguments=args,
            proposed_input_node_ids=list(input_ids or []),
            accepted_input_node_ids=[n for n in (input_ids or []) if self.monitor.graph.has_node(n)],
            is_protected_sink=bool(REGISTRY.get(tool) and REGISTRY[tool].protected_sink),
            authorization=authorization,
            decision_id=md.decision_id if md is not None else f"live_{uuid.uuid4().hex[:12]}",
            deciding_layer=deciding_layer,
            internal_reason=reason or "n/a",
            layer_verdicts=gate.layer_verdicts,
            deny_rule=rule,
            reason_category=category,
            reason_catalogue_version=version,
            execution_status=status,
            executed=status == ExecutionStatus.EXECUTED,
            data_id=data_id if status == ExecutionStatus.EXECUTED else None,
            output_digest=_digest(output) if status == ExecutionStatus.EXECUTED else None,
            error=error,
            agent_visible_feedback=feedback or "n/a",
        )
        return {"sequence": rec.sequence, "record_hash": rec.record_hash[:16], "authorization": rec.authorization.value, "execution_status": rec.execution_status.value}


def is_doc_id(value: str) -> bool:
    import re

    return re.match(DOC_ID, value or "") is not None
