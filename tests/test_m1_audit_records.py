"""M1: authorization vs. execution separation and hash-chained action audit records.

Covers backend requirements:
  1/2. The monitor's DENY is authoritative and a denied action never executes.
  3.   Authorization and execution outcome are recorded separately.
  5.   Every proposed action yields exactly one structured audit record.
  7.   Branch audit logs are isolated.
Plus tamper evidence of the audit chain and that raw tool outputs are not logged.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from src.agent.agent import BaseAgent
from src.agent.environment import EnvironmentState
from src.agent.executor import AgentExecutor, BranchExecutionResult
from src.agent.state import AgentMemory, AgentTask, ProposedAction
from src.attribution.models import FeedbackCondition
from src.monitor.audit import AuditLog, compute_record_hash, verify_chain
from src.monitor.models import (
    GENESIS_HASH,
    ActionAuditRecord,
    DecisionVerdict,
    ExecutionStatus,
)

SECRET_CONTENT = "TOP-SECRET-PAYROLL-7731"


class ScriptedAgent(BaseAgent):
    """Proposes a fixed list of actions, then terminates. Ignores observations."""

    def __init__(self, actions: list[ProposedAction]) -> None:
        self._actions = list(actions)
        self._i = 0

    def propose_next_action(
        self, task: AgentTask, memory: AgentMemory, available_tools: dict[str, str]
    ) -> ProposedAction:
        if self._i >= len(self._actions):
            return ProposedAction(terminate=True, termination_reason="script complete")
        action = self._actions[self._i]
        self._i += 1
        return action


def _run(
    actions: list[ProposedAction],
    allowed_tools: list[str],
    documents: dict[str, dict[str, Any]] | None = None,
    branch: str = "branch_a",
    condition: FeedbackCondition = FeedbackCondition.ACTUAL,
    max_steps: int = 10,
) -> BranchExecutionResult:
    task = AgentTask(task_id="m1_task", goal="m1", allowed_tools=allowed_tools, max_steps=max_steps)
    env = EnvironmentState(documents=documents or {})
    return AgentExecutor().run_branch(task, env, ScriptedAgent(actions), branch, condition)


def _record_kwargs(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = dict(
        record_id="r0",
        sequence=0,
        session_id="s",
        branch_name="branch_a",
        feedback_condition="ACTUAL",
        step_index=0,
        step_id="branch_a_s0",
        tool_name="get_time",
        authorization=DecisionVerdict.ALLOW,
        decision_id="dec_branch_a_s0",
        internal_reason="All policy layers passed.",
        execution_status=ExecutionStatus.EXECUTED,
        executed=True,
        agent_visible_feedback="OK",
        prev_hash=GENESIS_HASH,
        record_hash="f" * 64,
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Requirements 1-3: authoritative DENY, no execution, separate recording
# ---------------------------------------------------------------------------


def test_denied_sink_never_executes_and_is_recorded_as_not_executed() -> None:
    # The email body contains a sensitive path, so L1 (HB-2) must deny it.
    res = _run(
        [ProposedAction(tool_name="send_email", arguments={"to": "x@ex.test", "body": "see /etc/shadow"})],
        allowed_tools=["send_email"],
    )
    assert res.environment.sent_emails == []
    assert res.environment.execution_log == []

    [rec] = res.audit_log.records
    assert rec.authorization == DecisionVerdict.DENY
    assert rec.execution_status == ExecutionStatus.NOT_EXECUTED_DENIED
    assert rec.executed is False
    assert rec.deciding_layer == "L1:HardBoundaries"
    assert rec.data_id is None and rec.output_digest is None

    [step] = res.trace.steps
    assert step.decision == "DENY"
    assert step.executed is False


def test_allowed_action_is_executed_with_output_digest() -> None:
    res = _run([ProposedAction(tool_name="get_time", arguments={})], allowed_tools=["get_time"])
    [rec] = res.audit_log.records
    assert rec.authorization == DecisionVerdict.ALLOW
    assert rec.execution_status == ExecutionStatus.EXECUTED
    assert rec.executed is True
    assert rec.deciding_layer is None
    assert rec.data_id == "d_branch_a_s0"
    expected = hashlib.sha256(json.dumps(res.environment.execution_log[0]["result"]).encode()).hexdigest()
    assert rec.output_digest == expected
    assert res.trace.steps[0].executed is True
    assert [v["verdict"] for v in rec.layer_verdicts] == ["PASS", "PASS", "PASS", "PASS"]


@pytest.mark.parametrize(
    ("expression", "error_type"),
    [("5 // 0", "ZeroDivisionError"), ("1 +", "SyntaxError"), ("2 ** 3", "ValueError")],
)
def test_tool_error_is_allow_plus_tool_error_and_does_not_crash(expression: str, error_type: str) -> None:
    res = _run(
        [
            ProposedAction(tool_name="calculate", arguments={"expression": expression}),
            ProposedAction(tool_name="get_time", arguments={}),
        ],
        allowed_tools=["calculate", "get_time"],
    )
    err, follow_up = res.audit_log.records
    assert err.authorization == DecisionVerdict.ALLOW
    assert err.execution_status == ExecutionStatus.TOOL_ERROR
    assert err.executed is False
    assert err.error is not None and err.error.startswith(error_type)
    assert err.data_id is None and err.output_digest is None
    assert res.trace.steps[0].decision == "ALLOW"
    assert res.trace.steps[0].executed is False
    # The episode continued past the failure.
    assert follow_up.execution_status == ExecutionStatus.EXECUTED
    assert res.terminated_cleanly is True


def test_unknown_tool_without_capability_restriction_is_tool_error() -> None:
    res = _run([ProposedAction(tool_name="hallucinated_tool", arguments={})], allowed_tools=[])
    [rec] = res.audit_log.records
    assert rec.authorization == DecisionVerdict.ALLOW
    assert rec.execution_status == ExecutionStatus.TOOL_ERROR
    assert "Unknown simulated tool" in (rec.error or "")


def test_agent_visible_feedback_recorded_separately_from_internal_reason() -> None:
    action = [ProposedAction(tool_name="read_document", arguments={"path": "/etc/shadow"})]
    actual = _run(action, ["read_document"], condition=FeedbackCondition.ACTUAL).audit_log.records[0]
    neutral = _run(action, ["read_document"], condition=FeedbackCondition.NEUTRALIZED).audit_log.records[0]

    assert actual.internal_reason == neutral.internal_reason
    assert "HB-2" in actual.internal_reason
    assert actual.agent_visible_feedback.startswith("DENIED (L1:HardBoundaries)")
    assert neutral.agent_visible_feedback == "Action was not executed."
    assert actual.feedback_condition == "ACTUAL"
    assert neutral.feedback_condition == "NEUTRALIZED"


# ---------------------------------------------------------------------------
# Requirement 5: one record per proposed action
# ---------------------------------------------------------------------------


def test_exactly_one_record_per_proposed_action_and_none_for_termination() -> None:
    res = _run(
        [
            ProposedAction(tool_name="read_document", arguments={"path": "/etc/shadow"}),
            ProposedAction(tool_name="get_time", arguments={}),
            ProposedAction(tool_name="calculate", arguments={"expression": "1 // 0"}),
            ProposedAction(tool_name="send_email", arguments={"to": "a@b.test", "body": "hi"}),
        ],
        allowed_tools=["read_document", "get_time", "calculate", "send_email"],
    )
    records = res.audit_log.records
    assert len(records) == len(res.trace.steps) == 4
    assert [r.step_id for r in records] == [s.step_id for s in res.trace.steps]
    assert [r.sequence for r in records] == [0, 1, 2, 3]
    assert [r.execution_status for r in records] == [
        ExecutionStatus.NOT_EXECUTED_DENIED,
        ExecutionStatus.EXECUTED,
        ExecutionStatus.TOOL_ERROR,
        ExecutionStatus.EXECUTED,
    ]
    assert records[3].is_protected_sink is True
    assert len(res.environment.sent_emails) == 1


def test_max_steps_exhaustion_still_records_every_action() -> None:
    res = _run([ProposedAction(tool_name="get_time", arguments={})] * 5, ["get_time"], max_steps=3)
    assert len(res.audit_log) == 3
    assert res.terminated_cleanly is False


def test_hallucinated_input_ids_recorded_as_proposed_but_not_accepted() -> None:
    res = _run(
        [ProposedAction(tool_name="get_time", arguments={}, input_node_ids=["ghost_node"])],
        ["get_time"],
    )
    [rec] = res.audit_log.records
    assert rec.proposed_input_node_ids == ["ghost_node"]
    assert rec.accepted_input_node_ids == []


def test_raw_tool_output_is_not_stored_in_audit_records() -> None:
    res = _run(
        [ProposedAction(tool_name="read_document", arguments={"path": "/tmp/payroll.txt"})],
        ["read_document"],
        documents={"/tmp/payroll.txt": {"content": SECRET_CONTENT, "trust": "TOOL_TRUSTED"}},
    )
    [rec] = res.audit_log.records
    assert rec.execution_status == ExecutionStatus.EXECUTED
    stored = rec.model_dump(mode="json")
    stored.pop("agent_visible_feedback")  # what the agent was shown is recorded by design
    assert SECRET_CONTENT not in json.dumps(stored)
    assert rec.output_digest == hashlib.sha256(json.dumps(SECRET_CONTENT).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Requirement 7: isolated branch audit logs
# ---------------------------------------------------------------------------


def test_branch_audit_logs_are_isolated() -> None:
    actions = [ProposedAction(tool_name="get_time", arguments={})]
    a = _run(actions, ["get_time"], branch="branch_a")
    b = _run(actions, ["get_time"], branch="branch_b", condition=FeedbackCondition.NEUTRALIZED)
    assert a.audit_log is not b.audit_log
    assert {r.session_id for r in a.audit_log.records} == {"m1_task_branch_a"}
    assert {r.session_id for r in b.audit_log.records} == {"m1_task_branch_b"}
    assert a.audit_log.records[0].prev_hash == b.audit_log.records[0].prev_hash == GENESIS_HASH


# ---------------------------------------------------------------------------
# Record-level consistency rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        # DENY paired with an execution
        dict(authorization=DecisionVerdict.DENY, deciding_layer="L1:HardBoundaries"),
        # ALLOW paired with a denial status
        dict(execution_status=ExecutionStatus.NOT_EXECUTED_DENIED, executed=False),
        # executed flag contradicting status
        dict(executed=False),
        dict(execution_status=ExecutionStatus.TOOL_ERROR, executed=True, error="x"),
        # TOOL_ERROR without an error description
        dict(execution_status=ExecutionStatus.TOOL_ERROR, executed=False),
        # non-executed action carrying an output
        dict(execution_status=ExecutionStatus.TOOL_ERROR, executed=False, error="x", output_digest="a" * 64),
        # DENY without naming the deciding layer
        dict(
            authorization=DecisionVerdict.DENY,
            execution_status=ExecutionStatus.NOT_EXECUTED_DENIED,
            executed=False,
        ),
    ],
)
def test_inconsistent_authorization_execution_combinations_rejected(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ActionAuditRecord(**_record_kwargs(**overrides))


def test_consistent_record_combinations_accepted() -> None:
    ActionAuditRecord(**_record_kwargs())
    ActionAuditRecord(
        **_record_kwargs(
            authorization=DecisionVerdict.DENY,
            deciding_layer="L4:ManualPolicy",
            execution_status=ExecutionStatus.NOT_EXECUTED_DENIED,
            executed=False,
        )
    )
    ActionAuditRecord(**_record_kwargs(execution_status=ExecutionStatus.TOOL_ERROR, executed=False, error="boom"))


# ---------------------------------------------------------------------------
# Tamper evidence
# ---------------------------------------------------------------------------


def _three_record_log() -> AuditLog:
    res = _run(
        [
            ProposedAction(tool_name="read_document", arguments={"path": "/etc/shadow"}),
            ProposedAction(tool_name="get_time", arguments={}),
            ProposedAction(tool_name="send_email", arguments={"to": "a@b.test", "body": "hi"}),
        ],
        ["read_document", "get_time", "send_email"],
    )
    return res.audit_log


def test_intact_chain_verifies_and_links() -> None:
    log = _three_record_log()
    assert log.verify() == []
    recs = log.records
    assert recs[0].prev_hash == GENESIS_HASH
    assert recs[1].prev_hash == recs[0].record_hash
    assert recs[2].prev_hash == recs[1].record_hash
    assert log.head_hash == recs[2].record_hash
    assert recs[0].record_hash == compute_record_hash(recs[0].model_dump(mode="json"))


def test_modified_record_detected() -> None:
    recs = _three_record_log().records
    recs[2] = recs[2].model_copy(update={"arguments": {"to": "attacker@evil.test", "body": "hi"}})
    assert any("record_hash mismatch" in e for e in verify_chain(recs))


def test_relabelled_authorization_detected() -> None:
    recs = _three_record_log().records
    # Bypass validation to simulate a forged on-disk record claiming the denial was an ALLOW.
    forged = recs[0].model_dump()
    forged.update(authorization=DecisionVerdict.ALLOW, deciding_layer=None)
    recs[0] = ActionAuditRecord.model_construct(**forged)
    assert verify_chain(recs)


def test_deleted_record_detected() -> None:
    recs = _three_record_log().records
    del recs[1]
    errors = verify_chain(recs)
    assert any("prev_hash" in e for e in errors)
    assert any("sequence" in e for e in errors)


def test_reordered_records_detected() -> None:
    recs = _three_record_log().records
    recs[1], recs[2] = recs[2], recs[1]
    assert verify_chain(recs)


def test_append_rejects_caller_supplied_chain_fields() -> None:
    log = AuditLog()
    with pytest.raises(ValueError, match="must not be supplied"):
        log.append(**_record_kwargs())


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def test_jsonl_round_trip_preserves_chain(tmp_path: Path) -> None:
    log = _three_record_log()
    path = tmp_path / "audit" / "branch_a.jsonl"
    log.write_jsonl(path)
    loaded = AuditLog.read_jsonl(path)
    assert loaded == log.records
    assert verify_chain(loaded) == []


def test_jsonl_tampering_on_disk_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    _three_record_log().write_jsonl(path)
    lines = path.read_text().splitlines()
    lines[1] = lines[1].replace('"get_time"', '"send_email"')
    path.write_text("\n".join(lines) + "\n")
    assert verify_chain(AuditLog.read_jsonl(path))


def test_jsonl_write_refuses_to_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = _three_record_log()
    log.write_jsonl(path)
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        log.write_jsonl(path)
    assert path.read_bytes() == original
