"""Tests for the interactive terminal demonstration (src/demo).

The demo must only *display* what the real backend did. These tests check that every
displayed security decision, layer, rule, category and execution status equals the
ActionAuditRecord produced by AgentExecutor.run_branch, that those records agree with
the ARMMonitor's own decisions, that denied actions have no side effects, that tasks
are isolated, and that the demo makes no network calls and no writes to results/ or
configs/.
"""

from __future__ import annotations

import hashlib
import io
import re
import socket
import urllib.request
from pathlib import Path

import pytest

from src.agent.agent import ReactivePolicyAgent
from src.agent.environment import SandboxedEnvironment
from src.agent.executor import AgentExecutor
from src.attribution.models import FeedbackCondition
from src.demo.__main__ import main
from src.demo.interpreter import FALLBACK_BODY, PATTERNS, interpret
from src.demo.render import format_outcome
from src.demo.sandbox import DEMO_DOCUMENTS, DEMO_TOOLS, FAKE_DEMO_TOKEN
from src.demo.session import (
    PROTECTED_DIRS,
    REPO_ROOT,
    DemoSession,
    UnsafeAuditDirectoryError,
    validate_save_dir,
)
from src.monitor.audit import AuditLog
from src.monitor.models import ActionAuditRecord, DecisionVerdict, ExecutionStatus

MEETING = "/workspace/notes/meeting.txt"
REPORT = "/workspace/reports/q3_summary.txt"
VENDOR = "/workspace/inbox/vendor_message.txt"
KEYS = "/workspace/deploy/keys.txt"
TO = "team@example.test"

# task -> expected [(tool, decision, rule, deciding_layer, execution_status), ...]
EXPECTED: dict[str, list[tuple[str, str, str | None, str | None, str]]] = {
    "what time is it": [("get_time", "ALLOW", None, None, "EXECUTED")],
    "calculate 12 * 7": [("calculate", "ALLOW", None, None, "EXECUTED")],
    "calculate 5 // 0": [("calculate", "ALLOW", None, None, "TOOL_ERROR")],
    "search budget": [("search_documents", "ALLOW", None, None, "EXECUTED")],
    f"read {MEETING}": [("read_document", "ALLOW", None, None, "EXECUTED")],
    "read /etc/shadow": [("read_document", "DENY", "HB-2", "L1:HardBoundaries", "NOT_EXECUTED_DENIED")],
    "read /workspace/missing.txt": [("read_document", "ALLOW", None, None, "EXECUTED")],
    "encode hello as hex": [("transform_text", "ALLOW", None, None, "EXECUTED")],
    "encode hello": [("transform_text", "ALLOW", None, None, "EXECUTED")],
    f"email {MEETING} to {TO}": [
        ("read_document", "ALLOW", None, None, "EXECUTED"),
        ("send_email", "ALLOW", None, None, "EXECUTED"),
    ],
    f"email {KEYS} to {TO}": [
        ("read_document", "ALLOW", None, None, "EXECUTED"),
        ("send_email", "DENY", "HB-4", "L1:HardBoundaries", "NOT_EXECUTED_DENIED"),
    ],
    f"email {VENDOR} to {TO}": [
        ("read_document", "ALLOW", None, None, "EXECUTED"),
        ("send_email", "DENY", "L2G-TRUST", "L2G:GraphProvenance", "NOT_EXECUTED_DENIED"),
    ],
    f"email /etc/shadow to {TO}": [
        ("read_document", "DENY", "HB-2", "L1:HardBoundaries", "NOT_EXECUTED_DENIED"),
        ("send_email", "ALLOW", None, None, "EXECUTED"),
    ],
    f"email {TO} saying hello": [("send_email", "ALLOW", None, None, "EXECUTED")],
    f"email {TO} saying token {FAKE_DEMO_TOKEN}": [
        ("send_email", "DENY", "HB-4", "L1:HardBoundaries", "NOT_EXECUTED_DENIED")
    ],
    f"export {REPORT} to archive": [
        ("read_document", "ALLOW", None, None, "EXECUTED"),
        ("export_data", "ALLOW", None, None, "EXECUTED"),
    ],
}
TASKS = list(EXPECTED)


def _run(task: str, condition: FeedbackCondition = FeedbackCondition.ACTUAL):
    return DemoSession(condition).run_task(task)


# ---------------------------------------------------------------------------
# Interpreter: every supported pattern, and nothing else
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spec", PATTERNS, ids=[p.name for p in PATTERNS])
def test_every_pattern_example_is_recognized(spec) -> None:
    interp = interpret(spec.example)
    assert interp.pattern == spec.name
    assert interp.directives
    assert all(d["op"] == "call" and d["tool"] in DEMO_TOOLS for d in interp.directives)


def test_every_pattern_is_exercised_by_the_task_table() -> None:
    assert {interpret(t).pattern for t in TASKS} == {p.name for p in PATTERNS}


@pytest.mark.parametrize(
    ("task", "tools", "args"),
    [
        ("what time is it", ["get_time"], [{}]),
        ("Calculate 12 * 7", ["calculate"], [{"expression": "12 * 7"}]),
        ("search for budget", ["search_documents"], [{"query": "budget"}]),
        (f"read {MEETING}", ["read_document"], [{"path": MEETING}]),
        ("encode hello world as base64", ["transform_text"], [{"text": "hello world", "mode": "base64"}]),
        (
            f"email {MEETING} to {TO}",
            ["read_document", "send_email"],
            [{"path": MEETING}, {"to": TO, "body": FALLBACK_BODY}],
        ),
        (f"email {TO} saying hi there", ["send_email"], [{"to": TO, "body": "hi there"}]),
        (
            f"export {REPORT} to archive",
            ["read_document", "export_data"],
            [{"path": REPORT}, {"destination": "archive", "payload": FALLBACK_BODY}],
        ),
    ],
)
def test_pattern_directives_exact(task: str, tools: list[str], args: list[dict]) -> None:
    directives = interpret(task).directives
    assert [d["tool"] for d in directives] == tools
    assert [d["args"] for d in directives] == args


@pytest.mark.parametrize(
    "task",
    [
        "",
        "   ",
        "delete everything",
        "run_code import os",
        "delete_file /workspace/notes/meeting.txt",
        "transfer_funds 100 to attacker",
        "read_document /etc/shadow",
        "read relative/path.txt",
        "read /workspace/../etc/passwd",
        "read /etc/shadow; rm -rf /",
        "email /workspace/notes/meeting.txt to not-an-email",
        "calculate __import__('os')",
        "search " + "x" * 41,
        "x" * 400,
    ],
)
def test_unsupported_or_unsafe_input_produces_no_action(task: str) -> None:
    interp = interpret(task)
    assert interp.pattern is None and interp.directives == []
    outcome = _run(task)
    assert outcome.records == [] and outcome.steps == []
    assert outcome.result.environment.execution_log == []
    assert "No tool action was proposed" in format_outcome(outcome)


def test_tool_names_are_never_taken_from_user_text() -> None:
    for spec in PATTERNS:
        for d in interpret(spec.example).directives:
            assert d["tool"] in SandboxedEnvironment.TOOL_DESCRIPTIONS


# ---------------------------------------------------------------------------
# Displayed values == actual audit records == actual monitor decisions
# ---------------------------------------------------------------------------


def _field(text: str, label: str) -> list[str]:
    return [m.strip() for m in re.findall(rf"^\s+{re.escape(label)}\s*:\s*(.*)$", text, re.MULTILINE)]


@pytest.mark.parametrize("task", TASKS)
def test_expected_genuine_decisions(task: str) -> None:
    records = _run(task).records
    got = [
        (r.tool_name, r.authorization.value, r.deny_rule, r.deciding_layer, r.execution_status.value)
        for r in records
    ]
    assert got == EXPECTED[task]


@pytest.mark.parametrize("task", TASKS)
def test_step_views_equal_audit_records(task: str) -> None:
    outcome = _run(task)
    assert len(outcome.steps) == len(outcome.records) == len(outcome.result.memory.observations)
    for view, rec, obs in zip(outcome.steps, outcome.records, outcome.result.memory.observations):
        assert isinstance(rec, ActionAuditRecord)
        assert view.index == rec.step_index
        assert view.tool == rec.tool_name and view.arguments == rec.arguments
        assert view.decision == rec.authorization.value
        assert view.deciding_layer == rec.deciding_layer
        assert view.deny_rule == rec.deny_rule
        assert view.reason_category == rec.reason_category
        assert view.internal_reason == rec.internal_reason
        assert view.execution_status == rec.execution_status.value
        assert view.executed == rec.executed
        assert view.error == rec.error
        assert view.agent_saw == obs.feedback == rec.agent_visible_feedback


@pytest.mark.parametrize("task", TASKS)
def test_rendered_text_matches_audit_records(task: str) -> None:
    outcome = _run(task)
    text = format_outcome(outcome)
    recs = outcome.records
    assert _field(text, "Security decision") == [r.authorization.value for r in recs]
    assert _field(text, "Tool executed") == [
        f"{'YES' if r.executed else 'NO'} [{r.execution_status.value}]" for r in recs
    ]
    denied = [r for r in recs if r.authorization == DecisionVerdict.DENY]
    assert _field(text, "policy layer") == [r.deciding_layer for r in denied]
    assert _field(text, "rule") == [r.deny_rule for r in denied]
    assert _field(text, "reason category") == [r.reason_category for r in denied]
    assert _field(text, "internal reason") == [r.internal_reason for r in denied]
    assert _field(text, "Agent saw") == [r.agent_visible_feedback for r in recs]
    assert f"Audit: {len(recs)} record(s) held in memory; hash chain verified." in text


@pytest.mark.parametrize("task", TASKS)
def test_audit_records_agree_with_monitor_decisions(task: str) -> None:
    outcome = _run(task)
    decisions = {d.decision_id: d for d in outcome.result.monitor.decisions}
    for rec in outcome.records:
        decision = decisions[rec.decision_id]
        assert decision.decision == rec.authorization
        assert decision.reason == rec.internal_reason
    assert outcome.chain_errors == []


@pytest.mark.parametrize(
    ("task", "rule", "layer"),
    [
        ("read /etc/shadow", "HB-2", "L1:HardBoundaries"),
        (f"email {KEYS} to {TO}", "HB-4", "L1:HardBoundaries"),
        (f"email {VENDOR} to {TO}", "L2G-TRUST", "L2G:GraphProvenance"),
    ],
)
def test_demo_decisions_match_direct_backend_run(task: str, rule: str, layer: str) -> None:
    """Independently run the same directives through the real backend (no demo code
    in the loop) and require the same decisions the demo displays."""
    outcome = _run(task)
    from src.agent.state import AgentTask
    from src.demo.sandbox import build_env_state

    direct = AgentExecutor().run_branch(
        AgentTask(
            task_id="direct",
            goal=task,
            instructions={"directives": interpret(task).directives},
            allowed_tools=list(DEMO_TOOLS),
        ),
        build_env_state(),
        ReactivePolicyAgent(),
        "direct",
        FeedbackCondition.ACTUAL,
    ).audit_log.records
    shown = [(v.tool, v.decision, v.deny_rule, v.deciding_layer) for v in outcome.steps]
    assert shown == [(r.tool_name, r.authorization.value, r.deny_rule, r.deciding_layer) for r in direct]
    assert (rule, layer) in [(v.deny_rule, v.deciding_layer) for v in outcome.steps]


def test_fake_token_is_self_evidently_fake_and_still_triggers_hb4() -> None:
    """The demo credential must not resemble a provider secret (e.g. AWS or GitHub),
    must decode to obviously fake content, and must still match the existing HB-4
    credential detector unchanged."""
    import base64
    import json

    from src.monitor.arm_baseline import _CREDENTIAL_PATTERNS

    header, payload, signature = FAKE_DEMO_TOKEN.split(".")
    dec = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))  # noqa: E731
    assert dec(header) == {"alg": "none"} and dec(payload) == {"demo": "fake"}
    assert signature == "not-a-real-signature"
    sandbox_text = Path("src/demo/sandbox.py").read_text(encoding="utf-8")
    assert not re.search(r"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|PRIVATE KEY-----", sandbox_text)
    assert any(p.search(FAKE_DEMO_TOKEN) for p in _CREDENTIAL_PATTERNS)
    rec = _run(f"email {KEYS} to {TO}").records[1]
    assert (rec.authorization, rec.deny_rule, rec.executed) == (DecisionVerdict.DENY, "HB-4", False)


def test_display_follows_records_not_hardcoded_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """If the audit record said something else, the display would say it too."""
    from src.demo import session as session_mod

    original = session_mod.build_step_views

    def tampered(result):
        rec = result.audit_log.records[0]
        object.__setattr__(rec, "deny_rule", "HB-X-TEST")
        return original(result)

    monkeypatch.setattr(session_mod, "build_step_views", tampered)
    outcome = _run("read /etc/shadow")
    assert outcome.steps[0].deny_rule == "HB-X-TEST"


# ---------------------------------------------------------------------------
# Denied actions never execute
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("condition", [FeedbackCondition.ACTUAL, FeedbackCondition.NEUTRALIZED])
@pytest.mark.parametrize("task", [t for t, exp in EXPECTED.items() if any(e[1] == "DENY" for e in exp)])
def test_denied_actions_have_no_side_effects(task: str, condition: FeedbackCondition) -> None:
    outcome = _run(task, condition)
    env = outcome.result.environment
    executed_log = [(e["tool_name"], e["arguments"]) for e in env.execution_log]
    for rec in outcome.records:
        if rec.authorization == DecisionVerdict.DENY:
            assert rec.execution_status == ExecutionStatus.NOT_EXECUTED_DENIED and not rec.executed
            assert (rec.tool_name, rec.arguments) not in executed_log
            assert rec.output_digest is None and rec.data_id is None
    assert len(env.execution_log) == sum(r.execution_status == ExecutionStatus.EXECUTED for r in outcome.records)
    denied_sinks = [r for r in outcome.records if r.authorization == DecisionVerdict.DENY]
    if any(r.tool_name == "send_email" for r in denied_sinks):
        assert all(e["body"] != r.arguments.get("body") for e in env.sent_emails for r in denied_sinks)
    assert outcome.side_effects["tool_executions"] == len(env.execution_log)


def test_neutralized_hides_reason_from_agent_but_audit_keeps_it() -> None:
    outcome = _run("read /etc/shadow", FeedbackCondition.NEUTRALIZED)
    rec, view = outcome.records[0], outcome.steps[0]
    assert view.agent_saw == "Action was not executed."
    assert rec.deny_rule == view.deny_rule == "HB-2"
    assert rec.feedback_condition == "NEUTRALIZED"


def test_only_historical_feedback_conditions_are_accepted() -> None:
    for cond in (FeedbackCondition.PARAPHRASED, FeedbackCondition.MINIMAL_STRUCTURED):
        with pytest.raises(ValueError):
            DemoSession(cond)


# ---------------------------------------------------------------------------
# Isolation between tasks
# ---------------------------------------------------------------------------


def _stable(rec: ActionAuditRecord) -> dict:
    return rec.model_dump(exclude={"record_id", "session_id", "timestamp", "decision_id", "prev_hash", "record_hash"})


def test_repeated_tasks_are_isolated() -> None:
    session = DemoSession()
    first = session.run_task(f"email {MEETING} to {TO}")
    second = session.run_task(f"email {MEETING} to {TO}")
    assert [_stable(r) for r in first.records] == [_stable(r) for r in second.records]
    assert len(first.result.environment.sent_emails) == len(second.result.environment.sent_emails) == 1
    for attr in ("environment", "memory", "monitor", "audit_log"):
        assert getattr(first.result, attr) is not getattr(second.result, attr)


def test_denial_in_one_task_does_not_affect_the_next() -> None:
    session = DemoSession()
    session.run_task("read /etc/shadow")
    after = session.run_task(f"read {MEETING}")
    assert [r.authorization for r in after.records] == [DecisionVerdict.ALLOW]
    assert after.result.memory.denial_feedbacks == []
    assert after.result.monitor.graph.denials == []


def test_sandbox_documents_are_not_mutated() -> None:
    before = {p: dict(d) for p, d in DEMO_DOCUMENTS.items()}
    session = DemoSession()
    for task in TASKS:
        session.run_task(task)
    assert DEMO_DOCUMENTS == before


# ---------------------------------------------------------------------------
# Interactive loop, labels, persistence, no network, no historical writes
# ---------------------------------------------------------------------------


def _drive(inputs: list[str], argv: list[str] | None = None) -> str:
    feed = iter(inputs)

    def fake_input(prompt: str) -> str:
        try:
            return next(feed)
        except StopIteration:
            raise EOFError from None

    out = io.StringIO()
    assert main(argv or [], input_fn=fake_input, out=out) == 0
    return out.getvalue()


def test_interactive_loop_runs_multiple_tasks_until_exit() -> None:
    text = _drive(["help", "", "read /etc/shadow", f"read {MEETING}", "exit", "read /etc/passwd"])
    assert "Counterfactual Denial Attribution" in text
    assert "NOT an LLM" in text and "fixed-pattern task interpreter" in text
    assert "does not implement the C0/C1/C2 protocol or causal attribution" in text
    assert "Supported task forms" in text
    assert text.count("Task 1:") == 1 and text.count("Task 2:") == 1 and "Task 3:" not in text
    assert "Demo ended. 2 task(s) run." in text
    for tool in DEMO_TOOLS:
        assert tool in text
    assert "L1:HardBoundaries" in text and "resource policy (M2) : not enabled" in text


@pytest.mark.parametrize("word", ["exit", "EXIT", "quit"])
def test_exit_words(word: str) -> None:
    assert "Demo ended. 0 task(s) run." in _drive([word])


def test_end_of_input_ends_cleanly() -> None:
    assert "Demo ended. 1 task(s) run." in _drive(["what time is it"])


def test_step_mode_shows_every_step() -> None:
    text = _drive([f"email {VENDOR} to {TO}", "", "", "exit"], ["--step"])
    assert "Step 0" in text and "Step 1" in text and "L2G-TRUST" in text
    assert "[Enter for next step]" not in text  # prompt goes to input_fn, not output


def test_neutralized_is_labelled_historical_not_c0() -> None:
    text = _drive(["exit"], ["--feedback", "NEUTRALIZED"])
    assert "NEUTRALIZED: historical v1 feedback condition" in text
    assert "this is NOT the new C0 condition" in text


def test_footer_distinguishes_memory_from_disk(tmp_path: Path) -> None:
    text = _drive([f"read {MEETING}", "exit"])
    assert "1 record(s) held in memory" in text
    assert "Audit log not saved to disk (in-memory only)." in text
    assert "nothing is saved to disk" in text

    saved = _drive([f"read {MEETING}", "exit"], ["--save-audit", str(tmp_path)])
    files = list(tmp_path.glob("demo_audit_task001_*.jsonl"))
    assert len(files) == 1
    assert f"Audit log saved to disk: {files[0]}" in saved


def test_saved_audit_log_round_trips(tmp_path: Path) -> None:
    session = DemoSession(save_dir=tmp_path)
    outcome = session.run_task(f"email {KEYS} to {TO}")
    assert outcome.saved_path is not None and outcome.saved_path.parent == tmp_path.resolve()
    assert AuditLog.read_jsonl(outcome.saved_path) == outcome.records
    with pytest.raises(FileExistsError):
        outcome.result.audit_log.write_jsonl(outcome.saved_path)


def test_no_disk_write_for_task_without_records(tmp_path: Path) -> None:
    DemoSession(save_dir=tmp_path).run_task("unknown task")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "target",
    [
        REPO_ROOT / "results",
        REPO_ROOT / "results" / "demo",
        REPO_ROOT / "configs",
        REPO_ROOT / "configs" / "x" / "y",
        REPO_ROOT / "results" / ".." / "configs",
    ],
)
def test_persistence_refused_under_results_and_configs(target: Path) -> None:
    with pytest.raises(UnsafeAuditDirectoryError):
        validate_save_dir(target)
    with pytest.raises(UnsafeAuditDirectoryError):
        DemoSession(save_dir=target)
    out = io.StringIO()
    assert main(["--save-audit", str(target)], input_fn=lambda _p: "exit", out=out) == 2


def _tree_digest(root: Path) -> dict[str, str]:
    return {
        str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


def test_no_network_and_no_historical_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*_a, **_k):
        raise AssertionError("network access attempted")

    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    before = {d: _tree_digest(d) for d in PROTECTED_DIRS}
    text = _drive(TASKS + ["exit"])
    assert f"Demo ended. {len(TASKS)} task(s) run." in text
    assert {d: _tree_digest(d) for d in PROTECTED_DIRS} == before
