"""Plain-text rendering for the terminal demonstration (no decisions are made here)."""

from __future__ import annotations

import json
from typing import Any

from src.attribution.models import FeedbackCondition
from src.demo.interpreter import PATTERNS
from src.demo.sandbox import DEMO_TOOLS, DOCUMENT_NOTES
from src.demo.session import StepView, TaskOutcome
from src.agent.environment import SandboxedEnvironment

PROJECT_NAME = "Counterfactual Denial Attribution: Backend Demonstration"
RULE = "=" * 72
THIN = "-" * 72

_FEEDBACK_LABELS = {
    FeedbackCondition.ACTUAL: (
        "ACTUAL: historical v1 feedback condition; the agent sees the monitor's denial text"
    ),
    FeedbackCondition.NEUTRALIZED: (
        "NEUTRALIZED: historical v1 feedback condition; the agent sees 'Action was not executed.' "
        "(this is NOT the new C0 condition)"
    ),
}


def _j(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def banner(monitor: dict[str, Any], feedback: FeedbackCondition, save_dir: str | None) -> str:
    lines = [
        RULE,
        PROJECT_NAME,
        RULE,
        "Agent status : READY. Deterministic scripted agent (ReactivePolicyAgent) driven by",
        "               a fixed-pattern task interpreter. NOT an LLM; no model is called.",
        "Environment  : in-memory synthetic sandbox (no real files, network or email).",
        "Available tools:",
    ]
    lines += [f"  - {t:<17} {SandboxedEnvironment.TOOL_DESCRIPTIONS[t]}" for t in DEMO_TOOLS]
    lines += [
        "Security monitor: ACTIVE. Existing ARM-inspired ARMMonitor (authoritative ALLOW/DENY).",
        f"  layers evaluated     : {' -> '.join(monitor['layers'])}",
        f"  provenance mode      : {monitor['provenance_mode']}",
        f"  trust threshold      : {monitor['trust_threshold']}",
        f"  protected sinks      : {', '.join(monitor['protected_sinks'])}",
        f"  sensitive path rules : {len(monitor['sensitive_path_patterns'])} patterns",
        f"  resource policy (M2) : {'enabled' if monitor['resource_policy_enabled'] else 'not enabled'}",
        f"Feedback condition: {_FEEDBACK_LABELS[feedback]}",
        "Scope: this demo shows real monitor decisions on the historical v1 executor path.",
        "       It does not implement the C0/C1/C2 protocol or causal attribution.",
        "Audit records: kept in memory"
        + (f"; each task's log is also saved to {save_dir}" if save_dir else "; nothing is saved to disk."),
        "Type 'help' for supported tasks, 'exit' to quit.",
        RULE,
    ]
    return "\n".join(lines)


def help_text() -> str:
    lines = ["Supported task forms (fixed patterns, not free-form language):"]
    lines += [f"  {p.example:<58} -> {p.description}" for p in PATTERNS]
    lines.append("Sandbox documents:")
    lines += [f"  {path:<38} {note}" for path, note in DOCUMENT_NOTES.items()]
    lines.append("Any other path is simply 'not found' in the sandbox; the real filesystem is never read.")
    return "\n".join(lines)


def format_step(view: StepView) -> str:
    lines = [
        THIN,
        f"Step {view.index}",
        f"  Proposed action    : {view.tool} {_j(view.arguments)}",
        f"  Security decision  : {view.decision}",
    ]
    if view.decision == "DENY":
        lines += [
            "  Evaluator view (from the audit record; the agent receives only 'Agent saw'):",
            f"    policy layer     : {view.deciding_layer}",
            f"    rule             : {view.deny_rule}",
            f"    reason category  : {view.reason_category}",
            f"    internal reason  : {view.internal_reason}",
        ]
    else:
        lines.append(f"  Evaluator view     : {view.internal_reason} (from the audit record)")
    executed = "YES" if view.executed else "NO"
    lines.append(f"  Tool executed      : {executed} [{view.execution_status}]")
    if view.error:
        lines.append(f"  Tool error         : {view.error}")
    lines += [
        f"  Agent saw          : {view.agent_saw}",
        f"  Agent's next action: {view.next_action}",
    ]
    return "\n".join(lines)


def format_header(outcome: TaskOutcome) -> str:
    interp = outcome.interpretation
    lines = [f"Task {outcome.task_number}: {interp.text!r}"]
    if interp.recognized:
        lines.append(f"Interpreter: matched fixed pattern '{interp.pattern}'.")
    else:
        lines.append(f"Interpreter: {interp.message}")
    if not outcome.steps:
        lines.append(
            f"No tool action was proposed. Agent terminated: {outcome.result.termination_reason}"
        )
    return "\n".join(lines)


def format_outcome(outcome: TaskOutcome) -> str:
    parts = [format_header(outcome)] + [format_step(v) for v in outcome.steps] + [format_footer(outcome)]
    return "\n".join(parts)


def format_footer(outcome: TaskOutcome) -> str:
    lines = [THIN]
    fx = outcome.side_effects
    lines.append(
        f"Sandbox side effects: {fx['tool_executions']} tool execution(s), "
        f"{fx['simulated_emails']} simulated email(s), {fx['simulated_exports']} simulated export(s)."
    )
    chain = "verified" if not outcome.chain_errors else f"FAILED: {outcome.chain_errors}"
    lines.append(f"Audit: {len(outcome.records)} record(s) held in memory; hash chain {chain}.")
    if outcome.saved_path is not None:
        lines.append(f"Audit log saved to disk: {outcome.saved_path}")
    else:
        lines.append("Audit log not saved to disk (in-memory only).")
    return "\n".join(lines)
