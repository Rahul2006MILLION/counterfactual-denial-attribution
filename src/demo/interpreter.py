"""Fixed-pattern task interpreter for the terminal demonstration.

This is deliberately NOT natural-language understanding and NOT an LLM. A typed task
is matched against a small, fixed list of patterns; a match produces directives for
the existing deterministic ``ReactivePolicyAgent``. Anything else produces no
directives, so the agent proposes no tool call.

Input safety: only the tools listed in ``src.demo.sandbox.DEMO_TOOLS`` can ever be
named (the patterns hard-code the tool), arguments are restricted by strict regular
expressions, and paths are only looked up in the in-memory synthetic sandbox.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

MAX_TASK_CHARS = 300

_PATH = r"~?/[A-Za-z0-9._/-]{1,120}"
_EMAIL = r"[A-Za-z0-9._+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+"
_DEST = r"[A-Za-z0-9._:/-]{1,80}"

# Body sent if the agent has no produced output to cite (e.g. its read was denied).
FALLBACK_BODY = "Requested document was unavailable."


@dataclass(frozen=True)
class PatternSpec:
    name: str
    example: str
    description: str
    regex: re.Pattern[str]


@dataclass
class Interpretation:
    """Result of interpreting one typed task."""

    text: str
    pattern: str | None
    directives: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    @property
    def recognized(self) -> bool:
        return self.pattern is not None


def _p(rx: str) -> re.Pattern[str]:
    return re.compile(rx, re.IGNORECASE)


PATTERNS: tuple[PatternSpec, ...] = (
    PatternSpec("time", "what time is it", "get_time", _p(r"^(?:what time is it|time|get time)\??$")),
    PatternSpec(
        "calculate", "calculate 12 * 7", "calculate (+ - * // % only)",
        _p(r"^(?:calculate|calc|compute)\s+(?P<expr>[0-9+\-*/%(). ]{1,64})$"),
    ),
    PatternSpec(
        "search", "search budget", "search_documents",
        _p(r"^(?:search|find)\s+(?:for\s+)?(?P<query>[A-Za-z0-9 _.-]{1,40})$"),
    ),
    PatternSpec("read", "read /workspace/notes/meeting.txt", "read_document", _p(rf"^(?:read|open|show)\s+(?P<path>{_PATH})$")),
    PatternSpec(
        "encode", "encode hello as base64", "transform_text (base64, hex, summary or tag)",
        _p(r"^encode\s+(?P<text>.{1,120}?)(?:\s+as\s+(?P<mode>base64|hex|summary|tag))?$"),
    ),
    PatternSpec(
        "email_document", "email /workspace/notes/meeting.txt to team@example.test",
        "read_document, then send_email with its content (simulated)",
        _p(rf"^(?:email|send)\s+(?P<path>{_PATH})\s+to\s+(?P<to>{_EMAIL})$"),
    ),
    PatternSpec(
        "email_text", "email team@example.test saying hello",
        "send_email with literal text (simulated)",
        _p(rf"^email\s+(?P<to>{_EMAIL})\s+(?:saying|message|with)\s+(?P<text>.{{1,200}})$"),
    ),
    PatternSpec(
        "export_document", "export /workspace/reports/q3_summary.txt to archive",
        "read_document, then export_data with its content (simulated)",
        _p(rf"^export\s+(?P<path>{_PATH})\s+to\s+(?P<dest>{_DEST})$"),
    ),
)


def _call(tool: str, args: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"op": "call", "tool": tool, "args": args, **extra}


def _directives(name: str, g: dict[str, str]) -> list[dict[str, Any]]:
    if name == "time":
        return [_call("get_time", {})]
    if name == "calculate":
        return [_call("calculate", {"expression": g["expr"].strip()})]
    if name == "search":
        return [_call("search_documents", {"query": g["query"].strip()})]
    if name == "read":
        return [_call("read_document", {"path": g["path"]})]
    if name == "encode":
        return [_call("transform_text", {"text": g["text"], "mode": (g.get("mode") or "base64").lower()})]
    if name == "email_document":
        return [
            _call("read_document", {"path": g["path"]}),
            _call("send_email", {"to": g["to"], "body": FALLBACK_BODY}, use_last_output=True, body_template="{val}"),
        ]
    if name == "email_text":
        return [_call("send_email", {"to": g["to"], "body": g["text"]})]
    if name == "export_document":
        return [
            _call("read_document", {"path": g["path"]}),
            _call(
                "export_data", {"destination": g["dest"], "payload": FALLBACK_BODY},
                use_last_output=True, payload_template="{val}",
            ),
        ]
    raise AssertionError(f"unhandled pattern {name}")  # pragma: no cover


def interpret(text: str) -> Interpretation:
    """Match ``text`` against the fixed patterns; never invents an action."""
    task = " ".join(text.strip().split())
    if not task:
        return Interpretation(text=task, pattern=None, message="Empty task.")
    if len(task) > MAX_TASK_CHARS:
        return Interpretation(text=task[:MAX_TASK_CHARS], pattern=None, message="Task too long for the demo interpreter.")
    for spec in PATTERNS:
        m = spec.regex.match(task)
        if m is None:
            continue
        groups = {k: v for k, v in m.groupdict().items() if v is not None}
        if ".." in groups.get("path", "").split("/"):
            return Interpretation(text=task, pattern=None, message="Relative path segments ('..') are not accepted.")
        return Interpretation(text=task, pattern=spec.name, directives=_directives(spec.name, groups))
    return Interpretation(
        text=task,
        pattern=None,
        message="The fixed-pattern interpreter did not recognize this task (type 'help' for supported forms).",
    )
