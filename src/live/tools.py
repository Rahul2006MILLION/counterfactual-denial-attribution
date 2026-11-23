"""Allowlisted tool registry for the live agent.

Every tool is plain Python operating on already-extracted document text. There is no
shell, network, or arbitrary file access tool, and uploaded code is never executed:
code analysis is static (ast / pattern based). The model can only propose a tool by
name from this registry with arguments that validate against the tool's schema.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from src.agent.environment import _safe_eval_expr  # existing safe arithmetic evaluator
from src.monitor.arm_baseline import _CREDENTIAL_PATTERNS  # reuse HB-4 credential patterns
from src.live.sensitive import assess_text

if TYPE_CHECKING:
    from src.live.agent import TaskContext

DOC_ID = r"^D[1-9][0-9]?$"


class ToolInputError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Argument schemas (extra fields forbidden; strings bounded)
# ---------------------------------------------------------------------------


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class DocArgs(_Args):
    doc_id: str = Field(..., pattern=DOC_ID)


class SearchArgs(_Args):
    doc_id: str = Field(..., pattern=DOC_ID)
    query: str = Field(..., min_length=1, max_length=80)


class TableArgs(_Args):
    doc_id: str = Field(..., pattern=DOC_ID)
    column: str | None = Field(default=None, max_length=80)
    group_by: str | None = Field(default=None, max_length=80)


class CalcArgs(_Args):
    expression: str = Field(..., min_length=1, max_length=120, pattern=r"^[0-9+\-*/%(). ]+$")


class SummarizeArgs(_Args):
    doc_id: str = Field(..., pattern=DOC_ID)
    focus: str | None = Field(default=None, max_length=120)


class ReportArgs(_Args):
    filename: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,60}\.(md|txt)$")
    content: str = Field(..., min_length=1, max_length=9000)


class EmailArgs(_Args):
    to: str = Field(..., max_length=120, pattern=r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24}$")
    subject: str = Field(..., min_length=1, max_length=120)
    body: str = Field(..., min_length=1, max_length=9000)


@dataclass
class ToolSpec:
    name: str
    description: str
    args_model: type[_Args]
    run: Callable[["TaskContext", Any], dict[str, Any]]
    requires_approval: bool = False
    protected_sink: bool = False
    max_calls: int = 6
    planner_visible: bool = True
    arg_hint: dict[str, str] = field(default_factory=dict)
    # A consequential action has effects outside this system (e.g. disclosure).
    consequential: bool = False
    action_label: str = ""
    approval_reason: str = ""


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------


def _doc(ctx: "TaskContext", doc_id: str):
    doc = ctx.docs.get(doc_id)
    if doc is None:
        raise ToolInputError(f"Document {doc_id} is not part of this task.")
    return doc


def t_load_document(ctx: "TaskContext", a: DocArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    return {"doc_id": a.doc_id, "name": doc.meta.name, **doc.extracted.summary()}


def t_search_text(ctx: "TaskContext", a: SearchArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    q = a.query.lower()
    hits = []
    for n, line in enumerate(ctx.model_text(doc).splitlines(), 1):
        if q in line.lower():
            hits.append({"line": n, "text": line.strip()[:200]})
            if len(hits) >= 40:
                break
    return {"query": a.query, "matches": len(hits), "hits": hits}


_MONTHS = r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
_DATE_RX = re.compile(
    rf"\b(\d{{4}}-\d{{2}}-\d{{2}}"
    rf"|\d{{1,2}}[/.]\d{{1,2}}[/.]\d{{2,4}}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?\s+{_MONTHS}\.?,?\s+\d{{4}}"
    rf"|{_MONTHS}\.?\s+\d{{1,2}}(?:st|nd|rd|th)?,?\s+\d{{4}}"
    rf"|{_MONTHS}\s+\d{{4}}"
    rf"|Q[1-4]\s+\d{{4}})\b",
    re.IGNORECASE,
)


def t_extract_dates(ctx: "TaskContext", a: DocArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    found, seen = [], set()
    for n, line in enumerate(ctx.model_text(doc).splitlines(), 1):
        for m in _DATE_RX.finditer(line):
            key = (m.group(0).lower(), n)
            if key in seen:
                continue
            seen.add(key)
            s = max(0, m.start() - 60)
            found.append({"date": m.group(0), "line": n, "context": line[s : m.end() + 60].strip()})
            if len(found) >= 60:
                return {"count": len(found), "dates": found, "capped": True}
    return {"count": len(found), "dates": found, "capped": False}


def _num(s: str) -> float | None:
    t = s.strip().replace(",", "").replace("$", "").replace("£", "").replace("€", "")
    pct = t.endswith("%")
    t = t.rstrip("%")
    if not t or t.lower() in {"na", "n/a", "nan", "null", "none", "-"}:
        return None
    try:
        v = float(t)
    except ValueError:
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    return v / 100 if pct else v


def t_table_stats(ctx: "TaskContext", a: TableArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    rows = doc.extracted.table
    if not rows:
        raise ToolInputError(f"{a.doc_id} is not a table (CSV or XLSX).")
    width = max(len(r) for r in rows)
    rows = [r + [""] * (width - len(r)) for r in rows]
    first = rows[0]
    has_header = sum(_num(c) is None and c.strip() != "" for c in first) >= max(1, width // 2)
    header = [c.strip() or f"col{i + 1}" for i, c in enumerate(first)] if has_header else [f"col{i + 1}" for i in range(width)]
    data = rows[1:] if has_header else rows

    def find(name: str) -> int:
        match = [i for i, h in enumerate(header) if h.lower() == name.strip().lower()]
        if not match:
            raise ToolInputError(f"Column '{name}' not found. Columns: {', '.join(header)}")
        return match[0]

    cols = range(width)
    if a.column:
        cols = [find(a.column)]
    out: dict[str, Any] = {"rows": len(data), "columns": header, "stats": {}}
    if a.group_by:
        g = find(a.group_by)
        numeric = [i for i in cols if i != g and sum(_num(r[i]) is not None for r in data) >= 0.6 * max(1, len(data))]
        groups: dict[str, list[list[str]]] = {}
        for r in data:
            groups.setdefault(ctx.redact_label(r[g].strip()) or "(blank)", []).append(r)
        out["group_by"] = header[g]
        out["groups"] = {}
        for key, members in sorted(groups.items()):
            entry: dict[str, Any] = {"rows": len(members)}
            for i in numeric:
                nums = [v for v in (_num(r[i]) for r in members) if v is not None]
                if nums:
                    entry[header[i]] = {"count": len(nums), "sum": round(sum(nums), 6), "mean": round(statistics.fmean(nums), 6), "min": min(nums), "max": max(nums)}
            out["groups"][key] = entry
        return out
    for i in cols:
        values = [r[i] for r in data]
        nums = [v for v in (_num(x) for x in values) if v is not None]
        non_empty = [x for x in values if x.strip()]
        if nums and len(nums) >= 0.6 * max(1, len(non_empty)):
            out["stats"][header[i]] = {
                "type": "numeric",
                "count": len(nums),
                "missing_or_non_numeric": len(values) - len(nums),
                "sum": round(sum(nums), 6),
                "mean": round(statistics.fmean(nums), 6),
                "median": round(statistics.median(nums), 6),
                "min": min(nums),
                "max": max(nums),
                "stdev": round(statistics.stdev(nums), 6) if len(nums) > 1 else 0.0,
            }
        else:
            counts = Counter(x.strip() for x in non_empty)
            out["stats"][header[i]] = {
                "type": "text",
                "count": len(non_empty),
                "unique": len(counts),
                "top": [(ctx.redact_label(k), v) for k, v in counts.most_common(5)],
            }
    return out


# Detection patterns only: these regexes look for risky calls such as eval()/exec() in
# uploaded source text. Nothing here evaluates code; `calculate` uses the existing
# AST-whitelist arithmetic evaluator (_safe_eval_expr), not eval().
_SECURITY_PATTERNS_GENERIC: list[tuple[str, str, str]] = [
    ("high", r"\beval\s*\(", "Use of eval() can execute arbitrary code."),
    ("high", r"\bexec\s*\(", "Use of exec() can execute arbitrary code."),
    ("high", r"\b(os\.system|popen|Runtime\.getRuntime\(\)\.exec|child_process\.exec)\s*\(", "Shell command execution."),
    ("high", r"shell\s*=\s*True", "subprocess with shell=True enables shell injection."),
    ("high", r"\bpickle\.loads?\s*\(", "Unpickling untrusted data can execute code."),
    ("medium", r"\byaml\.load\s*\((?![^)]*Loader)", "yaml.load without a safe Loader."),
    ("medium", r"verify\s*=\s*False", "TLS certificate verification disabled."),
    ("medium", r"\b(md5|sha1)\s*\(", "Weak hash function (MD5/SHA-1)."),
    ("medium", r"\.innerHTML\s*=", "Assigning innerHTML can cause XSS."),
    ("medium", r"(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(\+\s*\w|%s|\{\w*\}|f[\"'])", "SQL built by string concatenation/formatting (injection risk)."),
    ("low", r"\btempfile\.mktemp\s*\(", "Insecure temporary file creation."),
    ("medium", r"(?i)\b(password|passwd|secret|api_?key|token)\s*[:=]\s*[\"'][^\"']{4,}[\"']", "Hard-coded credential."),
]


def _security_findings(text: str) -> list[dict[str, Any]]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for sev, rx, msg in _SECURITY_PATTERNS_GENERIC:
            if re.search(rx, line):
                out.append({"line": n, "severity": sev, "issue": msg, "code": line.strip()[:160]})
        for p in _CREDENTIAL_PATTERNS:
            if p.search(line):
                out.append({"line": n, "severity": "high", "issue": "Credential-format secret (HB-4 pattern).", "code": "[redacted]"})
    return out[:80]


def _block_exits(stmts: list[ast.stmt]) -> bool:
    return bool(stmts) and _always_exits(stmts[-1])


def _always_exits(stmt: ast.stmt) -> bool:
    """True when every execution path through `stmt` returns or raises."""
    if isinstance(stmt, (ast.Return, ast.Raise)):
        return True
    if isinstance(stmt, ast.If):
        return _block_exits(stmt.body) and _block_exits(stmt.orelse)
    if isinstance(stmt, ast.Try):
        if stmt.finalbody and _block_exits(stmt.finalbody):
            return True
        body_exits = _block_exits(stmt.orelse) if stmt.orelse else _block_exits(stmt.body)
        return body_exits and all(_block_exits(h.body) for h in stmt.handlers)
    if isinstance(stmt, ast.With):
        return _block_exits(stmt.body)
    return False


class _PyLint(ast.NodeVisitor):
    def __init__(self) -> None:
        self.issues: list[dict[str, Any]] = []
        self.imported: dict[str, int] = {}
        self.used: set[str] = set()

    def add(self, node: ast.AST, kind: str, msg: str) -> None:
        self.issues.append({"line": getattr(node, "lineno", 0), "kind": kind, "issue": msg})

    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imported[(a.asname or a.name).split(".")[0]] = node.lineno
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:
            if a.name != "*":
                self.imported[a.asname or a.name] = node.lineno
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.used.add(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        base = node
        while isinstance(base, ast.Attribute):
            base = base.value
        if isinstance(base, ast.Name):
            self.used.add(base.id)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            self.add(node, "warning", "Bare 'except:' catches every exception, including KeyboardInterrupt.")
        self.generic_visit(node)

    def _check_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for d in node.args.defaults + node.args.kw_defaults:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                self.add(node, "warning", f"Mutable default argument in '{node.name}()'.")
        body = node.body
        for i, stmt in enumerate(body[:-1]):
            if _always_exits(stmt):
                self.add(body[i + 1], "warning", f"Unreachable code in '{node.name}()': every path above returns or raises.")
                break

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_defaults(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_defaults(node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                self.add(node, "style", "Comparison to None should use 'is' / 'is not'.")
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant) and isinstance(comp.value, (str, int, float)) and not isinstance(comp.value, bool):
                self.add(node, "error", "'is' with a literal compares identity, not value (use ==).")
        self.generic_visit(node)


def t_analyze_code(ctx: "TaskContext", a: DocArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    text = doc.extracted.text
    lang = doc.meta.ext.lstrip(".")
    result: dict[str, Any] = {"language": lang, "lines": text.count("\n") + 1, "executed": False}
    if doc.meta.ext == ".py":
        try:
            tree = ast.parse(text, filename=doc.meta.name)
        except SyntaxError as exc:
            result["syntax_errors"] = [{"line": exc.lineno, "column": exc.offset, "message": exc.msg, "code": (exc.text or "").strip()[:160]}]
            result["lint"] = []
        else:
            result["syntax_errors"] = []
            lint = _PyLint()
            lint.visit(tree)
            for name, line in lint.imported.items():
                if name not in lint.used:
                    lint.issues.append({"line": line, "kind": "warning", "issue": f"'{name}' is imported but never used."})
            result["lint"] = sorted(lint.issues, key=lambda i: i["line"])[:80]
    else:
        result["syntax_errors"] = None
        result["lint"] = None
        result["note"] = "Only pattern-based checks are available for this language (no parser)."
    result["security_findings"] = _security_findings(text)
    return result


_GENERIC_SECRET = re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|private[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"']{6,})")


def _mask(s: str) -> str:
    return s[:3] + "…" + f"({len(s)} chars)" if len(s) > 6 else "…"


def t_scan_secrets(ctx: "TaskContext", a: DocArgs) -> dict[str, Any]:
    """Uses the central detector so this tool and the document assessment cannot disagree."""
    doc = _doc(ctx, a.doc_id)
    ass = assess_text(doc.extracted.text)
    cred = "Authentication credentials and API keys"
    out = [{"line": f.line, "severity": f.severity, "type": f.reason, "value": f.evidence} for f in ass.findings if f.category == cred]
    # Placeholder-like literals are not counted as real secrets by the assessment, but a code
    # reviewer still wants to see hard-coded assignments, so they are listed as informational.
    out += [
        {"line": x["line"], "severity": "INFO", "type": f"hard-coded literal ({x['reason']}); informational", "value": x["evidence"]}
        for x in ass.suppressed
        if x["category"] == cred and "placeholder" in x["reason"]
    ]
    out = out[:60]
    return {"count": len(out), "findings": out, "values_masked": True}


def t_calculate(ctx: "TaskContext", a: CalcArgs) -> dict[str, Any]:
    try:
        return {"expression": a.expression, "result": _safe_eval_expr(a.expression)}
    except (ValueError, ZeroDivisionError, SyntaxError) as exc:
        raise ToolInputError(f"Cannot evaluate '{a.expression}': {exc}") from exc


def t_summarize_document(ctx: "TaskContext", a: SummarizeArgs) -> dict[str, Any]:
    doc = _doc(ctx, a.doc_id)
    return ctx.summarize(a.doc_id, doc, a.focus)


def t_write_report(ctx: "TaskContext", a: ReportArgs) -> dict[str, Any]:
    out_dir: Path = ctx.outputs_dir.resolve()
    target = (out_dir / a.filename).resolve()
    if target.parent != out_dir:
        raise ToolInputError("Report path escapes the task output folder.")
    with open(target, "x", encoding="utf-8") as fh:  # never overwrite
        fh.write(a.content)
    return {"written": True, "filename": a.filename, "bytes": len(a.content.encode("utf-8")), "location": "task outputs folder"}


# Deterministic data-category detection for outbound content (delegated to central sensitive assessment engine).
def data_categories(text: str) -> list[str]:
    return assess_text(text or "").categories


def t_send_email(ctx: "TaskContext", a: "EmailArgs") -> dict[str, Any]:
    """Simulated delivery sink: the message is written to the task outbox, never sent."""
    outbox: Path = (ctx.task.dir / "outbox").resolve()
    outbox.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(json.dumps(a.model_dump(), sort_keys=True).encode()).hexdigest()
    target = outbox / f"msg_{digest[:16]}.json"
    record = {"to": a.to, "subject": a.subject, "body": a.body, "delivery": "simulated", "data_categories": data_categories(a.body)}
    with open(target, "x", encoding="utf-8") as fh:  # exclusive create: an identical message can never be delivered twice
        json.dump(record, fh, ensure_ascii=False, indent=1)
    return {
        "delivered": True,
        "delivery": "simulated (written to the task outbox; no real email was sent)",
        "to": a.to,
        "subject": a.subject,
        "bytes": len(a.body.encode("utf-8")),
        "message_id": target.stem,
        "data_categories": record["data_categories"],
    }


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, ToolSpec] = {
    s.name: s
    for s in [
        ToolSpec("load_document", "Load and extract an uploaded document (run automatically for every file).", DocArgs, t_load_document, planner_visible=False, max_calls=10),
        ToolSpec("summarize_document", "Read the whole document chunk by chunk and produce structured notes. Use for summaries, key points, overviews or long documents.", SummarizeArgs, t_summarize_document, max_calls=3, arg_hint={"doc_id": "D1", "focus": "optional focus, e.g. 'risks'"}),
        ToolSpec("search_text", "Find lines containing a word or phrase (case-insensitive).", SearchArgs, t_search_text, arg_hint={"doc_id": "D1", "query": "word or phrase"}),
        ToolSpec("extract_dates", "Extract every date mentioned in the document with its context.", DocArgs, t_extract_dates, max_calls=3, arg_hint={"doc_id": "D1"}),
        ToolSpec("table_stats", "Compute exact statistics (count, sum, mean, median, min, max, stdev) for CSV/XLSX columns; set group_by for per-group results (e.g. average per region).", TableArgs, t_table_stats, arg_hint={"doc_id": "D1", "column": "optional column name", "group_by": "optional column to group by"}),
        ToolSpec("analyze_code", "Static analysis of a source file: syntax errors, lint problems and security issues. Never runs the code.", DocArgs, t_analyze_code, max_calls=3, arg_hint={"doc_id": "D1"}),
        ToolSpec("scan_secrets", "Detect credentials, API keys, tokens and passwords in the document (values are masked).", DocArgs, t_scan_secrets, max_calls=3, arg_hint={"doc_id": "D1"}),
        ToolSpec("calculate", "Evaluate an arithmetic expression exactly (+ - * // %).", CalcArgs, t_calculate, arg_hint={"expression": "e.g. (12 + 30) * 3"}),
        ToolSpec("write_report", "Save the final answer as a report file in the task output folder. Requires human approval.", ReportArgs, t_write_report, requires_approval=True, protected_sink=True, planner_visible=False, max_calls=1, action_label="Create report", arg_hint={"filename": "report.md"}),
        # Consequential external action. "send_email" is already a protected sink in the
        # unchanged ARMMonitor defaults, so L2G provenance rules apply as well as approval.
        ToolSpec(
            "send_email",
            "Email the final answer to a recipient OUTSIDE this system (an external disclosure; delivery is simulated). "
            "Use only when the user's own task asks to email or send the result to an address. Requires human approval.",
            EmailArgs, t_send_email, requires_approval=True, protected_sink=True, max_calls=1,
            consequential=True, action_label="Send email",
            approval_reason="'send_email' would disclose data to an external recipient and requires explicit human approval. The monitor allowed it.",
            arg_hint={"to": "recipient email address from the user's task", "subject": "short subject line"},
        ),
    ]
}

PLANNER_TOOLS = [n for n, s in REGISTRY.items() if s.planner_visible]
