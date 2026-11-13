"""Live end-to-end checks against the real local Ollama model (not mocked).

Run:  uv run python -m src.live.smoke [--only NAME ...]

Each scenario uploads a genuine generated file, runs the full agent pipeline with the
local Qwen model, and checks concrete outcomes (tools executed, exact numbers, security
decisions, approval behaviour, files written). Model output varies between runs, so a
FAIL here means "this run did not meet the check", reported honestly.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Callable

from src.live import samples
from src.live.agent import Task, TaskManager
from src.live.config import Settings


def _wait(task: Task, on_approval: Callable[[Task], bool | None] | None = None, timeout: float = 900) -> None:
    t0 = time.time()
    decided = False
    while task.status not in ("completed", "failed") and time.time() - t0 < timeout:
        if task.status == "awaiting_approval" and on_approval and not decided:
            choice = on_approval(task)
            if choice is not None:
                task._approval_decision = choice
                task._approval_event.set()
                decided = True
        time.sleep(0.5)


def _tools(task: Task, status: str = "executed") -> list[str]:
    return [s["tool"] for s in task.steps if s.get("status") == status]


def run(only: list[str] | None = None) -> int:
    ws = Path(tempfile.mkdtemp(prefix="cda-live-smoke-"))
    m = TaskManager(Settings(workspace=ws))
    up = lambda name, data: m.workspace.save_upload(name, data).file_id  # noqa: E731

    scenarios: list[tuple[str, Callable[[], tuple[Task, list[tuple[str, bool]]]]]] = []

    def scenario(fn):
        scenarios.append((fn.__name__, fn))
        return fn

    @scenario
    def csv_average():
        t = m.create("Analyse this CSV and calculate the average revenue.", [up("sales.csv", samples.SAMPLE_CSV.encode())])
        _wait(t)
        stats = next((s["output"] for s in t.steps if s["tool"] == "table_stats" and s.get("status") == "executed"), {})
        mean = (stats.get("stats", {}).get("revenue") or {}).get("mean")
        ans = (t.result or {}).get("answer", "")
        return t, [("completed", t.status == "completed"), ("table_stats executed", bool(stats)), ("exact mean 1058.15 computed", mean == 1058.15), ("answer states 1058.15", "1058.15" in ans)]

    @scenario
    def python_errors():
        t = m.create("Find all errors and security vulnerabilities in this Python file.", [up("service.py", samples.SAMPLE_PY.encode())])
        _wait(t)
        out = next((s["output"] for s in t.steps if s["tool"] == "analyze_code" and s.get("status") == "executed"), {})
        issues = json.dumps(out)
        return t, [("completed", t.status == "completed"), ("analyze_code executed", bool(out)), ("eval() found", "eval()" in issues), ("shell=True found", "shell=True" in issues), ("bare except found", "Bare 'except:'" in issues), ("code not executed", out.get("executed") is False)]

    @scenario
    def pdf_dates():
        t = m.create("Extract the important dates from this document.", [up("atlas.pdf", samples.make_pdf(samples.PDF_LINES))])
        _wait(t)
        out = next((s["output"] for s in t.steps if s["tool"] == "extract_dates" and s.get("status") == "executed"), {})
        return t, [("completed", t.status == "completed"), ("PDF extracted", any(e["type"] == "extracted" for e in t.events)), ("extract_dates executed", bool(out)), (">= 3 dates found", out.get("count", 0) >= 3)]

    @scenario
    def docx_summary():
        t = m.create("Summarize this document in three bullet points.", [up("policy.docx", samples.make_docx(samples.DOCX_PARAS))])
        _wait(t)
        ans = (t.result or {}).get("answer", "")
        return t, [("completed", t.status == "completed"), ("DOCX extracted", any(e["type"] == "extracted" for e in t.events)), ("answer mentions questionnaire or vendor", any(w in ans.lower() for w in ("questionnaire", "vendor")))]

    @scenario
    def approval_approve():
        t = m.create("Summarize this document and save the summary as a report file named atlas.md.", [up("atlas.pdf", samples.make_pdf(samples.PDF_LINES))])
        _wait(t, on_approval=lambda _t: True)
        rep = (t.result or {}).get("report") or {}
        written = list((t.dir / "outputs").glob("*"))
        return t, [("completed", t.status == "completed"), ("approval was requested", any(e["type"] == "approval_required" for e in t.events)), ("report executed after approval", rep.get("status") == "executed"), ("file exists in task outputs", len(written) == 1)]

    @scenario
    def approval_reject():
        t = m.create("Summarize this document and save it as a report named policy.md.", [up("policy.docx", samples.make_docx(samples.DOCX_PARAS))])
        _wait(t, on_approval=lambda _t: False)
        rep = (t.result or {}).get("report") or {}
        return t, [("completed", t.status == "completed"), ("approval was requested", any(e["type"] == "approval_required" for e in t.events)), ("report not executed", rep.get("status") == "rejected"), ("no file written", not list((t.dir / "outputs").glob("*")))]

    @scenario
    def injection_blocked():
        t = m.create("Summarize these meeting notes and save a report named notes.md.", [up("notes.txt", samples.INJECTION_TXT.encode())])
        _wait(t, on_approval=lambda _t: True)
        flagged = any(e["type"] == "extracted" and e["data"].get("injection_findings") for e in t.events)
        rep = (t.result or {}).get("report") or {}
        return t, [("completed", t.status == "completed"), ("injection flagged, doc untrusted", flagged), ("report blocked by L2G-TRUST", rep.get("security", {}).get("rule") == "L2G-TRUST"), ("no file written", not list((t.dir / "outputs").glob("*")))]

    @scenario
    def missing_model():
        t = m.create("Summarize this.", [up("a.txt", b"hello world")], model="no-such-model:1b")
        _wait(t)
        return t, [("failed clearly", t.status == "failed"), ("model_not_found reported", (t.error or {}).get("kind") == "model_not_found")]

    failures = 0
    for name, fn in scenarios:
        if only and name not in only:
            continue
        t0 = time.time()
        task, checks = fn()
        ok = all(v for _, v in checks)
        failures += 0 if ok else 1
        print(f"\n{'PASS' if ok else 'FAIL'}  {name}  ({time.time() - t0:.0f}s, model {task.model}, status {task.status})")
        for label, v in checks:
            print(f"   [{'x' if v else ' '}] {label}")
        if task.plan:
            print(f"   plan: {task.plan['task_type']} -> {[s['tool'] for s in task.plan['steps']]}")
        for s in task.steps:
            sec = s["security"]
            print(f"   step {s['step_id']} {s['tool']}: {sec['verdict']} {sec['layer']} {sec['rule'] or ''} -> {s.get('status')}")
        if task.result:
            print("   answer:", task.result["answer"][:300].replace("\n", " | "))
        if task.error:
            print("   error:", task.error)
    print(f"\n{len([n for n, _ in scenarios if not only or n in only]) - failures} passed, {failures} failed. Workspace: {ws}")
    return 1 if failures else 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*")
    sys.exit(run(ap.parse_args().only))
