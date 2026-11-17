"""Capture real output from the existing terminal demo for the website's replay.

Run from the repository root:

    uv run python frontend/scripts/capture_demo.py [--force]

This drives the real CLI entry point (``src.demo.__main__.main``) with a fixed list
of tasks, exactly as a person typing them would, and stores the verbatim text it
printed. Nothing is invented or edited: the website only replays these strings.

The source revision is recorded honestly: the git HEAD commit, whether ``src/demo``
is committed or only present in the working tree, and SHA-256 digests of every
``src/demo`` file that produced the output.

Writes only ``frontend/src/data/demo-transcript.json`` (refuses to overwrite unless
``--force``). It never writes to results/ or configs/ and makes no network calls.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.demo.__main__ import main  # noqa: E402

OUTPUT = REPO_ROOT / "frontend" / "src" / "data" / "demo-transcript.json"
PROMPT = "\nEnter your task: "

TASKS: list[dict[str, str]] = [
    {"id": "allow-read", "label": "Read a document", "input": "read /workspace/notes/meeting.txt"},
    {"id": "hb2", "label": "Sensitive path", "input": "read /etc/shadow"},
    {"id": "hb4", "label": "Credential in email", "input": "email /workspace/deploy/keys.txt to team@example.test"},
    {"id": "l2g", "label": "Untrusted data flow", "input": "email /workspace/inbox/vendor_message.txt to team@example.test"},
    {"id": "tool-error", "label": "Allowed, tool fails", "input": "calculate 5 // 0"},
    {"id": "unrecognized", "label": "Unrecognized task", "input": "delete everything"},
]


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def source_revision() -> dict[str, object]:
    demo_files = sorted((REPO_ROOT / "src" / "demo").glob("*.py"))
    tracked = _git("ls-files", "--", "src/demo")
    status = _git("status", "--porcelain", "--", "src/demo")
    if not tracked:
        state = "src/demo is untracked (working tree only, not committed)"
    elif status:
        state = "src/demo has uncommitted modifications"
    else:
        state = "src/demo is committed at HEAD with no local changes"
    return {
        "git_head": _git("rev-parse", "HEAD"),
        "git_branch": _git("branch", "--show-current"),
        "src_demo_state": state,
        "src_demo_sha256": {
            str(p.relative_to(REPO_ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in demo_files
        },
    }


def capture() -> dict[str, object]:
    inputs = iter([t["input"] for t in TASKS] + ["exit"])

    def fake_input(_prompt: str) -> str:
        return next(inputs)

    out = io.StringIO()
    code = main([], input_fn=fake_input, out=out)
    if code != 0:
        raise SystemExit(f"demo exited with code {code}")
    text = out.getvalue()
    # The CLI prints the banner, then one output block per task. The prompt itself is
    # passed to input(), not printed, so split on the task headers the demo prints.
    banner, _, rest = text.partition("Task 1: ")
    rest = "Task 1: " + rest
    blocks: list[str] = []
    for n in range(1, len(TASKS) + 1):
        start = rest.index(f"Task {n}: ")
        end = rest.index(f"Task {n + 1}: ") if n < len(TASKS) else rest.index("Demo ended.")
        blocks.append(rest[start:end].rstrip("\n"))
    tail = rest[rest.index("Demo ended."):].strip()
    return {
        "banner": banner.rstrip("\n"),
        "tasks": [{**t, "output": b} for t, b in zip(TASKS, blocks)],
        "ending": tail,
        "full_stdout_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def main_cli() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="overwrite an existing transcript")
    args = parser.parse_args()
    if OUTPUT.exists() and not args.force:
        print(f"{OUTPUT} exists; pass --force to replace it.")
        return 1
    data = {
        "description": "Verbatim stdout of the existing terminal demo, captured for replay. Not live, not an LLM.",
        "command": "uv run python -m src.demo",
        "captured_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "python": platform.python_version(),
        "source": source_revision(),
        **capture(),
    }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(data['tasks'])} tasks)")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    raise SystemExit(main_cli())
