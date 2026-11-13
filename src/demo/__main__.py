"""Entry point: ``uv run python -m src.demo``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from typing import TextIO

from src.attribution.models import FeedbackCondition
from src.demo.render import banner, format_footer, format_header, format_outcome, format_step, help_text
from src.demo.session import DemoSession, UnsafeAuditDirectoryError

EXIT_WORDS = {"exit", "quit"}


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m src.demo",
        description="Interactive terminal demonstration of the existing monitor and executor.",
    )
    parser.add_argument(
        "--feedback",
        choices=["ACTUAL", "NEUTRALIZED"],
        default="ACTUAL",
        help="Historical v1 feedback condition shown to the agent (not C0/C1/C2).",
    )
    parser.add_argument("--step", action="store_true", help="Pause after each step (press Enter).")
    parser.add_argument(
        "--save-audit",
        metavar="DIR",
        default=None,
        help="Also save each task's audit log as JSONL in DIR (exclusive create; "
        "refused under results/ or configs/). Default: in memory only.",
    )
    return parser.parse_args(argv)


def main(
    argv: list[str] | None = None,
    input_fn: Callable[[str], str] = input,
    out: TextIO | None = None,
) -> int:
    out = out or sys.stdout
    args = _parse_args(argv)

    def say(text: str = "") -> None:
        print(text, file=out, flush=True)

    try:
        session = DemoSession(FeedbackCondition(args.feedback), save_dir=args.save_audit)
    except UnsafeAuditDirectoryError as exc:
        say(f"Error: {exc}")
        return 2

    say(banner(session.probe_monitor(), session.feedback_condition, str(session.save_dir) if session.save_dir else None))
    while True:
        try:
            text = input_fn("\nEnter your task: ")
        except (EOFError, KeyboardInterrupt):
            say()
            break
        stripped = text.strip()
        if not stripped:
            continue
        if stripped.lower() in EXIT_WORDS:
            break
        if stripped.lower() == "help":
            say(help_text())
            continue
        outcome = session.run_task(stripped)
        if args.step:
            say(format_header(outcome))
            for view in outcome.steps:
                say(format_step(view))
                try:
                    input_fn("  [Enter for next step] ")
                except (EOFError, KeyboardInterrupt):
                    break
            say(format_footer(outcome))
        else:
            say(format_outcome(outcome))
    say(f"Demo ended. {session.task_count} task(s) run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
