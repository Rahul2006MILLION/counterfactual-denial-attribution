"""M0 safety net: protect historical research evidence (EXP-001..EXP-009).

Two independent guarantees:

1. **Artifact immutability.** Every committed file in ``results/`` and ``configs/``
   matches the frozen SHA-256 manifest in
   ``tests/fixtures/historical_artifacts_sha256.json``. New experiment outputs
   must be written to a subdirectory of ``results/`` (e.g. ``results/cda/<run_id>/``),
   never as new top-level files that could be confused with historical ones.

2. **Behavioural reproducibility.** Each deterministic historical runner
   (Phases 1-4.3) is re-executed in memory (no files written to ``results/``)
   and its output must equal the committed JSON exactly, except for wall-clock
   timing fields, which are inherently non-deterministic.

Phase 5 (EXP-009) used a live LLM and cannot be re-executed deterministically;
it is protected by guarantee 1 only.

If a test here fails, a code change has altered historical behaviour or a
historical artifact. Do not "fix" the test by regenerating the manifest or the
committed results; investigate the change instead.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

import pytest

from src.evaluation.phase3_audit import generate_audit_report
from src.evaluation.phase3_runner import run_phase3_evaluation
from src.evaluation.phase4_2_runner import run_phase4_2_study
from src.evaluation.phase4_3_runner import run_phase4_3_audit
from src.evaluation.phase4_audit import run_phase4_1_audit
from src.evaluation.phase4_runner import run_phase4_evaluation
from src.evaluation.runner import run_comparison, run_phase2_comparison

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "tests" / "fixtures" / "historical_artifacts_sha256.json"

# Exact key names (not substrings) holding wall-clock timings. Enumerated from the
# committed Phase 1-4.3 JSON files; every other key must reproduce exactly.
TIMING_KEYS: frozenset[str] = frozenset(
    {
        "execution_latency_ms",
        "latency_ms",
        "max_latency_ms",
        "mean_agent_ms",
        "mean_attr_ms",
        "mean_attribution_ms",
        "mean_latency_ms",
        "mean_monitor_ms",
        "mean_ms",
        "median_ms",
        "p95_ms",
        "runtime_overhead",
    }
)


def _load_manifest() -> dict[str, str]:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))["files"]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _normalize(obj: Any) -> Any:
    """JSON round-trip (tuples -> lists, enums -> str) and drop timing keys."""
    obj = json.loads(json.dumps(obj, default=str))

    def _strip(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: _strip(v) for k, v in o.items() if k not in TIMING_KEYS}
        if isinstance(o, list):
            return [_strip(v) for v in o]
        return o

    return _strip(obj)


def _first_differences(a: Any, b: Any, path: str = "$", limit: int = 10) -> list[str]:
    """Return up to ``limit`` human-readable differences between two JSON values."""
    out: list[str] = []

    def _walk(x: Any, y: Any, p: str) -> None:
        if len(out) >= limit:
            return
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y)):
                if k not in x or k not in y:
                    out.append(f"{p}.{k}: present only in {'committed' if k not in x else 'recomputed'}")
                else:
                    _walk(x[k], y[k], f"{p}.{k}")
        elif isinstance(x, list) and isinstance(y, list):
            if len(x) != len(y):
                out.append(f"{p}: length {len(x)} (recomputed) != {len(y)} (committed)")
            for i, (xi, yi) in enumerate(zip(x, y)):
                _walk(xi, yi, f"{p}[{i}]")
        elif x != y:
            out.append(f"{p}: recomputed={x!r} committed={y!r}")

    _walk(a, b, path)
    return out


# ---------------------------------------------------------------------------
# Guarantee 1: artifact immutability
# ---------------------------------------------------------------------------


def test_manifest_covers_phase1_to_phase5_artifacts() -> None:
    manifest = _load_manifest()
    results = [p for p in manifest if p.startswith("results/")]
    configs = [p for p in manifest if p.startswith("configs/")]
    assert len(results) == 31
    assert len(configs) == 16
    for prefix in ("phase1_", "phase2_", "phase3_", "phase4_", "phase5_"):
        assert any(Path(p).name.startswith(prefix) for p in results), prefix


@pytest.mark.parametrize("rel_path", sorted(_load_manifest()))
def test_historical_artifact_unchanged(rel_path: str) -> None:
    path = REPO_ROOT / rel_path
    assert path.is_file(), f"Historical artifact missing: {rel_path}"
    assert _sha256(path) == _load_manifest()[rel_path], (
        f"Historical artifact modified: {rel_path}. Historical results must never be "
        "overwritten; write new outputs to a results/ subdirectory."
    )


def test_no_unregistered_top_level_result_files() -> None:
    """New outputs must live in results/<subdir>/, never beside historical files."""
    manifest = _load_manifest()
    top_level = sorted(
        str(p.relative_to(REPO_ROOT))
        for p in (REPO_ROOT / "results").iterdir()
        if p.is_file()
    )
    unregistered = [p for p in top_level if p not in manifest]
    assert not unregistered, (
        f"Unregistered top-level files in results/: {unregistered}. "
        "Write new experiment outputs to a subdirectory such as results/cda/<run_id>/."
    )


# ---------------------------------------------------------------------------
# Guarantee 2: deterministic behavioural reproducibility (Phases 1-4.3)
# ---------------------------------------------------------------------------


def _phase3_audit(tmp_path: Path) -> dict[str, Any]:
    # generate_audit_report always writes; direct it to a temp file, never results/.
    return generate_audit_report(output_path=tmp_path / "phase3_audit_report.json")


RECOMPUTERS: dict[str, Callable[[Path], Any]] = {
    "phase1_baseline_comparison.json": lambda _t: [asdict(r) for r in run_comparison(output_dir=None)],
    "phase2_strategy_comparison.json": lambda _t: run_phase2_comparison(output_dir=None),
    "phase3_attribution_results.json": lambda _t: run_phase3_evaluation(output_dir=None),
    "phase3_audit_report.json": _phase3_audit,
    "phase4_evaluation_results.json": lambda _t: run_phase4_evaluation(output_dir=None),
    "phase4_1_audit_results.json": lambda _t: run_phase4_1_audit(output_dir=None),
    "phase4_2_results.json": lambda _t: run_phase4_2_study(output_dir=None),
    "phase4_3_results.json": lambda _t: run_phase4_3_audit(output_dir=None),
}


@pytest.mark.parametrize("result_file", sorted(RECOMPUTERS))
def test_historical_runner_reproduces_committed_results(
    result_file: str, tmp_path: Path
) -> None:
    committed = _normalize(
        json.loads((REPO_ROOT / "results" / result_file).read_text(encoding="utf-8"))
    )
    recomputed = _normalize(RECOMPUTERS[result_file](tmp_path))
    diffs = _first_differences(recomputed, committed)
    assert not diffs, (
        f"Current code no longer reproduces committed {result_file}:\n  " + "\n  ".join(diffs)
    )


def test_normalizer_strips_only_timing_keys() -> None:
    sample = {"latency_ms": 1.0, "accuracy": 0.9, "nested": [{"mean_ms": 2.0, "tp": 3}]}
    assert _normalize(sample) == {"accuracy": 0.9, "nested": [{"tp": 3}]}


def test_difference_reporter_detects_metric_drift() -> None:
    """Guard against a vacuous comparison: a changed metric must be reported."""
    committed = {"attribution_accuracy": 0.9615, "cm": {"tp": 32}}
    drifted = {"attribution_accuracy": 0.9500, "cm": {"tp": 32}}
    assert _first_differences(drifted, committed) == [
        "$.attribution_accuracy: recomputed=0.95 committed=0.9615"
    ]
    assert _first_differences(committed, committed) == []
