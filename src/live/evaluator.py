"""Result aggregation: combines the deterministic layer with the contextual AI layer.

Rules (see docs/EVALUATION_ARCHITECTURE.md)
  * Deterministic findings are never removed or downgraded by the AI layer.
  * AI findings are suspicions: method `contextual_ai`, source `ai`, severity capped at MEDIUM,
    and any document with AI findings is `requires_review` rather than "confirmed".
  * Any AI-layer failure or coverage shortfall makes the evaluation `partial`. With no findings the
    UI-facing `status` becomes NOT_EVALUABLE, so an unfinished evaluation can never show as CLEAN.
  * The summary is not an input here; a summary succeeding says nothing about the evaluation.
"""

from __future__ import annotations

import copy
from typing import Any

from src.live.contextual import ContextualResult, evaluate_text
from src.live.detect_rules import normalise_text
from src.live.sensitive import (
    AssessmentStatus,
    DetectionMethod,
    DocumentAssessment,
    EvaluationStatus,
    SensitiveFinding,
    assess_text,
    mark_incomplete,
    redact_value,
)

_RANK = {"low": 0, "medium": 1, "high": 2}


def _ai_severity(f: Any) -> str:
    """AI suspicion is capped at MEDIUM, and low confidence caps it at LOW: only deterministic,
    validated detections can be HIGH."""
    cap = {"high": 1, "medium": 1, "low": 0}[f.confidence]
    return ("LOW", "MEDIUM")[min(_RANK[f.severity], cap)]


def _mask_quote(quote: str) -> str:
    """Evidence from the model is shown with any deterministic hit (card, key, ...) redacted."""
    q = quote.replace("\n", " ")[:120]
    for f in sorted(assess_text(q).findings, key=lambda f: -f.span[0]):
        a, b = f.span
        q = q[:a] + redact_value(q[a:b], f.category) + q[b:]
    return q


def merge_contextual(base: DocumentAssessment, ctx: ContextualResult | None, error: str | None = None) -> DocumentAssessment:
    """Return a NEW assessment = `base` (deterministic) + contextual results/failure."""
    ass = copy.deepcopy(base)
    if ass.status == AssessmentStatus.NOT_EVALUABLE and not ass.findings and ass.layers.get("deterministic") == "failed":
        return ass  # nothing could be extracted; the AI layer has nothing to add

    if ctx is None:
        ass.layers["contextual"] = "failed"
        return mark_incomplete(ass, f"AI contextual review did not run: {error or 'unknown error'}")

    ass.layers["contextual"] = "completed" if ctx.coverage_complete else ("failed" if ctx.chunks_ok == 0 else "partial")
    for f in ctx.findings:
        sev = _ai_severity(f)
        ass.findings.append(
            SensitiveFinding(
                doc_id=ass.doc_id, filename=ass.filename, content_hash=ass.content_hash, category=f.category,
                line=f.line, span=(0, 0), evidence=_mask_quote(f.quote), method=DetectionMethod.CONTEXTUAL_AI.value,
                confidence=f.confidence.upper(), reason=f"AI suspicion (needs review): {f.explanation}",
                timestamp=ass.evaluated_at, severity=sev, source="ai",
            )
        )
        ass.category_counts[f.category] = ass.category_counts.get(f.category, 0) + 1
    ass.categories = sorted(ass.category_counts)
    ass.total_findings = len(ass.findings)
    ass.is_sensitive = bool(ass.findings)
    if ctx.findings:
        ass.status = AssessmentStatus.COMPLETED
        ass.error = None
        if ass.evaluation_status == EvaluationStatus.COMPLETED.value:
            ass.evaluation_status = EvaluationStatus.REQUIRES_REVIEW.value
        ass.limitations.append(f"{len(ctx.findings)} finding(s) come from the AI layer and are unconfirmed suspicions.")
    if ctx.rejected:
        ass.limitations.append(f"{ctx.rejected} AI finding(s) were discarded by validation (not verbatim, example/fiction, or vague).")
    if ctx.errors:
        mark_incomplete(ass, "AI contextual review incomplete: " + " | ".join(ctx.errors[:3]))
    return ass


def run_contextual(base: DocumentAssessment, client: Any, model: str, text: str, filename: str, settings: Any, on_progress: Any = None) -> DocumentAssessment:
    """Run the AI layer over the full text and merge. Unexpected exceptions become a visible
    failure of the contextual layer; they are never swallowed into a clean result."""
    if base.layers.get("deterministic") == "failed":
        return base
    try:
        ctx = evaluate_text(
            client, model, normalise_text(text), filename,
            chunk_chars=settings.chunk_chars, overlap=settings.eval_chunk_overlap,
            max_chunks=settings.max_eval_chunks, on_progress=on_progress,
        )
    except Exception as exc:  # noqa: BLE001 - surfaced as evaluation failure, not hidden
        return merge_contextual(base, None, f"{type(exc).__name__}: {exc}")
    return merge_contextual(base, ctx)
