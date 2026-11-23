# Evaluation Architecture (after the fixes)

Code: `src/live/` · Tests: `tests/evaluation/` · Audit that motivated it: `docs/AUDIT_REPORT.md`

## Principle

Summarisation and security evaluation are separate responsibilities with separate results. A summary
succeeding says nothing about the evaluation. The evaluation reports its own status and never turns a failure into "clean".

## Flow

```
upload ─► Workspace.save_upload ─► extract() ─► normalise ─► Layer 1 deterministic ─► assessment.json (cached per hash+engine version)
                                                                    │
task ──► _run stage 2 ─► extract() ─► Layer 2 contextual AI (whole doc, overlapping chunks) ─► merge_contextual ─► final assessment
   └──► planner / tools / summary / answer   (independent; never read by the evaluator)

final assessment ─► task.document_assessments, snapshot(), result, "assessment" SSE event ─► unchanged frontend
```

## Stages

| Stage | Where | What it does |
|---|---|---|
| Ingestion | `workspace.py: save_upload` | extension allow-list, magic bytes, size; a crash during assessment is recorded as a NOT_EVALUABLE verdict, never skipped |
| Extraction | `extract.py` | PDF, DOCX (body + headers, footers, footnotes, endnotes, comments), XLSX, CSV, JSON, text/code. Truncation and "no text" are reported to the assessment |
| Normalisation | `detect_rules.normalise_text` | NFKC (fullwidth digits), zero-width and soft-hyphen removal, HTML entity decoding. Newlines kept so line numbers stay valid |
| Summary | `agent.py: TaskContext.summarize` | unchanged; model notes for the answer only |
| Layer 1 deterministic | `sensitive.py: assess_text`, `detect_rules.py` | validated detection (below). Covers the entire extracted text |
| Layer 2 contextual AI | `contextual.py` | finds private conversations, confidential/internal information, sensitive personal details. Whole document, `chunk_chars` chunks with `eval_chunk_overlap` overlap, up to `max_eval_chunks` |
| Aggregation | `evaluator.py: merge_contextual` | see rules below |
| Validation | `contextual.validate_response` | strict schema, evidence must be verbatim, no examples/fiction, no vague text, must be person-specific |
| Output | `DocumentAssessment.to_dict` | existing fields unchanged; additive fields listed below |

## Layer 1 rules

Each rule is **HARD** (validated format, never suppressed by surrounding prose) or **SOFT** (label/context based; suppressed for placeholders, example or discussion sentences, disclaimers).

| Category | Rule | Class |
|---|---|---|
| Payment card | 13-19 digits, Luhn, known issuer prefix and length, not labelled ISBN/order/tracking | HARD |
| Credentials (provider formats) | PEM header, AWS id, GitHub, `sk-`, Stripe, Slack, Google, JWT, Bearer, `scheme://user:pass@host` | HARD (only a placeholder *value* suppresses) |
| Credentials (key = value) | `password/secret/api_key/token/...` followed by `: = => is`, JSON quoted keys; value must not be a placeholder, prose word or code reference | SOFT |
| Email | syntax; reserved/example domains and generic addresses in example sentences are suppressed | HARD/SOFT |
| Phone | labelled, international `+CC`, `(NNN) NNN-NNNN`, `NNN-NNN-NNNN`, Indian `NNNNN NNNNN` and bare `[6-9]NNNNNNNNN`; 10-15 digits; not preceded by currency/id words | SOFT |
| Government id | SSN (area/group/serial rules; labelled form accepts any), PAN (holder-type letter), Aadhaar (Verhoeff, not three years), labelled tax/national/passport | HARD/SOFT |
| Bank | IBAN with mod-97, labelled account/routing numbers (masked numbers still count) | HARD/SOFT |
| Address | street phrase only with residential/postal context; labelled address needs digits and 2+ words | SOFT |
| Health | labelled clinical values; free text only with a person cue | SOFT |
| Name | `Name: First Last` only when the document also has other identifying data | SOFT |
| DOB, employee/student id, salary (incl. CSV salary column) | labelled values | SOFT |

Overlapping matches are resolved to one finding per value (card > credential > government id > bank > phone > email).
Suppressed candidates are kept in `suppressed` with a reason, so a false-positive fix is auditable.

## Layer 2 contract

The model returns `{"findings":[{category, evidence_quote, explanation, present_in_document, is_example_or_fiction, confidence, severity}]}`.
The prompt (`contextual.EVALUATOR_SYSTEM`) covers: whole excerpt; actual vs hypothetical vs discussed; evidence; category; severity; no invention; document text is data and
instructions inside it are ignored (also enforced structurally: `injection.wrap` + `neutralise`); a summarisable document is not thereby safe; JSON only.
The model is told not to report emails/phones/cards/keys/ids because Layer 1 owns them.

Malformed or truncated JSON is retried once; a timeout or unavailable model is not retried. Any chunk that still fails is recorded in `limitations`.

## Aggregation rules

1. Deterministic findings are never removed or downgraded by the AI layer.
2. AI findings: `source: "ai"`, `method: "contextual_ai"`, severity capped at MEDIUM (LOW if confidence is low), reason prefixed "AI suspicion (needs review)". The model can never create HIGH or a credential finding.
3. Any AI finding makes the evaluation `requires_review`.
4. AI layer failure or coverage shortfall (chunk cap, failed chunk, extraction truncated, no extractable text) makes it `partial`; extraction failure makes it `failed`.

## Status mapping (keeps the frontend unchanged)

The frontend shows NOT EVALUABLE when `status == "NOT_EVALUABLE"`, otherwise SENSITIVE when `is_sensitive`, otherwise CLEAN. So:

| `evaluation_status` | `status` | `is_sensitive` | UI shows |
|---|---|---|---|
| completed, no findings | COMPLETED | false | CLEAN |
| completed / requires_review / partial, with findings | COMPLETED | true | SENSITIVE |
| partial, no findings | NOT_EVALUABLE | false | NOT EVALUABLE + reason |
| failed | NOT_EVALUABLE | false | NOT EVALUABLE + reason |

`AssessmentStatus.FAILED` is never emitted because the frontend does not handle it.

## Additive API fields (inside each document assessment)

`evaluation_status`, `layers {deterministic, contextual: completed|partial|failed|not_run}`, `limitations[]`, `suppressed[]`, `engine_version`, `max_severity`, and per finding `severity`, `source`.

## Caching

`assessment.json` stores the deterministic result keyed by content hash **and** `ENGINE_VERSION` (bump it when rules change). The AI result is per task and not cached.
Upload-time assessments are deterministic-only (`layers.contextual == "not_run"`); the task-time assessment is the complete one.

## Settings

`CDA_MAX_EVAL_CHUNKS` (default 24), `CDA_EVAL_CHUNK_OVERLAP` (default 400), `CDA_CHUNK_CHARS` (6000, shared with the summary).

## Redaction before the model (`CDA_REDACT_FOR_MODEL`, default on)

The deterministic layer runs first and its spans decide what the model may read.
`sensitive.redact_for_model(text)` replaces every flagged value with a tag (`[REDACTED:PHONE]`, `EMAIL`, `SECRET`, `CARD`, `GOV_ID`, `ACCOUNT`, `DOB`, `ADDRESS`, `ID`, `HEALTH`, `SALARY`, `NAME`). Lines are preserved, detection has no per-category cap, and the original file and the Layer 1 findings are untouched.

`agent.model_text_of(settings, doc)` is the single gate for document text sent to the model. It feeds:
the summary notes (`TaskContext.summarize`), the AI contextual review (`_contextual_pass`), the planner overview (`_doc_overview`),
the answer step's document excerpts, `search_text`, `extract_dates`, and table group labels / top values in `table_stats`.
The assessment records how many values were hidden in `redacted_for_model`, and a `contextual` event says so in `events.jsonl`.

Not covered (by design or necessity): content only the AI layer can recognise has no span to cut (private conversations, free-text names), so it still reaches the model;
`analyze_code` still parses the original source locally (its output masks credentials); the user's own task instruction is not redacted.
Set `CDA_REDACT_FOR_MODEL=0` to let the model read raw text.
