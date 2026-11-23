# Evaluation Pipeline Audit Report

Scope: the live agent backend in `src/live/` (FastAPI) and how its output reaches `frontend/src/sections/agent.ts`.
The frontend was read only to learn the API contract; it was not modified.

Method: read every module on the path from upload to displayed result, ran the existing suite
(80 tests in `tests/test_sensitive_assessment.py` + `tests/test_live_agent.py`, all passing before any change), then
probed `assess_text()` with 30 realistic snippets (probe script kept out of the repo). Every claim below
about a miss or a false alarm was reproduced against the unmodified code.

## 1. Architecture overview

```
POST /api/upload  (api.py)
   -> Workspace.save_upload (workspace.py)     validation, magic bytes, writes original.<ext>
        -> get_or_create_assessment            extract() + assess_document()  [deterministic]  -> assessment.json cache
POST /api/tasks   (api.py) -> TaskManager.create -> worker thread TaskManager._run (agent.py)
   stage 2: extract() again -> get_or_create_assessment -> injection.scan -> load_document tool
   stage 4/5: model plans tools (summarize_document, scan_secrets, ...)
   stage 6/7: every tool call goes through SecurityGateway (security.py) -> ARMMonitor
   stage 8: model writes the answer from verified tool output
   result: task.result + snapshot() carry `document_assessments`, `has_sensitive_data`, `sensitive_categories`
SSE /api/tasks/{id}/events -> frontend renders "assessment" events (CLEAN / SENSITIVE / NOT EVALUABLE)
```

## 2. Evaluation pipeline flow and owning code

| Stage | File / function |
|---|---|
| Ingestion + validation | `workspace.py: Workspace.save_upload`, `_MAGIC`, `ALLOWED_EXTS` |
| Extraction | `extract.py: extract`, `_pdf`, `_docx`, `_xlsx`, `_csv`, `_json`; cap `MAX_TEXT_CHARS = 400_000` |
| Normalisation | none (raw extracted text goes to the detector) |
| Chunking | `extract.py: chunk_text` (no overlap); used only by `agent.py: TaskContext.summarize` |
| Summary | `agent.py: TaskContext.summarize` (LLM notes per chunk, sampled to `max_chunks = 8`) |
| Sensitive detection | `sensitive.py: assess_text` / `assess_document` (regex only, no LLM) |
| Flag/summary combination | `agent.py: _run` writes `task.document_assessments`; `Task.snapshot`, `task.result` |
| Second, separate secret scanner | `tools.py: t_scan_secrets` (`_GENERIC_SECRET` + monitor `_CREDENTIAL_PATTERNS`) |
| Outbound category check | `tools.py: data_categories` -> `assess_text` |
| Injection defence | `injection.py: scan`, `wrap`, `SYSTEM_GUARD` |

Summary and security evaluation are **already separate code paths** (the summary never feeds the flag).
So the inconsistency is not a coupling bug; it comes from the detector itself, the lack of any contextual layer,
and the way failures and stale results are represented. Details follow.

## 3. Root causes (all reproduced)

**RC1 - Phone detector misses ordinary numbers (false negative).** `_RX_PHONE` demands a separator between digit groups
or a `phone:`-style label directly followed by digits. `John Doe, phone number 9876543210, lives in Pune` (the
example from the task brief) produced **no finding**. `Call me on 9876543210` also missed. Bare 10-digit mobile numbers,
the most common form in India, are not matched at all.

**RC2 - Credential detector only knows `password=`-style assignments and four token formats.** `_RX_CREDENTIAL`
covers `password|passwd|pwd|secret_key|api_secret|client_secret` followed by `:`/`=`, plus `ghp_`, `AKIA`, `sk-`,
`Bearer`, PEM private keys. Missed: `api_key: 8f14...`, `My API key is sk_live_...`, `access_token=...`, JWTs, Slack
`xox*-` tokens, `aws_secret_access_key = ...`, `postgres://admin:pass@host/db` (only the email-ish part was flagged as an email),
`My password is Hunter2...` (sentence form) and JSON fields such as `{"password": "..."}` (the closing quote after the key stops `\\s*[:=]` from matching). Passing `password: <your-password>` or a discussion sentence
containing `password=hunter2` **was** flagged high severity (false positive), because the value is never checked for
placeholders and context is never checked.

**RC3 - Luhn-only card detection flags any long number.** `_RX_CARD_DIGITS` + `is_luhn_valid` accepts any 13-19 digit
run that passes the checksum, with no issuer-prefix or length check, so `ISBN 978-3-16-148410-0` and
`order 4532015112830` were reported as payment cards (and as phone numbers).

**RC4 - Overlapping detectors double-report one value.** `4111 1111 1111 1111` was reported as a card **and** a
phone number **and** a tax/government ID (Aadhaar-shaped `\d{4}\s\d{4}\s\d{4}`). `assess_text` has no span-level
de-duplication, so category lists are inflated and severity cannot be reasoned about.

**RC5 - Government ID patterns have no validators.** `\d{4}\s\d{4}\s\d{4}` (Aadhaar shape) matched
`2023 2024 2025`; `\d{3}-\d{2}-\d{4}` would match invalid SSNs (area 000/666/9xx); the PAN regex ignores the fixed
4th-letter set. The 12-digit Aadhaar without spaces is missed.

**RC6 - Phone pattern is simultaneously too loose and too strict.** `\(?\d{2,4}\)?[\s-]\d{3,4}[\s-]?\d{3,4}` flagged
`123 456 7890 units` (a quantity) while missing bare numbers (RC1).

**RC7 - Health and address rules key on common words.** `History of the Roman empire: chronic problems...` produced
a *Health information* flag (`history of`, `chronic`, `condition` are triggers by themselves). `10 Downing Street is famous`
and `In 1999 Apple Way ...` produced *Home address* flags (a street-shaped phrase alone is treated as a home address).

**RC8 - No notion of placeholder, example or discussion.** `name@example.com`, `<your-password>`, hypothetical examples and
"never store passwords like password=hunter2" are treated like real data. Only `_RX_SENTENCE_DISCLAIMER`
("does not contain ...") exists, and it is applied to just some rules. The task requires distinguishing sensitive
data being *discussed* from sensitive data *present*.

**RC9 - No contextual (AI) layer exists.** `sensitive.py` is 100 % regex. Private conversations, confidential or
internal information, and personal details with no fixed shape ("Hey Priya, I got my biopsy results back ... don't tell
Mom") can never be flagged. The model sees the document only through `summarize_document`, whose prompt *asks it to
mention personal information in its notes*, but nothing reads those notes back into the assessment. This is why the
answer text can say "contains personal information" while the sensitivity badge says CLEAN: two independent
mechanisms, one of which cannot see context.

**RC10 - Stale cached assessments survive detector changes.** `Workspace.get_or_create_assessment` returns
`assessment.json` whenever `content_hash` matches. The cache is not versioned, so a file uploaded under an older (weaker)
rule set keeps its old verdict forever. Separately, the cache loader builds `SensitiveFinding(...)` **without the
required `reason` argument**, which raises `TypeError`; that is swallowed by `except Exception: pass`, so the cache is
silently dead code today and any fix to it must be tested.

**RC11 - Silent loss of evidence.**
 - `extract()` truncates at 400 000 characters and records only a note on the *extraction*; the assessment still says
   `COMPLETED` / "no sensitive data" for text that was never scanned.
 - `assess_text(limit_per_category=20)` stops recording after 20 findings per category without saying so.
 - `save_upload` wraps assessment in `except Exception: pass`, so a crash leaves `meta.assessment = None` and the
   upload shows no sensitivity badge at all.
 - `summarize` reads at most `max_chunks = 8` evenly spaced chunks, so for long documents the model-side view of
   personal content in the middle or at the end is sampled away (coverage is reported in the notes, but it does not reach the flag).

**RC12 - Three independent secret detectors that disagree.** `sensitive._RX_CREDENTIAL`, `tools._GENERIC_SECRET`
(adds `token`, `api_key`, `access_key`) and the monitor's `_CREDENTIAL_PATTERNS` each define "a secret" differently.
`scan_secrets` can therefore report `token=...` while the document assessment reports clean (and vice versa).
The monitor's L1 patterns are part of the research-grade `ARMMonitor` and are intentionally left unchanged.

**RC13 - No evaluation-status model beyond COMPLETED / NOT_EVALUABLE.** There is no way to express "deterministic
layer ran, AI layer failed", "only part of the document was covered" or "needs human review". `status` is the only field
the frontend reads, and it treats anything that is not `NOT_EVALUABLE` and not `is_sensitive` as **CLEAN**
(`agent.ts`, "assessment" case). Any partial result with zero findings would therefore display as CLEAN unless the backend maps it to
`NOT_EVALUABLE`.

**RC14 - No severity and no explanation of classification.** `SensitiveFinding` has category, evidence, method,
confidence and a fixed `reason` string, but no severity, no corroboration and no source layer, so downstream cannot
tell "confirmed credential" from "weak suspicion".

## 4. Why the system sometimes summarises but does not flag

The summary comes from the model (reads sampled chunks, understands context). The flag comes from regexes
(no context, no understanding). When the personal content has a shape the regexes know, both agree. When it does not
(bare phone number RC1, `api_key: ...` RC2, a private message RC9, content past the truncation RC11, a cached verdict from
an older rule set RC10) the summary mentions it and the badge stays CLEAN.

## 5. Why false positives occur

RC2 (no placeholder or example awareness), RC3 (Luhn-only cards), RC4/RC5/RC6 (unvalidated ID and phone patterns),
RC7 (common-word triggers), RC8 (no discussed-vs-present distinction).

## 6. Why false negatives occur

RC1, RC2, RC5 (no-space Aadhaar), RC9 (no contextual layer), RC10 (stale cache), RC11 (truncation, per-category cap, sampled chunks).

## 7. File extraction and parsing weaknesses

 - Truncation at 400 000 chars is invisible to the assessment (RC11).
 - Normalisation is absent: no Unicode NFKC, so fullwidth digits (`９８７６...`) and zero-width characters
   inside a value defeat every regex; HTML-escaped `&#64;` is not decoded.
 - PDF pages with no extractable text only add an extraction note; the assessment is still `COMPLETED` with zero findings
   (scanned PDFs would show CLEAN). OCR is out of scope, but the result must not claim "clean".
 - XLSX/CSV are read as joined text, which is fine for the detector; DOCX reads only `word/document.xml`, so headers, footers,
   footnotes and comments (`word/header*.xml`, `footnotes.xml`, `comments.xml`) are not scanned.
 - Invalid JSON gets a note but the raw text is still scanned (good); no change needed.

## 8. Model / prompt weaknesses

 - `summarize` prompt: no instruction to separate real data from examples, no severity, no evidence format; it only says
   "include personal information as notes". Output is free-form bullets and is never parsed for security meaning.
 - Planner can skip `summarize_document` entirely, so the model never reads the content; the assessment (regex) is the only security signal.
 - Prompt injection defence (`injection.py`) is solid for tool selection, but there is no evaluator prompt at all, so nothing to defend yet.

## 9. Detection logic weaknesses

See RC1-RC8, RC12.

## 10. Confidence and threshold weaknesses

 - Everything is `HIGH` except phones under 10 digits. A regex hit and a Luhn-verified card carry the same label.
 - Only threshold: `limit_per_category = 20` (silent, RC11).
 - No AI-suspicion tier, so an uncorroborated model opinion could not be represented without pretending it is confirmed.

## 11. Error handling weaknesses

 - `except Exception: pass` in `save_upload` and in the cache loader (RC10/RC11).
 - `assess_text` has no failure state: a regex bug would raise and be swallowed upstream.
 - `FAILED` exists in `AssessmentStatus` but is never produced; the frontend does not handle it (it would render as CLEAN or SENSITIVE depending on findings).
 - Empty text returns `COMPLETED` with zero findings (e.g. a PDF of scanned images).

## 12. Prioritised fixes

1. Honest status model (RC13, RC11, RC10): `evaluation_status` = completed / partial / failed / requires_review, mapped onto the existing `status` field so the unchanged frontend never shows CLEAN for an unfinished evaluation.
2. Deterministic detector repair with validators (RC1-RC7), placeholder/example/discussion awareness (RC8), span de-duplication (RC4), severity (RC14).
3. Contextual AI layer with strict schema validation, verbatim-evidence check, overlapping chunks, full-document coverage (RC9, RC11); AI can never create a "confirmed credential".
4. Aggregation with corroboration rules (AI cannot override deterministic hits; AI-only suspicion becomes `requires_review`).
5. Versioned assessment cache and a working cache loader (RC10); no swallowed exceptions (RC11).
6. Normalisation (NFKC, zero-width removal) and DOCX header/footer/comment extraction (section 7).
7. Make `scan_secrets` reuse the central detector so the two scanners cannot disagree (RC12).
8. Regression tests for every item above, fixtures, documentation.

## 13. Expected behaviour after the fixes

 - `John Doe, phone number 9876543210` -> Phone number finding (MEDIUM severity), status completed.
 - `api_key: <real-looking value>` / JWT / Slack token / DB URL with credentials -> HIGH severity credential finding.
 - Placeholders, example domains, `<your-password>`, discussion of passwords, fictional characters, ISBNs, quantities -> no flag (recorded in `suppressed` for transparency).
 - Private conversation or confidential content -> AI finding with evidence quoted from the document; AI-only findings are labelled
   `requires_review`, never "confirmed credential".
 - Model timeout / malformed JSON / empty output / truncated extraction -> `partial` or `failed`, shown by the unchanged UI as
   "NOT EVALUABLE" when there are no findings, never as CLEAN.

## 14. Constraint compliance

No file under `frontend/` was modified. API field additions are additive (`evaluation_status`, `severity`, `layers`,
`suppressed`, `limitations`, `engine_version`); existing fields (`status`, `is_sensitive`, `categories`, `findings[*]`) keep their names and meaning.
The `ARMMonitor` and `src/monitor/` are not touched.
