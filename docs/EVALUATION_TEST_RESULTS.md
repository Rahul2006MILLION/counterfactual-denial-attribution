# Evaluation Test Results

Everything below was actually executed on 2026-11-23 in this repository (macOS, Python 3.12 via `uv`). Nothing here is projected.

## 1. Automated tests

| Command | Result |
|---|---|
| `uv run pytest tests/test_sensitive_assessment.py tests/test_live_agent.py -q` (before any change) | 80 passed |
| `uv run pytest tests/evaluation -q` | **126 passed** (116 before redaction was added, +10 in test_redaction.py) |
| `uv run pytest tests -q` (whole repository) | **646 passed**, 0 failed, 1 deprecation warning from Starlette's TestClient |

The suite uses a scripted fake for the Ollama transport, so it is deterministic and needs no model. Per-test input / expected / actual / pass-fail
is generated on every run into `tests/evaluation/report/test_report.md` (and `.json`).

| File | Tests | Covers |
|---|---|---|
| `test_deterministic.py` | 57 | A clearly sensitive, B harmless, validators, overlap, severity, normalisation, redaction, cap reporting, all fixtures at detector level |
| `test_contextual.py` | 25 | AI validation (hallucinated quote, fiction, vague, out-of-scope), failures (timeout, malformed JSON, missing fields, wrong types, empty), retry, partial coverage, chunk boundaries, start/middle/end, prompt contents, wrapper neutralisation |
| `test_pipeline.py` | 34 | all fixtures through the real API, summary-vs-evaluation independence, formats TXT/MD/CSV/JSON/DOCX/PDF/XLSX/PY, DOCX header, scanned PDF, extraction failure, unsupported file, truncation, cache regressions, swallowed-error regression, `scan_secrets` agreement, frontend contract fields |

## 2. Failures encountered while developing (and what they were)

| When | Failure | Root cause | Resolution |
|---|---|---|---|
| after rewriting the detector | 5 existing tests failed | (a) the word "example" inside `support@example.com` was read as "for example" and hid the password on the same line; (b) masked account `XXXX-XXXX-0000` was rejected as a placeholder | (a) example-context ignores words inside emails/URLs; (b) masked numbers with 4+ digits count |
| same | `test_assessment_across_supported_formats` still failed | the test expects `support@example.com` to be flagged, which contradicts the reserved-domain rule | test data changed to `support@corp-mail.org` (documented in KNOWN_LIMITATIONS #13) |
| after adding the AI layer | 2 existing tests failed | new `chunk` events broke a count; `scan_secrets` no longer reported the demo placeholder key | AI progress uses its own event type `contextual`; placeholder-like literals are listed by `scan_secrets` as INFO |
| new format tests | `a.csv`, `a.xlsx` phone not flagged | **real bug I introduced**: bare-mobile lookbehind excluded a preceding comma | lookbehind now allows CSV commas; test retained as regression |
| live model run 1 | `discussion_of_privacy.txt` flagged by the AI | generic sentence about medical history | `is_specific` validation + regression test |
| live model run 2 | AI reply truncated at 700 tokens on one file | reply too long | prompt/schema ask for <=5 findings, <=120-char quotes, <=25-word explanations; truncation was correctly reported `partial`/NOT EVALUABLE, never clean |

## 3. Live run against the real model (not part of pytest)

`qwen3:4b-4k` through the real FastAPI server and Ollama, one "Summarize this document" task per file, final code:

| File | evaluation_status | UI | Findings |
|---|---|---|---|
| `harmless_article.txt` | completed | CLEAN | none |
| `fictional_person.txt` | completed | CLEAN | none (2 AI suggestions discarded by validation) |
| private message note (ad hoc) | requires_review | SENSITIVE | 1 AI finding, MEDIUM, "Private conversation or correspondence" |
| `discussion_of_privacy.txt` | completed | CLEAN | none (1 AI suggestion discarded) |
| `mixed_content.txt` | completed | SENSITIVE | phone, email (deterministic); summary also produced |
| `prompt_injection_test.txt` | requires_review | SENSITIVE | email, phone, HIGH credential (deterministic) + 1 redundant AI finding on the password line |

Upload-only checks against the running server (deterministic layer): `personal_information`, `credentials`, `harmless_article`, `discussion_of_privacy`, `sensitive_at_end` returned the expected status/categories/severity.
Earlier in the same session, before the final prompt shortening, one run of `discussion_of_privacy.txt` returned `partial`/NOT_EVALUABLE because the model truncated its JSON; this is the designed failure behaviour and it is not a pass for the model.

Not run live: `credentials.txt`, `personal_information.txt`, `sensitive_at_end.txt` through the AI layer (they are covered at the pytest level with the scripted model); the 40 KB documents through the live model (time).

## 4. Frontend

No file under `frontend/` was touched (`find frontend -newer docs/AUDIT_REPORT.md` returned nothing). The frontend was **not** rendered in a browser in this session; compatibility is verified by
`test_api_contract_fields_for_frontend_are_intact` and by `ui_verdict()` in `tests/evaluation/conftest.py`, which mirrors the decision logic read from `agent.ts`.

## 5. Known gaps in verification

- Detector precision/recall was measured only on the hand-written cases and fixtures here; there is no labelled real-world corpus.
- The AI layer's behaviour depends on the model; results above are single runs, not statistics.
- See `docs/KNOWN_LIMITATIONS.md`.

## 6. Redaction before the model (added later)

- 10 new tests in `tests/evaluation/test_redaction.py`; full suite 646 passed. They check that no raw flagged value appears in any request sent to the model (summary, AI review, search, dates, secret scan, table groups) for `personal_information.txt` and `credentials.txt`, that flags are unaffected, that a control run with redaction off does leak the values (so the test can fail), and that private-message content with no pattern is still visible to the AI layer.
- Live run (real `qwen3:4b-4k`, `manual_tests/sensitive_file.txt`): task completed; 9 values replaced before the model read the file; none of the phone, email, password or API key appears anywhere in the task's `events.jsonl`. The AI layer still added one redundant MEDIUM suspicion on an ordinary sentence (known small-model noise).
- Not verified: the UI was not rendered with redaction on; the redaction behaviour is backend-only and the response shape only gained `redacted_for_model`.
