# Evaluation Testing Guide

## Run the application

```bash
cd /Users/rahuljain/agneticai-research
uv run uvicorn src.live.api:app --host 127.0.0.1 --port 8000
```

Frontend (unchanged): `npm --prefix frontend run dev` (or `preview`). The AI layer needs Ollama running with a local Qwen model (`ollama serve`; check `curl localhost:8000/api/health`).

## Run the automated tests

```bash
uv run pytest tests/evaluation -q          # the evaluation suite (126 tests, ~1s, no Ollama needed)
uv run pytest tests -q                     # everything (646 tests)
cat tests/evaluation/report/test_report.md # per-test input / expected / actual / pass-fail table written by each run
```

## Manual test: upload each fixture

Via the UI: attach the file, give the task "Summarize this document", and read the "Document Sensitivity" line in the activity log and the result card.
Via the API:

```bash
curl -s -F "files=@tests/evaluation/fixtures/credentials.txt" localhost:8000/api/upload
# then create a task with the returned file_id to run the AI layer too:
curl -s -X POST localhost:8000/api/tasks -H 'content-type: application/json' -d '{"instruction":"Summarize this document.","file_ids":["f_..."]}'
curl -s localhost:8000/api/tasks/<task_id> | python3 -m json.tool   # see document_assessments
```

| Fixture | Expected UI | Expected categories | Max severity | Summary |
|---|---|---|---|---|
| `personal_information.txt` | SENSITIVE | name, DOB, phone, email, address, employee id | MEDIUM | useful summary |
| `credentials.txt` | SENSITIVE | credentials (7 findings) | HIGH | summary produced |
| `harmless_article.txt` | CLEAN | none | none | summary produced |
| `fictional_person.txt` | CLEAN | none | none | summary produced |
| `mixed_content.txt` | SENSITIVE | phone, email only (operations text not flagged) | MEDIUM | summary covers the operations content |
| `sensitive_at_end.txt` (40 KB) | SENSITIVE | phone, card, credential (all at the end) | HIGH | summary produced |
| `sensitive_in_middle.txt`, `sensitive_at_start.txt` | SENSITIVE | phone | MEDIUM | |
| `prompt_injection_test.txt` | SENSITIVE | email, phone, credential; no write_report/email executed | HIGH | document marked untrusted |
| `discussion_of_privacy.txt` | CLEAN | none (`suppressed` lists 3 examples/placeholders) | none | |

With a live model the AI layer may add a MEDIUM/LOW "Private conversation..." finding and the status becomes `requires_review`; that is expected behaviour for AI-only suspicions, but see the false-positive section.
For a private-message test, upload a note such as: `Hey Priya, I got my biopsy results back and I am terrified. Please do not tell Mom.`: expect SENSITIVE, `requires_review`, one `source: "ai"` finding.

## Reading a result

`document_assessments.D1`: `status` (UI), `evaluation_status` (completed, partial, failed, requires_review), `layers`, `findings[]` (category, severity, source, line, redacted evidence, reason, confidence), `limitations[]`, `suppressed[]`.

## Finding false positives

A document flagged SENSITIVE that should not be: open `findings`, read each `reason` and `evidence`. `source: "deterministic"` means a rule fired (the `reason` names the rule); `source: "ai"` means a model suspicion. Then look at `suppressed` of similar clean documents to see which context rules exist. Fix by tightening a rule in `sensitive.py` / `detect_rules.py` and add a case to `test_harmless_content_is_not_flagged`.

## Finding false negatives

A document shown CLEAN that contains sensitive data: first check `evaluation_status` and `limitations` (partial/failed is never CLEAN). Then run the text through the detector directly:

```bash
uv run python -c "from src.live.sensitive import assess_text; a=assess_text(open('yourfile.txt').read()); print(a.categories, a.suppressed)"
```

If `suppressed` explains it, the context rule decided it was an example/placeholder. If nothing appears, add a case to `test_sensitive_content_is_flagged`, then extend the rule and bump `ENGINE_VERSION` (invalidates cached verdicts).

## Logs

- Task events: `.live_workspace/tasks/<task_id>/events.jsonl` (stage 2 holds `extracted`, `contextual` progress and `assessment` events).
- Audit chain: `.live_workspace/tasks/<task_id>/audit.jsonl`.
- Server logs (assessment crashes, cache problems) go to the uvicorn console via the `src.live.workspace` logger.
- Cached deterministic verdict: `.live_workspace/uploads/<file_id>/assessment.json`.

## Debugging a failed or partial evaluation

| Symptom (`limitations` / `error`) | Cause | Action |
|---|---|---|
| `AI contextual review incomplete: ... timed out / unreachable` | Ollama down or slow | `ollama serve`, check `/api/health`, raise `CDA_OLLAMA_TIMEOUT` |
| `... structured reply was truncated` / `invalid JSON` | small model overflowed 700 tokens | rerun; try a larger model via `CDA_OLLAMA_MODEL` |
| `Only the first N of M chunks` | document longer than `CDA_MAX_EVAL_CHUNKS` | raise the cap (costs time) |
| `Extracted text was truncated` | > 400,000 characters | split the file |
| `No extractable text was found` | scanned PDF | OCR it first |
| `Not a valid DOCX file` etc. | corrupt upload | re-export the file |

## Testing redaction before the model

1. Upload `manual_tests/sensitive_file.txt` and run "Summarize this document". The summary and the AI review work from a copy where phones, emails, passwords and keys are tags such as `[REDACTED:PHONE]`.
2. The file badge and the assessment still list the original categories (flagging uses the original text).
3. In `.live_workspace/tasks/<task_id>/events.jsonl`, search for the raw phone number or password: it must not appear. A `contextual` event states how many values were replaced.
4. Set `CDA_REDACT_FOR_MODEL=0`, restart the API and repeat: the model now reads the raw text (use this to confirm the switch works).
5. Automated: `uv run pytest tests/evaluation/test_redaction.py -q`. It inspects every request sent to the (scripted) model and asserts no raw value is present, with a control run where redaction is off.
