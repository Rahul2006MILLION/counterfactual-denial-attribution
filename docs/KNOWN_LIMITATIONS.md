# Known Limitations

Honest list of what the corrected evaluation still does not do.

1. **Not complete accuracy.** Deterministic rules are heuristic outside checksummed formats. Expect residual false positives and negatives on real-world data.
2. **Small local model.** Layer 2 was run live against `qwen3:4b-4k`. It is non-deterministic and sometimes produces truncated JSON (surfaced as `partial`), duplicates a deterministic finding under an AI category (seen on `prompt_injection_test.txt`), or flags generic text. Validation removes many but not all of these; AI results are always `requires_review`.
3. **Upload-time badge is deterministic only.** The file list badge at upload time cannot include the AI layer (no model is chosen yet); the task-time assessment is authoritative. A private conversation with no pattern-shaped data shows CLEAN at upload and SENSITIVE after a task runs.
4. **Cost and coverage.** The AI layer reviews at most `CDA_MAX_EVAL_CHUNKS` chunks (default 24 x 6000 chars = ~144k chars). Longer documents become `partial` (shown as NOT EVALUABLE if nothing was flagged). Extraction is capped at 400,000 characters, also reported as partial.
5. **Example/discussion suppression can hide real data.** A line that contains "for example", "sample", "fake", etc. suppresses SOFT matches on that line (emails of generic names, phones, `password=`, labelled ids). Provider-format secrets, valid cards, valid SSN/PAN/Aadhaar and IBANs are never suppressed by prose. Suppressed items are listed in `suppressed`.
6. **Obviously synthetic secrets.** Values containing `example`, `placeholder`, `dummy`, `changeme`, `xxxx`, `your_...` are treated as placeholders, including the well-known AWS documentation key.
7. **Phones.** Unlabelled phone numbers are matched only in the formats listed in `EVALUATION_ARCHITECTURE.md`; an unlabelled `555 349 8821` (space separated) is not flagged. Bare Indian mobile numbers are flagged by shape, so a 10-digit identifier starting with 6-9 can produce a false positive.
8. **Names.** A person's name is flagged only when labelled (`Name: ...`) and next to other identifying data. Free-text names are not detected deterministically.
9. **No OCR.** Scanned PDFs and images yield no text; they are reported NOT EVALUABLE, not clean.
10. **Languages.** Rules and the prompt are English-centric (Indian and US formats are covered; other national ids are not).
11. **Scope of the status field.** `FAILED` is never sent in `status` because the unchanged frontend cannot display it; use `evaluation_status` instead. The frontend therefore cannot distinguish `partial` from `failed` and cannot show `requires_review` wording (it shows SENSITIVE).
12. **Other scanners.** The monitor's L1 credential patterns (`src/monitor/arm_baseline.py`) and `analyze_code` still use their own patterns by design (research baseline, unchanged). `scan_secrets` now uses the central detector.
13. **Existing tests changed.** `tests/test_sensitive_assessment.py` used `support@example.com` and expected it to be flagged; this conflicted with reserved-domain suppression, so the address was changed to `support@corp-mail.org`. `FakeOllama` in `tests/test_live_agent.py` gained a handler for the new evaluator call.
14. **Redaction only hides what the deterministic detector flags.** Private conversations, free-text names and confidential wording still reach the model (and the AI layer must see them to judge them). A value the regex misses is not redacted. A user instruction that itself contains sensitive data is sent as written.
15. **Redaction changes what the model can say.** Summaries of redacted files contain tags instead of values, and `search_text` cannot find a redacted value. `analyze_code` runs on the original source locally.
16. **Redaction spans can include a label.** Some rules (date of birth, salary) match label and value together, so the label is replaced too.
