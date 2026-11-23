"""Redaction before the model: flagged values must never reach any model request."""

from __future__ import annotations

import dataclasses
import json

import pytest

from src.live.config import Settings
from src.live.sensitive import assess_text, redact_for_model
from tests.evaluation.conftest import fixture_bytes, run_task, ui_verdict
from tests.test_live_agent import FakeOllama, plan

RAW = {
    "personal_information.txt": ["9876543210", "priya.nair@brightmail-test.in", "EMP-40917", "Green Park Apartments"],
    "credentials.txt": ["Tr0ub4dor&3xK9", "sk-live-synth0123456789abcdef", "AKIAQ3ZT7SYNTH4A2B1C", "Zq81!mPlw3"],
}
ALL_TOOLS = plan(
    {"tool": "summarize_document", "doc_id": "D1", "purpose": "read"},
    {"tool": "search_text", "doc_id": "D1", "query": "phone", "purpose": "find"},
    {"tool": "extract_dates", "doc_id": "D1", "purpose": "dates"},
    {"tool": "scan_secrets", "doc_id": "D1", "purpose": "secrets"},
)


def sent_to_model(fake: FakeOllama) -> str:
    """Everything that was sent to the model in this task, as one string."""
    return json.dumps([c["payload"] for c in fake.calls if c["path"] == "/api/chat"], ensure_ascii=False)


def test_default_setting_is_on():
    """Input: default Settings. Expected: redaction for the model is enabled."""
    assert Settings().redact_for_model is True


def test_redact_for_model_replaces_values_and_keeps_context_and_lines():
    """Input: text with a phone, email and password. Expected: values replaced by tags, surrounding words and line count kept."""
    text = "Call Priya on phone: 9876543210 today.\nemail priya@brightmail-test.in\npassword: Zx9!kLm2pQ\nThanks."
    out, n = redact_for_model(text)
    assert n == 3 and out.count("\n") == text.count("\n")
    assert "9876543210" not in out and "priya@brightmail" not in out and "Zx9!kLm2pQ" not in out
    assert "[REDACTED:PHONE]" in out and "[REDACTED:EMAIL]" in out and "[REDACTED:SECRET]" in out
    assert out.startswith("Call Priya on phone: ") and out.endswith("Thanks.")


def test_redacted_text_is_clean_for_the_detector():
    """Input: a sensitive fixture after redaction. Expected: the deterministic detector finds nothing left to flag."""
    out, _ = redact_for_model(fixture_bytes("personal_information.txt").decode() + fixture_bytes("credentials.txt").decode())
    assert assess_text(out).findings == []


def test_redaction_has_no_per_category_cap():
    """Input: 30 emails (more than the 20-per-category listing cap). Expected: all 30 replaced."""
    out, n = redact_for_model("\n".join(f"user{i}@corp-mail.org" for i in range(30)))
    assert n == 30 and "@corp-mail.org" not in out


@pytest.mark.parametrize("name", sorted(RAW))
def test_no_raw_sensitive_value_reaches_any_model_request(settings, name):
    """Input: a sensitive fixture processed with summary, search, dates and secret-scan steps. Expected: no raw flagged value appears in any request sent to the model; the document is still flagged."""
    fake = FakeOllama(settings, plans=[ALL_TOOLS], answer="Summary.")
    snap = run_task(settings, name, fixture_bytes(name), fake=fake)
    blob = sent_to_model(fake)
    assert snap["status"] == "completed"
    for raw in RAW[name]:
        assert raw not in blob, f"{raw!r} reached the model"
    assert "[REDACTED:" in blob  # the model did read a redacted copy, not nothing
    a = snap["document_assessments"]["D1"]
    ass_ui = ui_verdict(a)
    assert ass_ui == "SENSITIVE" and a["redacted_for_model"] > 0  # flagging is unaffected


def test_control_without_redaction_the_model_sees_raw_values(settings):
    """Input: same task with CDA_REDACT_FOR_MODEL off. Expected: raw values DO reach the model (proves the test above can fail)."""
    s2 = dataclasses.replace(settings, redact_for_model=False)
    fake = FakeOllama(s2, plans=[ALL_TOOLS], answer="Summary.")
    snap = run_task(s2, "personal_information.txt", fixture_bytes("personal_information.txt"), fake=fake)
    assert "9876543210" in sent_to_model(fake)
    assert snap["document_assessments"]["D1"]["redacted_for_model"] == 0


def test_ai_layer_reads_the_redacted_copy_and_keeps_context(settings):
    """Input: personal_information.txt. Expected: the evaluator request contains the surrounding prose but not the phone number."""
    fake = FakeOllama(settings, plans=[plan()])
    run_task(settings, "personal_information.txt", fixture_bytes("personal_information.txt"), fake=fake)
    reqs = [json.dumps(p) for p in fake.chat_calls("findings")]
    assert reqs and all("9876543210" not in r for r in reqs) and any("delivery preferences" in r for r in reqs)


def test_table_group_labels_are_redacted(settings):
    """Input: CSV grouped by an email column. Expected: group names shown to the model are redacted."""
    csv = b"email,amount\nanu@corp-mail.org,10\nanu@corp-mail.org,20\nraj@corp-mail.org,5\n"
    fake = FakeOllama(settings, plans=[plan({"tool": "table_stats", "doc_id": "D1", "group_by": "email", "purpose": "g"})], answer="ok")
    snap = run_task(settings, "t.csv", csv, fake=fake)
    assert "corp-mail.org" not in sent_to_model(fake) and snap["status"] == "completed"


def test_what_redaction_cannot_hide_is_still_visible_to_ai_layer(settings):
    """Input: a private message with no pattern-shaped data. Expected: it is not redacted (documented limitation) and still reaches the AI layer."""
    note = b"Hey Priya, I got my biopsy results back and I am terrified. Please do not tell Mom.\n"
    fake = FakeOllama(settings, plans=[plan()])
    run_task(settings, "note.txt", note, fake=fake)
    assert "biopsy results" in " ".join(json.dumps(p) for p in fake.chat_calls("findings"))
