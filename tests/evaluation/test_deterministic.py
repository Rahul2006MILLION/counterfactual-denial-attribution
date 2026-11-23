"""Layer 1: deterministic detection, validators, false-positive and false-negative regressions."""

from __future__ import annotations

import pytest

from src.live import detect_rules as R
from src.live.sensitive import assess_text
from tests.evaluation.conftest import fixture_bytes

CRED = "Authentication credentials and API keys"


def cats(text: str) -> set[str]:
    return set(assess_text(text).categories)


# ------------------------------------------------------------ A. must be flagged
@pytest.mark.parametrize("label,text,expected", [
    ("RC1 bare 10-digit phone (task-brief example)", "John Doe, phone number 9876543210, lives in Pune", "Phone number"),
    ("RC1 bare mobile in prose", "Call me on 9876543210 tomorrow.", "Phone number"),
    ("international phone", "Reach her at +44 20 7946 0958.", "Phone number"),
    ("US formatted phone", "Office: (415) 555-2671", "Phone number"),
    ("RC2 api_key colon", "api_key: 8f14e45fceea167a5a36dedd4bea2543", CRED),
    ("RC2 api key in a sentence", "My API key is sk_live_abcdefghijklmnop1234", CRED),
    ("RC2 access_token assignment", "access_token=9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c", CRED),
    ("RC2 JWT", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk", CRED),
    ("RC2 Slack token", "xo" + "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx", CRED),  # built at runtime: synthetic value, avoids secret-scanner false alarms
    ("RC2 JSON password field", '{"password": "Zx9!kLm2pQ"}', CRED),
    ("RC2 sentence password", "My password is Hunter2Hunter2 please do not share", CRED),
    ("RC2 URL with credentials", "postgres://admin:S3cretPass@db.internal:5432/prod", CRED),
    ("PEM private key", "-----BEGIN RSA PRIVATE KEY-----", CRED),
    ("card with spaces (Visa test number)", "Card 4111 1111 1111 1111 exp 12/27", "Payment-card information"),
    ("SSN", "SSN 123-45-6789", "Tax or government identifier"),
    ("PAN", "PAN ABCPE1234F on file", "Tax or government identifier"),
    ("IBAN mod-97 valid", "IBAN DE89370400440532013000", "Bank or account number"),
    ("labelled account", "Account number 123456789012", "Bank or account number"),
    ("labelled passport", "Passport: K1234567", "Tax or government identifier"),
    ("diagnosis in a record", "Patient diagnosis: type 2 diabetes", "Health information"),
])
def test_sensitive_content_is_flagged(label, text, expected):
    """Input: realistic snippet that contains real-looking sensitive data. Expected: the category is flagged."""
    assert expected in cats(text), f"{label}: got {cats(text)}"


def test_aadhaar_with_valid_checksum_flagged_without_spaces_only_when_labelled():
    """Input: a 12-digit number with a valid Verhoeff check digit. Expected: flagged when spaced or labelled."""
    base = "23456789012"
    check = next(d for d in "0123456789" if R.verhoeff_ok(base + d))
    num = base + check
    spaced = f"{num[:4]} {num[4:8]} {num[8:]}"
    assert "Tax or government identifier" in cats(f"ID {spaced}")
    assert "Tax or government identifier" in cats(f"Aadhaar {num}")
    assert "Tax or government identifier" not in cats(f"order {num}")


# ------------------------------------------------------------ B. must NOT be flagged
@pytest.mark.parametrize("label,text", [
    ("RC8 password discussion with sample value", "Never store your password in plain text. Weak examples such as password=hunter2 are guessed instantly."),
    ("RC8 example email format", "Use the format name@example.com for examples."),
    ("RC2 placeholder api key", "api_key = YOUR_API_KEY_HERE"),
    ("RC2 angle-bracket placeholder", "password: <your-password>"),
    ("RC2 bearer placeholder", "Authorization header uses Bearer <token>"),
    ("RC2 code reference not a secret", 'password = os.environ["DB_PASSWORD"]'),
    ("RC2 prose about passwords", "The password is required and must be rotated."),
    ("RC3 ISBN is not a card", "ISBN 978-3-16-148410-0 and order 4532015112830 shipped"),
    ("RC5/RC6 quantities and years", "Revenue was 123 456 7890 units across 2023 2024 2025 periods"),
    ("dates are not phones", "Between 2020-01-01 and 2021-12-31 we saw 555 1234 hits"),
    ("RC7 history/chronic words", "History of the Roman empire: chronic problems plagued the senate; condition: dire"),
    ("RC7 famous street", "10 Downing Street is famous; in 1999 Apple Way was a popular road."),
    ("build hash that looks like an IBAN", "The identifier AB12CDEFGHIJKLMN is a build hash"),
    ("fiction", "John is a fictional character in a story who lives on Maple Street with a dragon."),
    ("salary words only", "Salary: competitive"),
    ("amount, not a phone", "Total: Rs. 9876543210 crore allocated"),
    ("reserved example domain", "Contact support@example.com"),
    ("version strings", "Released 2024-01-15, build 1234-56-7890 v2.3.4"),
])
def test_harmless_content_is_not_flagged(label, text):
    """Input: harmless text that merely resembles sensitive data. Expected: no finding."""
    assert cats(text) == set(), f"{label}: got {assess_text(text).categories}"


def test_suppressed_candidates_are_recorded_for_transparency():
    """Input: a placeholder password. Expected: no finding, but a `suppressed` entry with the reason."""
    a = assess_text("password: <your-password>")
    assert not a.findings and a.suppressed and "placeholder" in a.suppressed[0]["reason"]


# ------------------------------------------------------------ validators
def test_card_requires_issuer_and_luhn():
    """Input: Luhn-valid 13-digit and ISBN-like numbers. Expected: rejected; Visa test number accepted."""
    assert R.card_candidate_ok("x", 0, "4111111111111111")[0]
    assert not R.card_candidate_ok("x", 0, "9783161484100")[0]
    assert not R.card_candidate_ok("order 4532015112830", 6, "4532015112830")[0]


def test_ssn_rules():
    """Input: SSN-shaped numbers. Expected: invalid areas rejected unless explicitly labelled."""
    assert R.ssn_ok("123", "45", "6789", False)
    assert not R.ssn_ok("000", "45", "6789", True)
    assert not R.ssn_ok("987", "65", "4321", False)
    assert R.ssn_ok("987", "65", "4321", True)


# ------------------------------------------------------------ RC4 overlap, RC14 severity, normalisation
def test_rc4_one_value_one_finding():
    """Input: one card number. Expected: exactly one finding (no phone / government-id duplicate)."""
    a = assess_text("Card 4111 1111 1111 1111 on file")
    assert [f.category for f in a.findings] == ["Payment-card information"]


def test_rc14_severity_and_reason_on_every_finding():
    """Input: card, phone and credential. Expected: HIGH/MEDIUM severities and a specific reason on each finding."""
    a = assess_text("Card 4111 1111 1111 1111\nphone: 9876543210\napi_key = sk-live-synth0123456789abcdef\n")
    sev = {f.category: f.severity for f in a.findings}
    assert sev["Payment-card information"] == "HIGH" and sev[CRED] == "HIGH" and sev["Phone number"] == "MEDIUM"
    assert all(len(f.reason.split()) >= 4 and f.reason.lower() != "potentially sensitive content detected" for f in a.findings)


def test_normalisation_defeats_obfuscation():
    """Input: fullwidth digits and zero-width characters inside a phone number. Expected: still flagged."""
    assert "Phone number" in cats("Ｐhone: ９８７６５４３２１０")
    assert "Phone number" in cats("phone: 98765\u200b43210")
    assert "Email address" in cats("write to a&#64;corp-mail.org")


def test_evidence_is_redacted():
    """Input: credential, card and phone. Expected: raw values never appear in evidence snippets."""
    a = assess_text("api_key = sk-live-synth0123456789abcdef\nCard 4111 1111 1111 1111\nphone: 9876543210\n")
    blob = "\n".join(f.evidence for f in a.findings)
    assert "synth0123456789" not in blob and "4111 1111" not in blob and "9876543210" not in blob


def test_rc11_findings_cap_is_reported():
    """Input: 25 distinct emails. Expected: 20 listed and a limitation stating the omission."""
    a = assess_text("\n".join(f"user{i}@corp-mail.org" for i in range(25)))
    assert a.category_counts["Email address"] == 20 and any("not listed" in x for x in a.limitations)


# ------------------------------------------------------------ fixtures (deterministic expectations)
EXPECT = {
    "personal_information.txt": ({"Phone number", "Email address", "Home address", "Date of birth", "Employee or student identifier"}, False),
    "credentials.txt": ({CRED}, True),
    "mixed_content.txt": ({"Phone number", "Email address"}, False),
    "sensitive_at_end.txt": ({"Phone number", "Payment-card information", CRED}, False),
    "sensitive_in_middle.txt": ({"Phone number"}, False),
    "sensitive_at_start.txt": ({"Phone number"}, False),
    "prompt_injection_test.txt": ({"Phone number", CRED}, False),
}


@pytest.mark.parametrize("name", sorted(EXPECT))
def test_sensitive_fixtures_flag_expected_categories(name):
    """Input: a sensitive fixture file. Expected: its expected categories are flagged (credentials fixture: HIGH only)."""
    want, high_only = EXPECT[name]
    a = assess_text(fixture_bytes(name).decode(), filename=name)
    assert want <= set(a.categories), f"{name}: got {a.categories}"
    if high_only:
        assert {f.severity for f in a.findings} == {"HIGH"}


@pytest.mark.parametrize("name", ["harmless_article.txt", "fictional_person.txt", "discussion_of_privacy.txt"])
def test_harmless_fixtures_have_no_flags(name):
    """Input: harmless / fictional / discussion fixture. Expected: zero findings and no high severity."""
    a = assess_text(fixture_bytes(name).decode(), filename=name)
    assert a.findings == [] and not a.is_sensitive
