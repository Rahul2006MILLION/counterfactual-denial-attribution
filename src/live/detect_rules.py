"""Validators and context rules for the deterministic sensitive-data detector.

Everything here is pure and side-effect free. `sensitive.py` combines these helpers into
findings; keeping them separate makes each rule unit-testable.

Design rules
  * A pattern match alone is not enough where a checksum, issuer prefix or format
    validator exists (cards, Aadhaar, SSN, PAN, phone length).
  * Placeholder values (`<your-password>`, `xxxx`, `changeme`, reserved example domains)
    are suppressed, never reported as real data.
  * Provider-format secrets (AWS, GitHub, Slack, JWT, PEM ...) are only suppressed by
    placeholder VALUES, never by surrounding prose, so a sentence cannot hide a real key.
  * Suppressed candidates are returned with a reason so the caller can record them.
"""

from __future__ import annotations

import html
import re
import unicodedata

# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

_ZERO_WIDTH = re.compile("[​-‏‪-‮⁠-⁤﻿­]")


def normalise_text(text: str) -> str:
    """NFKC-fold (fullwidth digits/letters), drop zero-width characters, decode HTML entities.

    Newlines are preserved so line numbers stay valid."""
    if not text:
        return text
    if "&#" in text or "&amp;" in text or "&lt;" in text or "&gt;" in text:
        text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    return _ZERO_WIDTH.sub("", text)


# ---------------------------------------------------------------------------
# Placeholder / example / discussion awareness
# ---------------------------------------------------------------------------

_PLACEHOLDER_TOKENS = (
    "example", "placeholder", "changeme", "change_me", "change-me", "dummy", "redacted",
    "replace_me", "replace-me", "insert", "xxxx", "****", "<your", "your_", "your-", "yourkey",
    "yourpassword", "your password", "todo", "not_a_real", "notreal", "fake", "lorem",
)
_PLACEHOLDER_SHAPE = re.compile(
    r"^(?:<[^>]*>|\{\{.*\}\}|\$\{.*\}|%\w+%|\[[^\]]*\]|\.{3,}|…|-{3,}|\*{3,}|x{3,}|_{3,}|n/?a|none|null|nil|undefined|true|false)$",
    re.IGNORECASE,
)
_CODE_REFERENCE = re.compile(
    r"^(?:os\.|process\.|env\b|getenv|config\b|settings\b|self\.|args\.|params\b|request\.|input\(|getpass|secrets\.|vault|System\.)|[(\[]",
    re.IGNORECASE,
)
_PROSE_STOPWORDS = frozenset(
    "a an the it is are was be been being not no yes none null nil true false required optional stored hashed "
    "encrypted case sensitive invalid incorrect wrong reset expired correct too set empty blank missing secure "
    "strong weak always never saved provided changed at in on of to for your my our their his her its this that "
    "here there with without and or but if then so as by from can will would should must may might do does did "
    "never used shared safe private public hidden visible long short complex simple unique reused common default "
    "managed generated rotated mandatory enforced length policy manager protected shown masked".split()
)

# An example/discussion marker anywhere in the same line makes keyword-style matches
# (password=..., emails, phones) count as discussion. It never suppresses provider-format secrets.
_EXAMPLE_CONTEXT = re.compile(
    r"\b(?:e\.g\.?|for example|for instance|such as|examples?|sample|placeholder|dummy|fake|"
    r"hypothetical(?:ly)?|imagine|suppose|illustrat\w*|weak password|never (?:use|store|commit|hard-?code)|"
    r"do not (?:use|store|commit|hard-?code)|don't (?:use|store|commit|hard-?code)|"
    r"not (?:a )?real|template|fictional|made[- ]up)\b",
    re.IGNORECASE,
)


_EMAIL_OR_URL = re.compile(r"\S+@\S+|https?://\S+|\b\w+\.(?:com|org|net|edu|io)\b", re.IGNORECASE)


def has_example_context(line: str) -> bool:
    # "example.com" in an address is not prose saying "for example"
    return bool(_EXAMPLE_CONTEXT.search(_EMAIL_OR_URL.sub(" ", line)))


def is_placeholder_value(value: str) -> bool:
    v = (value or "").strip().strip("\"'`")
    if not v:
        return True
    low = v.lower()
    if _PLACEHOLDER_SHAPE.match(v):
        return True
    if any(tok in low for tok in _PLACEHOLDER_TOKENS):
        return True
    if len(set(low)) <= 2 and len(low) >= 4:  # aaaa, 0000, xyxy
        return True
    return False


def looks_random(value: str) -> bool:
    """Heuristic: >=8 chars mixing at least two of lower/upper/digit/symbol."""
    v = value.strip("\"'`")
    if len(v) < 8:
        return False
    classes = sum(
        bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    return classes >= 2


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

_RESERVED_DOMAINS = frozenset({"example.com", "example.org", "example.net", "example.edu", "test.com", "domain.com", "email.com", "yourdomain.com", "company.com", "mail.com"})
_RESERVED_TLDS = frozenset({"test", "invalid", "example", "localhost"})
_GENERIC_LOCALS = frozenset({"name", "user", "username", "email", "youremail", "your.name", "yourname", "someone", "john.doe", "jane.doe", "johndoe", "janedoe", "first.last", "firstname.lastname", "test", "foo", "bar", "abc", "xyz", "me", "you", "info", "admin", "sample", "demo"})


def email_suppression(email: str, line: str) -> str | None:
    """Return a reason string if this email is a placeholder/example, else None."""
    local, _, domain = email.lower().rpartition("@")
    domain = domain.rstrip(".")
    if domain in _RESERVED_DOMAINS:
        return f"reserved or placeholder domain '{domain}'"
    if domain.rsplit(".", 1)[-1] in _RESERVED_TLDS:
        return f"reserved top-level domain in '{domain}'"
    if local in _GENERIC_LOCALS and has_example_context(line):
        return "generic address inside an example or format description"
    return None


# ---------------------------------------------------------------------------
# Phone
# ---------------------------------------------------------------------------

_CURRENCY_BEFORE = re.compile(r"(?:[$€£₹¥]|\b(?:rs|inr|usd|eur|gbp|amount|total|price|cost|qty|quantity|order|invoice|id|no|ref|isbn|tracking)\b\.?)\s*[:#]?\s*$", re.IGNORECASE)


def phone_digits_ok(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if not 10 <= len(digits) <= 15:
        return False
    return len(set(digits)) > 2  # 0000000000 / 1212121212 are filler, not numbers


def phone_bare_context_ok(line: str, start: int) -> bool:
    """A bare digit run is a phone number unless a currency/id label directly precedes it."""
    return not _CURRENCY_BEFORE.search(line[max(0, start - 14):start])


_PHONE_LABEL = r"(?:phone|tel(?:ephone)?|mobile|mob|cell(?:ular)?|contact(?:\s+(?:number|no\.?))?|whatsapp|fax|call(?:\s+me)?(?:\s+(?:on|at))?|reach\s+(?:me|her|him|them)\s+at)"
PHONE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # (name, pattern with group 'v' for the number, confidence when valid)
    ("labelled", re.compile(rf"\b{_PHONE_LABEL}\b(?:\s*(?:number|no\.?|#))?\s*[:=\-]?\s*(?P<v>\+?\d[\d\s().\-]{{8,18}}\d)", re.IGNORECASE), "HIGH"),
    ("international", re.compile(r"(?<![\w+])(?P<v>\+\d{1,3}[\s.\-]?(?:\(\d{1,4}\)|\d{1,4})(?:[\s.\-]?\d{2,5}){2,4})(?!\d)"), "HIGH"),
    ("us_formatted", re.compile(r"(?<![\w.])(?P<v>\(\d{3}\)\s?\d{3}[\s.\-]?\d{4}|\d{3}[\-.]\d{3}[\-.]\d{4})(?![\w])"), "HIGH"),
    ("in_grouped", re.compile(r"(?<![\w.])(?P<v>[6-9]\d{4}[\s\-]\d{5})(?![\w])"), "MEDIUM"),
    ("in_mobile", re.compile(r"(?<![\w.+\-])(?<!\d,)(?P<v>[6-9]\d{9})(?![\w])"), "MEDIUM"),  # comma allowed: CSV/XLSX cells
]


# ---------------------------------------------------------------------------
# Payment cards
# ---------------------------------------------------------------------------

def luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(ds) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(ds)):
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def card_brand(digits: str) -> str | None:
    """Issuer + length validation. Returns brand name or None if not a plausible card."""
    n = len(digits)
    p2, p3, p4 = int(digits[:2]), int(digits[:3]), int(digits[:4])
    if digits[0] == "4" and n in (16, 19):
        return "Visa"
    if (51 <= p2 <= 55 or 2221 <= p4 <= 2720) and n == 16:
        return "Mastercard"
    if p2 in (34, 37) and n == 15:
        return "American Express"
    if (p4 == 6011 or 644 <= p3 <= 649 or p2 == 65) and 16 <= n <= 19:
        return "Discover"
    if 3528 <= p4 <= 3589 and 16 <= n <= 19:
        return "JCB"
    if (300 <= p3 <= 305 or p2 in (36, 38, 39)) and n in (14, 16):
        return "Diners Club"
    if p2 == 62 and 16 <= n <= 19:
        return "UnionPay"
    if (p2 in (60, 81, 82)) and n == 16:
        return "RuPay"
    return None


_CARD_NEGATIVE_LABEL = re.compile(r"\b(?:isbn|order|tracking|invoice|serial|barcode|upc|ean|sku|shipment|parcel|awb)\b[^\d]{0,12}$", re.IGNORECASE)


def card_candidate_ok(line: str, start: int, digits: str) -> tuple[bool, str]:
    if len(set(digits)) <= 1:
        return False, "repeated digits"
    if _CARD_NEGATIVE_LABEL.search(line[max(0, start - 24):start]):
        return False, "number is labelled as an order/ISBN/tracking identifier"
    if not luhn_ok(digits):
        return False, "fails Luhn checksum"
    brand = card_brand(digits)
    if brand is None:
        return False, "no recognised card issuer prefix/length"
    return True, brand


# ---------------------------------------------------------------------------
# Government identifiers
# ---------------------------------------------------------------------------

_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 2, 3, 4, 0, 6, 7, 8, 9, 5), (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7), (4, 0, 1, 2, 3, 9, 5, 6, 7, 8), (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2), (7, 6, 5, 9, 8, 2, 1, 0, 4, 3), (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9), (1, 5, 7, 6, 2, 8, 3, 0, 9, 4), (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7), (9, 4, 5, 3, 1, 2, 6, 8, 7, 0), (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5), (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff_ok(number: str) -> bool:
    if not number.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def aadhaar_ok(digits: str) -> bool:
    if not (len(digits) == 12 and digits[0] in "23456789" and verhoeff_ok(digits) and len(set(digits)) > 2):
        return False
    groups = [int(digits[i:i + 4]) for i in (0, 4, 8)]
    return not all(1900 <= g <= 2100 for g in groups)  # three consecutive years are not an ID


def ssn_ok(area: str, group: str, serial: str, labelled: bool) -> bool:
    if group == "00" or serial == "0000" or area == "000":
        return False
    if labelled:
        return True
    return area != "666" and not area.startswith("9")


PAN_RX = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")  # 4th letter = holder type
SSN_RX = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
AADHAAR_SPACED_RX = re.compile(r"(?<![\d-])([2-9]\d{3})[ \-]?(\d{4})[ \-]?(\d{4})(?![\d-])")
AADHAAR_LABEL_RX = re.compile(r"\b(?:aadhaar|aadhar|uidai|uid)\b", re.IGNORECASE)
SSN_LABEL_RX = re.compile(r"\b(?:ssn|social\s+security|tax\s*id|itin)\b", re.IGNORECASE)
