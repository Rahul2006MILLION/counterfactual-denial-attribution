"""Authoritative sensitive-data tracking and security assessment engine.

Every uploaded document undergoes deterministic and contextual assessment for sensitive
data (PII, financial records, credentials, identifiers, health information), independently
of model planning, tool selection, or whether actions are allowed or denied.

Detection is strictly evidence-backed: bare mentions of category words, policy discussions,
and aggregate financial totals are distinguished from actual individual sensitive records.
Sentence-scoped negation handling ensures disclaimers do not produce false positives without
suppressing actual evidence.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AssessmentStatus(str, Enum):
    COMPLETED = "COMPLETED"
    NOT_EVALUABLE = "NOT_EVALUABLE"
    FAILED = "FAILED"


class DetectionMethod(str, Enum):
    REGEX = "regex"
    CHECKSUM_LUHN = "checksum_luhn"
    CHECKSUM = "checksum"  # Verhoeff / issuer-prefix validated
    CONTEXTUAL = "contextual"  # deterministic, context-dependent rule
    CONTEXTUAL_AI = "contextual_ai"  # model suspicion; never a confirmed detection


class EvaluationStatus(str, Enum):
    """Honest outcome of the whole evaluation (additive field; `status` stays for the UI)."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    REQUIRES_REVIEW = "requires_review"


# Bump whenever detection rules change: cached assessments from older versions are discarded.
ENGINE_VERSION = "2.0"

SEVERITY_BY_CATEGORY: dict[str, str] = {
    "Payment-card information": "HIGH",
    "Authentication credentials and API keys": "HIGH",
    "Tax or government identifier": "HIGH",
    "Bank or account number": "HIGH",
    "Health information": "HIGH",
    "Email address": "MEDIUM",
    "Phone number": "MEDIUM",
    "Home address": "MEDIUM",
    "Date of birth": "MEDIUM",
    "Employee or student identifier": "MEDIUM",
    "Salary or compensation": "MEDIUM",
    "Personal name (with identifying data)": "MEDIUM",
}


class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def is_luhn_valid(num_str: str) -> bool:
    digits = [int(c) for c in num_str if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    return (
        sum(
            (val * 2 - 9 if val * 2 > 9 else val * 2) if idx % 2 == 1 else val
            for idx, val in enumerate(reversed(digits))
        )
        % 10
        == 0
    )


def redact_value(raw: str, category: str) -> str:
    """Redact sensitive values so raw credentials or identifiers are never stored or displayed."""
    val = raw.strip()
    if category == "Email address":
        parts = val.split("@", 1)
        if len(parts) == 2:
            local, domain = parts
            masked = (local[0] + "***" + local[-1]) if len(local) > 2 else (local[:1] + "***")
            return f"{masked}@{domain}"
        return "[EMAIL_REDACTED]"
    if category == "Payment-card information":
        digits = re.sub(r"[^0-9]", "", val)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        return f"****-****-****-{last4}"
    if category == "Phone number":
        digits = re.sub(r"[^0-9]", "", val)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        return f"***-***-{last4}"
    if category in ("Tax or government identifier", "Government identifier"):
        digits = re.sub(r"[^0-9A-Za-z]", "", val)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        return f"***-**-{last4}"
    if category in ("Bank or account number", "Bank account information"):
        digits = re.sub(r"[^0-9A-Za-z]", "", val)
        last4 = digits[-4:] if len(digits) >= 4 else "XXXX"
        return f"[ACCT_***{last4}]"
    if category == "Authentication credentials and API keys":
        return "[CREDENTIAL_REDACTED]"
    if category == "Date of birth":
        return "[DOB_REDACTED]"
    if category in ("Home address", "Physical address"):
        return "[ADDRESS_REDACTED]"
    if category in ("Employee or student identifier", "Personal and organizational identifiers"):
        return "[ID_REDACTED]"
    if category == "Health information":
        return "[HEALTH_INFO_REDACTED]"
    if category == "Salary or compensation":
        return "[COMPENSATION_REDACTED]"
    if category == "Personal name (with identifying data)":
        return "[NAME_REDACTED]"
    return "[REDACTED]"


def make_evidence_snippet(line: str, start: int, end: int, category: str) -> str:
    """Generate a redacted line context around a match."""
    redacted = redact_value(line[start:end], category)
    before = line[max(0, start - 25):start].lstrip()
    after = line[end:min(len(line), end + 25)].rstrip()
    prefix = "... " if start > 25 else ""
    suffix = " ..." if (len(line) - end) > 25 else ""
    return f"{prefix}{before}{redacted}{after}{suffix}".strip()


@dataclass
class SensitiveFinding:
    doc_id: str
    filename: str
    content_hash: str
    category: str
    line: int
    span: tuple[int, int]
    evidence: str
    method: str
    confidence: str
    reason: str
    timestamp: str = field(default_factory=_now)
    severity: str = "MEDIUM"
    source: str = "deterministic"  # "deterministic" | "ai"

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "source": self.source,
            "doc_id": self.doc_id,
            "filename": self.filename,
            "content_hash": self.content_hash,
            "category": self.category,
            "line": self.line,
            "span": list(self.span),
            "evidence": self.evidence,
            "method": self.method,
            "confidence": self.confidence,
            "reason": self.reason,
            "timestamp": self.timestamp,
        }


@dataclass
class DocumentAssessment:
    doc_id: str
    filename: str
    content_hash: str
    status: AssessmentStatus
    evaluated_at: str
    total_findings: int
    categories: list[str]
    category_counts: dict[str, int]
    findings: list[SensitiveFinding]
    is_sensitive: bool
    error: str | None = None
    evaluation_status: str = EvaluationStatus.COMPLETED.value
    layers: dict[str, str] = field(default_factory=lambda: {"deterministic": "completed", "contextual": "not_run"})
    limitations: list[str] = field(default_factory=list)
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION
    redacted_for_model: int = 0  # sensitive values hidden from the model in this task (0 = none / not applied)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_status": self.evaluation_status,
            "layers": self.layers,
            "limitations": self.limitations,
            "suppressed": self.suppressed,
            "engine_version": self.engine_version,
            "redacted_for_model": self.redacted_for_model,
            "max_severity": max((f.severity for f in self.findings), key=lambda v: {"LOW": 0, "MEDIUM": 1, "HIGH": 2}.get(v, 0), default=None),
            "doc_id": self.doc_id,
            "filename": self.filename,
            "content_hash": self.content_hash,
            "status": self.status.value if isinstance(self.status, AssessmentStatus) else str(self.status),
            "evaluated_at": self.evaluated_at,
            "total_findings": self.total_findings,
            "categories": self.categories,
            "category_counts": self.category_counts,
            "findings": [f.to_dict() for f in self.findings],
            "is_sensitive": self.is_sensitive,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], doc_id: str | None = None) -> "DocumentAssessment":
        """Inverse of to_dict (used by the cache). Raises on malformed input so callers can discard it."""
        did = doc_id or d["doc_id"]
        findings = [
            SensitiveFinding(
                doc_id=did, filename=d["filename"], content_hash=d["content_hash"], category=f["category"], line=f["line"],
                span=tuple(f["span"]), evidence=f["evidence"], method=f["method"], confidence=f["confidence"],
                reason=f["reason"], timestamp=f.get("timestamp", d.get("evaluated_at", "")),
                severity=f.get("severity", "MEDIUM"), source=f.get("source", "deterministic"),
            )
            for f in d.get("findings", [])
        ]
        return cls(
            doc_id=did, filename=d["filename"], content_hash=d["content_hash"], status=AssessmentStatus(d["status"]),
            evaluated_at=d.get("evaluated_at", ""), total_findings=d.get("total_findings", len(findings)),
            categories=list(d.get("categories", [])), category_counts=dict(d.get("category_counts", {})), findings=findings,
            is_sensitive=bool(d.get("is_sensitive", bool(findings))), error=d.get("error"),
            evaluation_status=d.get("evaluation_status", "completed"), layers=dict(d.get("layers", {})),
            limitations=list(d.get("limitations", [])), suppressed=list(d.get("suppressed", [])),
            engine_version=d.get("engine_version", ""), redacted_for_model=int(d.get("redacted_for_model", 0)),
        )


# ---------------------------------------------------------------------------
# Deterministic detection (layer 1)
#
# Every rule is either HARD (checksum / issuer / provider-format validated; never
# suppressed by surrounding prose) or SOFT (label- or context-dependent; suppressed when the
# value is a placeholder or the sentence is an example / discussion / disclaimer).
# ---------------------------------------------------------------------------

from src.live import detect_rules as R  # noqa: E402

_RX_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RX_DOB = re.compile(
    r"\b(?:date\s+of\s+birth|dob|born|birth\s*date)\b[:\s]*([^\n,;]{0,30}(?:\d{1,4}[/-]\d{1,2}[/-]\d{1,4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{2,4}))",
    re.IGNORECASE,
)
_RX_GOVT_LABELED = re.compile(
    r"\b(?:tax\s*(?:id|identifier|number|no\.?)|national\s*id|itin|ein|ssn|social\s+security(?:\s+(?:number|no\.?))?)\b\s*[:=]\s*([A-Za-z0-9-]{4,20})\b"
    r"|\b(?:passport(?:\s+(?:no|num|number|#))?)\b\s*[:=]?\s*([A-PR-WYa-pr-wy][0-9]{7,8}|[0-9]{8,9})\b",
    re.IGNORECASE,
)
_RX_TEST_GOV = re.compile(r"\bTEST-GOV-[A-Z0-9-]+\b")
_RX_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_RX_BANK_LABELED = re.compile(
    r"\b(?:bank\s+account|account(?:\s+(?:number|no|#))?|acct(?:\s*#|\b)|routing(?:\s+(?:number|no))?|iban|swift(?:\s+code)?|bic)\b"
    r"[:\s#]*([0-9X*-]{4,25})\b",
    re.IGNORECASE,
)
_RX_CARD_CONTEXT = re.compile(r"\b(?:credit\s*card|debit\s*card|visa|mastercard|amex)\b\s*[:=]?\s*([0-9X*-]{12,25})\b", re.IGNORECASE)
_RX_CARD_DIGITS = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_RX_ADDRESS_STREET = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9\.\s]{2,30}\s+(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Lane|Ln\.?|Drive|Dr\.?|Court|Ct\.?|Circle|Cir\.?|Way|Highway|Hwy\.?)\b",
    re.IGNORECASE,
)
_ADDRESS_CUE = re.compile(
    r"\b(?:lives?|living|resid\w*|address|located\s+at|ship\w*|deliver\w*|mail\w*|home|flat|apt|apartment|suite|house|moved\s+to|based\s+at|zip|postcode|pin\s*code|customer|patient)\b|,\s*[A-Z][A-Za-z ]+,?\s*(?:[A-Z]{2}\s+)?\d{5,6}\b|\b\d{5,6}\b",
    re.IGNORECASE,
)
_RX_ADDRESS_LABELED = re.compile(
    r"(?<!email )(?<!ip )(?<!mac )(?<!web )(?<!wallet )\b(?:home\s+address|residential\s+address|mailing\s+address|billing\s+address|street\s+address|address)\s*[:=]\s*([^\n]{5,80})",
    re.IGNORECASE,
)
_RX_ORG_ID = re.compile(r"\b(?:employee|staff|worker|student)\s*(?:id|number|no\.?|#)\s*[:=]\s*([A-Za-z0-9-]{3,20})\b", re.IGNORECASE)
_RX_HEALTH_LABELED = re.compile(
    r"\b(?:diagnos[ie]s|medications?|prescriptions?|allergies|symptoms?|medical\s+(?:history|condition|note)|patient\s+(?:id|number|no|ref|reference)|rx)\s*[:=]\s*(?P<v>[^\n;]{3,60})"
    r"|\b(?:blood\s+pressure|heart\s+rate|glucose|insulin)\b\s*[:=]\s*(?P<n>\d+[^\n.;]{0,20})",
    re.IGNORECASE,
)
_RX_HEALTH_FREE = re.compile(r"\b(?:diagnosed\s+(?:with|as)|suffering\s+from|prescribed|treated\s+for)\s+(?P<v>[A-Za-z][A-Za-z\s-]{3,40})", re.IGNORECASE)
_PERSON_CUE = re.compile(r"\b(?:patient|he|she|his|her|my|mr|mrs|ms|dr|name|dob|age|aged|i\s+(?:am|have|was)|client)\b", re.IGNORECASE)
_RX_SALARY = re.compile(
    r"\b(?:Annual\s+salary|Monthly\s+salary|Base\s+salary|Hourly\s+rate|Weekly\s+wage|Salary|Wage|Compensation)\b"
    r"[\"']?\s*[:=]\s*[\"']?(?:(?:INR|USD|EUR|GBP|Rs\.?|\$)\s?\d{1,3}(?:,\d{3})*(?:\.\d{2})?|\d{1,3}(?:,\d{3})+(?:\.\d{2})?(?:\s*(?:INR|USD|EUR|GBP|currency\s+units?|per\s+(?:annum|year|month|hr|hour|week)))?|\d{1,3},\d{3}|\d{4,8})\b",
    re.IGNORECASE,
)
_RX_NAME_LABELED = re.compile(
    r"\b(?:full\s+name|patient\s+name|customer\s+name|employee\s+name|applicant\s+name|candidate\s+name|name)\s*[:=]\s*([A-Z][a-z]+(?:[ '-][A-Z][a-z]+){1,3})\b"
)
_RX_SENTENCE_DISCLAIMER = re.compile(
    r"\b(?:does\s+not\s+contain|do\s+not\s+contain|not\s+contain|contains?\s+aggregate\w*\s+[^.\n]*\s+only|not\s+include|free\s+of|neither\s+[^.\n]+\s+nor)\b",
    re.IGNORECASE,
)

# Credentials -----------------------------------------------------------
_PROVIDER_TOKENS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("API secret key (sk-)", re.compile(r"\bsk-[A-Za-z0-9_-]{14,}")),
    ("Stripe-style key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("Bearer token", re.compile(r"\bBearer\s+([A-Za-z0-9_\-\.=]{20,})")),
    ("URL with embedded password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@[^\s/]+", re.IGNORECASE)),
]
_KEY_NAME = (
    r"[A-Za-z0-9_.-]*?(?:password|passwd|pwd|passphrase|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|"
    r"access[_-]?token|refresh[_-]?token|session[_-]?(?:id|token)|client[_-]?secret|private[_-]?key|token|credentials?)"
)
_RX_KEYVAL = re.compile(
    rf"\b(?P<key>{_KEY_NAME})\b[\"']?\s*(?P<op>[:=]|=>|\bis\b|\bare\b)\s*[\"'`]?(?P<val>[^\s\"'`,;]{{4,}})",
    re.IGNORECASE,
)
_PASSWORDISH = re.compile(r"pass|pwd|secret", re.IGNORECASE)


def _iban_ok(iban: str) -> bool:
    s = iban[4:] + iban[:4]
    try:
        return int("".join(str(int(c, 36)) for c in s)) % 97 == 1
    except ValueError:
        return False


def is_luhn_valid(num_str: str) -> bool:  # noqa: F811 - single public definition, delegates to validator
    return R.luhn_ok(num_str)


def _is_valid_account_value(val: str) -> bool:
    clean = val.strip().lower()
    if clean in _NON_VALUE_WORDS:
        return False
    # Masked numbers (XXXX-XXXX-4321) still identify an account; all-mask or all-same values do not.
    if len(re.findall(r"\d", val)) < 4:
        return False
    return bool(re.search(r"[X*]", val, re.IGNORECASE)) or len(set(re.sub(r"\D", "", val))) > 2


def _is_valid_id_value(val: str) -> bool:
    clean = val.strip().lower()
    if clean in _NON_VALUE_WORDS or R.is_placeholder_value(val):
        return False
    return len(clean) >= 3 and any(c.isdigit() or c.isalpha() for c in clean)


_NON_VALUE_WORDS = frozenset({
    "number", "numbers", "detail", "details", "record", "records", "figure", "figures",
    "information", "identifier", "identifiers", "data", "holder", "holders", "policy",
    "procedure", "procedures", "only", "such", "none", "not",
})

# priority: lower wins when two candidates overlap on a line
_PRIO = {
    "Payment-card information": 0,
    "Authentication credentials and API keys": 1,
    "Tax or government identifier": 2,
    "Bank or account number": 3,
    "Phone number": 4,
    "Email address": 5,
}


@dataclass
class _Cand:
    cat: str
    line_no: int
    start: int
    end: int
    method: DetectionMethod
    conf: Confidence
    reason: str
    line_offset: int


def _scan_line(line: str, line_no: int, line_offset: int, filename: str, out: list[_Cand], suppressed: list[dict[str, Any]]) -> None:
    example_ctx = R.has_example_context(line)
    soft_blocked = example_ctx or bool(_RX_SENTENCE_DISCLAIMER.search(line))

    def add(cat: str, m_start: int, m_end: int, method: DetectionMethod, conf: Confidence, reason: str) -> None:
        out.append(_Cand(cat, line_no, m_start, m_end, method, conf, reason, line_offset))

    def suppress(cat: str, m_start: int, m_end: int, why: str) -> None:
        if len(suppressed) < 50:
            suppressed.append({"category": cat, "line": line_no, "reason": why, "evidence": make_evidence_snippet(line, m_start, m_end, cat)})

    # -- Payment cards (HARD: Luhn + issuer + length) --
    for m in _RX_CARD_DIGITS.finditer(line):
        digits = re.sub(r"\D", "", m.group())
        ok, info = R.card_candidate_ok(line, m.start(), digits)
        if ok:
            add("Payment-card information", m.start(), m.end(), DetectionMethod.CHECKSUM_LUHN, Confidence.HIGH, f"Valid {info} card number (passes Luhn checksum and issuer/length rules)")
        elif len(digits) >= 13 and R.luhn_ok(digits):
            suppress("Payment-card information", m.start(), m.end(), f"Luhn-valid number rejected: {info}")
    if not soft_blocked:
        for m in _RX_CARD_CONTEXT.finditer(line):
            if _is_valid_account_value(m.group(1)):
                add("Payment-card information", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Payment card number given under a card label")

    # -- Credentials: provider formats (HARD) --
    for name, rx in _PROVIDER_TOKENS:
        for m in rx.finditer(line):
            value = m.group(1) if rx.groups else m.group()
            if R.is_placeholder_value(value):
                suppress("Authentication credentials and API keys", m.start(), m.end(), f"{name} with placeholder value")
                continue
            span = (m.start(1), m.end(1)) if rx.groups else (m.start(), m.end())
            add("Authentication credentials and API keys", span[0], span[1], DetectionMethod.REGEX, Confidence.HIGH, f"Matches the {name} format")

    # -- Credentials: key = value (SOFT) --
    for m in _RX_KEYVAL.finditer(line):
        key, op, val = m.group("key"), m.group("op").lower(), m.group("val").rstrip(".,)")
        low = val.lower()
        if low in R._PROSE_STOPWORDS or R._CODE_REFERENCE.search(val):
            suppress("Authentication credentials and API keys", m.start(), m.end(), "value is prose or a code reference, not a literal secret")
            continue
        if R.is_placeholder_value(val):
            suppress("Authentication credentials and API keys", m.start(), m.end(), "value is a placeholder")
            continue
        if soft_blocked:
            suppress("Authentication credentials and API keys", m.start(), m.end(), "sentence is an example, disclaimer or discussion")
            continue
        random_like = R.looks_random(val)
        password_key = bool(_PASSWORDISH.search(key))
        if op in ("is", "are"):
            if not (random_like or re.search(r"\d", val)):
                suppress("Authentication credentials and API keys", m.start(), m.end(), "prose after 'is' without a secret-like value")
                continue
        elif len(val) < (6 if password_key else 8):
            continue
        elif not password_key and not (random_like or re.search(r"\d", val)):
            continue
        add("Authentication credentials and API keys", m.start("val"), m.end("val"), DetectionMethod.REGEX,
            Confidence.HIGH if (random_like or password_key and op != "is") else Confidence.MEDIUM,
            f"Literal value assigned to '{key[-30:]}'")

    # -- Email --
    for m in _RX_EMAIL.finditer(line):
        why = R.email_suppression(m.group(), line)
        if why:
            suppress("Email address", m.start(), m.end(), why)
        else:
            add("Email address", m.start(), m.end(), DetectionMethod.REGEX, Confidence.HIGH, "Syntactically valid email address on a non-reserved domain")

    # -- Government identifiers --
    for m in R.SSN_RX.finditer(line):
        labelled = bool(R.SSN_LABEL_RX.search(line))
        if R.ssn_ok(*m.groups(), labelled):
            add("Tax or government identifier", m.start(), m.end(), DetectionMethod.CHECKSUM, Confidence.HIGH if labelled else Confidence.MEDIUM, "US SSN format with valid area/group/serial")
        else:
            suppress("Tax or government identifier", m.start(), m.end(), "NNN-NN-NNNN with invalid area/group/serial")
    for m in R.PAN_RX.finditer(line):
        add("Tax or government identifier", m.start(), m.end(), DetectionMethod.CHECKSUM, Confidence.HIGH, "Indian PAN format with valid holder-type letter")
    aad_label = bool(R.AADHAAR_LABEL_RX.search(line))
    for m in R.AADHAAR_SPACED_RX.finditer(line):
        digits = "".join(m.groups())
        spaced = m.group() != digits
        if R.aadhaar_ok(digits) and (spaced or aad_label):
            add("Tax or government identifier", m.start(), m.end(), DetectionMethod.CHECKSUM, Confidence.HIGH, "12-digit Aadhaar number passing Verhoeff checksum")
        elif spaced:
            suppress("Tax or government identifier", m.start(), m.end(), "12-digit group fails Aadhaar Verhoeff checksum")
    for m in _RX_TEST_GOV.finditer(line):
        add("Tax or government identifier", m.start(), m.end(), DetectionMethod.REGEX, Confidence.HIGH, "Synthetic government-ID token format (TEST-GOV)")
    if not soft_blocked:
        for m in _RX_GOVT_LABELED.finditer(line):
            val = m.group(1) or m.group(2) or ""
            if _is_valid_id_value(val) and any(c.isdigit() for c in val):
                add("Tax or government identifier", m.start(), m.end(), DetectionMethod.REGEX, Confidence.HIGH, "Government/tax identifier value under an identifying label")

    # -- Bank accounts --
    for m in _RX_IBAN.finditer(line):
        if _iban_ok(m.group()):
            add("Bank or account number", m.start(), m.end(), DetectionMethod.CHECKSUM, Confidence.HIGH, "IBAN passing the mod-97 check")
    if not soft_blocked:
        for m in _RX_BANK_LABELED.finditer(line):
            if _is_valid_account_value(m.group(1)):
                add("Bank or account number", m.start(), m.end(), DetectionMethod.REGEX, Confidence.HIGH, "Account/routing number under a banking label")

    # -- Phone numbers (SOFT) --
    seen: list[tuple[int, int]] = []
    for name, rx, conf in R.PHONE_PATTERNS:
        for m in rx.finditer(line):
            s, e = m.start("v"), m.end("v")
            if any(s < b and a < e for a, b in seen):
                continue
            raw = m.group("v")
            if not R.phone_digits_ok(raw):
                continue
            digits = re.sub(r"\D", "", raw)
            if len(digits) >= 13 and R.luhn_ok(digits) and R.card_brand(digits):
                continue
            if name in ("in_mobile", "in_grouped") and not R.phone_bare_context_ok(line, s):
                suppress("Phone number", s, e, "digit run labelled as an amount/id/order, not a phone number")
                continue
            if re.search(r"\d{4}-\d{2}-\d{2}", line[max(0, s - 1):e + 1]):
                continue
            if soft_blocked:
                suppress("Phone number", s, e, "sentence is an example, disclaimer or discussion")
                seen.append((s, e))
                continue
            seen.append((s, e))
            add("Phone number", s, e, DetectionMethod.REGEX, Confidence.HIGH if conf == "HIGH" else Confidence.MEDIUM, f"Telephone number ({name.replace('_', ' ')} format, {len(digits)} digits)")

    if soft_blocked:
        return  # remaining rules are label-based and soft

    # -- Date of birth --
    for m in _RX_DOB.finditer(line):
        if m.group(1) and any(c.isdigit() for c in m.group(1)):
            add("Date of birth", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Date given under a date-of-birth label")

    # -- Address --
    for m in _RX_ADDRESS_STREET.finditer(line):
        if _ADDRESS_CUE.search(line):
            add("Home address", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.MEDIUM, "Street address with residential/postal context")
        else:
            suppress("Home address", m.start(), m.end(), "street-shaped phrase with no residential/postal context")
    for m in _RX_ADDRESS_LABELED.finditer(line):
        val = m.group(1)
        if re.search(r"\d", val) and (len(val.split()) >= 2 or "," in val) and not R.is_placeholder_value(val):
            add("Home address", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Address value under an address label")

    # -- Employee / student identifiers --
    for m in _RX_ORG_ID.finditer(line):
        if _is_valid_id_value(m.group(1)):
            add("Employee or student identifier", m.start(), m.end(), DetectionMethod.REGEX, Confidence.HIGH, "Staff/student identifier under an identifying label")

    # -- Health information --
    for m in _RX_HEALTH_LABELED.finditer(line):
        val = m.group("v") or m.group("n") or ""
        if val.strip().lower() not in _NON_VALUE_WORDS and not R.is_placeholder_value(val) and re.search(r"[A-Za-z0-9]{3}", val):
            add("Health information", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Clinical value (diagnosis, medication, vitals or patient id) under a medical label")
    if _PERSON_CUE.search(line):
        for m in _RX_HEALTH_FREE.finditer(line):
            add("Health information", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.MEDIUM, "Individual's condition or treatment stated in running text")

    # -- Salary --
    if not re.search(r"\b(?:budget|actual\s+expenditure|expenditure|operating|variance)\b", line, re.IGNORECASE):
        for m in _RX_SALARY.finditer(line):
            add("Salary or compensation", m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Individual salary or wage figure")


def _resolve_overlaps(cands: list[_Cand]) -> list[_Cand]:
    """One value, one finding: when spans overlap on a line keep the most specific category."""
    kept: list[_Cand] = []
    for c in sorted(cands, key=lambda c: (c.line_no, _PRIO.get(c.cat, 9), c.start)):
        if any(k.line_no == c.line_no and c.start < k.end and k.start < c.end for k in kept):
            continue
        kept.append(c)
    return sorted(kept, key=lambda c: (c.line_no, c.start))


def assess_text(
    text: str,
    doc_id: str = "D1",
    filename: str = "document",
    content_hash: str = "",
    limit_per_category: int = 20,
) -> DocumentAssessment:
    """Deterministic layer: scan the whole text; return located, redacted, severity-tagged findings."""
    evaluated_at = _now()
    text = R.normalise_text(text or "")
    cands: list[_Cand] = []
    suppressed: list[dict[str, Any]] = []
    limitations: list[str] = []

    lines = text.splitlines(keepends=True)
    offsets, pos = [], 0
    for ln in lines:
        offsets.append(pos)
        pos += len(ln)

    csv_salary_col = -1
    first = next((l.strip() for l in lines if l.strip()), "")
    if "," in first and (filename.lower().endswith(".csv") or True):
        headers = [h.strip().strip("\"'").lower() for h in first.split(",")]
        for i, h in enumerate(headers):
            if h in ("salary", "compensation", "wage", "base_salary", "annual_salary", "monthly_salary"):
                csv_salary_col = i
                break

    first_line_no = next((i for i, l in enumerate(lines, 1) if l.strip()), 1)
    for idx, (raw, off) in enumerate(zip(lines, offsets), 1):
        line = raw.rstrip("\r\n")
        _scan_line(line, idx, off, filename, cands, suppressed)
        if csv_salary_col >= 0 and idx > first_line_no and "," in line:
            parts = line.split(",")
            if len(parts) > csv_salary_col:
                val = parts[csv_salary_col].strip().strip("\"'")
                if re.match(r"^(?:(?:INR|USD|EUR|GBP|Rs\.?|\$)\s?)?\d+(?:,\d{3})*(?:\.\d{2})?$", val):
                    vs = line.find(parts[csv_salary_col])
                    cands.append(_Cand("Salary or compensation", idx, vs, vs + len(parts[csv_salary_col]), DetectionMethod.CONTEXTUAL, Confidence.HIGH, "Salary value in a salary column", off))

    resolved = _resolve_overlaps(cands)

    # A labelled name only becomes a finding when it is attached to other identifying data.
    if resolved:
        for idx, (raw, off) in enumerate(zip(lines, offsets), 1):
            line = raw.rstrip("\r\n")
            if R.has_example_context(line):
                continue
            for m in _RX_NAME_LABELED.finditer(line):
                resolved.append(_Cand("Personal name (with identifying data)", idx, m.start(), m.end(), DetectionMethod.CONTEXTUAL, Confidence.MEDIUM,
                                      "Person's name under a name label in a document that also contains identifying data", off))
        resolved.sort(key=lambda c: (c.line_no, c.start))

    findings: list[SensitiveFinding] = []
    counts: dict[str, int] = {}
    omitted: dict[str, int] = {}
    for c in resolved:
        if counts.get(c.cat, 0) >= limit_per_category:
            omitted[c.cat] = omitted.get(c.cat, 0) + 1
            continue
        counts[c.cat] = counts.get(c.cat, 0) + 1
        line = lines[c.line_no - 1].rstrip("\r\n")
        findings.append(SensitiveFinding(
            doc_id=doc_id, filename=filename, content_hash=content_hash, category=c.cat, line=c.line_no,
            span=(c.line_offset + c.start, c.line_offset + c.end),
            evidence=make_evidence_snippet(line, c.start, c.end, c.cat),
            method=c.method.value, confidence=c.conf.value, reason=c.reason, timestamp=evaluated_at,
            severity=SEVERITY_BY_CATEGORY.get(c.cat, "MEDIUM"), source="deterministic",
        ))
    for cat, n in omitted.items():
        limitations.append(f"{n} further '{cat}' finding(s) were not listed (limit {limit_per_category} per category); category is flagged.")

    return DocumentAssessment(
        doc_id=doc_id, filename=filename, content_hash=content_hash, status=AssessmentStatus.COMPLETED,
        evaluated_at=evaluated_at, total_findings=len(findings), categories=sorted(counts), category_counts=counts,
        findings=findings, is_sensitive=bool(findings), limitations=limitations, suppressed=suppressed,
    )


def _not_evaluable(doc_id: str, filename: str, content_hash: str, error: str, evaluation_status: str = "failed") -> DocumentAssessment:
    return DocumentAssessment(
        doc_id=doc_id, filename=filename, content_hash=content_hash, status=AssessmentStatus.NOT_EVALUABLE,
        evaluated_at=_now(), total_findings=0, categories=[], category_counts={}, findings=[], is_sensitive=False,
        error=error, evaluation_status=evaluation_status, layers={"deterministic": "failed", "contextual": "not_run"},
    )


def mark_incomplete(ass: DocumentAssessment, reason: str) -> DocumentAssessment:
    """Record that evaluation did not cover everything. With no findings the UI-facing `status`
    becomes NOT_EVALUABLE so an unfinished evaluation can never display as CLEAN; with findings,
    the document stays flagged (a partial result can add risk, never remove it)."""
    ass.limitations.append(reason)
    if ass.evaluation_status in (EvaluationStatus.COMPLETED.value, EvaluationStatus.REQUIRES_REVIEW.value):
        ass.evaluation_status = EvaluationStatus.PARTIAL.value
    if not ass.findings:
        ass.status = AssessmentStatus.NOT_EVALUABLE
        ass.error = f"Evaluation incomplete: {reason}"
    return ass


def assess_document(
    doc_id: str,
    filename: str,
    content_hash: str,
    text: str | None = None,
    error: str | None = None,
    truncated: bool = False,
    notes: list[str] | None = None,
) -> DocumentAssessment:
    """Deterministic assessment entry point. Extraction problems are never treated as clean."""
    if error is not None or text is None:
        return _not_evaluable(doc_id, filename, content_hash, error or "Document contents could not be extracted or assessed.")
    if not re.search(r"\w", re.sub(r"\[(?:Page \d+|Sheet: [^\]]*)\]", "", text)):
        return _not_evaluable(doc_id, filename, content_hash, "No extractable text was found (for example a scanned PDF); the document was not evaluated.")
    ass = assess_text(text, doc_id=doc_id, filename=filename, content_hash=content_hash)
    if truncated:
        mark_incomplete(ass, "Extracted text was truncated; content beyond the cut-off was not evaluated.")
    for n in notes or []:
        if "No extractable text" in n:
            mark_incomplete(ass, n)
    return ass


# ---------------------------------------------------------------------------
# Redaction: what the model is allowed to read
# ---------------------------------------------------------------------------

REDACTION_TAGS: dict[str, str] = {
    "Payment-card information": "CARD",
    "Authentication credentials and API keys": "SECRET",
    "Tax or government identifier": "GOV_ID",
    "Bank or account number": "ACCOUNT",
    "Phone number": "PHONE",
    "Email address": "EMAIL",
    "Date of birth": "DOB",
    "Home address": "ADDRESS",
    "Employee or student identifier": "ID",
    "Health information": "HEALTH",
    "Salary or compensation": "SALARY",
    "Personal name (with identifying data)": "NAME",
}


def redact_for_model(text: str) -> tuple[str, int]:
    """Replace every value the deterministic layer flags with a tag such as `[REDACTED:PHONE]`.

    Returns (redacted text, number of values replaced). Lines are preserved so line numbers still
    match the original. Detection runs on the full text with no per-category cap, so nothing the
    detector can see is left in. Content only the AI layer could recognise (private conversations,
    free-text names) is NOT removed: there is no span to cut.
    """
    t = R.normalise_text(text or "")
    if not t:
        return t, 0
    a = assess_text(t, limit_per_category=10**9)
    out = t
    n = 0
    for f in sorted(a.findings, key=lambda f: -f.span[0]):
        lo, hi = f.span
        if f.source != "deterministic" or hi <= lo:
            continue
        out = out[:lo] + f"[REDACTED:{REDACTION_TAGS.get(f.category, 'SENSITIVE')}]" + out[hi:]
        n += 1
    return out, n
