"""Append-only, SHA-256 hash-chained action audit log.

ARM (Chinaei, 2026) records decisions in a hash-chained audit log; the Phase 1
baseline simplified this to an in-memory list of ``PolicyDecision`` objects.
This module restores tamper evidence for the per-action audit trail:

- Each record stores ``prev_hash`` (the previous record's hash, or
  ``GENESIS_HASH`` for the first record) and its own ``record_hash``.
- ``record_hash`` is the SHA-256 of the record's canonical JSON with
  ``record_hash`` itself excluded.
- Any edit, deletion, insertion, or reordering breaks verification.

The chain detects modification of a stored log; it does not by itself prove
that the log is complete or authentic against an adversary who can rewrite the
entire file (that would require signing or an external anchor).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from src.monitor.models import GENESIS_HASH, ActionAuditRecord


def compute_record_hash(record_fields: dict[str, Any]) -> str:
    """Return the SHA-256 of a record's canonical JSON, excluding ``record_hash``."""
    payload = {k: v for k, v in record_fields.items() if k != "record_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(records: list[ActionAuditRecord]) -> list[str]:
    """Verify sequence numbers, hash links, and record hashes. Returns error strings."""
    errors: list[str] = []
    expected_prev = GENESIS_HASH
    for idx, rec in enumerate(records):
        if rec.sequence != idx:
            errors.append(f"record {idx}: sequence {rec.sequence} != expected {idx}")
        if rec.prev_hash != expected_prev:
            errors.append(f"record {idx}: prev_hash does not link to previous record")
        recomputed = compute_record_hash(rec.model_dump(mode="json"))
        if recomputed != rec.record_hash:
            errors.append(f"record {idx}: record_hash mismatch (content modified)")
        expected_prev = rec.record_hash
    return errors


class AuditLog:
    """In-memory append-only audit log for one execution branch."""

    def __init__(self) -> None:
        self._records: list[ActionAuditRecord] = []

    @property
    def records(self) -> list[ActionAuditRecord]:
        """Return a copy of the records in append order."""
        return list(self._records)

    def __len__(self) -> int:
        return len(self._records)

    @property
    def head_hash(self) -> str:
        """Hash of the most recent record (``GENESIS_HASH`` when empty)."""
        return self._records[-1].record_hash if self._records else GENESIS_HASH

    def append(self, **fields: Any) -> ActionAuditRecord:
        """Create, hash, validate, and append a record.

        ``sequence``, ``prev_hash`` and ``record_hash`` are assigned here and must
        not be supplied by the caller.
        """
        reserved = {"sequence", "prev_hash", "record_hash"} & fields.keys()
        if reserved:
            raise ValueError(f"Fields assigned by AuditLog must not be supplied: {sorted(reserved)}")

        draft = ActionAuditRecord(
            **fields,
            sequence=len(self._records),
            prev_hash=self.head_hash,
            record_hash="0" * 64,
        )
        record_hash = compute_record_hash(draft.model_dump(mode="json"))
        record = draft.model_copy(update={"record_hash": record_hash})
        self._records.append(record)
        return record

    def verify(self) -> list[str]:
        """Verify the full chain. Returns an empty list when intact."""
        return verify_chain(self._records)

    def write_jsonl(self, path: Path) -> None:
        """Write records as JSON Lines. Refuses to overwrite an existing file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8") as handle:
            for rec in self._records:
                handle.write(rec.model_dump_json() + "\n")

    @staticmethod
    def read_jsonl(path: Path) -> list[ActionAuditRecord]:
        """Load records from a JSON Lines file (call ``verify_chain`` to check them)."""
        records: list[ActionAuditRecord] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(ActionAuditRecord.model_validate_json(line))
        return records
