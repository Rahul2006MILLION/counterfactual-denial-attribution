"""Validated Pydantic v2 data models and integrity-lattice trust types."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum, IntEnum
from typing import Any, Iterable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(UTC)


class TrustLevel(IntEnum):
    """Five-level integrity lattice from ARM (Chinaei, 2026).

    Ordering: ToolDesc < ToolUntrusted < ToolTrusted < UserInput < SysInstr.
    Integer values enforce lattice ordering without string comparisons.
    """

    TOOL_DESC = 0
    TOOL_UNTRUSTED = 1
    TOOL_TRUSTED = 2
    USER_INPUT = 3
    SYS_INSTR = 4

    @property
    def label(self) -> str:
        """Return the canonical human-readable lattice label."""
        labels = {
            TrustLevel.TOOL_DESC: "ToolDesc",
            TrustLevel.TOOL_UNTRUSTED: "ToolUntrusted",
            TrustLevel.TOOL_TRUSTED: "ToolTrusted",
            TrustLevel.USER_INPUT: "UserInput",
            TrustLevel.SYS_INSTR: "SysInstr",
        }
        return labels[self]


def conservative_join(levels: Iterable[TrustLevel]) -> TrustLevel:
    """Return the minimum (least-trusted) level across contributing sources.

    Returns ``TrustLevel.SYS_INSTR`` when ``levels`` is empty, matching
    ARM's Definition 4 default when no data ancestors exist.
    """
    collected = list(levels)
    if not collected:
        return TrustLevel.SYS_INSTR
    return min(collected)


class EventType(str, Enum):
    """Types of agent session events."""

    TOOL_CALL = "TOOL_CALL"
    TOOL_RESULT = "TOOL_RESULT"
    DENIAL = "DENIAL"
    USER_MESSAGE = "USER_MESSAGE"
    SYSTEM_INSTRUCTION = "SYSTEM_INSTRUCTION"


class EventStatus(str, Enum):
    """Execution status of an agent event."""

    PENDING = "PENDING"
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


class NodeType(str, Enum):
    """Provenance graph node categories."""

    CALL = "Call"
    DATA = "Data"
    DATA_FIELD = "DataField"
    DENIED_ACTION = "DeniedAction"


class EdgeType(str, Enum):
    """Provenance graph directed edge relationships."""

    DIRECT_OUTPUT = "DIRECT_OUTPUT"
    INPUT_TO = "INPUT_TO"
    FIELD_OF = "FIELD_OF"
    COUNTERFACTUAL = "COUNTERFACTUAL"


class DecisionVerdict(str, Enum):
    """Final enforcement verdict for a tool invocation."""

    ALLOW = "ALLOW"
    DENY = "DENY"


class LayerVerdict(str, Enum):
    """Per-layer policy evaluation verdict."""

    PASS = "PASS"
    DENY = "DENY"


class AgentEvent(BaseModel):
    """Structured record of an agent or tool-execution event."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1)
    session_id: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)
    event_type: EventType
    tool_name: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: Any = None
    status: EventStatus
    parent_event_ids: list[str] = Field(default_factory=list)

    @field_validator("event_id", "session_id", "tool_name")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Identifier/name fields must not be blank.")
        return value


class DenialEvent(BaseModel):
    """Structured record of a denied tool invocation and observed feedback."""

    model_config = ConfigDict(extra="forbid")

    denial_id: str = Field(..., min_length=1)
    source_event_id: str = Field(..., min_length=1)
    denied_action: str = Field(..., min_length=1)
    denial_reason: str = Field(..., min_length=1)
    feedback_observed: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("denial_id", "source_event_id", "denied_action", "denial_reason")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("DenialEvent fields must not be blank.")
        return value


class ProvenanceNode(BaseModel):
    """Node in the runtime provenance graph."""

    model_config = ConfigDict(extra="forbid")

    node_id: str = Field(..., min_length=1)
    node_type: NodeType
    trust_level: TrustLevel
    source_id: str = Field(..., min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("node_id", "source_id")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Node identifiers must not be blank.")
        return value


class ProvenanceEdge(BaseModel):
    """Directed edge in the runtime provenance graph."""

    model_config = ConfigDict(extra="forbid")

    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    relationship_type: EdgeType
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("source_id", "target_id")
    @classmethod
    def _must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Edge endpoint IDs must not be blank.")
        return value

    @model_validator(mode="after")
    def _disallow_self_loop(self) -> ProvenanceEdge:
        if self.source_id == self.target_id:
            raise ValueError(f"Self-loop edges are not permitted: {self.source_id}")
        return self


class PolicyDecision(BaseModel):
    """Deterministic enforcement decision emitted by the monitor."""

    model_config = ConfigDict(extra="forbid")

    decision_id: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    decision: DecisionVerdict
    reason: str = Field(..., min_length=1)
    evidence: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)


class ExecutionStatus(str, Enum):
    """What actually happened to a proposed action, independent of authorization.

    Authorization (``DecisionVerdict``) answers "was the action permitted?".
    ``ExecutionStatus`` answers "did the tool actually run, and did it succeed?".
    """

    EXECUTED = "EXECUTED"
    NOT_EXECUTED_DENIED = "NOT_EXECUTED_DENIED"
    TOOL_ERROR = "TOOL_ERROR"


GENESIS_HASH = "0" * 64


class ActionAuditRecord(BaseModel):
    """Structured, hash-chained audit record for one proposed agent action.

    Authorization and execution are recorded in separate fields and checked for
    consistency: a DENY can never be paired with an execution, and only an
    EXECUTED action may carry an output digest or data ID.

    Raw tool outputs are deliberately NOT stored (only a SHA-256 digest), so the
    audit trail never becomes a second copy of protected content.
    ``internal_reason`` is the monitor's full reason for auditors; it is not
    necessarily what the agent saw, which is recorded in ``agent_visible_feedback``.
    """

    model_config = ConfigDict(extra="forbid")

    # Identity and context
    record_id: str = Field(..., min_length=1)
    sequence: int = Field(..., ge=0)
    session_id: str = Field(..., min_length=1)
    branch_name: str = Field(..., min_length=1)
    feedback_condition: str = Field(..., min_length=1)
    step_index: int = Field(..., ge=0)
    step_id: str = Field(..., min_length=1)
    timestamp: datetime = Field(default_factory=utc_now)

    # Proposal (what the agent asked for)
    tool_name: str = Field(..., min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    proposed_input_node_ids: list[str] = Field(default_factory=list)
    accepted_input_node_ids: list[str] = Field(default_factory=list)
    is_protected_sink: bool = False

    # Authorization (what the monitor decided)
    authorization: DecisionVerdict
    decision_id: str = Field(..., min_length=1)
    deciding_layer: str | None = None
    internal_reason: str = Field(..., min_length=1)
    layer_verdicts: list[dict[str, str]] = Field(default_factory=list)

    # Execution (what actually happened)
    execution_status: ExecutionStatus
    executed: bool
    data_id: str | None = None
    output_digest: str | None = None
    error: str | None = None

    # What the agent was shown
    agent_visible_feedback: str = Field(..., min_length=1)

    # Tamper evidence
    prev_hash: str = Field(..., min_length=64, max_length=64)
    record_hash: str = Field(..., min_length=64, max_length=64)

    @model_validator(mode="after")
    def _authorization_execution_consistent(self) -> ActionAuditRecord:
        status = self.execution_status
        if self.executed != (status == ExecutionStatus.EXECUTED):
            raise ValueError(
                f"executed={self.executed} is inconsistent with execution_status={status.value}."
            )
        if self.authorization == DecisionVerdict.DENY and status != ExecutionStatus.NOT_EXECUTED_DENIED:
            raise ValueError("A DENIED action must have execution_status NOT_EXECUTED_DENIED.")
        if status == ExecutionStatus.NOT_EXECUTED_DENIED and self.authorization != DecisionVerdict.DENY:
            raise ValueError("NOT_EXECUTED_DENIED requires authorization DENY.")
        if status == ExecutionStatus.TOOL_ERROR and not self.error:
            raise ValueError("TOOL_ERROR requires a non-empty error description.")
        if status != ExecutionStatus.EXECUTED and (self.data_id or self.output_digest):
            raise ValueError("Only EXECUTED actions may carry a data_id or output_digest.")
        if self.authorization == DecisionVerdict.DENY and not self.deciding_layer:
            raise ValueError("A DENIED action must name the deciding policy layer.")
        return self
