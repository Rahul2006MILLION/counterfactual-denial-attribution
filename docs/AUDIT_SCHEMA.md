# Action Audit Record Schema (M1)

Every action an agent proposes during `AgentExecutor.run_branch` produces exactly one
`ActionAuditRecord` (`src/monitor/models.py`), appended to the branch's `AuditLog`
(`src/monitor/audit.py`) and returned as `BranchExecutionResult.audit_log`.
Terminating (`terminate=true`) produces no record, because no action was proposed.

## Authorization vs. execution

The two questions are recorded in separate fields:

| Question | Field | Values |
|---|---|---|
| Was the action permitted? | `authorization` | `ALLOW`, `DENY` (the monitor's verdict; authoritative) |
| Did the tool actually run? | `execution_status` | `EXECUTED`, `NOT_EXECUTED_DENIED`, `TOOL_ERROR` |

Only three combinations are valid, and the model rejects any other combination at construction time:

| `authorization` | `execution_status` | `executed` | Meaning |
|---|---|---|---|
| `ALLOW` | `EXECUTED` | `true` | Permitted and ran successfully. |
| `ALLOW` | `TOOL_ERROR` | `false` | Permitted, but the tool raised (e.g. unknown tool, `calculate("5 // 0")`). `error` is required. |
| `DENY` | `NOT_EXECUTED_DENIED` | `false` | Blocked by the monitor; the tool was never invoked. `deciding_layer` is required. |

Only `EXECUTED` records may carry `data_id` / `output_digest`.

## Fields

| Group | Field | Description |
|---|---|---|
| Identity | `record_id`, `sequence`, `session_id`, `branch_name`, `feedback_condition`, `step_index`, `step_id`, `timestamp` | `sequence` is 0-based within the branch; `feedback_condition` is the branch's intervention condition (e.g. `ACTUAL`, `NEUTRALIZED`). |
| Proposal | `tool_name`, `arguments`, `proposed_input_node_ids`, `accepted_input_node_ids`, `is_protected_sink` | `proposed_*` is what the agent claimed; `accepted_*` are the IDs that exist in the provenance graph and were passed to the monitor. |
| Authorization | `authorization`, `decision_id`, `deciding_layer`, `internal_reason`, `layer_verdicts` | `internal_reason` is the monitor's full reason for auditors. `layer_verdicts` lists each evaluated layer and its `PASS`/`DENY`. |
| Execution | `execution_status`, `executed`, `data_id`, `output_digest`, `error` | `output_digest` is the SHA-256 of the output's canonical JSON. |
| Agent view | `agent_visible_feedback` | Exactly what the agent was shown for this action. It may differ from `internal_reason` (e.g. under `NEUTRALIZED`). |
| Tamper evidence | `prev_hash`, `record_hash` | See below. |

### M2 additions (additive; all evaluator-only)

| Field | Set when | Description |
|---|---|---|
| `deny_rule` | `authorization=DENY` | Rule ID of the denying layer (e.g. `HB-2`, `RP-CONCEAL`, `L4-TOOL`), taken from `LayerResult.evidence["rule"]`. |
| `reason_category` | `authorization=DENY` | The rule's single category in the C2 reason catalogue (`src/monitor/reason_catalogue.py`). |
| `reason_catalogue_version` | `authorization=DENY` | Catalogue version, currently `cda-c2-reasons-v1` (final). Records produced by the M2 commit `1c13d02` carry `cda-c2-reasons-v0-draft`. |
| `raw_output_digest` | `EXECUTED` and mediation ran | SHA-256 of the tool's raw output before monitor mediation. `output_digest` is always the digest of what the agent actually received. |
| `redaction_applied` | `EXECUTED` | `true` if monitor result mediation ran on this output (listing tools under a `ResourcePolicy`). |
| `redaction_count` | `EXECUTED` | Number of entries removed from the output. Never shown to the agent. |

Validation: the three reason fields are set together or not at all, and only on DENY (the executor always sets them on DENY). Mediation fields only appear on `EXECUTED`; `redaction_count > 0` requires `redaction_applied`, and `redaction_applied` requires `raw_output_digest`.

### Raw outputs are not stored

Tool outputs are recorded only as `output_digest`, so the audit trail is not a second
copy of protected content. Note that `agent_visible_feedback` deliberately records what
the agent saw, so for an allowed read it currently contains the returned content
(`OK: <output>`). Separating agent-visible content from protected content is in scope
for M2/M3.

## Hash chain

- `prev_hash` is the previous record's `record_hash`, or `GENESIS_HASH` (64 zeros) for the first record.
- `record_hash` is the SHA-256 of the record's canonical JSON (sorted keys, compact separators) with `record_hash` excluded.
- `verify_chain(records)` reports sequence gaps, broken links, and content mismatches, so edits, deletions, insertions, and reordering are all detected.
- `AuditLog.write_jsonl(path)` writes JSON Lines and refuses to overwrite an existing file; `AuditLog.read_jsonl(path)` loads records for verification.

**Limit:** the chain detects modification of a stored log. It does not prove authenticity against an adversary who can rewrite the entire file; that would need signing or an external anchor.

## Scope of M1

- Applies to the live executor path (`AgentExecutor`), which is used by Phase 4+ runners and the Ollama adapter. The scripted Phase 2 (`scenarios.py`) and Phase 3 (`replay.py`) paths are unchanged.
- The agent-facing observation (`AgentObservation`) is unchanged; for example, a tool error is still shown to the agent with `allowed=false`. Agent-visible views are M3.
- Historical runners do not read audit logs. In `phase4_3_runner` and `phase5_runner`, a simulated "missing Branch B" is built with `dataclasses.replace(ra, trace=...)` and therefore shares Branch A's audit log. New runners must not do this.

## Behaviour corrections in `executor.py`

1. `TraceStepRecord.executed` is now `false` for denied steps (it was `true` for every monitored step).
2. A tool error's trace `decision` now records the monitor's actual verdict (`ALLOW`) instead of `DENY`.
3. Any exception raised by a tool is recorded as `TOOL_ERROR`. Previously only `ValueError` was caught, so `ZeroDivisionError` or `SyntaxError` from `calculate()` crashed the episode.

The M0 regression guard confirms none of these changes alter any committed historical result (EXP-001..EXP-008).
