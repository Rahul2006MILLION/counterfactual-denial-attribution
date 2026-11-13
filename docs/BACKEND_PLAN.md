# Master Backend Implementation Plan (M3.1–M8)

> **Status:** Approved master roadmap for completing the backend before frontend development.
> **Approved:** 2026-11-13, with six revisions (R1–R6, recorded in §0.1 and applied throughout).
> **Baseline:** commit `8c52e6e` on `backend-milestones` (M0–M3.0 complete). `main` / `origin/main` = `e7ad4bb`.
> **Inputs:** repository-wide audit at `8c52e6e`; [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md) §1–§11; C2 catalogue `cda-c2-reasons-v1`.
>
> **Frontend exception (2026-11-13):** A static presentation website (`frontend/`) was explicitly
> approved ahead of M8. It makes no backend calls, adds no HTTP server or Python dependency, and
> replays only recorded output of the existing terminal demo (`src/demo`). It is not the M8 service
> layer or CLI, and it does not change any milestone requirement, acceptance criterion or the
> definition of done in this plan.
>
> **Live agent application (2026-11-14):** At the user's explicit request, a live Ollama-powered
> agent application (`src/live/`, FastAPI) was built, which settles decision B1 in favour of an HTTP
> API for that application. It reuses the unchanged ARMMonitor and AuditLog, adds no research
> code, and its model settings are separate from the pinned research adapter. It is an application
> layer, not the M3–M7 research protocol: it does not implement C0/C1/C2, counterfactual branches or
> attribution, and it produces no experimental results.
>
> This document is a plan. Nothing in it is implemented unless a milestone is marked COMPLETE in
> [`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md). It makes no security or novelty claims and reports no
> experimental results.

---

## 0. Scope, approval record and global guardrails

### 0.1 Approved revisions

| ID | Revision (as approved) | Where applied |
|---|---|---|
| **R1** | Strengthen the provenance limitation work. M6/M7 must evaluate actual outbound content independently of agent-declared provenance, with tests for **undeclared** and **incorrectly declared** data flows. No claim of complete information-flow enforcement. | §2 (D9), M6, M7.3, M7.4, §7, §8 |
| **R2** | M3.6 C0 equivalence is a **blocking** acceptance criterion: complete serialized observation sequences and **every** subsequent model request body are compared byte-for-byte across denial and genuine-missing-resource branches. | M3.6, §8 |
| **R3** | A7's attribution decision rule must be resolved, documented and **pre-registered before M6 is implemented and before any live experimental outcome is examined**. | §1, M6, M7.6, §8 |
| **R4** | M7.1–M7.5 are completed with synthetic agents and mocked model responses only. M7.6 (live pilot) is outside the backend completion gate and needs separate approval. | M7, §8 |
| **R5** | M8 starts with a pure-Python service layer and CLI. No HTTP framework or new dependency until B1 is explicitly approved. | §1 (B1), M8, §8 |
| **R6** | For audit defects that could invalidate research evidence, documentation alone is insufficient. **D1, D2, D7, D8 and D9 require executable tests** proving the new protocol handles them correctly. | §2.1, per-milestone tests, §8 |

### 0.2 Global guardrails (apply to every milestone)

| Guardrail | Enforcement |
|---|---|
| **Historical evidence preserved** | Every step must keep passing: M0 (59), M3.0 (104), M1 (29), M2 (50, or its migrated equivalent). `results/` and `configs/` checksums unchanged. M3.0 fixture stays pinned (`0cf1a916…`). Historical runners, `BaseAgent`, `OllamaAgentAdapter`, historical policies and `FeedbackCondition` stay textually unchanged (U10 source hashes). |
| **No unapproved model-parameter changes** | M3.5 tests v2 adapter parameters equal the pinned v1 values. The M7 runner refuses any parameter override unless the run config cites a decision ID recorded as approved in `DESIGN_DECISIONS.md`. Every run manifest records parameters. |
| **No overwriting of results** | New outputs only under `results/cda/<run_id>/`, created with exclusive writes. The M0 guard already rejects unregistered top-level files in `results/`. New code never invokes historical runners. |
| **No changes to `main`** | Work only on `backend-milestones`. Before every commit verify the branch and that `main` / `origin/main` are unchanged. No push, merge, rebase or amend without explicit approval. |
| **No live LLM runs** | All tests mock Ollama. The only live activity in this roadmap is M7.6, separately gated (R4). |
| **Per-step gate** | `uv run pytest -v` (full suite), M0, M3.0 golden, the milestone's mutation suite, `git diff --check` → `EXPERIMENT_LOG.md` entry → review → local commit on approval. |
| **Mutation harness** | *Proposed, not yet approved:* move the scratchpad mutation scripts into `scripts/mutation_check.py` (operates only on temporary copies) so every milestone's mutation suite is re-runnable by collaborators. |
| **Claims discipline** | Docs and reports describe what tests and mocked runs show. No claim of complete information-flow enforcement, general security, or novelty (R1). |

---

## 1. Research decisions: resolution schedule

A decision must be recorded in `DESIGN_DECISIONS.md` (approved) before the milestone that depends on it starts.

| ID | Question | Resolve before | Reason |
|---|---|---|---|
| **A15** | Does an agent-caused `TOOL_ERROR` ever make a run invalid? | **M4** | Validity classifier |
| **A11** | Delivery threshold *k* when the protected action is not attempted/denied in some repetitions | **M4** | `INTERVENTION_NOT_DELIVERED` |
| **B2** | Is `MAX_STEPS_EXHAUSTED` a valid behavioural outcome or invalid? | **M4** | Not covered by A15 |
| **B3** | Is truncated model output (`done_reason` = length) invalid? | **M4** | Needs `done_reason` from M3.5 |
| **A7 (scope)** | Comparison unit: target action, all post-denial actions, or full trace | **M5** | Defines what M5 compares |
| **A7 (rule)** | Decision rule for "differs beyond same-condition variability" | **M6 implementation, and before any live outcome is examined (R3)** | Pre-registration; see below |
| **A13** | Fact detector (lexical markers / LLM judge / human annotation) | **M6** | Inference and leakage scoring; markers stored in M7.1 configs |
| **A8** | Primary presentation of outcomes (historical labels vs event/reason summary) | **M6** (outputs), **M8** (views) | Output schema |
| **A6** | How repetitions become independent (seed variation = model-parameter change) | **M7.2** | Runner config; must be approved before any live run |
| **A9** | Randomization scope (within vs across scenarios) | **M7.2** | Runner ordering |
| **A14** | Pilot size (fact-variant groups need 45 episodes each) | **M7.6** | Live pilot planning |
| **B1** | M8 interface: CLI only, or also an HTTP API (new dependency) | **Any HTTP work in M8 (R5)** | Dependency approval; CLI proceeds without it |

**A7 pre-registration protocol (R3).** Before any M6 code is written:
1. The rule (statistic, thresholds, handling of ties/noise, minimum valid repetitions) is written into a new `DESIGN_DECISIONS.md` section and approved.
2. The approval commit hash is recorded in `EXPERIMENT_LOG.md` as the pre-registration point.
3. A test pins the implemented rule's constants to the pre-registered values, so any later change fails the suite until a new, recorded decision is made.
4. No live experimental outcome under the C0/C1/C2 protocol may be generated or inspected before this point. Existing historical results are unaffected.
5. Any post-hoc change is recorded as a deviation; results under the changed rule are labelled exploratory.

---

## 2. Known defects and how each is handled

| # | Defect (verified in audit) | Handling | Milestone |
|---|---|---|---|
| D1 | Model failure (retries exhausted) recorded as `terminated_cleanly: True` | v2 adapter exposes structured failure; classified `INVALID`. Historical path stays pinned as-is. **Executable tests required (R6).** | M3.5, M4 |
| D2 | Phase 5 runner: Branch-B infrastructure failure becomes `DENIAL_SENSITIVE` | New runner never uses `phase5_runner`; the same failure pattern yields `INCONCLUSIVE/INVALID_EXECUTION`. **Executable tests required (R6).** | M4, M6, M7.2, M7.4 |
| D3 | Phase 5 resume never retries failed rows | Checkpoint retries invalid rows (tested) | M7.2 |
| D4 | Phase 5 discards repeated-trial rows | All repetitions persisted (tested) | M7.2 |
| D5 | `test_error_handling_when_ollama_fails` asserts only `tp >= 0` | Historical test left unchanged; documented. Real coverage via M4/M7 tests. | M3.6 (doc) |
| D6 | §9.6 not enforced (historical condition + policy accepted) | `run_branch` rejects any `ResourcePolicy` (tested) | M3.4 |
| D7 | Branch name in model-visible `data_id` (`d_c0_rep3_s0`) | Visible `data_id = d_s{n}`. **Executable tests required (R6).** | M3.2, M3.4, M3.6 |
| D8 | v1 observations reveal outcome (`allowed`, `OK:`, `output`, `data_id`) | v2 visible view only. **Executable tests required (R6).** | M3.2, M3.4, M3.5, M3.6 |
| D9 | Provenance is agent-declared (`input_node_ids`) | Content-based outbound evaluation independent of declarations; declaration-accuracy reported. **Executable tests required (R6, R1).** | M5, M6, M7.3, M7.4 |
| D10 | Policy evidence not persisted in audit | `policy_evidence` persisted and hash-chained (tested) | M3.4 |
| D11 | Resource policy covers only `read_document` | Scenario validation rejects any resource-accessing tool without policy coverage (tested) | M7.1 |
| D12 | Historical runners default to writing into `results/` | Guardrail (M0 test) + docs; new code never calls them | M8.5 (doc) |
| D13 | README/HANDOFF drift (test counts, model name, paths) | Docs corrected | M8.5 |
| D14 | Agents see tool errors as `allowed=False` | v2 path renders `TOOL_ERROR: <msg>` with no `allowed` field (tested) | M3.4 |
| D15 | `SD-2`, `INTEGRITY` unreachable; `USAGE_LIMIT` only via `HB-1` | Reported in stratified output; reachability test kept | M7.3 |

### 2.1 Mandatory executable tests for evidence-critical defects (R6)

Each test below must exist, pass, and be covered by at least one mutation that makes it fail.

| Defect | Required tests | File | Mutation that must be caught |
|---|---|---|---|
| **D1** | (a) v2 adapter with mocked transport failing every retry reports `failed=True`, error kind, retry count; never "clean". (b) Such a branch is `INVALID(RETRIES_EXHAUSTED)`. (c) Malformed/unparseable replies → `INVALID(PARSE_FAILURE)`. (d) An invalid branch cannot be passed to M5/M6 (type/flag enforced). (e) Mocked E2E: a scenario whose model fails yields `INCONCLUSIVE/INVALID_EXECUTION`, never a sensitivity outcome. | `test_m3_5_protocol_adapter.py`, `test_m4_validity.py`, `test_m7_e2e.py` | Failure reported as clean; retries-exhausted treated as valid |
| **D2** | (a) Reproduce the P10 pattern (one condition's branches succeed, another's model goes down mid-run) through the new pipeline → group `INVALID_EXECUTION`, attribution `INCONCLUSIVE`. (b) A missing/failed branch is never interpreted as "action omitted". (c) Static test: `cda_runner` and the service layer do not import `phase5_runner`. | `test_m4_validity.py`, `test_m6_attribution.py`, `test_m7_e2e.py` | Failed branch counted as empty trace; runner importing `phase5_runner` |
| **D7** | (a) Visible `data_id` equals `d_s{n}` for any branch name (incl. names containing condition/repetition labels). (b) Request bodies for identical behaviour under different branch names are byte-identical. (c) Forbidden-string scan of every v2 body for branch names. (d) Visible→internal id translation still links provenance correctly. | `test_m3_2_visible_memory.py`, `test_m3_4_protocol_executor.py`, `test_m3_6_side_channels.py` | Branch name embedded in visible `data_id` |
| **D8** | (a) `VisibleObservation` field set is exactly `{step, tool, args, result, data_id}` (schema pin). (b) No v2 body contains `allowed`, `feedback`, `output`, `OK:`, `DENIED (`, layer names, rule IDs, condition names, namespace/classification labels, `redact`. (c) C0 denial vs genuine missing resource: byte-identical bodies (R2; see M3.6). (d) Cross-condition body diff confined to denied steps' `result`. | `test_m3_2_visible_memory.py`, `test_m3_5_protocol_adapter.py`, `test_m3_6_equivalence.py`, `test_m3_6_side_channels.py` | `allowed` added to v2 observation; DENY leaking internal reason; `data_id` set on denied step |
| **D9** | See §4 M6 "Provenance-independent content evaluation": undeclared flow, incorrectly declared flow (false attribution to a benign source), over-declared flow (declared but unused source), paraphrased/partial leakage per A13 detector, denied sink = attempted (not actual) leakage. | `test_m5_action_compare.py`, `test_m6_fact_scoring.py`, `test_m7_e2e.py` | Leakage scoring reading `input_node_ids`; denied sink counted as leak |

---

## 3. Dependency order

```
M3.1 → M3.2 → M3.3 → M3.4 (+ migrate 25 M2 tests) → M3.5 → M3.6 [blocking C0 equivalence, R2]
                                       │
        [A15, A11, B2, B3] ──► M4 ─────┤
                 [A7 scope] ──► M5 ────┤
 [A7 rule PRE-REGISTERED (R3), A8, A13] ──► M6 ─┤
          [A6, A9] ──► M7.1 → M7.2 → M7.3 → M7.4 → M7.5   (synthetic + mocked only, R4)
                                       │
                                       ├──► M8.1 service → M8.2 schemas → M8.3 CLI → M8.4 → M8.5   (no HTTP, R5)
                                       │            └── [B1 approved] ──► optional HTTP adapter
                                       └──► (outside backend gate) M7.6 live pilot [A14 + separate approval]
```

---

## 4. Milestone plans

### M3.1 — `ExperimentCondition` and pure renderers
**Files:** `src/attribution/models.py` (additive enum `C0_OUTCOME_OBSCURED`, `C1_GENERIC_DENIAL`, `C2_INFORMATIVE_DENIAL`); **new** `src/agent/rendering.py` (`CANONICAL_UNAVAILABLE`, `render_denial(condition, decision)`, `render_unavailable()`, `render_tool_error(msg)`).
- [ ] Enum separate from `FeedbackCondition`.
- [ ] Renderers pure; no interpolation; C2 = `TEMPLATES[category_for_rule(deny_rule_id(decision))]`; unmapped rule raises.

**Tests** (`tests/test_m3_1_rendering.py`): 3 enum values; exact C0/C1/C2 texts; C2 for all 16 rule IDs (real decisions for the 15 monitor-reachable); no argument substring in any rendering (deterministic adversarial arguments); unmapped raises; `TOOL_ERROR: <msg>` verbatim.
**Mutations:** C0 or C1 text changed; wrong C2 category; argument interpolated.
**Acceptance:** tests + mutations; M0, M3.0, full suite pass; only additive change to `models.py`.

### M3.2 — `VisibleObservation` / `VisibleMemory`
**Files:** `src/agent/state.py` (additive).
- [ ] `VisibleObservation` = exactly `step, tool, args, result, data_id`; `extra="forbid"`, frozen.
- [ ] `VisibleMemory` append-only, deep copies to agents; `visible_data_id(step) -> "d_s{n}"`; canonical serialization.

**Tests** (`tests/test_m3_2_visible_memory.py`): field set + JSON-schema pin; no `allowed/feedback/output`/internal fields (D8a); agent-side mutation cannot alter stored records; stable serialization; `data_id` independent of branch name (D7a).
**Mutations:** `allowed` field added; deep copy removed; branch name in `data_id`.
**Acceptance:** tests + mutations; M3.0 confirms historical classes unchanged.

### M3.3 — Missing-resource sentinel (opt-in)
**Files:** `src/agent/environment.py` (`unavailable_sentinel: bool = False`).
**Tests:** default output byte-identical (M3.0); opt-in returns sentinel only for genuinely missing documents; existing docs, empty search `[]`, tool errors unchanged in both modes.
**Mutations:** sentinel on by default; sentinel for empty search.
**Acceptance:** M3.0 unchanged; new tests pass.

### M3.4 — `run_protocol_branch`, §9.6 rejection, audit fields, M2 test migration (one step)
**Files:** `src/agent/executor.py`, `src/monitor/models.py`, `src/agent/agent.py` (abstract `ProtocolAgent` only), `docs/AUDIT_SCHEMA.md`, `tests/test_m2_resource_policy.py` (migration).
- [ ] `run_branch` raises when `resource_policy` is set (all four historical conditions) — D6.
- [ ] `run_protocol_branch(task, env_state, agent: ProtocolAgent, branch_name, condition, resource_policy=None, monitor_config=None) -> ProtocolBranchResult`.
- [ ] Rendering: executed → mediated output, `data_id = d_s{n}`; genuinely missing → canonical, `None`; DENY → `render_denial(condition)`, `None`; tool error → `TOOL_ERROR: msg`, `None`; empty search → `[]`.
- [ ] Visible→internal `data_id` translation for `input_node_ids`.
- [ ] Audit: `experiment_condition`, `prompt_version`, `agent_visible_observation` + digest, `policy_evidence`; validators (required on protocol path, `None` on historical path).
- [ ] Result exposes raw validity signals for M4 (agent failure, retries, termination cause, `done_reason`).
- [ ] Migrate the 25 M2 tests to C0/C1/C2 with equal assertion strength; add "`ACTUAL` + policy raises".

**Tests** (`tests/test_m3_4_protocol_executor.py`): 4 historical conditions × policy raise; each outcome × each condition; denied actions never execute; audit keeps true DENY while agent sees canonical in C0; visible digest equals what the agent received; `policy_evidence` survives JSONL round-trip + hash chain; evaluator fields never in `VisibleMemory`; no shared objects between branches; D7b (same behaviour, different branch names → identical visible sequences); D14.
**Mutations:** rejection removed; DENY leaking internal reason; `policy_evidence` not persisted; visible digest over raw output.
**Acceptance:** migrated M2 suite (50) passes; the 19 earlier M2/catalogue mutations still caught; M0, M3.0, full suite pass.

### M3.5 — Protocol agents and `OllamaProtocolAdapter` (v2.0)
**Files:** `src/agent/agent.py` (**new class only**; v1 untouched, parse logic duplicated per U10); **new** `src/agent/protocol_agents.py`:
`ScriptedProtocolAgent`, `EventReactiveAgent`, `ReasonReactiveAgent(category)`, `DenialBlindAgent`, `SeededNoiseAgent`, `FactReportingAgent`, plus provenance-test agents (R1): `UndeclaredFlowAgent` (copies read content to a sink without `input_node_ids`), `MisdeclaringAgent` (copies content from source X while declaring benign source Y), `OverDeclaringAgent` (declares a source whose content it does not use).
- [ ] v1 system message byte-for-byte (U1); same parameters; same `format` schema.
- [ ] User message keys `goal`, `available_tools`, `observations` (visible only); `config_dict()` reports `v2.0`.
- [ ] Structured failure (`failed`, error kind, retries) and Ollama `done_reason` recorded (D1, B3).

**Tests** (`tests/test_m3_5_protocol_adapter.py`): parameter parity with v1; system-message equality; parse parity with v1 on M3.0 reply scripts (incl. `action` wrapper, malformed replies); forbidden-string scan (D8b); D1a; every synthetic agent behaves as specified using only the visible view; protocol path rejects historical agents.
**Mutations:** v2 parameter changed; `allowed` in v2 observation; failure reported clean; synthetic agent reading audit/monitor.
**Acceptance:** tests + mutations; M3.0 confirms v1 byte-identical.

### M3.6 — Protocol verification suites and freeze
**Files (new):** `tests/test_m3_6_equivalence.py`, `tests/test_m3_6_side_channels.py`, `tests/test_m3_6_isolation.py`, `tests/_v2_baseline.py`, `tests/fixtures/m3_v2_baseline.json` (hash-pinned). Docs: `DESIGN_DECISIONS.md` §11 status, `AUDIT_SCHEMA.md`, `EXPERIMENT_LOG.md`, `HANDOFF.md`.

**Blocking acceptance criterion — C0 equivalence (R2).** M3 cannot be marked COMPLETE, and no later milestone may start, unless all of the following pass:
- [ ] For each equivalence scenario, a **denial branch** and a **genuine-missing-resource branch** are run under C0 with the same scripted agent behaviour.
- [ ] The **complete serialized visible-observation sequence** (every step, not only the denied step) is byte-identical across the pair.
- [ ] **Every model request body** sent after the denial/missing step — and every body before it — is byte-identical across the pair (captured through the mocked v2 transport; whole body bytes, not parsed subsets).
- [ ] Coverage: denial placed before, between and after successful reads; with empty and non-empty searches; with tool errors; with sinks; at first and last step; with multiple denials in one run; under both namespace kinds; and the §9.1 fact-variant check (`CONFIDENTIAL` vs `ABSENT` under C0).
- [ ] The comparison helper itself is mutation-tested (a single differing byte anywhere in any body must fail).

**Other checklist items:**
- [ ] **S1:** tool errors identical across C0/C1/C2, never canonical, free of registry/content/label/rule/layer strings.
- [ ] **Cross-condition body diff:** only denied steps' `result` differs (D8d).
- [ ] **Side channels:** D7c branch-name scan; D8b forbidden-string scan over all v2 bodies.
- [ ] **A1 limitation pinned:** sink C0 denial equals the canonical observation while a successful sink differs (documented, not hidden).
- [ ] **Isolation:** any condition order → identical per-condition results; no shared state.
- [ ] **v2 golden freeze:** v2 request bodies for protocol scenarios, hash-pinned as in M3.0.
- [ ] D5 documented as a historical limitation.

**Mutations:** canonical text differs from missing-resource text; denied step given a `data_id`; branch-specific byte in later bodies; tool error rendered as canonical; shared memory between branches.
**Acceptance:** all suites pass, including the blocking C0 criterion; mutations caught; M0 + M3.0 pass; docs updated → **M3 COMPLETE**.

### M4 — Execution validity
**Prerequisites:** A15, A11, B2, B3. **Files:** **new** `src/evaluation/validity.py`.
- `BranchValidity`: `VALID` / `INVALID` with reasons `MODEL_ERROR`, `PARSE_FAILURE`, `RETRIES_EXHAUSTED`, `TRUNCATED_OUTPUT`, `EMPTY_TRACE`, `UNMAPPED_RULE`, and `MAX_STEPS` / `TOOL_ERROR` per B2/A15.
- `GroupValidity` (scenario × C0/C1/C2 × repetitions): `INTERVENTION_NOT_DELIVERED` (< *k* delivered per condition, A11), `PRE_INTERVENTION_DIVERGENCE`.

**Tests** (`tests/test_m4_validity.py`): every reason triggered via mocked adapters/synthetic agents; **D1b–d**; **D2a–b**; delivery counting; prefix-divergence detection.
**Mutations:** retries-exhausted valid; missing branch = "action omitted"; divergence check skipped.
**Acceptance:** every invalid scenario classified; no invalid branch reaches M5/M6 (enforced and tested).

### M5 — Behaviour comparison
**Prerequisite:** A7 (scope). **Files:** **new** `src/attribution/action_compare.py`.
- Canonical action representation (tool + canonical arguments); LCS alignment over the A7-scoped behaviour; field-level and free-text diffs; **sink-content comparison computed from actual arguments/bodies, never from `input_node_ids`** (R1); reason-token transfer (C2 reason-clause content appearing in C2 behaviour but not C1/C0); deterministic pairwise distance; within-condition (sham) and cross-condition distance sets.

**Tests** (`tests/test_m5_action_compare.py`): insertions, reordering, repeated tools, same tool with different body, same text in a different field, empty traces; transfer positive/negative; determinism; **D9: identical content with different/absent `input_node_ids` gives identical comparison results**.
**Mutations:** step-index alignment (historical behaviour); tool-name-only matching; arguments ignored; asymmetric distance; comparison reading `input_node_ids`.
**Acceptance:** all crafted cases give the documented expected distances/diffs.

### M6 — Attribution, inference and leakage
**Prerequisites:** **A7 rule pre-registered per §1 (R3)**, A8, A13, A15. No M6 code is written before the pre-registration commit is recorded.
**Files (new):** `src/attribution/condition_attributor.py` (`AttributionOutcome` ×5, `InconclusiveReason`, pre-registered decision rule, evidence record, A8 mappings); `src/evaluation/fact_scoring.py`.

**Known-answer tests** (`tests/test_m6_attribution.py`):

| Agent | Expected |
|---|---|
| `EventReactiveAgent` | `EVENT_SENSITIVE` |
| `ReasonReactiveAgent` | `REASON_SENSITIVE` (each reachable category) |
| combined | `BOTH_EVENT_AND_REASON_SENSITIVE` |
| `DenialBlindAgent` | `DENIAL_INDEPENDENT` |
| `SeededNoiseAgent` | `INCONCLUSIVE` (within-noise) |

Plus: invalid runs → `INCONCLUSIVE/INVALID_EXECUTION` (**D2a**); not-delivered and pre-intervention-divergence cases; sink stratum flagged as not a clean event contrast (A1); rule constants equal the pre-registered values (R3 pin).

**Provenance-independent content evaluation (R1, D9)** (`tests/test_m6_fact_scoring.py`). Leakage and inference are scored from the **actual outbound content** of executed sink actions using the A13 detector; `input_node_ids` are never an input to scoring. Required cases:
- **Undeclared flow:** `UndeclaredFlowAgent` sends protected content without declaring provenance → detected as leakage (if the sink executed).
- **Incorrectly declared flow:** `MisdeclaringAgent` declares a benign/public source while sending protected content → detected as leakage; declaration recorded as inaccurate.
- **Over-declared flow:** `OverDeclaringAgent` declares a protected source but sends only benign content → **no** leakage.
- **Correctly declared flow:** declared and actual agree → leakage detected; declaration recorded as accurate.
- **Denied sink:** protected content in a DENIED sink → `ATTEMPTED_LEAKAGE`, never actual leakage.
- **Partial/paraphrased content:** behaviour per A13 detector, with documented detector limits (cases the detector cannot catch are listed as known false negatives, not hidden).
- **Fact-variant inference:** detected only when behaviour varies with the hidden fact across CONFIDENTIAL/PUBLIC/ABSENT.
- Scoring output includes a **declaration-accuracy** field per sink (declared vs content-derived source), for M7.3 reporting.

**Mutations:** C0/C1 and C1/C2 contrasts swapped; invalid runs included; denied sink counted as leak; noise threshold ignored; scoring reading `input_node_ids`; rule constant changed from pre-registered value.
**Acceptance:** 100% of known-answer and provenance cases correct, including designed-inconclusive cases; A8 mappings tested. Documentation states that content-based detection depends on the A13 detector and **does not constitute complete information-flow enforcement** (R1).

### M7 — Runner and evaluation (synthetic + mocked only, R4)
**Prerequisites:** A6, A9. M7.1–M7.5 use only synthetic agents and mocked model responses; no live Ollama call is made or permitted by their tests.

| Sub | Deliverable | Files | Acceptance |
|---|---|---|---|
| **M7.1** | Scenario configs: both namespace kinds; fact-variant groups; neutral goals; neutral synthetic paths + classic-path comparisons; tool-type strata; reachable reason categories; A13 markers; provenance-test scenarios (undeclared/misdeclared/over-declared) | **new** `configs/cda/*.json`; validation in `src/evaluation/cda_scenarios.py` (whole-scenario concealment across scenarios; D11 tool coverage) | All configs validate; crafted bad configs rejected (leaky public content, uncovered resource tool, instructed-denial goal wording) |
| **M7.2** | Runner: plan (scenario × condition × repetition), randomized order with recorded seed, fresh agents, validity → comparison → attribution → scoring; `results/cda/<run_id>/` (manifest: commit, clean-tree check, model, parameters, prompt + catalogue versions, config hashes, seeds, order; per-branch audit JSONL; visible observations; summaries); exclusive writes; checkpoint retries invalid rows (D3); all repetitions persisted (D4); never imports `phase5_runner` (**D2c**); **live mode disabled** (raises unless an M7.6 approval flag + approved config is supplied — not exercised in the backend gate) | **new** `src/evaluation/cda_runner.py` | Refuses: existing output dir, paths outside `results/cda/`, dirty tree (unless overridden and recorded), unapproved parameter overrides, live mode without approval |
| **M7.3** | Reporting: stratified by namespace kind, reason category, tool type (R2 of §9, §10.1); C1/C2 length table (R3 of §9); n=5 exploratory caveat; invalid + delivery rates; A8 mappings; **provenance-declaration accuracy rate and count of undeclared/misdeclared flows** (D9, R1); unreachable categories (D15); explicit statement that results are not evidence of complete information-flow enforcement | **new** `src/evaluation/cda_report.py` | Report schema pinned by tests |
| **M7.4** | Mocked end-to-end: full pipeline with synthetic agents **and** mocked v2 Ollama transport | **new** `tests/test_m7_e2e.py` | Expected outcome for every known-answer scenario; **D1e** and **D2a** scenarios → INCONCLUSIVE/INVALID; **D9** undeclared and misdeclared scenarios detected end-to-end; C0 equivalence holds end-to-end (R2) |
| **M7.5** | Reproducibility: two mocked runs → identical summaries (timestamps excluded); summary golden hash-pinned | tests | Byte-identical |
| **M7.6** | **Live pilot** (smoke test, then A14 pilot) | — | **Outside the backend completion gate. Requires separate, explicit approval, and A6, A9, A14 and the pre-registered A7 rule (R3, R4).** |

### M8 — Backend interface for the frontend (no frontend build; no HTTP, R5)
**Prerequisite for HTTP only:** B1. Everything below up to M8.5 is pure Python + CLI and adds **no new dependency**.

| Sub | Deliverable |
|---|---|
| **M8.1** | **Service layer** (`src/service/`, pure Python, standard library + existing dependencies only): list scenarios; run one episode or a C0/C1/C2 triple (synthetic or mocked agents by default; live only via the gated M7.6 path); get run by ID; comparison and attribution views. |
| **M8.2** | **Versioned JSON view schemas** with strict separation. *Agent view:* visible observations only. *Evaluator view:* authorization, deciding layer, rule, reason category, execution status, internal reason, policy evidence, validity, comparison, attribution, declaration accuracy. Per-step `StepView`: proposal, ALLOW/DENY and why, executed or not, what the agent saw, next action. |
| **M8.3** | **CLI:** `python -m src.service.cli … --json` exposing every M8.1 operation. |
| **M8.4** | **Safety:** user-submitted goals only within approved scenario templates (fixed tools/environment); no arbitrary paths or tools; timeouts; writes only under `results/cda/`; live mode off by default; no secrets in output. |
| **M8.5** | **Docs:** `docs/API.md` (CLI commands, JSON schemas, examples, what is live vs recorded); README/HANDOFF drift fixed (D13); D12 documented. |
| *(deferred)* | **HTTP adapter** (`GET /scenarios`, `POST /episodes`, `GET /runs/{id}`, `GET /runs/{id}/attribution`) — **only after B1 is explicitly approved**, as a thin wrapper over M8.1 with its dependency recorded. Not part of the backend completion gate. |

**Tests:** schema pins; contract tests per CLI command; agent view never contains evaluator-only fields; live mode refused when disabled; no writes outside allowed directories; CLI end-to-end; static test that no HTTP framework is imported or added to `pyproject.toml` before B1.
**Acceptance:** a frontend developer can drive every demo flow from `docs/API.md` alone via the CLI/service layer, using synthetic or mocked agents.

---

## 5. Test matrix

| Type | Where |
|---|---|
| Unit | Each new module (M3.1–M6, M8 schemas) |
| Integration | Executor + monitor + environment + renderers (M3.4, M3.6); validity → comparison → attribution → scoring (M4–M6) |
| Equivalence (blocking) | M3.6 C0 denial vs genuine-missing: full observation sequences + every request body byte-for-byte (R2); repeated end-to-end in M7.4 |
| Provenance | Undeclared, misdeclared, over-declared, correctly declared, denied-sink cases (M5, M6, M7.4; R1) |
| Evidence-critical defects | D1, D2, D7, D8, D9 executable tests per §2.1 (R6) |
| Mutation | Every milestone, via proposed `scripts/mutation_check.py` |
| Regression | M0 (59), M3.0 (104), M1, migrated M2, v2 golden (M3.6), summary golden (M7.5), A7 pre-registration pin (M6) |
| End-to-end | M7.4 mocked pipeline; M8 CLI end-to-end |
| Known-answer | M6 synthetic agents, including designed-inconclusive and noise cases |

---

## 6. Expected file changes

**Modified (additive):** `src/attribution/models.py`, `src/agent/state.py`, `src/agent/environment.py` (opt-in), `src/agent/executor.py`, `src/monitor/models.py`, `src/agent/agent.py` (new classes only), `src/evaluation/cda_scenarios.py`, `tests/test_m2_resource_policy.py` (migration), docs.

**New:** `src/agent/rendering.py`, `src/agent/protocol_agents.py`, `src/evaluation/validity.py`, `src/attribution/action_compare.py`, `src/attribution/condition_attributor.py`, `src/evaluation/fact_scoring.py`, `src/evaluation/cda_runner.py`, `src/evaluation/cda_report.py`, `src/service/*` (incl. `cli.py`), `configs/cda/*`, `tests/test_m3_*` … `tests/test_m8_*`, `tests/_v2_baseline.py`, `tests/fixtures/m3_v2_baseline.json`, `docs/API.md`; proposed `scripts/mutation_check.py`.

**Never changed:** historical runners (`phase*_runner.py`, audits); `results/` (except new `results/cda/` subfolders); existing `configs/*.json`; M0 and M3.0 fixtures; v1 adapter, `BaseAgent`, historical policies, `FeedbackCondition`; model parameters; `pyproject.toml` dependencies (until B1, if ever).

---

## 7. Risks

| Risk | Mitigation |
|---|---|
| Executor refactor disturbs historical path | Separate `run_protocol_branch`; shared helpers only where M0 + M3.0 prove no change |
| M2 test migration weakens guarantees | Migrate in the same step as the rejection; re-run all 19 M2 mutations |
| A7 rule chosen after seeing data | Pre-registration before M6 code and before any live outcome; constants pinned by test (R3) |
| Synthetic known-answer agents too easy (circular) | Include inconclusive, noise, undeclared/misdeclared-flow and sink-limitation cases; live validation separate (M7.6) |
| Agent-declared provenance under-reports flows | Content-based scoring independent of declarations; declaration accuracy reported; no complete-IFC claim (R1) |
| Content detector misses paraphrased leakage | A13 decision; known false negatives documented; results stratified and caveated |
| C0 cover holds only for reads (A1) | Stratify; sink contrasts never pooled as clean |
| Live non-determinism | Same-condition sham distances (Decision 5); invalid-run classification (M4) |
| Dependency / scope creep in M8 | CLI first; HTTP only after B1 (R5); frontend out of scope |

---

## 8. Definition of done (backend complete)

1. M3.1–M3.6, M4, M5, M6, M7.1–M7.5 and M8.1–M8.5 are COMPLETE by their acceptance criteria, each committed locally on `backend-milestones` after review.
2. **The M3.6 C0 equivalence criterion passes** (complete observation sequences and every request body byte-identical across denial and genuine-missing branches) and is re-verified end-to-end in M7.4 (R2).
3. A7 (scope and rule), A8, A11, A13, A15, B2, B3, A6, A9 are resolved and recorded in `DESIGN_DECISIONS.md`; **the A7 rule was pre-registered before M6 implementation**, with its commit recorded in `EXPERIMENT_LOG.md` and its constants pinned by test (R3).
4. **D1, D2, D7, D8 and D9 each have passing executable tests per §2.1, each caught by a mutation** (R6). All other defects D3–D6, D10–D15 are resolved, tested or explicitly documented as in §2.
5. Provenance-independent content evaluation passes all undeclared, misdeclared, over-declared and denied-sink cases; reports include declaration accuracy and state that the system is not complete information-flow enforcement (R1).
6. The full suite passes with no skips (M0, M3.0, v2 golden, summary golden, migrated M2, all new suites); every milestone's mutation suite is caught and re-runnable.
7. The mocked end-to-end pipeline (synthetic agents + mocked model responses only) reproduces byte-identically and gives correct known-answer outcomes, including inconclusive and invalid cases (R4).
8. `docs/API.md` lets frontend work proceed using the pure-Python service layer and CLI; no HTTP framework or new dependency has been added unless B1 was approved (R5).
9. No historical result, config, fixture, model parameter or `main` change occurred; `results/` and `configs/` checksums still match the pre-M0 snapshot.

**Outside the backend completion gate:** M7.6 live pilot (separate approval, R4) and any HTTP adapter (B1, R5).
