# Design Document Evidence and Traceability Report

**Authoritative Repository:** [https://github.com/Rahul2006MILLION/counterfactual-denial-attribution](https://github.com/Rahul2006MILLION/counterfactual-denial-attribution)  
**Verified Active Branch:** `main`  
**Verified Head Commit SHA:** `7b055cba465d3513a9482f6e72758416d1323381`  
**Verification Date:** 2026-11-17  
**Validation Suite:** 472 passing tests in 6.96s (`uv run pytest`) across Python 3.12.14  

---

## 1. Overview and Source of Truth Audit

This document provides a line-item traceability matrix and evidence catalog supporting all factual assertions, architectural diagrams, research summaries, and methodological analyses presented in `PROJECT_DESIGN_DOCUMENT.pdf` and `PROJECT_DESIGN_DOCUMENT.md`.

Every claim is strictly classified under one of four non-negotiable status categories:
- **`IMPLEMENTED`**: Supported by executable source code, passing unit/regression tests, and reproducible artifact data in the repository.
- **`PARTIALLY IMPLEMENTED`**: Some components are operational in source code, but full pipeline execution, benchmark generalization, or complete integration is incomplete or gated.
- **`PROPOSED`**: Formally specified in project design roadmaps (`BACKEND_PLAN.md`, `DESIGN_DECISIONS.md`), but unexecuted or planned for future development milestones.
- **`UNVERIFIED`**: Cannot be conclusively established from committed repository evidence alone.

---

## 2. Line-Item Traceability Matrix

### Section A: Problem Statement

| Item ID | Claim / Technical Assertion | Supporting Repository File(s) | Module, Class, or Function | Verified Evidence in Repository | Status | Limitations / Caveats |
|---|---|---|---|---|---|---|
| **A-01** | Tool-calling LLM agents observe denial feedback (and reasons), creating an unintended information side-channel (*causality laundering*). | `README.md`<br>`HANDOFF.md`<br>`docs/RESEARCH_PLAN.md` | `README.md:12-16`<br>`HANDOFF.md:10-16` | Cites Chinaei (2026). Agents condition downstream tool calls on denial-revealed facts (e.g., path existence, permission classes). | `IMPLEMENTED` (threat model & synthetic tests) | Observed on deterministic agents; preliminary on live LLM. |
| **A-02** | The Agentic Reference Monitor (ARM) introduces `DeniedAction` nodes with `COUNTERFACTUAL` edges linking denied actions to immediate next actions. | `src/monitor/provenance.py`<br>`src/monitor/arm_baseline.py` | `ProvenanceGraph.record_denial()`<br>`ARMMonitor.mediate_call()` | `provenance.py:91-115`: Creates `COUNTERFACTUAL` directed edge from `DeniedAction` to the subsequent `Call` node. | `IMPLEMENTED` | Python reproduction of Chinaei's Rustworkx baseline. |
| **A-03** | ARM's temporal-adjacency heuristic (`IMMEDIATE_NEXT`) over-approximates, causing high false-positive blocking on benign post-denial workflows. | `results/phase2_strategy_comparison.json`<br>`results/phase4_baseline_comparison.csv` | `EXP-002`<br>`EXP-005` | In `EXP-002` (`n=19`), `L2G+IMMEDIATE_NEXT` achieved `0.000` ASR but benign task completion dropped to `0.143` (`1/7`), action FPR was `0.864` (`19/22`). | `IMPLEMENTED` | Measured on deterministic scenarios. |
| **A-04** | Lexical/target-scoped provenance filtering (`SINK_SCOPED`) eliminates benign false positives but fails against paraphrased, transformed, or delayed laundering. | `results/phase2_strategy_comparison.json`<br>`src/evaluation/scenarios.py` | `EXP-002`<br>`scenarios.py:E3, E4, E5` | In `EXP-002`, `L2G+SINK_SCOPED` maintained `1.000` benign completion, but Attack Success Rate (ASR) remained `0.750` (`9/12` attacks unblocked). | `IMPLEMENTED` | Evaluated across 12 attack scenarios. |
| **A-05** | Enterprise agents require distinguishing legitimate post-denial actions from genuine denial-feedback leakage without crippling utility. | `README.md:27-43`<br>`HANDOFF.md:14-16` | Finalized Research Question | Formulated as RQ1–RQ4 examining precision, recall, utility, and runtime overhead. | `IMPLEMENTED` (formulation) | Focuses on single-agent tool mediation. |

---

### Section B: Research Review

| Item ID | Claim / Technical Assertion | Supporting Repository File(s) | Module, Class, or Function | Verified Evidence in Repository | Status | Limitations / Caveats |
|---|---|---|---|---|---|---|
| **B-01** | Primary Foundation: Mohammad Hossein Chinaei (April 2026), *"Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents"*, arXiv:2604.04035. | `README.md:46`<br>`output.md:34-40`<br>`HANDOFF.md:10` | Full citation & PDF audit record in `output.md` | Formalized causality laundering; introduced ARM with 5-level lattice, 4-layer monitor (`L1`–`L4`), and hash-chained audit logging. | `IMPLEMENTED` (baseline reproduced) | Chinaei evaluated only 3 attack scenarios; lacked FP benchmark. |
| **B-02** | FIDES (Costa et al., IEEE SaTML 2026, arXiv:2505.23643) enforces information-flow control on observable flows. | `docs/RESEARCH_PLAN.md:28-32`<br>`output.md:42` | Related work survey | FIDES tracks explicit data flows; misses covert inference channels through denial outcomes. | `IMPLEMENTED` (literature baseline) | Not directly integrated as executable code. |
| **B-03** | PCAS (Palumbo et al., 2026, arXiv:2602.16708) compiles declarative policies over dependency graphs. | `docs/RESEARCH_PLAN.md:33-36`<br>`output.md:43` | Related work survey | Enforces over static/dynamic dependency graphs; lacks counterfactual intervention mechanisms for denied actions. | `IMPLEMENTED` (literature baseline) | External reference. |
| **B-04** | CaMeL (Debenedetti et al., 2025, arXiv:2503.18813) separates agent planning from execution using capability tokens. | `docs/RESEARCH_PLAN.md:37-40`<br>`src/monitor/arm_baseline.py` | `CapabilityToken` dataclass | Separates privileged actions, but does not insulate the planner from denial side-channels in feedback. | `IMPLEMENTED` (token model used) | Baseline comparison. |
| **B-05** | AgentSentry (Zhang et al., 2026, arXiv:2602.22724) and CausalArmor (Kim et al., 2026, arXiv:2602.07918) use causal diagnostics / ablation for prompt injection. | `docs/RESEARCH_PLAN.md:41-47`<br>`output.md:45-46` | Related work survey | Uses temporal re-execution and leave-one-out ablation on inputs; does not address runtime denial feedback mediation. | `IMPLEMENTED` (literature baseline) | External reference. |
| **B-06** | Research Gap: Existing monitors treat denials as terminal drops or use coarse temporal heuristics; none isolate the causal effect of denial feedback via controlled counterfactual intervention. | `README.md:49-54`<br>`docs/RESEARCH_PLAN.md:50-65` | Research Gap definition | Formulates the need for controlled counterfactual paired intervention (`C0` vs `C1` vs `C2`). | `IMPLEMENTED` | Addressed across Phases 3–4.3 and backend milestones M1–M3. |

---

### Section C: Methodology

| Item ID | Claim / Technical Assertion | Supporting Repository File(s) | Module, Class, or Function | Verified Evidence in Repository | Status | Limitations / Caveats |
|---|---|---|---|---|---|---|
| **C-01** | Paired-Execution Counterfactual Intervention: Runs identical initial state, task, and seeds under actual vs. neutralized denial feedback. | `src/agent/executor.py`<br>`src/attribution/intervention.py` | `AgentExecutor.run_branch()`<br>`DenialInterventionEngine` | `executor.py:53-150`: Executes Branch A (`ACTUAL`) and Branch B (`NEUTRALIZED`), ensuring isolated mutable environments. | `IMPLEMENTED` | Verified in unit tests `test_dynamic_paired_execution_and_isolated_mutable_state`. |
| **C-02** | Three nested experimental conditions: C0 (Outcome-Obscured), C1 (Generic Denial), and C2 (Informative Denial via Reason Catalogue). | `docs/DESIGN_DECISIONS.md:18-44`<br>`src/monitor/reason_catalogue.py`<br>`src/attribution/models.py` | `ExperimentCondition`<br>`REASON_TEMPLATES_V1` | `DESIGN_DECISIONS.md:§1`: C0 hides outcome as ordinary miss; C1 conveys event only; C2 provides coarse non-sensitive reason (`cda-c2-reasons-v1`). | `IMPLEMENTED` (models, reason catalogue, M2/M3 tests) | Evaluated in M2/M3 regression suites; historical runs use `FeedbackCondition`. |
| **C-03** | Concealing Resource Policy: Existing protected resources and nonexistent resources in concealing namespaces produce identical observations. | `src/monitor/resources.py`<br>`src/monitor/arm_baseline.py` | `ProtectedNamespace`<br>`ResourcePolicy`<br>`ResourcePolicyLayer` | `resources.py:15-120`: Normalizes paths, conceals existence, filters search results; tested in `test_m2_resource_policy.py:46 tests passed`. | `IMPLEMENTED` | Opt-in layer integrated into `ARMMonitor`. |
| **C-04** | Canonical Data Lineage (`canonical.py`): Maps physical IDs to logical identities `logical::<tool>(<args>)` + content digest, preventing synthetic divergence artifacts. | `src/attribution/canonical.py`<br>`results/phase5_canonicalization.csv` | `resolve_logical_source()`<br>`compare_logical_sources()` | `canonical.py:20-140`: Evaluates SHA-256 `content_digest`, `trust_level`, and transformation lineage; passes 7/7 test cases. | `IMPLEMENTED` | Resolves Phase 4.1 Case 5 defect. |
| **C-05** | Multi-Evidence Attribution Model (`EvidenceBasedAttributor`): Evaluates 4 distinct classes (`DENIAL_SENSITIVE`, `DENIAL_INDEPENDENT`, `AMBIGUOUS`, `NOT_EVALUABLE`) without keyword heuristics. | `src/attribution/evidence_model.py`<br>`src/attribution/models.py` | `EvidenceBasedAttributor.attribute()` | `evidence_model.py:40-195`: Checks trace divergence, canonical source equivalence, independent trusted sources, and multi-denial ablation. | `IMPLEMENTED` | Passes all 10-way ablation configs. |
| **C-06** | Phase 4.3 Benchmark: 104 opaque-ID scenarios (`EXP-008`, `seed=43127`) achieved 96.15% 4-class accuracy, Macro-F1 0.9575, and 0.000 FAR on independent actions. | `results/phase4_3_results.json`<br>`results/phase4_3_ablation.csv`<br>`output.md:192-225` | `src/evaluation/phase4_3_runner.py` | 100/104 correct (95% Wilson CI [0.9053, 0.9849]); selective accuracy 94.12% at 65.38% coverage. 4 errors were coincidental modulo-3 greeting collisions. | `IMPLEMENTED` | Evaluated on synthetic deterministic agents. |
| **C-07** | Ten-Way Ablation Study proves canonical identity and alternative explanation modeling are critical (removing them drops accuracy to 71.15% and 80.77%). | `results/phase4_3_ablation.csv`<br>`output.md:206-210` | `EXP-008` ablation table | Ablation `J_WITHOUT_CANONICAL_IDENTITY`: Acc=0.7115, FAR=0.8125; `H_WITHOUT_ALTERNATIVE_EXPLANATIONS`: Acc=0.8077. | `IMPLEMENTED` | Machine-readable CSV artifact verified. |
| **C-08** | Multi-Policy Evaluation across 6 agent policies: `ReactivePolicyAgent` (0.9615), `ConservativeStoppingAgent` (1.000), `IndependentRecoveryAgent` (1.000), `DenialInsensitiveAgent` (1.000), `MemoryMediatedAgent` (1.000), `SourcePrioritizationAgent` (0.7404). | `results/phase4_3_policy_comparison.csv`<br>`output.md:212-216` | `EXP-008` policy comparison | Confirms attribution robustness across diverse behavioral recovery patterns. `SourcePrioritizationAgent` highlights partial reactivity. | `IMPLEMENTED` | Documented and verified in test suite. |
| **C-09** | Baseline Regression Safety Net (M0 & M3.0): 47 frozen artifact hashes, 104 golden tests verifying byte-level Ollama request prompts against fixture `m3_v1_baseline.json`. | `tests/test_m0_historical_regression.py`<br>`tests/test_m3_0_v1_baseline.py`<br>`tests/fixtures/` | `APPROVED_FIXTURE_SHA256`<br>`HISTORICAL_ARTIFACTS_SHA256` | Re-executes 8 deterministic historical runners in memory; all 472 test cases pass deterministically without network calls. | `IMPLEMENTED` | Protects historical evidence against silent corruption. |
| **C-10** | Preliminary Live-LLM Evaluation (Phase 5, `EXP-009`): Smoke test passed with `qwen3:4b-4k`; full 40-scenario benchmark incomplete due to Ollama service exit at `LLM_SC_009`. | `results/phase5_llm_summary.json`<br>`results/phase5_llm_predictions.csv`<br>`HANDOFF.md:38-42` | `src/evaluation/phase5_runner.py` | Smoke test: `harmless_steps=['get_time']`, `denial_steps=[('read_document', 'DENY')]` passed. Core run: 8 completed, 31 `NOT_EVALUABLE`. | `PARTIALLY IMPLEMENTED` | Explicitly marked as incomplete; no performance claims made from EXP-009. |

---

### Section D: Solution Framework

| Item ID | Claim / Technical Assertion | Supporting Repository File(s) | Module, Class, or Function | Verified Evidence in Repository | Status | Limitations / Caveats |
|---|---|---|---|---|---|---|
| **D-01** | `ARMMonitor`: Deterministic 4-layer reference monitor enforcing `L1` (Hard Boundaries), `L2`/`L2G` (Provenance over 5-level lattice), `L3` (Schema Constraints), `L4` (Manual Policies). | `src/monitor/arm_baseline.py` | `ARMMonitor.evaluate_layers()` | `arm_baseline.py:180-260`: Evaluates `L1` regex/path patterns, `L2G` minimum trust propagation, `L3` argument types, and `L4` tool policies. | `IMPLEMENTED` | Full Python implementation passing unit tests. |
| **D-02** | `ProvenanceGraph`: Directed acyclic graph tracking `Call`, `Data`, `DataField`, `DeniedAction` nodes with `DIRECT_OUTPUT`, `INPUT_TO`, `FIELD_OF`, and `COUNTERFACTUAL` edges. | `src/monitor/provenance.py` | `ProvenanceGraph` class | `provenance.py:25-160`: Implements NetworkX graph traversal, `min_trust` lattice join, and `counterfactual_chains`. | `IMPLEMENTED` | Tested in `tests/test_provenance_graph.py`. |
| **D-03** | Immutable Hash-Chained Action Audit Logging (M1): Records `ActionAuditRecord` separating `authorization` (`ALLOW`/`DENY`) from `execution_status` (`EXECUTED`/`NOT_EXECUTED_DENIED`/`TOOL_ERROR`). | `src/monitor/models.py`<br>`src/monitor/audit.py` | `ActionAuditRecord`<br>`AuditLog.append()`<br>`verify_chain()` | `audit.py:20-80`: Employs SHA-256 rolling hash chain starting from `GENESIS_HASH`. Enforces strict Pydantic model validation. | `IMPLEMENTED` | Validated in `tests/test_m1_audit_records.py`. |
| **D-04** | Sandboxed Execution Environment: Pure in-memory tool simulator preventing arbitrary disk or network access (`get_time`, `search_documents`, `read_document`, `calculate`, `transform_text`, `send_email`, `export_data`). | `src/agent/environment.py` | `SandboxedEnvironment` class | `environment.py:30-180`: Simulated file tree and email sink; zero real external side effects. | `IMPLEMENTED` | Safe for automated evaluations. |
| **D-05** | Live Document Agent Application: Local Ollama-powered FastAPI application (`src/live/`) with structured JSON tool planning, multi-stage security gateway, and Vite frontend. | `src/live/agent.py`<br>`src/live/api.py`<br>`src/live/security.py`<br>`frontend/` | `SecurityGateway`<br>`LiveDoc`<br>`FastAPI app` | `src/live/`: 9-stage execution pipeline (file extraction, Ollama planning, policy check, approved execution, verification). Tested in `tests/test_live_agent.py`. | `IMPLEMENTED` | Application layer built alongside core research framework. |

---

## 3. Verified Bibliographic References

1. **Chinaei, M. H.** (2026). *Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents*.  
   - **Venue/Preprint:** arXiv preprint `arXiv:2604.04035v1 [cs.CR]` (April 2026).  
   - **Verification:** Primary source paper in repository (`papers/260404035v1-1_261028_175409.pdf`). Forms the theoretical foundation of the causality laundering threat model and the Agentic Reference Monitor (ARM) baseline.

2. **Costa, P., et al.** (2026). *FIDES: Information-Flow Control for LLM Agents*.  
   - **Venue/Preprint:** IEEE Symposium on Security and Privacy (SaTML) 2026 / arXiv preprint `arXiv:2505.23643`.  
   - **Verification:** Cited in `docs/RESEARCH_PLAN.md:28` and `output.md:42`. Information-flow benchmark tracking observable data flows.

3. **Palumbo, E., et al.** (2026). *PCAS: Policy Compiler for Agent Systems*.  
   - **Venue/Preprint:** arXiv preprint `arXiv:2602.16708` (February 2026).  
   - **Verification:** Cited in `docs/RESEARCH_PLAN.md:33` and `output.md:43`. Enforces declarative security over agent dependency graphs.

4. **Debenedetti, E., et al.** (2025). *CaMeL: Capability-Based Architectures for Tool-Calling Agents*.  
   - **Venue/Preprint:** arXiv preprint `arXiv:2503.18813` (March 2025).  
   - **Verification:** Cited in `docs/RESEARCH_PLAN.md:37` and `output.md:44`. Explores capability tokens and structural planner/executor separation.

5. **Zhang, X., et al.** (2026). *AgentSentry: Runtime Causal Diagnostics for Autonomous Agents*.  
   - **Venue/Preprint:** arXiv preprint `arXiv:2602.22724` (February 2026).  
   - **Verification:** Cited in `docs/RESEARCH_PLAN.md:41` and `output.md:45`. Employs temporal causal diagnostics and counterfactual re-execution at tool boundaries.

6. **Kim, S., et al.** (2026). *CausalArmor: Leave-One-Out Attribution for Indirect Prompt Injection*.  
   - **Venue/Preprint:** arXiv preprint `arXiv:2602.07918` (February 2026).  
   - **Verification:** Cited in `docs/RESEARCH_PLAN.md:45` and `output.md:46`. Implements input ablation for prompt injection attribution.

---

## 4. Information Not Established by Repository Evidence

In strict compliance with academic integrity guidelines, the following facts are explicitly recognized as **NOT established** by repository evidence and are excluded from all performance claims:

1. **Large-Scale Live Frontier LLM Evaluation:**  
   Phase 5 (`EXP-009`) was interrupted when the local Ollama process exited after scenario `LLM_SC_009`. 31 of 40 core scenarios, all 10 prompt-injection scenarios, and 2 sham controls failed with `ConnectionRefusedError`. Therefore, the repository does not support empirical attribution accuracy claims on live frontier LLMs.
2. **Real-World System Side Effects:**  
   All experimental results (`EXP-001` through `EXP-008`) operate over an in-memory simulated environment (`SandboxedEnvironment`). Real-world external API latency, network failures, and distributed database side effects are not measured.
3. **Institutional and Author Identities:**  
   The repository does not contain university affiliations, course codes, or advisor names. Author information is limited to Git commit authors (`Rahul Jain` and `Dhruv-vm`). No personal academic titles or institutional endorsements are claimed.
4. **Absolute Mathematical Proof of Causality:**  
   As documented in `HANDOFF.md` §1 and `docs/RESEARCH_PLAN.md`, trace divergence under intervention indicates sensitivity under tested conditions, not formal mathematical proof of general causality. Absence of divergence does not prove independence (as demonstrated by coincidental greeting collisions).
