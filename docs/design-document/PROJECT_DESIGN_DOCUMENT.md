# Counterfactual Denial Attribution in Tool-Using LLM Agents
**A Controlled Counterfactual Framework for Disentangling Denial-Feedback Side-Channels from Legitimate Agent Actions**

---

## SECTION A: PROBLEM STATEMENT

Tool-calling Large Language Model (LLM) agents autonomously interact with private files, enterprise databases, and external APIs by requesting tool invocations. Runtime reference monitors intercept these requests at the execution boundary to allow or deny actions under security policies. However, denying an unauthorized tool call does not terminate the information channel: an agent observes the denial outcome and associated feedback messages, enabling it to infer protected internal states (e.g., resource existence, directory structures, or policy rules) and subsequently exfiltrate this inferred knowledge through subsequent, seemingly innocuous tool calls. This covert side-channel vulnerability is formalized as **causality laundering** (Chinaei, 2026).

Existing defenses rely on the Agentic Reference Monitor (ARM) baseline, which inserts `DeniedAction` nodes into a runtime provenance graph and connects them to subsequent calls using conservative temporal-adjacency heuristics (`COUNTERFACTUAL` edges). This heuristic introduces critical trade-offs:
1. **Severe Over-Approximation (False Positives):** ARM's `IMMEDIATE_NEXT` strategy assumes any tool call immediately following a denial is tainted, dropping benign task completion from 100.0% to 14.3% with an action false positive rate of 86.4% (`EXP-002`).
2. **Under-Approximation on Coordinated Leakage:** Heuristic lexical filtering (`SINK_SCOPED`) eliminates benign false positives but fails against paraphrased, transformed, delayed, or multi-step laundering, leaving an attack success rate of 75.0% to 100.0%.
3. **The Core Engineering Gap:** Enterprise AI systems lack a principled, causal attribution mechanism capable of distinguishing legitimate post-denial actions from genuine denial-induced information leakage without crippling agent operational utility.

---

## SECTION B: RESEARCH REVIEW

The theoretical foundation of this project is established by **Mohammad Hossein Chinaei (April 2026, arXiv:2604.04035)**, who introduced the *causality laundering* threat model and the **Agentic Reference Monitor (ARM)**. ARM formalizes runtime security for tool-calling agents via a 5-level integrity lattice ($\text{ToolDesc} < \text{ToolUntrusted} < \text{ToolTrusted} < \text{UserInput} < \text{SysInstr}$), a 4-layer deterministic policy pipeline (`L1` Hard Boundaries, `L2G` Graph-Aware Provenance, `L3` Schema Constraints, `L4` Manual Policies), and SHA-256 hash-chained audit logging. However, Chinaei acknowledged key structural limitations: ARM's temporal-adjacency heuristic cannot differentiate accidental proximity from true causal dependence, lacks large-scale false-positive benchmarks, and was evaluated on only three manual attack traces.

Related research in agent security addresses adjacent aspects of the problem:
- **Information-Flow Control:** *FIDES* (Costa et al., IEEE SaTML 2026, arXiv:2505.23643) and *PCAS* (Palumbo et al., 2026, arXiv:2602.16708) compile declarative policies over observable data dependencies. While effective against direct flow leakage, they fail to track implicit knowledge acquired through negative outcomes (denials).
- **Architectural Isolation:** *CaMeL* (Debenedetti et al., 2025, arXiv:2503.18813) enforces capability-based planner/executor separation. However, if the planning model observes rich denial feedback, structural separation alone does not prevent inference laundering.
- **Causal Diagnostics & Input Ablation:** *AgentSentry* (Zhang et al., 2026, arXiv:2602.22724) and *CausalArmor* (Kim et al., 2026, arXiv:2602.07918) investigate runtime re-execution and leave-one-out input ablation for indirect prompt injection. However, neither addresses runtime denial mediation or the multi-step information channels created by security monitors.

**Research Gap:** No prior framework isolates the causal influence of runtime denial signals via controlled counterfactual interventions across structured feedback conditions.

---

## SECTION C: METHODOLOGY

To overcome heuristic over-approximation, this project establishes a controlled, counterfactual attribution framework that separates denial influence from correlation:

1. **Paired-Execution Counterfactual Intervention:**
   Every monitored agent episode runs in isolated, dual sandboxes under identical tasks, seeds, initial states, and permissions:
   - **Branch A (Observed Execution):** Receives informative or actual denial feedback ($c_A$).
   - **Branch B (Counterfactual Control):** Receives neutralized or outcome-obscured feedback ($c_B$).
   The framework defines a nested condition spectrum: **C0** (Outcome-Obscured: indistinguishable from normal missing resources), **C1** (Generic Denial: reveals the denial event without a reason), and **C2** (Informative Denial: coarse, non-sensitive explanation from versioned catalogue `cda-c2-reasons-v1`).
2. **Canonical Lineage Resolution (`canonical.py`):**
   Eliminates synthetic divergence artifacts by mapping runtime IDs to canonical logical sources ($\text{logical}::\text{tool}(\text{args})$) verified against SHA-256 content digests and lattice trust, resolving equivalent operations executed across branches.
3. **Multi-Evidence Attribution Engine (`evidence_model.py`):**
   A keyword-free evidence model evaluates four distinct classes:
   - `DENIAL_SENSITIVE`: Downstream action omitted or divergent under feedback neutralization, exhibiting sink/transformation sensitivity.
   - `DENIAL_INDEPENDENT`: Action and canonical provenance remain invariant across branches, or derive from independent trusted sources.
   - `AMBIGUOUS`: Divergence cannot be separated from stochastic variation or non-separable multi-denial interactions.
   - `NOT_EVALUABLE`: Replay preconditions failed (e.g., mismatched permissions, missing branch, or execution abort).
4. **Empirical Validation Evidence:**
   - **Phase 4.3 Independent Benchmark (`n=104`, seed 43127):** Across 104 opaque-ID scenarios, the model achieved **96.15% 4-class overall accuracy** (100/104, 95% Wilson CI [0.9053, 0.9849]), Macro-F1 of **0.9575**, **0.000 false attribution rate (FAR)** on independent actions, and **94.12% selective accuracy** at 65.38% coverage.
   - **10-Way Ablation Study:** Demonstrated that removing canonical identity drops accuracy to 71.15% (FAR 81.25%), and removing alternative explanation modeling drops accuracy to 80.77%.
   - **Multi-Policy Evaluation:** Successfully verified across 6 distinct agent policies (`ReactivePolicyAgent`, `ConservativeStoppingAgent`, `IndependentRecoveryAgent`, `DenialInsensitiveAgent`, `MemoryMediatedAgent`, `SourcePrioritizationAgent`).
   - **Integrity Baseline:** Regression safety nets (M0 and M3.0) enforce 47 frozen artifact checksums and 104 golden tests pinning byte-level model request bodies.
   - *Status of Live LLMs:* A local live agent application (`src/live/`) is operational with `qwen3:4b-4k`; full benchmark evaluation (Phase 5) is partially implemented (8/40 executed; remaining uncompleted due to daemon restart).

---

## SECTION D: SOLUTION FRAMEWORK

The framework operates as a modular, non-bypassable runtime mediation and attribution architecture:

```
+---------------------------------------------------------------------------------------------------------+
|                                    SOLUTION ARCHITECTURE & WORKFLOW                                      |
+---------------------------------------------------------------------------------------------------------+
|                                                                                                         |
|   +------------------------------------+             +----------------------------------------------+   |
|   |         AgentTask & State          |             |            Sandboxed Environment             |   |
|   |   (Identical Seeds / Capability)   |             |       (get_time, search, read, calc,         |   |
|   +-----------------+------------------+             |         transform, email, export)            |   |
|                     |                                +----------------------+-----------------------+   |
|                     v                                                       ^                           |
|   +-----------------+------------------+                                    |                           |
|   |           Agent Policy             |                                    | (ALLOW)                   |
|   |  (Reactive / Ollama Live Adapter)  |                                    |                           |
|   +-----------------+------------------+                                    |                           |
|                     | ProposedAction                                        |                           |
|                     v                                                       |                           |
|   +-----------------+-------------------------------------------------------+-----------------------+   |
|   |                                       ARMMonitor Core                                           |   |
|   |  L1: Hard Boundaries  |  L2G: Graph Lattice Trust  |  L3: Schema Constraints  |  L4: Tool Policy  |   |
|   |  Result Mediation     |  Concealing Namespace      |  Hash-Chained Action Audit Logging (M1)    |   |
|   +-----------------+-------------------------------------------------------+-----------------------+   |
|                     |                                                       |                           |
|                     | (DENY)                                                |                           |
|                     v                                                       |                           |
|   +-----------------+------------------+                                    |                           |
|   |     DenialInterventionEngine       |                                    |                           |
|   |  C0: Obscured | C1: Generic Denial |                                    |                           |
|   |  C2: Coarse Reason (Reason Catalog)|                                    |                           |
|   +-----------------+------------------+                                    |                           |
|                     |                                                       |                           |
|                     v Rendered Feedback                                     v Provenance Updates        |
|   +-----------------+-------------------------------------------------------+-----------------------+   |
|   |                       Provenance Graph & Hash-Chained Audit Trail                               |   |
|   |  Call / Data / DeniedAction Nodes | DirectOutput / InputTo / Counterfactual Edges               |   |
|   +------------------------------------+------------------------------------------------------------+   |
|                                        |                                                                |
|                                        v Paired Traces (Branch A & Branch B)                            |
|   +------------------------------------+------------------------------------------------------------+   |
|   |                    Canonical Source Resolver & Evidence-Based Attributor                        |   |
|   |   Canonical Identity Mapping  -->  Divergence Analysis  -->  Multi-Evidence Decision Engine     |   |
|   |                                                                                                 |   |
|   |   Verdicts: [DENIAL_SENSITIVE]  |  [DENIAL_INDEPENDENT]  |  [AMBIGUOUS]  |  [NOT_EVALUABLE]     |   |
|   +------------------------------------+------------------------------------------------------------+   |
|                                        |                                                                |
|                                        v Attribution Policy Enforcement (Adaptive Gating)               |
|   +------------------------------------+------------------------------------------------------------+   |
|   |   AttributionPolicyAdapter: Gated execution of privileged sinks without blocking benign actions  |   |
|   +-------------------------------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------------------------------+
```

### Core Components & Responsibilities
1. **Reference Monitor & Audit Pipeline (`src/monitor/`):**
   - `arm_baseline.py` (`ARMMonitor`): Evaluates 4 sequential policy layers (`L1` regex/path patterns, `L2G` minimum trust propagation over a 5-level lattice, `L3` Pydantic argument schemas, and `L4` capability permissions). Interposes on search/read results in concealing namespaces (`resources.py`) to prevent existence leaks.
   - `audit.py` & `models.py` (M1): Emits an immutable, SHA-256 hash-chained `ActionAuditRecord` for every proposed action, strictly separating `authorization` (`ALLOW`/`DENY`) from `execution_status` (`EXECUTED`/`NOT_EXECUTED_DENIED`/`TOOL_ERROR`).
2. **Intervention & Attribution Engine (`src/attribution/`):**
   - `intervention.py`: Translates raw security denials into experimental conditions (`C0`, `C1`, `C2` or `NEUTRALIZED`).
   - `canonical.py`: Resolves synthetic branch identifiers to unified logical sources via canonical argument matching and content hashes.
   - `evidence_model.py` (`EvidenceBasedAttributor`): Synthesizes trace divergence, logical source equivalence, and counter-evidence to produce robust attribution classifications and structured `EvidenceExplanation` audit objects.
3. **Agent Sandbox & Interactive Service (`src/agent/`, `src/live/`):**
   - `executor.py` & `environment.py`: Orchestrates dual branch executions in an isolated, in-memory tool sandbox.
   - `src/live/`: Provides an end-to-end interactive application using local Ollama models (`qwen3:4b-4k`), streaming execution traces via FastAPI SSE to a presentation frontend.

---

## REFERENCES
1. **M. H. Chinaei**, *"Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents,"* arXiv:2604.04035 [cs.CR], Apr. 2026.
2. **P. Costa et al.**, *"FIDES: Information-Flow Control for LLM Agents,"* in *IEEE SaTML*, 2026. [arXiv:2505.23643]
3. **E. Palumbo et al.**, *"PCAS: Policy Compiler for Agent Systems,"* arXiv:2602.16708, Feb. 2026.
4. **E. Debenedetti et al.**, *"CaMeL: Capability-Based Architectures for Tool-Calling Agents,"* arXiv:2503.18813, Mar. 2025.
5. **X. Zhang et al.**, *"AgentSentry: Runtime Causal Diagnostics for Autonomous Agents,"* arXiv:2602.22724, Feb. 2026.
6. **S. Kim et al.**, *"CausalArmor: Leave-One-Out Attribution for Indirect Prompt Injection,"* arXiv:2602.07918, Feb. 2026.
