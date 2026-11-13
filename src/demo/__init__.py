"""Interactive terminal demonstration of the existing backend (additive, not research code).

Launch with ``uv run python -m src.demo``.

The demo reuses the real ``ReactivePolicyAgent``, ``AgentExecutor.run_branch``,
``ARMMonitor``, ``SandboxedEnvironment``, ``AgentMemory`` and hash-chained
``ActionAuditRecord`` log. It does not decide anything itself: every displayed
security decision, layer, rule, category and execution status is read from the audit
records that ``run_branch`` produced.

Scope and honesty notes:
- The agent is a deterministic scripted agent driven by a fixed-pattern task
  interpreter (``src.demo.interpreter``). It is not an LLM and does not understand
  free-form language.
- It runs the historical v1 executor path with a historical ``FeedbackCondition``
  (``ACTUAL`` or ``NEUTRALIZED``). It does not implement the C0/C1/C2 protocol and
  does not perform causal attribution.
- The environment is an in-memory synthetic sandbox; no real files, network or
  email are touched.
"""
