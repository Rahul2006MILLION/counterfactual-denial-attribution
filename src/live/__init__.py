"""Live, locally running AI agent (Ollama) for the Counterfactual Denial Attribution project.

This package is an application layer built on top of the research backend. It reuses the
existing ARMMonitor (unchanged) as the authoritative policy engine and the existing
hash-chained AuditLog. It does not change any research code, historical results,
configurations, fixtures or the research model parameters.

Pipeline for every task:
  uploaded files -> validation -> extraction -> Ollama plans structured tool calls
  -> live policy pre-check -> ARMMonitor (L1/L2G/L3/L4) -> human approval if required
  -> allowlisted tool executes in the task workspace -> verification -> final answer.

Start the server:  uv run uvicorn src.live.api:app --port 8000
"""
