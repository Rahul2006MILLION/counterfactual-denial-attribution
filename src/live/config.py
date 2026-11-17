"""Runtime settings for the live agent, read from environment variables.

These settings belong to the live application only. They do not affect the research
adapter (src/agent/agent.py), whose parameters stay pinned by the M3.0 tests.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    ollama_url: str = field(default_factory=lambda: os.environ.get("CDA_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/"))
    # Empty means "auto-detect a local Qwen model".
    ollama_model: str = field(default_factory=lambda: os.environ.get("CDA_OLLAMA_MODEL", "").strip())
    num_ctx: int = field(default_factory=lambda: _int("CDA_OLLAMA_NUM_CTX", 8192))
    num_predict: int = field(default_factory=lambda: _int("CDA_OLLAMA_NUM_PREDICT", 1024))
    temperature: float = field(default_factory=lambda: _float("CDA_OLLAMA_TEMPERATURE", 0.1))
    request_timeout: float = field(default_factory=lambda: _float("CDA_OLLAMA_TIMEOUT", 300.0))
    workspace: Path = field(
        default_factory=lambda: Path(os.environ.get("CDA_LIVE_WORKSPACE", str(REPO_ROOT / ".live_workspace"))).resolve()
    )
    max_upload_bytes: int = field(default_factory=lambda: _int("CDA_MAX_UPLOAD_MB", 10) * 1024 * 1024)
    max_files_per_task: int = field(default_factory=lambda: _int("CDA_MAX_FILES_PER_TASK", 5))
    # Characters of document text sent to the model per request (fits num_ctx with room
    # for instructions and the answer).
    chunk_chars: int = field(default_factory=lambda: _int("CDA_CHUNK_CHARS", 6000))
    max_chunks: int = field(default_factory=lambda: _int("CDA_MAX_CHUNKS", 8))
    max_plan_steps: int = field(default_factory=lambda: _int("CDA_MAX_PLAN_STEPS", 4))
    approval_timeout: float = field(default_factory=lambda: _float("CDA_APPROVAL_TIMEOUT", 600.0))


# Preference order when no model is configured. Smaller first: optimised for limited RAM.
PREFERRED_MODELS: tuple[str, ...] = (
    "qwen3:4b-4k",
    "qwen3:4b",
    "qwen2.5:3b-instruct",
    "qwen2.5:3b",
)


def get_settings() -> Settings:
    return Settings()
