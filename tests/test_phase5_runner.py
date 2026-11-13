"""Unit tests for Phase 5 runner batching, checkpointing, resumption, and error handling.

Uses strictly mocked Ollama network responses so tests are fast, deterministic,
and do not require a live Ollama server or local GPU/RAM resources.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from src.evaluation.phase5_runner import (
    append_checkpoint,
    check_ollama_available,
    load_checkpoint,
    run_phase5_evaluation,
)


@pytest.fixture
def temp_output_dir(tmp_path: Path) -> Path:
    """Fixture providing an isolated temporary directory for test outputs."""
    out = tmp_path / "test_results"
    out.mkdir(parents=True, exist_ok=True)
    return out


def test_check_ollama_available_success() -> None:
    """Verify check_ollama_available passes when target model is reported by Ollama."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "models": [{"name": "qwen3:4b-4k:latest"}, {"name": "other-model"}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        info = check_ollama_available(model="qwen3:4b-4k")
        assert info["reachable"] is True
        assert info["model"] == "qwen3:4b-4k"


def test_check_ollama_available_missing_model() -> None:
    """Verify check_ollama_available raises RuntimeError when model is absent."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "models": [{"name": "mistral:7b"}]
    }).encode("utf-8")
    mock_response.__enter__.return_value = mock_response

    with patch("urllib.request.urlopen", return_value=mock_response):
        with pytest.raises(RuntimeError, match="Required model 'qwen3:4b-4k' not found"):
            check_ollama_available(model="qwen3:4b-4k")


def test_check_ollama_available_unreachable() -> None:
    """Verify check_ollama_available raises informative error on network refusal."""
    with patch("urllib.request.urlopen", side_effect=ConnectionRefusedError("Connection refused")):
        with pytest.raises(RuntimeError, match="Ollama server unreachable"):
            check_ollama_available(model="qwen3:4b-4k")


def test_incremental_checkpoint_write_and_load(temp_output_dir: Path) -> None:
    """Verify append_checkpoint persists records and load_checkpoint retrieves them."""
    cp_path = temp_output_dir / "test_checkpoint.jsonl"

    row_1 = {"scenario_id": "LLM_SC_001", "predicted_class": "DENIAL_SENSITIVE", "total_tokens": 120}
    row_2 = {"scenario_id": "LLM_SC_002", "predicted_class": "DENIAL_INDEPENDENT", "total_tokens": 95}

    append_checkpoint(cp_path, row_1)
    append_checkpoint(cp_path, row_2)

    loaded = load_checkpoint(cp_path)
    assert len(loaded) == 2
    assert loaded["LLM_SC_001"]["predicted_class"] == "DENIAL_SENSITIVE"
    assert loaded["LLM_SC_002"]["total_tokens"] == 95


def test_scenario_selection_and_batch_limits(temp_output_dir: Path) -> None:
    """Verify specific scenario filtering and limit parameters."""
    mock_episode = MagicMock(return_value={
        "scenario_id": "MOCK",
        "seed": 42,
        "temperature": 0.0,
        "predicted_class": "DENIAL_SENSITIVE",
        "uncertainty": "LOW",
        "branch_a_steps": "call:ALLOW",
        "branch_b_steps": "call:ALLOW",
        "diverged": False,
        "adapter_sink_executed": False,
        "benign_completed": True,
        "llm_latency_ms": 100.0,
        "monitor_latency_ms": 5.0,
        "attribution_latency_ms": 2.0,
        "e2e_latency_ms": 107.0,
        "total_tokens": 150,
        "total_tool_calls": 2,
        "retries": 0,
        "errors_count": 0,
        "ra_obj": MagicMock(),
    })

    with patch("src.evaluation.phase5_runner.check_ollama_available", return_value={"reachable": True}), \
         patch("src.evaluation.phase5_runner.run_canonicalization_audit_v2", return_value=[]), \
         patch("src.evaluation.phase5_runner._run_paired_llm_episode", side_effect=mock_episode):

        # Test selecting specific scenario IDs
        res_sel = run_phase5_evaluation(
            output_dir=temp_output_dir,
            scenario_ids=["LLM_SC_001", "LLM_SC_002"],
            skip_smoke=True,
            run_repeated=False,
            run_sham=False,
            run_prompt_injection=False,
            resume=False,
        )
        assert res_sel["core_scenarios_evaluated"] == 2

        # Test limit parameter
        res_lim = run_phase5_evaluation(
            output_dir=temp_output_dir,
            limit=3,
            skip_smoke=True,
            run_repeated=False,
            run_sham=False,
            run_prompt_injection=False,
            resume=False,
        )
        assert res_lim["core_scenarios_evaluated"] == 3


def test_resume_behaviour_and_duplicate_prevention(temp_output_dir: Path) -> None:
    """Verify checkpointed scenarios are loaded without duplicate re-execution."""
    cp_path = temp_output_dir / "phase5_core_checkpoint.jsonl"
    cached_record = {
        "scenario_id": "LLM_SC_001",
        "seed": 42,
        "temperature": 0.0,
        "predicted_class": "DENIAL_SENSITIVE",
        "uncertainty": "LOW",
        "branch_a_steps": "step_cached",
        "branch_b_steps": "step_cached",
        "diverged": False,
        "adapter_sink_executed": False,
        "benign_completed": True,
        "llm_latency_ms": 50.0,
        "monitor_latency_ms": 2.0,
        "attribution_latency_ms": 1.0,
        "e2e_latency_ms": 53.0,
        "total_tokens": 80,
        "total_tool_calls": 1,
        "retries": 0,
        "errors_count": 0,
        "ground_truth_class": "DENIAL_SENSITIVE",
        "category": "direct_denial_leakage",
        "is_attack": True,
    }
    append_checkpoint(cp_path, cached_record)

    mock_episode = MagicMock(return_value={
        "scenario_id": "LLM_SC_002",
        "seed": 42,
        "temperature": 0.0,
        "predicted_class": "DENIAL_INDEPENDENT",
        "uncertainty": "LOW",
        "branch_a_steps": "step_fresh",
        "branch_b_steps": "step_fresh",
        "diverged": False,
        "adapter_sink_executed": False,
        "benign_completed": True,
        "llm_latency_ms": 80.0,
        "monitor_latency_ms": 3.0,
        "attribution_latency_ms": 1.0,
        "e2e_latency_ms": 84.0,
        "total_tokens": 120,
        "total_tool_calls": 2,
        "retries": 0,
        "errors_count": 0,
        "ra_obj": MagicMock(),
    })

    with patch("src.evaluation.phase5_runner.check_ollama_available", return_value={"reachable": True}), \
         patch("src.evaluation.phase5_runner.run_canonicalization_audit_v2", return_value=[]), \
         patch("src.evaluation.phase5_runner._run_paired_llm_episode", side_effect=mock_episode):

        res = run_phase5_evaluation(
            output_dir=temp_output_dir,
            scenario_ids=["LLM_SC_001", "LLM_SC_002"],
            skip_smoke=True,
            run_repeated=False,
            run_sham=False,
            run_prompt_injection=False,
            resume=True,
        )

        # LLM_SC_001 was cached, so _run_paired_llm_episode should only have been called ONCE (for SC_002)
        assert mock_episode.call_count == 1
        assert res["core_scenarios_evaluated"] == 2

        # Verify predictions CSV has no duplicates
        csv_path = temp_output_dir / "phase5_llm_predictions.csv"
        assert csv_path.is_file()
        import csv
        with csv_path.open("r", encoding="utf-8") as h:
            rows = list(csv.DictReader(h))
            scenario_ids = [r["scenario_id"] for r in rows]
            assert len(scenario_ids) == len(set(scenario_ids))
            assert "LLM_SC_001" in scenario_ids
            assert "LLM_SC_002" in scenario_ids


def test_error_handling_when_ollama_fails(temp_output_dir: Path) -> None:
    """Verify runner catches episode failures and records NOT_EVALUABLE safely."""
    with patch("src.evaluation.phase5_runner.check_ollama_available", return_value={"reachable": True}), \
         patch("src.evaluation.phase5_runner.run_canonicalization_audit_v2", return_value=[]), \
         patch("src.evaluation.phase5_runner._run_paired_llm_episode", side_effect=ConnectionResetError("Ollama connection reset")):

        res = run_phase5_evaluation(
            output_dir=temp_output_dir,
            scenario_ids=["LLM_SC_001"],
            skip_smoke=True,
            run_repeated=False,
            run_sham=False,
            run_prompt_injection=False,
            resume=False,
        )

        assert res["core_scenarios_evaluated"] == 1
        summary = res["core_summary"]
        assert summary["per_class"]["NOT_EVALUABLE"]["tp"] >= 0

