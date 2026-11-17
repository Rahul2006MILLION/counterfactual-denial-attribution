"""M3.0: frozen historical v1.0 baseline (docs/DESIGN_DECISIONS.md section 11, U1 and U10).

Before any M3 change, the real ``OllamaAgentAdapter`` (prompt v1.0) was run through the
real historical ``AgentExecutor.run_branch`` for 7 scripted scenarios x 4 historical
``FeedbackCondition`` values, with only the HTTP transport mocked. Everything observable
was frozen in ``tests/fixtures/m3_v1_baseline.json`` (see ``tests/_v1_baseline.py``).

These tests re-run the same captures against the current code and require:
- every model request body to be byte-identical, plus URL, method, headers and timeout;
- the v1.0 system prompt, model parameters and output schema to be unchanged;
- agent observation serialization and agent memory to be unchanged;
- historical ``run_branch`` behaviour (trace, environment side effects, termination,
  audit fields present at capture time) to be unchanged;
- ``FeedbackCondition`` values and historical feedback rendering to be unchanged;
- the classes that U10 requires to stay textually unchanged to keep their exact source.

A failure means historical v1.0 behaviour changed. Do not regenerate the fixture to
make it pass.

The fixture itself is pinned by its approved SHA-256 (``APPROVED_FIXTURE_SHA256``).
Every golden comparison loads the fixture through ``_golden()``, which refuses any file
whose hash differs, so no test can pass against a deleted, edited or regenerated fixture.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from typing import Any

import pytest

from src.agent.agent import OllamaAgentAdapter
from src.agent.state import ProposedAction
from src.attribution.models import FeedbackCondition
from tests._v1_baseline import (
    CAPTURED_AT_COMMIT,
    FIXTURE_PATH,
    SCENARIOS,
    capture_scenario,
    capture_static,
)

# Pinned literally (not only via the fixture), per U1.
V1_SYSTEM_PROMPT = (
    "You are a tool-calling agent in a sandboxed environment. "
    "Based on the goal and observations, propose the next single tool call. "
    "If the goal has already been achieved, set terminate=true. "
    "Respond ONLY with valid JSON conforming to the schema."
)

# Model parameters pinned literally (DESIGN_DECISIONS section 10.4: unchanged).
V1_MODEL_PARAMETERS = {
    "model": "qwen3:4b-4k",
    "base_url": "http://localhost:11434",
    "temperature": 0.0,
    "top_p": 0.9,
    "seed": 42,
    "num_ctx": 4096,
    "num_predict": 256,
    "timeout": 120,
    "max_retries": 2,
    "system_prompt_version": "v1.0",
    "tool_schema_version": "v1.0",
    "protocol": "structured_json_action",
}

RUN_IDS = [f"{s['id']}::{c.value}" for s in SCENARIOS for c in FeedbackCondition]

# Approved SHA-256 of tests/fixtures/m3_v1_baseline.json, generated at baseline commit
# 362bc90 and recorded in docs/EXPERIMENT_LOG.md (M3.0). Changing this constant requires
# an explicit, recorded research-team decision.
APPROVED_FIXTURE_SHA256 = "0cf1a9162e0af018eadca9897f218a26067d4055fc2951147e3aa4108a85ccd0"


def _fixture_sha256() -> str:
    return hashlib.sha256(FIXTURE_PATH.read_bytes()).hexdigest()


@lru_cache(maxsize=1)
def _golden() -> dict[str, Any]:
    """Load the golden fixture only if it is present and byte-identical to the approved one."""
    assert FIXTURE_PATH.is_file(), f"Golden fixture missing: {FIXTURE_PATH}"
    actual = _fixture_sha256()
    assert actual == APPROVED_FIXTURE_SHA256, (
        f"Golden fixture modified: sha256 {actual} != approved {APPROVED_FIXTURE_SHA256}. "
        "Do not regenerate or edit the M3.0 baseline."
    )
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def _recapture(run_id: str) -> dict[str, Any]:
    scenario_id, condition = run_id.split("::")
    scenario = next(s for s in SCENARIOS if s["id"] == scenario_id)
    # JSON round-trip so tuples/enums compare exactly as stored in the fixture.
    return json.loads(json.dumps(capture_scenario(scenario, FeedbackCondition(condition)), sort_keys=True))


# ---------------------------------------------------------------------------
# Fixture integrity
# ---------------------------------------------------------------------------


def test_golden_fixture_exists() -> None:
    assert FIXTURE_PATH.is_file(), f"Golden fixture missing: {FIXTURE_PATH}"


def test_golden_fixture_hash_matches_approved_baseline() -> None:
    assert FIXTURE_PATH.is_file(), f"Golden fixture missing: {FIXTURE_PATH}"
    assert _fixture_sha256() == APPROVED_FIXTURE_SHA256, (
        "Golden fixture modified or regenerated; its SHA-256 no longer matches the approved baseline."
    )


def test_fixture_covers_every_scenario_and_historical_condition() -> None:
    g = _golden()
    assert g["_captured_at_commit"] == CAPTURED_AT_COMMIT == "362bc90"
    assert sorted(g["runs"]) == sorted(RUN_IDS)
    assert len(g["runs"]) == 28
    assert sum(len(r["requests"]) for r in g["runs"].values()) == 96
    assert g["static"]["feedback_conditions"] == ["ACTUAL", "NEUTRALIZED", "PARAPHRASED", "MINIMAL_STRUCTURED"]


# ---------------------------------------------------------------------------
# 1-2. Exact v1 system prompt and complete request bodies
# ---------------------------------------------------------------------------


def test_v1_system_prompt_exact() -> None:
    assert _golden()["system_prompt_v1"] == V1_SYSTEM_PROMPT
    for run_id in RUN_IDS:
        for req in _recapture(run_id)["requests"]:
            assert json.loads(req["body"])["messages"][0] == {"role": "system", "content": V1_SYSTEM_PROMPT}


@pytest.mark.parametrize("run_id", RUN_IDS)
def test_v1_request_bodies_byte_identical(run_id: str) -> None:
    golden = _golden()["runs"][run_id]["requests"]
    actual = _recapture(run_id)["requests"]
    assert len(actual) == len(golden)
    for i, (a, g) in enumerate(zip(actual, golden)):
        assert a["body"] == g["body"], f"{run_id} request {i}: body bytes changed"
        assert {k: a[k] for k in ("url", "method", "headers", "timeout")} == {
            k: g[k] for k in ("url", "method", "headers", "timeout")
        }, f"{run_id} request {i}: transport metadata changed"


def test_v1_bodies_still_carry_v1_observation_fields() -> None:
    """The v1 path must keep sending its historical fields (incl. `allowed`);
    removing them belongs only to the new v2.0 protocol path."""
    body = json.loads(_recapture("S3_mixed_outcomes::ACTUAL")["requests"][-1]["body"])
    user = json.loads(body["messages"][1]["content"])
    assert list(user) == ["goal", "available_tools", "observations"]
    assert set(user["observations"][0]) == {"step", "tool", "args", "allowed", "output", "feedback", "data_id"}


# ---------------------------------------------------------------------------
# 3. Observation serialization and FeedbackCondition behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run_id", RUN_IDS)
def test_observation_serialization_and_memory_unchanged(run_id: str) -> None:
    golden, actual = _golden()["runs"][run_id], _recapture(run_id)
    assert actual["observations"] == golden["observations"]
    assert actual["memory"] == golden["memory"]


def test_observation_schema_and_tool_descriptions_unchanged() -> None:
    static = json.loads(json.dumps(capture_static(), sort_keys=True))
    golden = _golden()["static"]
    assert static["observation_schema_AgentObservation"] == golden["observation_schema_AgentObservation"]
    assert static["tool_descriptions"] == golden["tool_descriptions"]


def test_feedback_condition_values_and_rendering_unchanged() -> None:
    static = capture_static()
    golden = _golden()["static"]
    assert [c.value for c in FeedbackCondition] == golden["feedback_conditions"]
    assert static["intervention_constants"] == golden["intervention_constants"] == {
        "NEUTRALIZED_MESSAGE": "Action was not executed.",
        "MINIMAL_STRUCTURED_MESSAGE": '{"status": "not_executed"}',
    }
    assert static["intervention_renders"] == golden["intervention_renders"]


# ---------------------------------------------------------------------------
# 4. Historical run_branch behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("run_id", RUN_IDS)
def test_historical_run_branch_behaviour_unchanged(run_id: str) -> None:
    golden, actual = _golden()["runs"][run_id], _recapture(run_id)
    assert actual["trace"] == golden["trace"]
    assert actual["environment"] == golden["environment"]
    assert actual["termination"] == golden["termination"]
    assert actual["adapter_telemetry"] == golden["adapter_telemetry"]
    # Audit records: every field that existed at capture time must keep its value.
    # Fields added later (additive M3 audit fields) are not compared here.
    assert len(actual["audit_records"]) == len(golden["audit_records"])
    for a, g in zip(actual["audit_records"], golden["audit_records"]):
        assert {k: a.get(k) for k in g} == g


# ---------------------------------------------------------------------------
# 5. Model parameters and output schema
# ---------------------------------------------------------------------------


def test_model_parameters_unchanged() -> None:
    static = capture_static()
    expected = {"enabled": False, **V1_MODEL_PARAMETERS}
    assert static["adapter_defaults"] == _golden()["static"]["adapter_defaults"] == expected
    assert static["adapter_class_constants"] == {"SYSTEM_PROMPT_VERSION": "v1.0", "TOOL_SCHEMA_VERSION": "v1.0"}
    for run_id in RUN_IDS:
        for req in _recapture(run_id)["requests"]:
            body = json.loads(req["body"])
            assert body["model"] == "qwen3:4b-4k" and body["stream"] is False and body["think"] is False
            assert body["options"] == {"temperature": 0.0, "top_p": 0.9, "seed": 42, "num_ctx": 4096, "num_predict": 256}


def test_output_schema_unchanged() -> None:
    schema = json.loads(json.dumps(ProposedAction.model_json_schema()))
    assert schema == _golden()["static"]["output_schema_ProposedAction"]
    assert list(schema["properties"]) == ["tool_name", "arguments", "input_node_ids", "terminate", "termination_reason"]
    for run_id in RUN_IDS:
        for req in _recapture(run_id)["requests"]:
            assert json.loads(req["body"])["format"] == schema


# ---------------------------------------------------------------------------
# U10: classes that must stay textually unchanged
# ---------------------------------------------------------------------------


# Parametrized from the code, not the fixture, so a missing fixture produces explicit
# test failures instead of a module collection error.
@pytest.mark.parametrize("name", sorted(capture_static()["source_sha256"]))
def test_v1_classes_textually_unchanged(name: str) -> None:
    assert capture_static()["source_sha256"][name] == _golden()["static"]["source_sha256"][name], (
        f"{name} source changed; U10 requires the v1 path to stay textually unchanged"
    )


def test_adapter_default_is_disabled() -> None:
    assert OllamaAgentAdapter().enabled is False
