from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sbp_lex.aurion15.core.inventory import (
    CognitiveInventoryError,
    build_cognitive_engine_inventory,
    validate_cognitive_engine_inventory,
)
from sbp_lex.aurion15.runtime.registry import ENGINE_REGISTRY, register
from sbp_lex.classification.router import evaluate_ap_acf_profile
from sbp_lex.config.thresholds import (
    LOW_TIER,
    MEDIUM_TIER,
    TOP_TIER,
    clamp_factor,
    compute_financial_operational_factor,
    get_corroboration_required,
)
from sbp_lex.shared.types import EngineResult
from sbp_lex.shared.state_schema import STATE_TEMPLATE


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _classification_state() -> dict[str, object]:
    return {
        "ap_acf_class": "CLASS_2",
        "ap_acf_subclass": "CLASS_2",
        "requested_autonomy_level": 20,
        "autonomy_ceiling": 30,
        "operational_environment": "controlled",
        "public_exposure": "limited",
        "operational_scope": "local",
        "environment_modifiers": {
            "human_proximity": "controlled",
            "geographic_isolation": "not-applicable",
            "operational_containment": "verified",
        },
    }


def test_engine_result_uses_independent_default_data() -> None:
    first = EngineResult(True, "first")
    second = EngineResult(True, "second")
    first.data["changed"] = True

    assert second.data == {}
    assert first.to_dict()["data"] == {"changed": True}


def test_runtime_registry_preserves_registered_function_contract() -> None:
    registry_key = "static_correctness_fixture"

    @register(registry_key)
    def fixture_engine(payload: dict[str, object]) -> EngineResult:
        return EngineResult(True, registry_key, data=payload)

    try:
        assert ENGINE_REGISTRY[registry_key] is fixture_engine
        assert fixture_engine({"input": "retained"}).data == {
            "input": "retained"
        }
    finally:
        ENGINE_REGISTRY.pop(registry_key)


def test_state_template_remains_a_string_keyed_runtime_mapping() -> None:
    assert STATE_TEMPLATE["context"] is None
    assert STATE_TEMPLATE["filed_governance_integrity_bypass_permitted"] is False


def test_threshold_boundaries_and_fail_closed_defaults_are_numeric() -> None:
    assert clamp_factor(None) == 0
    assert compute_financial_operational_factor(499.99) == 1
    assert compute_financial_operational_factor(500) == 2
    assert compute_financial_operational_factor(50_000) == 3
    assert get_corroboration_required(LOW_TIER) == 2
    assert get_corroboration_required(MEDIUM_TIER) == 3
    assert get_corroboration_required(TOP_TIER) == 5
    assert get_corroboration_required("UNKNOWN") == 5


def test_classification_rejects_non_string_class_identifier() -> None:
    state = _classification_state()
    state["ap_acf_class"] = None

    assert evaluate_ap_acf_profile(state) == (False, "ap_acf_class_unknown")


def test_cognitive_inventory_wrong_layer_type_raises_contract_error() -> None:
    candidate = build_cognitive_engine_inventory()
    candidate["layers"] = None

    with pytest.raises(
        CognitiveInventoryError,
        match="COGNITIVE_LAYER_SET_INVALID",
    ):
        validate_cognitive_engine_inventory(candidate)


def test_fixed_wire_v1_transport_bytes_are_current() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(_REPOSITORY_ROOT / "wire_protocol" / "verify_fixed_transport.py"),
        ],
        cwd=_REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr or completed.stdout
    result = json.loads(completed.stdout)
    assert result["schema"] == "SBP_LEX_FIXED_TRANSPORT_V1_VERIFICATION"
    assert result["status"] == "PASS_NON_AUTHORIZING_TRANSPORT_BYTES_ONLY"
    assert set(result["files"]) == {
        "SPEC.md",
        "rust/Cargo.toml",
        "rust/src/lib.rs",
        "vectors/adversarial_cases.txt",
        "vectors/golden_transcript.jsonl",
    }
