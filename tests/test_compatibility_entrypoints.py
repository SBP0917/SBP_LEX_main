from __future__ import annotations

from unittest.mock import patch

from sbp_lex.execution.engine import ExecutionEngine
from sbp_lex.response_controller.runner import run_pipeline


def test_execution_engine_forwards_all_mandatory_dependencies() -> None:
    dependencies = {
        "signature_provider": object(),
        "three_p_attestation_provider": object(),
        "skg_evaluator": object(),
        "skg_attestation_provider": object(),
        "filed_framework_evaluator": object(),
        "filed_framework_attestation_provider": object(),
        "filed_licence_evaluator": object(),
        "filed_licence_attestation_provider": object(),
        "filed_lifecycle_evaluator": object(),
        "filed_lifecycle_attestation_provider": object(),
        "filed_governance_integrity_evaluator": object(),
        "filed_governance_integrity_attestation_provider": object(),
    }
    engine = ExecutionEngine(**dependencies)
    state = {"request": "one"}

    with patch(
        "sbp_lex.execution.engine.run_execution_gate",
        return_value=state,
    ) as gate:
        assert engine.execute(state) is state

    gate.assert_called_once_with(state, **dependencies)


def test_response_controller_routes_only_through_complete_v2_pipeline() -> None:
    request = {"action": "review"}
    signals = {"intent_signal": "review"}
    dependencies = {
        "signature_provider": object(),
        "three_p_evaluator": object(),
        "three_p_attestation_provider": object(),
        "skg_evaluator": object(),
        "skg_attestation_provider": object(),
        "filed_framework_evaluator": object(),
        "filed_framework_attestation_provider": object(),
        "filed_licence_evaluator": object(),
        "filed_licence_attestation_provider": object(),
        "filed_lifecycle_evaluator": object(),
        "filed_lifecycle_attestation_provider": object(),
        "effect_adapter": object(),
        "effect_permit_ttl_ms": 500,
    }
    expected = {"decision": "DENY"}

    with patch(
        "sbp_lex.response_controller.runner.run_v2",
        return_value=expected,
    ) as full_pipeline:
        assert run_pipeline(request, signals, **dependencies) is expected

    full_pipeline.assert_called_once_with(request, signals, **dependencies)
