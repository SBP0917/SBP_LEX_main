from __future__ import annotations

from copy import deepcopy
from unittest.mock import patch

import sbp_lex.identity as identity_api
import sbp_lex.identity.durable_boundaries as durable_module
import sbp_lex.identity.impersonation_protection as impersonation_module
from sbp_lex.identity.impersonation_protection import (
    IMPERSONATION_DENY,
    IMPERSONATION_PASS,
)
from sbp_lex.response_controller.runner import run_pipeline
from tests.test_foundational_public_pipeline import (
    _pass_aurion,
    _public_inputs,
    _run_arguments,
)

pytest_plugins = ("tests.test_foundational_public_pipeline",)


def _strings(value: object) -> set[str]:
    if type(value) is str:
        return {value}
    if type(value) is dict:
        return {
            text
            for key, item in value.items()
            for text in (*_strings(key), *_strings(item))
        }
    if isinstance(value, (list, tuple)):
        return {text for item in value for text in _strings(item)}
    return set()


def _signature_material(value: object) -> set[str]:
    if type(value) is dict:
        material = {
            item
            for key, item in value.items()
            if key == "signature_b64" and type(item) is str
        }
        return material | {
            text for item in value.values() for text in _signature_material(item)
        }
    if isinstance(value, (list, tuple)):
        return {text for item in value for text in _signature_material(item)}
    return set()


def _assert_no_possession_proof_material(
    result: dict,
    proof: dict,
) -> None:
    assert "possession_proof" not in result
    result_strings = _strings(result)
    proof_signatures = _signature_material(proof.get("signature"))
    assert proof_signatures
    assert proof_signatures.isdisjoint(result_strings)


def test_identity_package_exposes_only_public_impersonation_api() -> None:
    impersonation_names = set(impersonation_module.__all__)
    durable_names = set(durable_module.__all__)
    public_names = impersonation_names | durable_names
    assert public_names <= set(identity_api.__all__)
    for name in impersonation_names:
        assert getattr(identity_api, name) is getattr(impersonation_module, name)
    for name in durable_names:
        assert getattr(identity_api, name) is getattr(durable_module, name)
    for test_only_name in (
        "_install_test_only_impersonation_deployment_pins",
        "_register_test_only_impersonation_composition_boundary",
        "_reset_test_only_impersonation_composition_boundaries",
    ):
        assert test_only_name not in identity_api.__all__
        assert not hasattr(identity_api, test_only_name)


def test_response_controller_traverses_live_impersonation_and_execution_gate(
    public_fixture,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    with patch(
        "sbp_lex.pipeline.runner.run_aurion15",
        side_effect=_pass_aurion,
    ):
        result = run_pipeline(
            request,
            signals,
            **_run_arguments(public_fixture, possession_proof=proof),
        )

    assert result["impersonation_protection_result"] == IMPERSONATION_PASS
    assert result["impersonation_effect_authority_granted"] is False
    assert (
        result["impersonation_protection_record"]["effect_authority_granted"] is False
    )
    execution_checks = {
        entry["check"]: entry["passed"]
        for entry in result["execution_trace"]
        if type(entry) is dict and "check" in entry
    }
    assert execution_checks["impersonation_protection_current_and_valid"] is True
    assert execution_checks["foundational_request_controls_current_and_valid"] is True
    assert result["effect_result"] == "BLOCKED"
    assert not result.get("effect_permit")
    _assert_no_possession_proof_material(result, proof)


def test_response_controller_missing_possession_proof_fails_closed(
    public_fixture,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    result = run_pipeline(
        request,
        signals,
        **_run_arguments(public_fixture, possession_proof=None),
    )

    assert result["impersonation_protection_result"] == IMPERSONATION_DENY
    assert result["impersonation_effect_authority_granted"] is False
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result.get("effect_result") != "SUCCESS"
    assert not result.get("effect_permit")
    _assert_no_possession_proof_material(result, proof)


def test_response_controller_tampered_possession_proof_fails_closed(
    public_fixture,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    tampered = deepcopy(proof)
    tampered["digest"] = "0" * 128
    result = run_pipeline(
        request,
        signals,
        **_run_arguments(public_fixture, possession_proof=tampered),
    )

    assert result["impersonation_protection_result"] == IMPERSONATION_DENY
    assert result["impersonation_effect_authority_granted"] is False
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result.get("effect_result") != "SUCCESS"
    assert not result.get("effect_permit")
    _assert_no_possession_proof_material(result, tampered)
