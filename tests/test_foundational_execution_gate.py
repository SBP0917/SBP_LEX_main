from __future__ import annotations

from typing import Any

import pytest

from sbp_lex.baseline.application_startup import (
    APPLICATION_STARTUP_STATE_FIELDS,
    ApplicationIntegrityRuntimeBundle,
)
from sbp_lex.baseline.request_controls import FoundationalRequestDependencies
from sbp_lex.execution import execution_gate


FOUNDATIONAL_CHECKS = (
    "application_integrity_current_and_valid",
    "digital_provenance_authenticated",
    "sovereign_identity_current_and_valid",
    "authority_boundary_current_and_valid",
    "impersonation_protection_current_and_valid",
    "australian_minor_access_current_and_valid",
    "foundational_request_controls_current_and_valid",
    "foundational_baseline_digest_current_and_valid",
    "authority_provenance_current_and_valid",
)


def _bundle() -> ApplicationIntegrityRuntimeBundle:
    return object.__new__(ApplicationIntegrityRuntimeBundle)


def _dependencies() -> FoundationalRequestDependencies:
    return FoundationalRequestDependencies(
        provenance_registry_snapshot=None,
        provenance_trust_context=None,
        sovereign_identity_evaluator=None,
        sovereign_identity_attestation_provider=None,
        authority_boundary_evaluator=None,
        authority_boundary_attestation_provider=None,
        impersonation_trust_context=None,
    )


def _state() -> dict[str, Any]:
    state: dict[str, Any] = {
        "execution_trace": [],
        "application_integrity_result": "PASS",
        "application_integrity_result_digest": "1" * 128,
        "application_integrity_receipt_digest": "2" * 128,
        "application_integrity_manifest_digest": "3" * 128,
        "application_integrity_runtime_measurement_digest": "4" * 128,
        "application_integrity_trust_context_digest": "5" * 128,
        "foundational_baseline_digest": "6" * 128,
    }
    assert all(field in state for field in APPLICATION_STARTUP_STATE_FIELDS)
    return state


def _patch_foundational_checks(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[str],
    *,
    failing_check: str | None = None,
    application_mutation: bool = False,
) -> None:
    monkeypatch.setattr(execution_gate, "verify_hash_chain", lambda state: True)

    def application_verifier(state: dict, **kwargs: object) -> None:
        calls.append(FOUNDATIONAL_CHECKS[0])
        if failing_check == FOUNDATIONAL_CHECKS[0]:
            raise ValueError("APPLICATION_FAILURE")
        if application_mutation:
            state["application_integrity_result_digest"] = "f" * 128

    monkeypatch.setattr(
        execution_gate,
        "verify_and_project_application_startup",
        application_verifier,
    )

    verifier_names = (
        "verify_digital_provenance_state",
        "verify_sovereign_identity",
        "verify_authority_boundary",
        "_impersonation_control_current_and_valid",
        "verify_australian_minor_access",
        "verify_foundational_request_controls",
        "verify_foundational_baseline",
        "verify_authority_provenance",
    )
    for check, verifier_name in zip(FOUNDATIONAL_CHECKS[1:], verifier_names):
        monkeypatch.setattr(
            execution_gate,
            verifier_name,
            lambda *args, _check=check, **kwargs: (
                calls.append(_check) or _check != failing_check
            ),
        )


def _run(state: dict[str, Any], **overrides: object) -> dict[str, Any]:
    arguments: dict[str, object] = {
        "application_integrity_bundle": _bundle(),
        "application_integrity_result": {},
        "foundational_request_dependencies": _dependencies(),
    }
    arguments.update(overrides)
    return execution_gate.run_execution_gate(state, **arguments)


def test_exact_eight_check_order_precedes_three_p(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _patch_foundational_checks(monkeypatch, calls)
    monkeypatch.setattr(
        execution_gate,
        "verify_three_p_core",
        lambda *args, **kwargs: calls.append("three_p") or False,
    )

    result = _run(_state())

    assert calls == [*FOUNDATIONAL_CHECKS, "three_p"]
    assert [entry["check"] for entry in result["execution_trace"]] == [
        "hash_chain_presence_and_integrity",
        *FOUNDATIONAL_CHECKS,
        "three_p_core_constitutional_constraint",
    ]
    assert result["execution_reason"] == "three_p_core_failure"


@pytest.mark.parametrize("failing_check", FOUNDATIONAL_CHECKS)
def test_each_foundational_failure_short_circuits_before_three_p(
    monkeypatch: pytest.MonkeyPatch,
    failing_check: str,
) -> None:
    calls: list[str] = []
    _patch_foundational_checks(
        monkeypatch,
        calls,
        failing_check=failing_check,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_three_p_core",
        lambda *args, **kwargs: calls.append("three_p") or True,
    )

    result = _run(_state())

    failure_index = FOUNDATIONAL_CHECKS.index(failing_check)
    assert calls == list(FOUNDATIONAL_CHECKS[: failure_index + 1])
    assert result["execution_result"] == "HALT"
    assert result["decision"] == "DENY"
    assert result["execution_reason"] == f"{failing_check}_failure"
    assert result["execution_trace"][-1] == {
        "check": failing_check,
        "passed": False,
        "reason": f"{failing_check}_failure",
    }


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        (
            {"application_integrity_bundle": None},
            "application_integrity_current_and_valid_failure",
        ),
        (
            {"application_integrity_result": None},
            "application_integrity_current_and_valid_failure",
        ),
        (
            {"foundational_request_dependencies": None},
            "digital_provenance_authenticated_failure",
        ),
        (
            {"foundational_request_dependencies": object()},
            "digital_provenance_authenticated_failure",
        ),
    ],
)
def test_missing_or_wrong_dependencies_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, object],
    reason: str,
) -> None:
    calls: list[str] = []
    _patch_foundational_checks(monkeypatch, calls)
    monkeypatch.setattr(
        execution_gate,
        "verify_three_p_core",
        lambda *args, **kwargs: calls.append("three_p") or True,
    )

    result = _run(_state(), **overrides)

    assert result["execution_reason"] == reason
    assert "three_p" not in calls


def test_application_projection_mutation_fails_even_when_verifier_returns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _patch_foundational_checks(
        monkeypatch,
        calls,
        application_mutation=True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_three_p_core",
        lambda *args, **kwargs: calls.append("three_p") or True,
    )

    result = _run(_state())

    assert result["execution_reason"] == (
        "application_integrity_current_and_valid_failure"
    )
    assert calls == [FOUNDATIONAL_CHECKS[0]]


def test_post_aggregate_mutation_fails_at_aggregate_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _patch_foundational_checks(monkeypatch, calls)
    expected_digest = "6" * 128
    monkeypatch.setattr(
        execution_gate,
        "verify_foundational_baseline",
        lambda state, **kwargs: (
            calls.append(
                "foundational_baseline_digest_current_and_valid"
            )
            or state.get("foundational_baseline_digest") == expected_digest
        ),
    )
    state = _state()
    state["foundational_baseline_digest"] = "7" * 128

    result = _run(state)

    assert calls == list(FOUNDATIONAL_CHECKS[:-1])
    assert result["execution_reason"] == (
        "foundational_baseline_digest_current_and_valid_failure"
    )
