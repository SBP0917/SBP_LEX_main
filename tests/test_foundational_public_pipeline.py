from __future__ import annotations

import os
from copy import deepcopy
from dataclasses import replace
from unittest.mock import patch

import pytest

os.environ["SBP_LEX_IMPERSONATION_RUNTIME_MODE"] = "TEST_ONLY"

from main import run_sbp_lex
from sbp_lex.baseline.application_startup import (
    APPLICATION_INTEGRITY_STARTUP_STAGE,
    application_startup_hash_payload,
    verify_and_project_application_startup,
)
from sbp_lex.pipeline.runner import (
    PipelineHybridTrustContexts,
    _append_hash_chain,
    _request_fingerprint,
    run_v2,
)
from sbp_lex.audit.audit_ledger import verify_audit_record
from sbp_lex.execution.rust_authority_client import RustAuthorityClient
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_DENY,
    GOVERNANCE_INTEGRITY_ESCALATE,
    governance_integrity_revocation_binding,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_STAGES,
)
from sbp_lex.security.integrity import GENESIS_HASH, canonical_integrity_hash
from sbp_lex.shared.state_builder import build_state
from tests.test_controlled_local_adapter import ControlledLocalAdapterTests
from wire_protocol.v2.python import sbp_lex_wire_v2 as wire_v2
from wire_protocol.v2.python.golden import (
    BASE_MS as WIRE_BASE_MS,
    build_transcript as build_wire_transcript,
    fixture_admission as wire_fixture_admission,
)


_FOUNDATIONAL_INPUT_FIELDS = (
    "identity",
    "biometric_attestation_digest",
    "identity_jurisdictions",
    "identity_access_grants",
    "participant_id",
    "stakeholder_class",
    "participant_role",
    "participant_mandate_id",
    "evaluation_time",
    "impersonation_session_id",
    "impersonation_audience",
    "impersonation_challenge",
    "subject_id",
    "session_id",
    "service_id",
    "request_nonce",
)


class _IdentityEvaluationReplay:
    """Replay the exact signed source used to bind a possession proof."""

    def __init__(self, evaluator: object, source: dict) -> None:
        self.identity_evaluator_id = evaluator.identity_evaluator_id
        self.identity_evaluator_version = evaluator.identity_evaluator_version
        self.identity_issuer_role = evaluator.identity_issuer_role
        self.identity_issuer_credential_id = (
            evaluator.identity_issuer_credential_id
        )
        self._source = deepcopy(source)

    def evaluate_identity(self, *, stage: str, snapshot: dict) -> dict:
        return deepcopy(self._source)


class _AuthorityBoundaryEvaluationReplay:
    """Replay the exact signed source used to bind a possession proof."""

    def __init__(self, evaluator: object, source: dict) -> None:
        self.evaluator_id = evaluator.evaluator_id
        self.evaluator_version = evaluator.evaluator_version
        self.authority_role = evaluator.authority_role
        self.authority_credential_id = evaluator.authority_credential_id
        self._source = deepcopy(source)

    def evaluate_authority_boundary(
        self,
        *,
        stage: str,
        snapshot: dict,
    ) -> dict:
        return deepcopy(self._source)


def _reset_provenance_claim_state(fixture: ControlledLocalAdapterTests) -> None:
    durable = fixture.foundation.provenance.durable
    durable.seen_claims.clear()
    durable.seen_requests.clear()
    durable.stream_heads.clear()
    durable.registry_head = None
    durable.last_time = None
    durable.transition_sequence = 0
    durable.state_digest = GENESIS_HASH
    durable.last_revocation_head_digest = GENESIS_HASH
    fixture.foundation.provenance.revocation_source.calls = 0


def _public_inputs(
    fixture: ControlledLocalAdapterTests,
    *,
    payload_update: dict | None = None,
) -> tuple[dict, dict, dict]:
    request = fixture.request()
    if payload_update is not None:
        request["payload"].update(deepcopy(payload_update))
    request["payload"]["output"]["fact_verified_ratio"] = 1
    request["indexed_attestations"] = [
        {"verified": True, "source": "authority-a"},
        {"verified": True, "source": "authority-b"},
    ]
    foundational = fixture.foundation._state()
    for field in _FOUNDATIONAL_INPUT_FIELDS:
        request[field] = deepcopy(foundational[field])

    fingerprint_state = build_state(request)
    fingerprint = _request_fingerprint(fingerprint_state)
    request["digital_provenance_graph"] = (
        fixture.foundation.provenance.graph(
            request_fingerprint=fingerprint
        )
    )

    proof_state = build_state(request)
    proof_state["request_fingerprint"] = fingerprint
    verify_and_project_application_startup(
        proof_state,
        bundle=fixture.application_bundle,
        result=fixture.application_result,
    )
    proof_state["release_manifest_digest"] = proof_state[
        "application_integrity_manifest_digest"
    ]
    proof_state["runtime_measurement_digest"] = proof_state[
        "application_integrity_runtime_measurement_digest"
    ]
    _append_hash_chain(
        proof_state,
        APPLICATION_INTEGRITY_STARTUP_STAGE,
        application_startup_hash_payload(proof_state),
    )
    _append_hash_chain(
        proof_state,
        "state_construction",
        {
            "request_fingerprint": fingerprint,
            "action": proof_state.get("action"),
            "payload": proof_state.get("payload"),
            "context": proof_state.get("context"),
            "sources": proof_state.get("sources"),
            "identity": proof_state.get("identity"),
            "license_tier": proof_state.get("license_tier"),
            "execution_rights": proof_state.get("execution_rights"),
        },
    )
    fixture.foundation.state = proof_state
    fixture.foundation.run_through_authority()
    possession_proof = fixture.foundation.impersonation.proof(proof_state)
    replay_dependencies = replace(
        fixture.foundational_dependencies,
        sovereign_identity_evaluator=_IdentityEvaluationReplay(
            fixture.foundational_dependencies.sovereign_identity_evaluator,
            proof_state["sovereign_identity_record"]["evaluation_source"],
        ),
        authority_boundary_evaluator=_AuthorityBoundaryEvaluationReplay(
            fixture.foundational_dependencies.authority_boundary_evaluator,
            proof_state["authority_boundary_record"]["evaluation_source"],
        ),
    )
    fixture.foundational_dependencies = replay_dependencies
    fixture.foundation.dependencies = replay_dependencies
    _reset_provenance_claim_state(fixture)

    signals = {
        "intent_signal": "review",
        "risk_potential_signal": 0,
        "authority_link_signal": {"linked": True},
        "jurisdiction_signal": {"jurisdiction": "AU"},
        "dependency_signal": {"risk_level": "LOW"},
        "policy_conflict_signal": {
            "conflicts_detected": False,
            "severity": "LOW",
        },
        "operational_context_signal": {"system_state": "NORMAL"},
        "precedence_signal": {"resolved": True},
    }
    return request, signals, possession_proof


def _run_arguments(
    fixture: ControlledLocalAdapterTests,
    *,
    possession_proof: dict | None,
    foundational_dependencies: object | None = None,
) -> dict:
    return {
        "signature_provider": fixture.authority,
        "three_p_evaluator": fixture.evaluator,
        "three_p_attestation_provider": fixture.authority,
        "skg_evaluator": fixture.skg_evaluator,
        "skg_attestation_provider": fixture.authority,
        "filed_framework_evaluator": fixture.framework_evaluator,
        "filed_framework_attestation_provider": fixture.authority,
        "filed_lifecycle_evaluator": fixture.lifecycle_evaluator,
        "filed_lifecycle_attestation_provider": fixture.authority,
        "filed_governance_integrity_evaluator": (
            fixture.governance_integrity_evaluator
        ),
        "filed_governance_integrity_attestation_provider": fixture.authority,
        "filed_governance_integrity_revocation_binding": (
            governance_integrity_revocation_binding(
                status="ACTIVE",
                sequence=1,
            )
        ),
        "filed_licence_evaluator": fixture.licence_evaluator,
        "filed_licence_attestation_provider": fixture.authority,
        "application_integrity_bundle": fixture.application_bundle,
        "foundational_request_dependencies": (
            fixture.foundational_dependencies
            if foundational_dependencies is None
            else foundational_dependencies
        ),
        "possession_proof": possession_proof,
        "effect_adapter": fixture.adapter,
        "effect_permit_ttl_ms": 500,
        "hybrid_trust_contexts": PipelineHybridTrustContexts(
            signature=fixture.authority_context,
            signature_owner_pin=fixture.authority_owner_pin,
            three_p=fixture.authority_context,
            three_p_owner_pin=fixture.authority_owner_pin,
            skg=fixture.authority_context,
            skg_owner_pin=fixture.authority_owner_pin,
            filed_framework=fixture.authority_context,
            filed_framework_owner_pin=fixture.authority_owner_pin,
            filed_licence=fixture.authority_context,
            filed_licence_owner_pin=fixture.authority_owner_pin,
            filed_lifecycle=fixture.authority_context,
            filed_lifecycle_owner_pin=fixture.authority_owner_pin,
            filed_governance_integrity=fixture.authority_context,
            filed_governance_integrity_owner_pin=(
                fixture.authority_owner_pin
            ),
        ),
    }


@pytest.fixture
def public_fixture() -> ControlledLocalAdapterTests:
    fixture = ControlledLocalAdapterTests(
        "test_real_local_effect_requires_point_of_use_receipt"
    )
    fixture.setUp()
    try:
        yield fixture
    finally:
        fixture.tearDown()


def _pass_aurion(state: dict) -> dict:
    state["current_candidate"] = {
        "type": "direct",
        "action": state["action"],
        "payload": deepcopy(state["payload"]),
    }
    state["candidate_attempt_count"] = 1
    state["aurion15_result"] = "pass"
    return state


@pytest.mark.parametrize("entrypoint", (run_sbp_lex, run_v2))
def test_public_pipeline_traverses_foundations_then_blocks_unadmitted_rust_route(
    public_fixture: ControlledLocalAdapterTests,
    entrypoint,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    with patch(
        "sbp_lex.pipeline.runner.run_aurion15",
        side_effect=_pass_aurion,
    ):
        result = entrypoint(
            request,
            signals,
            **_run_arguments(public_fixture, possession_proof=proof),
        )

    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result["effect_result"] == "BLOCKED"
    assert result["execution_reason"] == "RUST_AUTHORITY_ROUTE_NOT_ADMITTED"
    assert result["rust_authority_route_status"] == "NOT_ADMITTED"
    assert result["controlled_local_adapter_classification"] == (
        "ISOLATED_TEST_ONLY_NOT_LIVE"
    )
    assert public_fixture.handler.invocations == 0
    stages = [entry["stage"] for entry in result["hash_chain"]]
    expected = [
        APPLICATION_INTEGRITY_STARTUP_STAGE,
        "state_construction",
        *result["foundational_baseline_record"]["foundational_order"],
        "foundational_baseline",
    ]
    assert [stage for stage in stages if stage in expected] == expected
    assert "possession_proof" not in result
    assert result["tokens"]["foundational"]["authority_granted"] is False
    assert "rust_authority_effect" in stages


def test_injected_validated_unadmitted_rust_terminal_is_audit_only(
    public_fixture: ControlledLocalAdapterTests,
) -> None:
    registry, messages = build_wire_transcript("MODE_1")
    admission = wire_fixture_admission(registry, "MODE_1")
    external = [messages[index] for index in (0, 2, 3, 4, 5, 7, 9, 13)]

    class FixtureTransport:
        authenticated_peer_identity = "TEST-PINNED-PEER"
        binary_identity = "TEST-PINNED-BINARY"

        def exchange(self, request_frames, *, deadline_ms):
            assert len(request_frames) == len(external)
            assert deadline_ms == 1_000
            return [wire_v2.encode_frame(message) for message in messages]

    route = RustAuthorityClient(
        registry=registry,
        admission=admission,
        verifier=wire_v2.fixture_verify,
        trusted_now_ms=lambda: WIRE_BASE_MS + 5_000,
        request_builder=lambda _state: [
            wire_v2.encode_frame(message) for message in external
        ],
        state_binding_validator=lambda _state, pinned: pinned is admission,
        transport=FixtureTransport(),
        expected_peer_identity="TEST-PINNED-PEER",
        expected_binary_identity="TEST-PINNED-BINARY",
        session_deadline_ms=1_000,
        allow_test_only=True,
    )
    request, signals, proof = _public_inputs(public_fixture)
    arguments = _run_arguments(public_fixture, possession_proof=proof)
    arguments["rust_authority_route"] = route
    with patch(
        "sbp_lex.pipeline.runner.run_aurion15",
        side_effect=_pass_aurion,
    ):
        result = run_v2(request, signals, **arguments)

    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result["effect_result"] == "BLOCKED"
    assert result["execution_reason"] == "RUST_AUTHORITY_ROUTE_NOT_ADMITTED"
    assert result["rust_authority_route_status"] == "NOT_ADMITTED"
    assert result["rust_authority_terminal_validated"] is True
    assert result["rust_authority_terminal_evidence"][
        "complete_signed_terminal_transcript_validated"
    ] is True
    assert result["rust_authority_terminal_evidence"]["outcome"] == "SUCCESS"
    assert result["rust_authority_terminal_evidence"][
        "route_admission_state"
    ] == "NOT_ADMITTED"
    assert result["rust_authority_terminal_evidence"][
        "programme_success_eligible"
    ] is False
    assert result["rust_authority_terminal_evidence"][
        "effect_authority_granted"
    ] is False
    assert result["effect_trace"][-1]["event"] == (
        "rust_authority_unadmitted_terminal_validated"
    )
    assert result["effect_trace"][-1]["reported_terminal_outcome"] == "SUCCESS"
    assert result["audit_record"]["rust_authority_terminal_evidence"] == (
        result["rust_authority_terminal_evidence"]
    )
    assert public_fixture.handler.invocations == 0
    assert verify_audit_record(
        result,
        skg_evaluator=public_fixture.skg_evaluator,
        skg_attestation_provider=public_fixture.authority,
        skg_attestation_trust_context=public_fixture.authority_context,
        skg_owner_pinned_context_digest=public_fixture.authority_owner_pin,
        filed_lifecycle_evaluator=public_fixture.lifecycle_evaluator,
        filed_lifecycle_attestation_provider=public_fixture.authority,
        filed_lifecycle_attestation_trust_context=(
            public_fixture.authority_context
        ),
        filed_lifecycle_owner_pinned_context_digest=(
            public_fixture.authority_owner_pin
        ),
        filed_governance_integrity_evaluator=(
            public_fixture.governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=public_fixture.authority,
        filed_governance_integrity_attestation_trust_context=(
            public_fixture.authority_context
        ),
        filed_governance_integrity_owner_pinned_context_digest=(
            public_fixture.authority_owner_pin
        ),
    )


@pytest.mark.parametrize(
    "missing_dependency",
    (
        "filed_governance_integrity_evaluator",
        "filed_governance_integrity_attestation_provider",
        "filed_governance_integrity_revocation_binding",
    ),
)
def test_public_pipeline_halts_for_missing_governance_integrity_dependency(
    public_fixture: ControlledLocalAdapterTests,
    missing_dependency: str,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    arguments = _run_arguments(public_fixture, possession_proof=proof)
    arguments[missing_dependency] = None

    result = run_v2(request, signals, **arguments)

    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result.get("effect_result") != "SUCCESS"
    assert public_fixture.handler.invocations == 0


@pytest.mark.parametrize(
    ("function_result", "expected_decision"),
    (
        (GOVERNANCE_INTEGRITY_DENY, "DENY"),
        (GOVERNANCE_INTEGRITY_ESCALATE, "ESCALATE"),
    ),
)
def test_public_pipeline_halts_on_governance_integrity_veto(
    public_fixture: ControlledLocalAdapterTests,
    function_result: str,
    expected_decision: str,
) -> None:
    public_fixture.governance_integrity_evaluator.result = function_result
    request, signals, proof = _public_inputs(public_fixture)

    result = run_v2(
        request,
        signals,
        **_run_arguments(public_fixture, possession_proof=proof),
    )

    assert result["decision"] == expected_decision
    assert result["execution_result"] == "HALT"
    assert result.get("effect_result") != "SUCCESS"
    assert public_fixture.handler.invocations == 0


@pytest.mark.parametrize(
    "missing_field",
    (
        "provenance_registry_snapshot",
        "provenance_trust_context",
        "sovereign_identity_evaluator",
        "sovereign_identity_attestation_provider",
        "authority_boundary_evaluator",
        "authority_boundary_attestation_provider",
        "impersonation_trust_context",
    ),
)
def test_public_pipeline_fails_closed_for_each_missing_foundational_dependency(
    public_fixture: ControlledLocalAdapterTests,
    missing_field: str,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    dependencies = replace(
        public_fixture.foundational_dependencies,
        **{missing_field: None},
    )
    result = run_v2(
        request,
        signals,
        **_run_arguments(
            public_fixture,
            possession_proof=proof,
            foundational_dependencies=dependencies,
        ),
    )
    assert result["decision"] == "DENY"
    assert result["execution_result"] == "HALT"
    assert result["execution_reason"] == "foundational_baseline_denial"
    assert "authority" not in result.get("tokens", {})
    assert not result.get("effect_permit")


def test_public_pipeline_fails_closed_for_missing_or_tampered_startup_and_proof(
    public_fixture: ControlledLocalAdapterTests,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    missing_bundle = _run_arguments(public_fixture, possession_proof=proof)
    missing_bundle["application_integrity_bundle"] = None
    result = run_sbp_lex(request, signals, **missing_bundle)
    assert result["foundational_failure_stage"] == (
        APPLICATION_INTEGRITY_STARTUP_STAGE
    )
    assert result["decision"] == "DENY"

    tampered = deepcopy(public_fixture.application_bundle.manifest)
    tampered["release_sequence"] += 1
    object.__setattr__(public_fixture.application_bundle, "manifest", tampered)
    result = run_sbp_lex(
        request,
        signals,
        **_run_arguments(public_fixture, possession_proof=proof),
    )
    assert result["foundational_failure_stage"] == (
        APPLICATION_INTEGRITY_STARTUP_STAGE
    )
    assert result["decision"] == "DENY"


def test_public_pipeline_missing_possession_proof_never_reaches_authority(
    public_fixture: ControlledLocalAdapterTests,
) -> None:
    request, signals, _ = _public_inputs(public_fixture)
    result = run_v2(
        request,
        signals,
        **_run_arguments(public_fixture, possession_proof=None),
    )
    assert result["decision"] == "DENY"
    assert result["foundational_failure_stage"].startswith(
        "impersonation_protection:"
    )
    assert "authority" not in result.get("tokens", {})
    assert "possession_proof" not in result
