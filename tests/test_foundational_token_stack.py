from __future__ import annotations

from copy import deepcopy

import pytest

import sbp_lex.security.token_stack as token_stack
from sbp_lex.baseline.foundational_baseline import (
    bind_foundational_baseline_hash,
    evaluate_foundational_baseline,
    foundational_baseline_hash_payload,
)
from sbp_lex.config.pipeline_config import FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
from sbp_lex.governance.three_p_doctrine import (
    THREE_P_ATTESTATION_PURPOSE,
    evaluate_three_p_core,
    three_p_hash_payload,
)
from sbp_lex.governance.authority_provenance import (
    AUTHORITY_PROVENANCE_STAGE,
    authority_provenance_hash_payload,
)
from sbp_lex.licensing.filed_licensing import LICENCE_ROOT_BINDING_STAGE
from sbp_lex.provenance.digital_provenance import (
    ADMIT as DIGITAL_PROVENANCE_ADMIT,
    NO_AUTHORIZATION_EFFECT as PROVENANCE_NO_AUTHORIZATION_EFFECT,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_signed_object,
)
from sbp_lex.security.token_stack import (
    REQUIRED_CORE_TOKENS,
    _TOKEN_ISSUANCE_CONTRACTS,
    issue_token,
    verify_required_tokens,
    verify_token,
)
from tests.licence_support import (
    PassingFiledLicenceEvaluator,
    append_filed_licence_evaluation,
    filed_licence_request_fields,
)


APPLICATION_DIGEST_FIELDS = (
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
)
AGGREGATE_AUTHORITY_FIELDS = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
FILED_LICENCE_TOKEN_FIELDS = {
    "licence_binding_stage",
    "licence_evaluation_sequence",
    "filed_licence_digest",
    "licence_id",
    "license_tier",
    "licence_bindings_digest",
    "licence_invalidation_status",
    "licence_revocation_status",
    "licence_revocation_sequence",
}


class PassingThreePCoreEvaluator:
    evaluator_id = "three-p-foundational-token-fixture"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "three-p-foundational-token-credential"

    def __init__(self, provider: HybridMLDSA87Ed448SoftwareProvider) -> None:
        self.provider = provider

    def evaluate(self, *, stage: str, snapshot: dict) -> dict:
        return build_signed_object(
            {
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_three_p_digest": snapshot["prior_three_p_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determinations": {
                    primitive: {
                        "result": "SATISFIED",
                        "evidence_references": [
                            {
                                "evidence_id": (
                                    f"{primitive}:{snapshot['evaluation_sequence']}"
                                ),
                                "source": "controlled-test-evidence",
                                "digest": canonical_integrity_hash(
                                    {
                                        "primitive": primitive,
                                        "stage": stage,
                                        "sequence": snapshot[
                                            "evaluation_sequence"
                                        ],
                                    }
                                ),
                            }
                        ],
                    }
                    for primitive in ("P1", "P2", "P3")
                },
            },
            provider=self.provider,
            purpose=THREE_P_ATTESTATION_PURPOSE,
        )


def _digest(label: str) -> str:
    return canonical_integrity_hash({"fixture": label})


def _provider() -> HybridMLDSA87Ed448SoftwareProvider:
    return HybridMLDSA87Ed448SoftwareProvider.generate(
        provider_id="TEST_ONLY:FOUNDATIONAL_TOKEN_HYBRID",
        three_p_attestation_admitted=True,
        licence_attestation_admitted=True,
    )


def _verification_pin(provider):
    context = provider.hybrid_verification_context(allow_test_only=True)
    return {
        "trust_context": context,
        "owner_pinned_context_digest": context.context_digest,
    }


def _three_p_pin(provider):
    context = provider.hybrid_verification_context(allow_test_only=True)
    return {
        "three_p_trust_context": context,
        "three_p_owner_pinned_context_digest": context.context_digest,
    }


def _provenance_receipt(graph_digest: str) -> dict:
    payload = {
        "schema_id": "SBP_LEX_PROVENANCE_VERIFICATION_RECEIPT_V2",
        "result": DIGITAL_PROVENANCE_ADMIT,
        "graph_digest": graph_digest,
        "release_manifest_digest": _digest(
            "application_integrity_manifest_digest"
        ),
        "runtime_measurement_digest": _digest(
            "application_integrity_runtime_measurement_digest"
        ),
        "durable_claim_result": "CLAIMED",
        "durable_claim_digest": _digest("durable-claim"),
        "durable_transition_receipt_digest": _digest(
            "durable-transition"
        ),
        "durable_live_heads_digest": _digest("durable-live-heads"),
        "revocation_head_digest": _digest("revocation-head"),
        "clock_evidence_digest": _digest("clock-evidence"),
        "production_durable_storage_proven_by_module": False,
        "lineage_authenticated": True,
        "lineage_only": True,
        **dict(PROVENANCE_NO_AUTHORIZATION_EFFECT),
    }
    return {
        **payload,
        "digest": canonical_integrity_hash(payload),
        "signature": {
            "provider_id": "provenance-provider",
            "algorithm": "Ed25519",
            "key_id": "provenance-key",
            "custody_class": "HARDWARE_BACKED",
            "effect_authority": False,
            "signature_b64": "c2lnbmF0dXJl",
        },
        "verified": False,
    }


def _minor_record() -> dict:
    record = {
        "result": "PASS",
        "applicable": True,
        "age_assurance_result": "AT_LEAST_16",
        "reason": "AUTHENTICATED_DETERMINATION",
        "privacy_data_destroyed": True,
        "youth_penalty_applied": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority": False,
    }
    record["record_digest"] = canonical_integrity_hash(record)
    return record


def _apply_foundational_prerequisites(state: dict) -> None:
    provenance_digest = _digest("provenance")
    impersonation_record = {
        "result": "PASS",
        "reason": "IMPERSONATION_PROTECTION_COMPLETED",
        "biometric_proof_established": False,
        "identity_issued": False,
        "identity_label_grants_access": False,
        "role_label_grants_authority": False,
        "mandate_label_grants_authority": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }
    state.update(
        {
            "application_integrity_result": "PASS",
            **{field: _digest(field) for field in APPLICATION_DIGEST_FIELDS},
            "digital_provenance_result": DIGITAL_PROVENANCE_ADMIT,
            "digital_provenance_digest": provenance_digest,
            "digital_provenance_lineage_authenticated": True,
            "digital_provenance_lineage_only": True,
            "digital_provenance_verification_receipt": (
                _provenance_receipt(provenance_digest)
            ),
            "sovereign_identity_result": "VERIFIED",
            "sovereign_identity_revocation_status": "ACTIVE",
            "sovereign_identity_digest": _digest("sovereign-identity"),
            "sovereign_identity_record": {
                "result": "VERIFIED",
                "revocation_status": "ACTIVE",
                "biometric_proof_established": False,
                "access_granted": False,
                "authority_granted": False,
                "licence_granted": False,
                "execution_authority_granted": False,
                "effect_authority_granted": False,
            },
            "authority_boundary_result": "BOUNDARY_PASS",
            "authority_boundary_digest": _digest("authority-boundary"),
            "authority_boundary_trace_digest": _digest("boundary-trace"),
            "authority_boundary_record": {
                "result": "BOUNDARY_PASS",
                "stakeholder_label_grants_rights": False,
                "authority_granted": False,
                "licence_granted": False,
                "execution_authority_granted": False,
                "effect_authority_granted": False,
                "pipeline_bypass_permitted": False,
            },
            "stakeholder_label_grants_rights": False,
            "participant_authority_granted": False,
            "participant_licence_granted": False,
            "participant_execution_authority_granted": False,
            "participant_effect_authority_granted": False,
            "participant_pipeline_bypass_permitted": False,
            "impersonation_protection_result": "PASS",
            "impersonation_protection_digest": canonical_integrity_hash(
                [impersonation_record]
            ),
            "impersonation_protection_trace": [
                deepcopy(impersonation_record)
            ],
            "impersonation_protection_record": impersonation_record,
            "impersonation_protection_reason": (
                "IMPERSONATION_PROTECTION_COMPLETED"
            ),
            "australian_minor_access": _minor_record(),
            "foundational_baseline_hash_binding_index": None,
            "foundational_baseline_hash_binding_hash": None,
        }
    )
    for field in (
        "biometric_proof_established",
        "identity_issued",
        "identity_label_grants_access",
        "role_label_grants_authority",
        "mandate_label_grants_authority",
        "access_granted",
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
    ):
        state[f"impersonation_{field}"] = False


def _token_ready_state(
    provider: HybridMLDSA87Ed448SoftwareProvider,
) -> dict:
    state = {
        **filed_licence_request_fields(),
        "request_fingerprint": "f" * 128,
        "state_hash": GENESIS_HASH,
        "hash_chain": [],
        "evaluation_time": 1,
        "action": "review",
        "payload": {},
        "context": {},
        "resolved_authority": "owner",
        "jurisdiction": "AU",
        "requested_autonomy_level": 20,
        "authority_first_result": "ALLOW",
        "authority_first_reason": "authority_valid",
        "safety_profile": {"computed_tier": "LOW"},
        "corroboration_required": None,
        "tokens": {},
        "token_stack_valid": False,
        "token_verification_failures": [],
        "token_trace": [],
    }
    evaluate_three_p_core(
        state,
        evaluator=PassingThreePCoreEvaluator(provider),
        attestation_provider=provider,
        stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        **_verification_pin(provider),
    )
    three_p_entry = build_hash_chain_entry(
        previous_hash=GENESIS_HASH,
        stage=f"three_p_core:{FOUNDATIONAL_BASELINE_AGGREGATE_STAGE}",
        payload=three_p_hash_payload(state),
    )
    state["hash_chain"].append(three_p_entry)
    state["state_hash"] = three_p_entry["hash"]
    _apply_foundational_prerequisites(state)
    evaluate_foundational_baseline(state)
    bind_foundational_baseline_hash(state)
    return state


def _issue_foundational(
    state: dict,
    provider: HybridMLDSA87Ed448SoftwareProvider,
) -> None:
    issue_token(
        state,
        token_name="foundational",
        issuer=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        issued_at_stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        payload=foundational_baseline_hash_payload(state),
        provider=provider,
        three_p_attestation_provider=provider,
        **_three_p_pin(provider),
    )


def _apply_authority_provenance_binding(state: dict) -> None:
    record = {"result": "PASS", "fixture": "authenticated-provenance"}
    trace = [record]
    state.update(
        {
            "authority_provenance_result": "PASS",
            "authority_provenance_record": record,
            "authority_provenance_trace": trace,
            "authority_provenance_digest": canonical_integrity_hash(record),
            "authority_provenance_trace_digest": canonical_integrity_hash(trace),
            "authority_provenance_trust_context_digest": _digest(
                "authority-provenance-context"
            ),
            "authority_provenance_clock_receipt_digest": _digest(
                "authority-provenance-clock"
            ),
            "authority_provenance_registry_head_digest": _digest(
                "authority-provenance-registry"
            ),
        }
    )
    entry = build_hash_chain_entry(
        previous_hash=state["state_hash"],
        stage=AUTHORITY_PROVENANCE_STAGE,
        payload=authority_provenance_hash_payload(state),
    )
    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]


def _resign_token(
    state: dict,
    provider: HybridMLDSA87Ed448SoftwareProvider,
    mutate,
) -> None:
    token = state["tokens"]["foundational"]
    body = {
        key: deepcopy(value)
        for key, value in token.items()
        if key not in {"digest", "signature", "verified"}
    }
    mutate(body)
    state["tokens"]["foundational"] = build_signed_object(
        body,
        provider=provider,
    )


def test_foundational_token_mints_before_licence_with_exact_schema() -> None:
    provider = _provider()
    state = _token_ready_state(provider)

    _issue_foundational(state, provider)

    token = state["tokens"]["foundational"]
    assert verify_token(
        state,
        "foundational",
        provider=provider,
        **_verification_pin(provider),
    )
    assert not FILED_LICENCE_TOKEN_FIELDS.intersection(token)
    assert token["issued_chain_stage"] == FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
    assert token["payload"] == foundational_baseline_hash_payload(state)
    for field in APPLICATION_DIGEST_FIELDS:
        assert token[field] == state[field]
    assert token["foundational_baseline_digest"] == state[
        "foundational_baseline_digest"
    ]
    for field in AGGREGATE_AUTHORITY_FIELDS:
        assert token[field] is False


def test_duplicate_foundational_issuance_fails() -> None:
    provider = _provider()
    state = _token_ready_state(provider)
    _issue_foundational(state, provider)

    with pytest.raises(ValueError, match="TOKEN_ALREADY_ISSUED"):
        _issue_foundational(state, provider)


@pytest.mark.parametrize(
    "mutation",
    ["missing_three_p", "invalid_three_p", "invalid_aggregate", "wrong_payload", "wrong_tail"],
)
def test_foundational_issuance_prerequisites_fail_closed(mutation: str) -> None:
    provider = _provider()
    state = _token_ready_state(provider)
    payload = foundational_baseline_hash_payload(state)
    if mutation == "missing_three_p":
        state.pop("three_p_core_record")
    elif mutation == "invalid_three_p":
        state["three_p_core_digest"] = _digest("invalid-three-p")
    elif mutation == "invalid_aggregate":
        state["foundational_baseline_digest"] = _digest("invalid-aggregate")
    elif mutation == "wrong_payload":
        payload = {"wrong": "payload"}
    else:
        entry = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage="collective_attach",
            payload={"later": True},
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

    with pytest.raises(ValueError):
        issue_token(
            state,
            token_name="foundational",
            issuer=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
            issued_at_stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
            payload=payload,
            provider=provider,
            three_p_attestation_provider=provider,
            **_three_p_pin(provider),
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "state_application_digest",
        "state_aggregate_digest",
        "token_application_digest",
        "payload",
        "chain",
        "signature",
        "issuer",
        "stage",
        "authority_flag",
        "extra_field",
    ],
)
def test_foundational_token_tamper_fails_closed(mutation: str) -> None:
    provider = _provider()
    state = _token_ready_state(provider)
    _issue_foundational(state, provider)
    if mutation == "state_application_digest":
        state[APPLICATION_DIGEST_FIELDS[0]] = _digest("mutated-application")
    elif mutation == "state_aggregate_digest":
        state["foundational_baseline_digest"] = _digest("mutated-aggregate")
    elif mutation == "token_application_digest":
        _resign_token(
            state,
            provider,
            lambda body: body.update(
                {APPLICATION_DIGEST_FIELDS[0]: _digest("substituted")}
            ),
        )
    elif mutation == "payload":
        _resign_token(
            state,
            provider,
            lambda body: body.update({"payload": {"substituted": True}}),
        )
    elif mutation == "chain":
        state["hash_chain"][-1]["payload_hash"] = _digest("mutated-chain")
    elif mutation == "signature":
        state["tokens"]["foundational"]["signature"]["signatures"][0][
            "signature_b64"
        ] = "AAAA"
    elif mutation == "issuer":
        _resign_token(
            state,
            provider,
            lambda body: body.update({"issuer": "substituted"}),
        )
    elif mutation == "stage":
        _resign_token(
            state,
            provider,
            lambda body: body.update({"issued_at_stage": "substituted"}),
        )
    elif mutation == "authority_flag":
        _resign_token(
            state,
            provider,
            lambda body: body.update({"authority_granted": True}),
        )
    else:
        _resign_token(
            state,
            provider,
            lambda body: body.update({"extra": "not-exact"}),
        )

    assert verify_token(
        state,
        "foundational",
        provider=provider,
        **_verification_pin(provider),
    ) is False


def test_normal_token_still_requires_filed_licence() -> None:
    provider = _provider()
    state = _token_ready_state(provider)
    _apply_authority_provenance_binding(state)

    with pytest.raises(
        ValueError,
        match="TOKEN_ISSUANCE_FILED_LICENCE_BINDING_MISSING",
    ):
        issue_token(
            state,
            token_name="authority",
            issuer="root_of_trust",
            issued_at_stage="root_of_trust",
            payload={},
            provider=provider,
            three_p_attestation_provider=provider,
            **_three_p_pin(provider),
        )


def test_later_token_binds_application_and_foundational_digests() -> None:
    provider = _provider()
    state = _token_ready_state(provider)
    _apply_authority_provenance_binding(state)
    append_filed_licence_evaluation(
        state,
        stage=LICENCE_ROOT_BINDING_STAGE,
        evaluator=PassingFiledLicenceEvaluator(provider),
        provider=provider,
    )
    licence_record = state["filed_licence_record"]
    issue_token(
        state,
        token_name="authority",
        issuer="root_of_trust",
        issued_at_stage="root_of_trust",
        payload={
            "authority_first_result": state["authority_first_result"],
            "authority_first_reason": state["authority_first_reason"],
            "licence_id": state["licence_id"],
            "license_tier": state["license_tier"],
            "filed_licence_digest": state["filed_licence_digest"],
            "licence_bindings_digest": canonical_integrity_hash(
                licence_record["evaluation_snapshot"]["bindings"]
            ),
        },
        provider=provider,
        three_p_attestation_provider=provider,
        **_three_p_pin(provider),
    )
    token = state["tokens"]["authority"]

    assert verify_token(
        state,
        "authority",
        provider=provider,
        **_verification_pin(provider),
    )
    for field in APPLICATION_DIGEST_FIELDS:
        assert token[field] == state[field]
    assert token["foundational_baseline_digest"] == state[
        "foundational_baseline_digest"
    ]
    for field in token_stack._AUTHORITY_PROVENANCE_BINDING_FIELDS:
        assert token[field] == state[field]

    app_mutated = deepcopy(state)
    app_mutated[APPLICATION_DIGEST_FIELDS[0]] = _digest("app-mutated")
    assert verify_token(
        app_mutated,
        "authority",
        provider=provider,
        **_verification_pin(provider),
    ) is False

    aggregate_mutated = deepcopy(state)
    aggregate_mutated["foundational_baseline_digest"] = _digest(
        "aggregate-mutated"
    )
    assert verify_token(
        aggregate_mutated,
        "authority",
        provider=provider,
        **_verification_pin(provider),
    ) is False


def test_required_order_is_foundational_then_existing_order() -> None:
    assert REQUIRED_CORE_TOKENS[:4] == [
        "foundational",
        "authority_provenance",
        "authority",
        "skg",
    ]
    assert _TOKEN_ISSUANCE_CONTRACTS["foundational"] == (
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
    )


def test_stack_chronology_requires_foundational_before_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(token_stack, "verify_token", lambda *args, **kwargs: True)
    state = {
        "tokens": {
            name: {"issued_chain_index": index + 1}
            for index, name in enumerate(REQUIRED_CORE_TOKENS)
        },
        "token_trace": [],
    }
    verify_required_tokens(state, provider=None)
    assert state["token_stack_valid"] is True

    state["tokens"]["foundational"]["issued_chain_index"] = state["tokens"][
        "authority"
    ]["issued_chain_index"]
    verify_required_tokens(state, provider=None)
    assert state["token_stack_valid"] is False
    assert "core_token_chronology" in state["token_verification_failures"]
