from __future__ import annotations

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.governance.authority_provenance import (
    AUTHORITY_PROVENANCE_DENY,
    AUTHORITY_PROVENANCE_PASS,
    evaluate_authority_provenance,
    verify_authority_provenance,
)
from sbp_lex.security.authority_trust import AuthorityProvenanceDependencies
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object,
)
import sbp_lex.security.authority_trust as authority_trust
from sbp_lex.shared.state_builder import build_state
from tests.authority_provenance_support import (
    AuthorityProvenanceFixture,
    append_authority_provenance_binding,
)


@pytest.fixture
def fixture() -> AuthorityProvenanceFixture:
    return AuthorityProvenanceFixture.create()


def _admitted(fixture: AuthorityProvenanceFixture) -> dict:
    state = fixture.state()
    evaluate_authority_provenance(
        state, dependencies=fixture.dependencies
    )
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_PASS
    append_authority_provenance_binding(state)
    assert verify_authority_provenance(
        state,
        dependencies=fixture.dependencies,
        require_hash_binding=True,
    )
    return state


def test_exact_signed_provenance_projects_only_authenticated_values(
    fixture: AuthorityProvenanceFixture,
) -> None:
    state = _admitted(fixture)
    assert state["submitted_authority_claim"] == "caller-claim"
    assert state["submitted_ap_acf_class"] == "CALLER_CLASS"
    assert state["resolved_authority"] == "external-authority"
    assert state["jurisdiction"] == "AU"
    assert state["ap_acf_class"] == "EXTERNAL_CLASS"
    assert state["ap_acf_subclass"] == "EXTERNAL_SUBCLASS"
    assert state["governance_policy_record"]["policy_id"] == "TEST_ONLY_POLICY"
    for field in (
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_authority_granted",
        "pipeline_bypass_permitted",
        "downstream_override_permitted",
    ):
        assert state[f"authority_provenance_{field}"] is False
        assert state["authority_provenance_record"][field] is False


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("resolved_authority", "caller-overwrite"),
        ("jurisdiction", "NZ"),
        ("ap_acf_class", "CALLER_CLASS"),
        ("ap_acf_subclass", "CALLER_SUBCLASS"),
        ("governance_policy_digest", canonical_integrity_hash({"fake": True})),
        ("request_fingerprint", canonical_integrity_hash({"changed": True})),
        ("evaluation_time", 101),
    ),
)
def test_live_projection_or_request_mutation_fails(
    fixture: AuthorityProvenanceFixture, field: str, value: object
) -> None:
    state = _admitted(fixture)
    state[field] = value
    assert not verify_authority_provenance(
        state, dependencies=fixture.dependencies
    )


def test_missing_or_attacker_selected_context_denies(
    fixture: AuthorityProvenanceFixture,
) -> None:
    state = fixture.state()
    evaluate_authority_provenance(state, dependencies=None)
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY

    attacker = AuthorityProvenanceDependencies(
        fixed_context_id="ATTACKER_CONTEXT",
        owner_pinned_context_digest=canonical_integrity_hash(
            {"attacker": "self-consistent"}
        ),
    )
    state = fixture.state()
    evaluate_authority_provenance(state, dependencies=attacker)
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY


def test_independent_upstream_raw_key_pin_rejects_forged_identity(
    fixture: AuthorityProvenanceFixture,
) -> None:
    attacker = Ed25519SoftwareProvider.from_private_key(
        Ed25519PrivateKey.generate(),
        skg_attestation_admitted=True,
    )
    state = fixture.state()
    original_source = state["sovereign_identity_record"]["evaluation_source"]
    state["sovereign_identity_record"]["evaluation_source"] = (
        build_legacy_non_effect_signed_object(
            {
                key: deepcopy(value)
                for key, value in original_source.items()
                if key not in {"digest", "signature", "verified"}
            },
            provider=attacker,
        )
    )
    state["sovereign_identity_trace"] = [
        deepcopy(state["sovereign_identity_record"])
    ]
    state["sovereign_identity_digest"] = canonical_integrity_hash(
        state["sovereign_identity_trace"]
    )
    evaluate_authority_provenance(
        state, dependencies=fixture.dependencies
    )
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY


def test_authority_flag_from_external_evaluator_is_rejected(
    fixture: AuthorityProvenanceFixture,
) -> None:
    fixture.evaluator.force_authority = True
    state = fixture.state()
    evaluate_authority_provenance(
        state, dependencies=fixture.dependencies
    )
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY
    assert state["authority_provenance_authority_granted"] is False


@pytest.mark.parametrize("dependency", ("clock", "registry"))
def test_terminal_live_head_change_fails_closed(
    fixture: AuthorityProvenanceFixture, dependency: str
) -> None:
    setattr(getattr(fixture, dependency), "change_on_second_call", True)
    state = fixture.state()
    evaluate_authority_provenance(
        state, dependencies=fixture.dependencies
    )
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY
    assert state["authority_provenance_reason"].endswith(
        "TERMINAL_HEAD_RECHECK_FAILED"
    )


def test_trace_hash_and_chain_tamper_fail(fixture: AuthorityProvenanceFixture) -> None:
    state = _admitted(fixture)
    tampered = deepcopy(state)
    tampered["authority_provenance_record"]["reason"] = "forged"
    tampered["authority_provenance_trace"][0] = deepcopy(
        tampered["authority_provenance_record"]
    )
    tampered["authority_provenance_digest"] = canonical_integrity_hash(
        tampered["authority_provenance_record"]
    )
    tampered["authority_provenance_trace_digest"] = canonical_integrity_hash(
        tampered["authority_provenance_trace"]
    )
    assert not verify_authority_provenance(
        tampered, dependencies=fixture.dependencies
    )

    broken = deepcopy(state)
    broken["hash_chain"][-1]["previous_hash"] = canonical_integrity_hash(
        {"wrong": "predecessor"}
    )
    assert not verify_authority_provenance(
        broken, dependencies=fixture.dependencies
    )


def test_state_builder_does_not_promote_submitted_claims() -> None:
    state = build_state(
        {
            "resolved_authority": "caller-authority",
            "jurisdiction": "AU",
            "ap_acf_class": "CALLER_CLASS",
            "ap_acf_subclass": "CALLER_SUBCLASS",
            "payload": {"policy": {"active": True}},
        }
    )
    assert state["submitted_authority_claim"] == "caller-authority"
    assert state["requested_jurisdiction"] == "AU"
    assert state["submitted_ap_acf_class"] == "CALLER_CLASS"
    assert state["resolved_authority"] == ""
    assert state["jurisdiction"] == ""
    assert state["ap_acf_class"] is None
    assert state["governance_policy_record"] == {}


def test_production_mode_mechanically_disables_test_registration_and_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(authority_trust, "_RUNTIME_MODE", "PRODUCTION")
    with pytest.raises(
        RuntimeError, match="TEST_ONLY_AUTHORITY_TRUST_API_DISABLED"
    ):
        authority_trust._reset_test_only_authority_trust()
    with pytest.raises(
        RuntimeError, match="TEST_ONLY_AUTHORITY_TRUST_API_DISABLED"
    ):
        authority_trust._install_test_only_authority_trust_pins(
            context_id="attacker",
            context_digest="0" * 128,
            owner_public_key_hex="00" * 32,
        )


def test_malformed_trace_is_structured_deny_and_never_raises(
    fixture: AuthorityProvenanceFixture,
) -> None:
    state = fixture.state()
    state["authority_provenance_trace"] = [object()]
    evaluate_authority_provenance(state, dependencies=fixture.dependencies)
    assert state["authority_provenance_result"] == AUTHORITY_PROVENANCE_DENY
    assert state["authority_provenance_reason"] == (
        "AUTHORITY_PROVENANCE_DUPLICATE_ADMISSION"
    )
    assert not verify_authority_provenance(
        state, dependencies=fixture.dependencies
    )
