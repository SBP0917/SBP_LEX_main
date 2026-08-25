from __future__ import annotations

from types import SimpleNamespace

import pytest

from sbp_lex.baseline.application_startup import (
    ApplicationIntegrityRuntimeBundle,
)
from sbp_lex.baseline.request_controls import FoundationalRequestDependencies
from sbp_lex.config.pipeline_config import (
    AURION_PASS_RESULT,
    DOMAIN_PASS_RESULT,
    EXECUTION_APPROVED,
    GOVERNANCE_ALLOW,
    PROCEDURAL_TRUTH_PASS,
)
from sbp_lex.execution import controlled_local_adapter as local_adapter
from sbp_lex.execution import execution_gate
from tests.test_controlled_local_adapter import BoundaryEvidenceProvider


_DIGEST_A = "a" * 128
_DIGEST_B = "b" * 128
_DIGEST_C = "c" * 128
_DIGEST_D = "d" * 128
_DIGEST_E = "e" * 128


def _gate_state() -> dict[str, object]:
    return {
        "execution_trace": [],
        "application_integrity_result": "PASS",
        "application_integrity_result_digest": "1" * 128,
        "application_integrity_receipt_digest": "2" * 128,
        "application_integrity_manifest_digest": "3" * 128,
        "application_integrity_runtime_measurement_digest": "4" * 128,
        "application_integrity_trust_context_digest": "5" * 128,
        "governance_result": GOVERNANCE_ALLOW,
        "procedural_truth_result": PROCEDURAL_TRUTH_PASS,
        "corroboration_met": True,
        "domain_result": DOMAIN_PASS_RESULT,
        "aurion15_result": AURION_PASS_RESULT,
    }


def _patch_gate_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
    calls: list[str],
    *,
    skg_result: bool = True,
    lifecycle_result: bool = True,
    governance_integrity_result: bool = True,
) -> None:
    monkeypatch.setattr(execution_gate, "verify_hash_chain", lambda state: True)
    monkeypatch.setattr(
        execution_gate,
        "_run_foundational_execution_checks",
        lambda *args, **kwargs: calls.append("foundational") or None,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_authority_provenance",
        lambda *args, **kwargs: calls.append("authority_provenance") or True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_three_p_core",
        lambda *args, **kwargs: calls.append("three_p") or True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_skg_authority",
        lambda *args, **kwargs: calls.append("skg") or skg_result,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_filed_licence",
        lambda *args, **kwargs: calls.append("licence") or True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_filed_frameworks",
        lambda *args, **kwargs: calls.append("frameworks") or True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_filed_lifecycle",
        lambda *args, **kwargs: calls.append("lifecycle")
        or lifecycle_result,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_filed_governance_integrity",
        lambda *args, **kwargs: calls.append("governance_integrity")
        or governance_integrity_result,
    )
    monkeypatch.setattr(execution_gate, "verify_tier_consistency", lambda state: True)
    monkeypatch.setattr(
        execution_gate,
        "verify_collective_signal_consistency",
        lambda state: True,
    )
    monkeypatch.setattr(
        execution_gate,
        "get_required_threshold_tokens",
        lambda state: [],
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_required_tokens",
        lambda state, **kwargs: state,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_execution_boundary_clear",
        lambda state: True,
    )
    monkeypatch.setattr(
        execution_gate,
        "verify_execution_attestation_clear",
        lambda state: True,
    )


def test_execution_gate_enforces_exact_governance_prerequisite_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    _patch_gate_prerequisites(monkeypatch, calls)
    skg_evaluator = object()
    governance_provider = BoundaryEvidenceProvider(
        role="execution-gate-prerequisite-order",
        effect_authority=False,
        three_p_attestation_admitted=False,
        framework_attestation_admitted=True,
        licence_attestation_admitted=True,
        skg_attestation_admitted=True,
        lifecycle_attestation_admitted=True,
        governance_integrity_attestation_admitted=True,
    )
    governance_context = governance_provider.hybrid_verification_context()
    skg_provider = governance_provider
    lifecycle_evaluator = object()
    lifecycle_provider = governance_provider
    governance_integrity_evaluator = object()
    governance_integrity_provider = governance_provider
    application_bundle = object.__new__(ApplicationIntegrityRuntimeBundle)
    foundational_dependencies = FoundationalRequestDependencies(
        provenance_registry_snapshot=None,
        provenance_trust_context=None,
        sovereign_identity_evaluator=None,
        sovereign_identity_attestation_provider=None,
        authority_boundary_evaluator=None,
        authority_boundary_attestation_provider=None,
        impersonation_trust_context=None,
    )

    state = execution_gate.run_execution_gate(
        _gate_state(),
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_provider,
        skg_attestation_trust_context=governance_context,
        skg_owner_pinned_context_digest=governance_context.context_digest,
        filed_framework_attestation_provider=governance_provider,
        filed_framework_attestation_trust_context=governance_context,
        filed_framework_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        filed_licence_attestation_provider=governance_provider,
        filed_licence_attestation_trust_context=governance_context,
        filed_licence_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        filed_lifecycle_evaluator=lifecycle_evaluator,
        filed_lifecycle_attestation_provider=lifecycle_provider,
        filed_lifecycle_attestation_trust_context=governance_context,
        filed_lifecycle_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        filed_governance_integrity_evaluator=(
            governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            governance_integrity_provider
        ),
        filed_governance_integrity_attestation_trust_context=(
            governance_context
        ),
        filed_governance_integrity_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        application_integrity_bundle=application_bundle,
        application_integrity_result={},
        foundational_request_dependencies=foundational_dependencies,
    )

    assert calls == [
        "foundational",
        "authority_provenance",
        "three_p",
        "skg",
        "licence",
        "frameworks",
        "lifecycle",
        "governance_integrity",
    ]
    assert state["decision"] == EXECUTION_APPROVED
    assert state["execution_result"] == "EXECUTE"


@pytest.mark.parametrize(
    ("skg_result", "lifecycle_result", "reason", "calls"),
    [
        (
            False,
            True,
            "skg_authority_failure",
            ["authority_provenance", "three_p", "skg"],
        ),
        (
            True,
            False,
            "filed_lifecycle_failure",
            [
                "authority_provenance",
                "three_p",
                "skg",
                "licence",
                "frameworks",
                "lifecycle",
            ],
        ),
    ],
)
def test_execution_gate_fails_closed_on_new_prerequisites(
    monkeypatch: pytest.MonkeyPatch,
    skg_result: bool,
    lifecycle_result: bool,
    reason: str,
    calls: list[str],
) -> None:
    actual_calls: list[str] = []
    _patch_gate_prerequisites(
        monkeypatch,
        actual_calls,
        skg_result=skg_result,
        lifecycle_result=lifecycle_result,
    )
    governance_provider = BoundaryEvidenceProvider(
        role="execution-gate-prerequisite-failure",
        effect_authority=False,
        three_p_attestation_admitted=False,
        framework_attestation_admitted=True,
        licence_attestation_admitted=True,
        skg_attestation_admitted=True,
        lifecycle_attestation_admitted=True,
        governance_integrity_attestation_admitted=True,
    )
    governance_context = governance_provider.hybrid_verification_context()

    state = execution_gate.run_execution_gate(
        _gate_state(),
        skg_attestation_provider=governance_provider,
        skg_attestation_trust_context=governance_context,
        skg_owner_pinned_context_digest=governance_context.context_digest,
        filed_framework_attestation_provider=governance_provider,
        filed_framework_attestation_trust_context=governance_context,
        filed_framework_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        filed_lifecycle_attestation_provider=governance_provider,
        filed_lifecycle_attestation_trust_context=governance_context,
        filed_lifecycle_owner_pinned_context_digest=(
            governance_context.context_digest
        ),
        application_integrity_bundle=object.__new__(
            ApplicationIntegrityRuntimeBundle
        ),
        application_integrity_result={},
        foundational_request_dependencies=FoundationalRequestDependencies(
            provenance_registry_snapshot=None,
            provenance_trust_context=None,
            sovereign_identity_evaluator=None,
            sovereign_identity_attestation_provider=None,
            authority_boundary_evaluator=None,
            authority_boundary_attestation_provider=None,
            impersonation_trust_context=None,
        ),
    )

    assert actual_calls == [
        "foundational",
        *calls,
    ]
    assert state["execution_result"] == "HALT"
    assert state["execution_reason"] == reason


def _binding_state() -> dict[str, object]:
    state: dict[str, object] = {
        "request_fingerprint": _DIGEST_A,
        "state_hash": _DIGEST_B,
        "action": "write_local_record",
        "payload": {"value": 1},
        "current_candidate": {"candidate": "one"},
        "tokens": {"authority": {"verified": True}},
        "three_p_core_digest": _DIGEST_C,
        "three_p_trace_hash": _DIGEST_D,
        "skg_authority_digest": _DIGEST_E,
        "skg_authority_trace_digest": _DIGEST_A,
        "filed_lifecycle_digest": _DIGEST_B,
        "filed_governance_integrity_result": "PASS",
        "filed_governance_integrity_digest": _DIGEST_C,
        "filed_governance_integrity_revocation_binding": {
            "status": "ACTIVE",
            "sequence": 7,
            "digest": local_adapter.canonical_integrity_hash(
                {"status": "ACTIVE", "sequence": 7}
            ),
        },
        "filed_governance_integrity_authority_granted": False,
        "filed_governance_integrity_licence_granted": False,
        "filed_governance_integrity_execution_authority_granted": False,
        "filed_governance_integrity_effect_granted": False,
        "filed_governance_integrity_bypass_permitted": False,
        "filed_licence_digest": _DIGEST_C,
        "license_tier": "PERSONAL",
        "licence_id": "licence-one",
        "licence_revocation_status": "ACTIVE",
        "licence_revocation_sequence": 7,
        "filed_licence_record": {
            "evaluation_snapshot": {"bindings": {"identity": "subject-one"}}
        },
        "filed_framework_digest": _DIGEST_D,
        "resolved_authority": {"authority": "authority-one"},
        "jurisdiction": {"jurisdiction": "jurisdiction-one"},
    }
    foundational_record: dict[str, str] = {}
    for field in local_adapter._FOUNDATIONAL_EFFECT_FIELDS:
        if field.startswith("application_integrity_") or field == (
            "foundational_baseline_digest"
        ):
            state[field] = _DIGEST_E
        else:
            foundational_record[field] = _DIGEST_E
    state["foundational_baseline_record"] = foundational_record
    for field in local_adapter._AUTHORITY_PROVENANCE_EFFECT_FIELDS:
        state[field] = _DIGEST_E
    return state


def _point_of_use_evidence() -> dict[str, object]:
    return {
        "digest": _DIGEST_E,
        "determination": {
            "revocation_status": "ACTIVE",
            "revocation_sequence": 7,
        }
    }


def _hybrid_trust_contexts() -> local_adapter.LocalEffectHybridTrustContexts:
    provider = BoundaryEvidenceProvider(
        role="execution-skg-lifecycle-integration",
        effect_authority=True,
        three_p_attestation_admitted=True,
    )
    context = provider.hybrid_verification_context()
    return local_adapter.LocalEffectHybridTrustContexts(
        authority=context,
        authority_owner_pin=context.context_digest,
        receipt=context,
        receipt_owner_pin=context.context_digest,
        three_p=context,
        three_p_owner_pin=context.context_digest,
        skg=context,
        skg_owner_pin=context.context_digest,
        filed_framework=context,
        filed_framework_owner_pin=context.context_digest,
        filed_licence=context,
        filed_licence_owner_pin=context.context_digest,
        filed_lifecycle=context,
        filed_lifecycle_owner_pin=context.context_digest,
        filed_governance_integrity=context,
        filed_governance_integrity_owner_pin=context.context_digest,
    )


def test_effect_binding_includes_skg_and_lifecycle_digests() -> None:
    state = _binding_state()
    binding = local_adapter._effect_binding(
        state,
        adapter_id=_DIGEST_E,
        handler_id="handler-one",
        licence_point_of_use_evidence=_point_of_use_evidence(),
    )

    assert binding["skg_authority_digest"] == _DIGEST_E
    assert binding["skg_authority_trace_digest"] == _DIGEST_A
    assert binding["filed_lifecycle_digest"] == _DIGEST_B
    for field in local_adapter._AUTHORITY_PROVENANCE_EFFECT_FIELDS:
        assert binding[field] == _DIGEST_E

    changed = _binding_state()
    changed["filed_lifecycle_digest"] = _DIGEST_D
    changed_binding = local_adapter._effect_binding(
        changed,
        adapter_id=_DIGEST_E,
        handler_id="handler-one",
        licence_point_of_use_evidence=_point_of_use_evidence(),
    )
    assert changed_binding["effect_id"] != binding["effect_id"]


def test_effect_binding_fails_closed_without_skg_or_lifecycle_digest() -> None:
    for field, code in (
        ("skg_authority_digest", "EFFECT_BINDING_SKG_AUTHORITY_INVALID"),
        ("filed_lifecycle_digest", "EFFECT_BINDING_FILED_LIFECYCLE_INVALID"),
    ):
        state = _binding_state()
        del state[field]
        with pytest.raises(local_adapter.LocalEffectError, match=code):
            local_adapter._effect_binding(
                state,
                adapter_id=_DIGEST_E,
                handler_id="handler-one",
                licence_point_of_use_evidence=_point_of_use_evidence(),
            )


def test_adapter_mint_uses_stored_governance_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = object.__new__(local_adapter.ControlledLocalAdapter)
    governance_provider = BoundaryEvidenceProvider(
        role="stored-governance-dependencies",
        effect_authority=False,
        three_p_attestation_admitted=False,
        framework_attestation_admitted=True,
        licence_attestation_admitted=True,
        skg_attestation_admitted=True,
        lifecycle_attestation_admitted=True,
        governance_integrity_attestation_admitted=True,
    )
    skg_evaluator = object()
    skg_provider = governance_provider
    lifecycle_evaluator = object()
    lifecycle_provider = governance_provider
    governance_integrity_evaluator = object()
    governance_integrity_provider = governance_provider
    adapter._skg_evaluator = skg_evaluator
    adapter._skg_attestation_provider = skg_provider
    adapter._filed_framework_evaluator = object()
    adapter._filed_framework_attestation_provider = governance_provider
    adapter._filed_licence_evaluator = object()
    adapter._filed_licence_attestation_provider = governance_provider
    adapter._filed_lifecycle_evaluator = lifecycle_evaluator
    adapter._filed_lifecycle_attestation_provider = lifecycle_provider
    adapter._filed_governance_integrity_evaluator = (
        governance_integrity_evaluator
    )
    adapter._filed_governance_integrity_attestation_provider = (
        governance_integrity_provider
    )
    adapter._max_permit_ttl_ms = 1_000
    adapter._receipt_provider = SimpleNamespace(key_id="receipt-key")
    adapter._adapter_id = _DIGEST_A
    adapter._observe_time = lambda: 100
    adapter._handler_for_state = lambda state: SimpleNamespace(
        handler_id="handler-one"
    )
    calls: dict[str, tuple[object, object]] = {}

    monkeypatch.setattr(
        local_adapter,
        "verify_hash_chain_entries",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_three_p_core",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "_foundational_current_and_unchanged",
        lambda *args, **kwargs: True,
    )

    def verify_skg(*args: object, **kwargs: object) -> bool:
        calls["skg"] = (kwargs["evaluator"], kwargs["attestation_provider"])
        return True

    def verify_lifecycle(*args: object, **kwargs: object) -> bool:
        calls["lifecycle"] = (
            kwargs["evaluator"],
            kwargs["attestation_provider"],
        )
        return True

    def verify_governance_integrity(
        *args: object, **kwargs: object
    ) -> bool:
        calls["governance_integrity"] = (
            kwargs["evaluator"],
            kwargs["attestation_provider"],
        )
        return True

    monkeypatch.setattr(local_adapter, "verify_skg_authority", verify_skg)
    monkeypatch.setattr(local_adapter, "verify_filed_lifecycle", verify_lifecycle)
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_governance_integrity",
        verify_governance_integrity,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_frameworks",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_licence",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "probe_filed_licence_current",
        lambda *args, **kwargs: (_point_of_use_evidence(), None),
    )
    monkeypatch.setattr(local_adapter, "verify_token", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        local_adapter,
        "get_required_threshold_tokens",
        lambda state: [],
    )
    monkeypatch.setattr(
        local_adapter,
        "_effect_binding",
        lambda *args, **kwargs: {"effect_id": _DIGEST_B},
    )
    monkeypatch.setattr(
        local_adapter,
        "build_signed_object",
        lambda body, **kwargs: {
            **body,
            "digest": _DIGEST_C,
            "signature": "signature",
            "verified": True,
        },
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_signed_object",
        lambda *args, **kwargs: True,
    )
    state = {
        "execution_result": "EXECUTE",
        "decision": EXECUTION_APPROVED,
        "hash_chain": [{"stage": "execution_gate", "hash": _DIGEST_D}],
        "state_hash": _DIGEST_D,
    }
    authority_provider = SimpleNamespace(
        effect_authority=True,
        key_id="authority-key",
    )

    adapter.build_permit(
        state,
        authority_provider=authority_provider,
        three_p_attestation_provider=object(),
        ttl_ms=500,
        hybrid_trust_contexts=_hybrid_trust_contexts(),
    )

    assert calls["skg"] == (skg_evaluator, skg_provider)
    assert calls["lifecycle"] == (lifecycle_evaluator, lifecycle_provider)
    assert calls["governance_integrity"] == (
        governance_integrity_evaluator,
        governance_integrity_provider,
    )


def test_adapter_dispatch_fails_closed_when_lifecycle_is_not_current(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = object.__new__(local_adapter.ControlledLocalAdapter)
    governance_provider = BoundaryEvidenceProvider(
        role="dispatch-lifecycle-currentness",
        effect_authority=False,
        three_p_attestation_admitted=False,
        framework_attestation_admitted=True,
        licence_attestation_admitted=True,
        skg_attestation_admitted=True,
        lifecycle_attestation_admitted=True,
        governance_integrity_attestation_admitted=True,
    )
    adapter._max_permit_ttl_ms = 1_000
    permit_fields = {
        "schema",
        "permit_id",
        "request_fingerprint",
        "issued_state_hash",
        "action",
        "payload_digest",
        "candidate_digest",
        "authority_digest",
        "jurisdiction_digest",
        "three_p_core_digest",
        "three_p_trace_hash",
        "skg_authority_digest",
        "skg_authority_trace_digest",
        "filed_lifecycle_digest",
        "filed_licence_digest",
        "license_tier",
        "licence_id",
        "licence_bindings_digest",
        "licence_revocation_status",
        "licence_revocation_sequence",
        "licence_point_of_use_evidence_digest",
        "licence_point_of_use_revocation_sequence",
        "filed_framework_digest",
        "token_stack_digest",
        "adapter_id",
        "handler_id",
        "effect_id",
        "issued_chain_index",
        "issued_chain_stage",
        "issued_at_ms",
        "expires_at_ms",
        "digest",
        "signature",
            "verified",
            *local_adapter._FOUNDATIONAL_EFFECT_FIELDS,
            *local_adapter._AUTHORITY_PROVENANCE_EFFECT_FIELDS,
            *local_adapter._GOVERNANCE_INTEGRITY_EFFECT_FIELDS,
        }
    permit = {field: "value" for field in permit_fields}
    permit.update(
        {
            "schema": local_adapter.PERMIT_SCHEMA,
            "permit_id": "a" * 32,
            "issued_at_ms": 100,
            "expires_at_ms": 200,
        }
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_signed_object",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_hash_chain_entries",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_three_p_core",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "_foundational_current_and_unchanged",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_skg_authority",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_frameworks",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_licence",
        lambda *args, **kwargs: True,
    )
    monkeypatch.setattr(
        local_adapter,
        "verify_filed_lifecycle",
        lambda *args, **kwargs: False,
    )

    with pytest.raises(
        local_adapter.LocalEffectError,
        match="EFFECT_POINT_OF_USE_FILED_LIFECYCLE_INVALID",
    ):
        adapter._verify_permit(
            {},
            permit,
            authority_provider=object(),
            three_p_attestation_provider=object(),
            skg_evaluator=object(),
            skg_attestation_provider=governance_provider,
            filed_framework_evaluator=object(),
            filed_framework_attestation_provider=governance_provider,
            filed_licence_evaluator=object(),
            filed_licence_attestation_provider=governance_provider,
            filed_lifecycle_evaluator=object(),
            filed_lifecycle_attestation_provider=governance_provider,
            filed_governance_integrity_evaluator=object(),
            filed_governance_integrity_attestation_provider=(
                governance_provider
            ),
            application_integrity_bundle=None,
            application_integrity_result=None,
            foundational_request_dependencies=None,
            now_ms=150,
            hybrid_trust_contexts=_hybrid_trust_contexts(),
        )
