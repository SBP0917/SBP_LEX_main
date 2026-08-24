from __future__ import annotations

from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.governance.filed_governance_integrity import (
    AUTHORITY_ANOMALY_DETECTION,
    AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE,
    BLACK_SWAN_DETECTION_ARCHITECTURE,
    CRISIS_PROPAGATION_MODELLING,
    FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE,
    FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE,
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY,
    FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_DENY,
    GOVERNANCE_INTEGRITY_ESCALATE,
    GOVERNANCE_INTEGRITY_PASS,
    STRATEGIC_INSTABILITY_EARLY_WARNING,
    evaluate_filed_governance_integrity,
    filed_governance_integrity_hash_payload,
    governance_integrity_revocation_binding,
    verify_filed_governance_integrity,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)


class GovernanceIntegrityProvider:
    token_signing_admitted = True

    def __init__(self) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:FILED_GOVERNANCE_INTEGRITY",
            key_epoch=1,
            key_version="test-1",
        )
        self.governance_integrity_attestation_admitted = True

    def __getattr__(self, name):
        return getattr(self._provider, name)


def _trust(provider: GovernanceIntegrityProvider | None) -> dict:
    if provider is None:
        return {
            "attestation_trust_context": None,
            "owner_pinned_context_digest": None,
        }
    context = provider.hybrid_verification_context(allow_test_only=True)
    return {
        "attestation_trust_context": context,
        "owner_pinned_context_digest": context.context_digest,
    }


class GovernanceIntegrityEvaluator:
    evaluator_id = "filed-governance-integrity-evidence"
    evaluator_version = "1"
    authority_role = FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE
    authority_credential_id = "filed-governance-integrity-credential"

    def __init__(self, provider: GovernanceIntegrityProvider) -> None:
        self.provider = provider
        self.result = GOVERNANCE_INTEGRITY_PASS
        self.signing_purpose = (
            FILED_GOVERNANCE_INTEGRITY_ATTESTATION_PURPOSE
        )
        self.determination_overrides: dict[str, object] = {}
        self.replay_source: dict | None = None
        self.return_unsigned = False
        self.raise_error = False
        self.calls = 0

    def _evaluate(
        self,
        governance_function: str,
        *,
        stage: str,
        snapshot: dict,
    ) -> dict:
        self.calls += 1
        if self.raise_error:
            raise RuntimeError("evaluator unavailable")
        if self.replay_source is not None:
            return deepcopy(self.replay_source)
        function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ]
        determination = {
            "result": self.result,
            "evidence_references": [
                {
                    "evidence_id": (
                        f"{function_id}:{snapshot['evaluation_sequence']}"
                    ),
                    "source": "admitted-governance-integrity-evidence",
                    "digest": canonical_integrity_hash(
                        {
                            "function": governance_function,
                            "stage": stage,
                            "sequence": snapshot["evaluation_sequence"],
                        }
                    ),
                }
            ],
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_granted": False,
            "bypass_permitted": False,
        }
        determination.update(self.determination_overrides)
        revocation = snapshot["revocation_binding"]
        body = {
            "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
            "result_vocabulary_authority": (
                FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
            ),
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "authority_credential": {
                "credential_id": self.authority_credential_id,
                "authority_role": self.authority_role,
            },
            "governance_integrity_function": governance_function,
            "function_id": function_id,
            "stage": stage,
            "evaluation_sequence": snapshot["evaluation_sequence"],
            "implementation_order_authority": (
                FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
            ),
            "request_fingerprint": snapshot["request_fingerprint"],
            "pre_evaluation_state_hash": snapshot["state_hash"],
            "evaluation_time": snapshot["evaluation_time"],
            "prior_governance_integrity_digest": snapshot[
                "prior_governance_integrity_digest"
            ],
            "three_p_core_digest": snapshot["three_p_core_digest"],
            "three_p_trace_hash": snapshot["three_p_trace_hash"],
            "skg_digest": snapshot["skg_digest"],
            "revocation_status": revocation["status"],
            "revocation_sequence": revocation["sequence"],
            "revocation_digest": revocation["digest"],
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determination": determination,
        }
        if self.return_unsigned:
            return body
        return build_hybrid_signed_object(
            body,
            provider=self.provider,
            purpose=self.signing_purpose,
        )

    def evaluate_black_swan_detection_architecture(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            BLACK_SWAN_DETECTION_ARCHITECTURE,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_crisis_propagation_modelling(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            CRISIS_PROPAGATION_MODELLING,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_authority_anomaly_detection(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            AUTHORITY_ANOMALY_DETECTION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_strategic_instability_early_warning(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            STRATEGIC_INSTABILITY_EARLY_WARNING,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_autonomous_containment_revocation_cascade(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            AUTONOMOUS_CONTAINMENT_REVOCATION_CASCADE,
            stage=stage,
            snapshot=snapshot,
        )


def _append_chain(state: dict, stage: str, payload: dict) -> None:
    previous_hash = (
        state["hash_chain"][-1]["hash"]
        if state["hash_chain"]
        else GENESIS_HASH
    )
    entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=stage,
        payload=payload,
    )
    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]


def _advance_three_p(state: dict, stage: str) -> None:
    sequence = len(state["three_p_trace"]) + 1
    digest = canonical_integrity_hash(
        {"three_p_stage": stage, "sequence": sequence}
    )
    trace_hash = canonical_integrity_hash(
        {
            "prior_trace_hash": state.get("three_p_trace_hash"),
            "three_p_core_digest": digest,
            "sequence": sequence,
        }
    )
    state["three_p_core_result"] = "PASS"
    state["three_p_core_digest"] = digest
    state["three_p_trace_hash"] = trace_hash
    state["three_p_trace"].append(
        {
            "three_p_core_digest": digest,
            "trace_hash": trace_hash,
        }
    )
    _append_chain(
        state,
        f"three_p_core:{stage}",
        {
            "three_p_core_digest": digest,
            "three_p_trace_hash": trace_hash,
        },
    )


def _state() -> dict:
    skg_record = {
        "result": "PASS",
        "authority_granted": False,
        "execution_authority_granted": False,
        "downstream_override_permitted": False,
        "evidence": "authenticated",
    }
    state = {
        "request_fingerprint": canonical_integrity_hash(
            {"request": "governance-integrity"}
        ),
        "evaluation_time": 123456,
        "hash_chain": [],
        "state_hash": "",
        "three_p_core_result": "",
        "three_p_core_digest": None,
        "three_p_trace_hash": None,
        "three_p_trace": [],
        "skg_authority_result": "PASS",
        "skg_authority_record": skg_record,
        "skg_authority_digest": canonical_integrity_hash(skg_record),
        "filed_governance_integrity_revocation_binding": (
            governance_integrity_revocation_binding(
                status="ACTIVE",
                sequence=7,
            )
        ),
        "filed_governance_integrity_trace": [],
        "filed_governance_integrity_results": {},
        "filed_governance_integrity_digest": None,
    }
    _append_chain(
        state,
        "state_construction",
        {"request_fingerprint": state["request_fingerprint"]},
    )
    return state


def _run_function(
    state: dict,
    governance_function: str,
    evaluator: GovernanceIntegrityEvaluator | None,
    provider: GovernanceIntegrityProvider | None,
) -> dict:
    stage = FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
    _advance_three_p(state, stage)
    evaluate_filed_governance_integrity(
        state,
        governance_function,
        evaluator=evaluator,
        attestation_provider=provider,
        **_trust(provider),
    )
    _append_chain(
        state,
        stage,
        filed_governance_integrity_hash_payload(state),
    )
    _advance_three_p(state, f"{stage}:post")
    return state


def _complete(
    evaluator: GovernanceIntegrityEvaluator,
    provider: GovernanceIntegrityProvider,
) -> dict:
    state = _state()
    for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER:
        _run_function(state, governance_function, evaluator, provider)
    return state


def test_exact_filed_names_and_implementation_defined_metadata_are_locked() -> None:
    assert FILED_GOVERNANCE_INTEGRITY_ORDER == (
        "Black Swan detection architecture",
        "Crisis propagation modelling",
        "Authority anomaly detection",
        "Strategic instability early warning",
        "Autonomous containment & revocation cascade",
    )
    assert "NOT_FILED" in FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS
    assert "NOT_FILED_ORDER" in FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
    assert "NOT_FILED_VOCABULARY" in (
        FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
    )
    assert FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY == (
        "PASS",
        "DENY",
        "ESCALATE",
    )


def test_complete_signed_traversal_is_bound_and_non_authorizing() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    state = _complete(evaluator, provider)

    assert verify_filed_governance_integrity(
        state,
        evaluator=evaluator,
        attestation_provider=provider,
        **_trust(provider),
    )
    assert evaluator.calls == 5
    assert state["filed_governance_integrity_results"] == {
        function: GOVERNANCE_INTEGRITY_PASS
        for function in FILED_GOVERNANCE_INTEGRITY_ORDER
    }
    for record in state["filed_governance_integrity_trace"]:
        assert record["authority_granted"] is False
        assert record["licence_granted"] is False
        assert record["execution_authority_granted"] is False
        assert record["effect_granted"] is False
        assert record["bypass_permitted"] is False
        assert set(record["evaluation_source"]["determination"]) == {
            "result",
            "evidence_references",
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_granted",
            "bypass_permitted",
        }


@pytest.mark.parametrize("missing", ["evaluator", "provider"])
def test_missing_dependencies_fail_closed(missing: str) -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    state = _state()
    function = FILED_GOVERNANCE_INTEGRITY_ORDER[0]
    stage = FILED_GOVERNANCE_INTEGRITY_STAGES[function]
    _advance_three_p(state, stage)

    evaluate_filed_governance_integrity(
        state,
        function,
        evaluator=None if missing == "evaluator" else evaluator,
        attestation_provider=None if missing == "provider" else provider,
        **_trust(None if missing == "provider" else provider),
    )

    assert state["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert "NOT_INJECTED" in state["filed_governance_integrity_reason"] or (
        "NOT_ADMITTED" in state["filed_governance_integrity_reason"]
    )
    assert evaluator.calls == 0


def test_missing_reordered_and_duplicate_functions_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    assert not verify_filed_governance_integrity(
        _state(),
        evaluator=evaluator,
        attestation_provider=provider,
        **_trust(provider),
    )

    reordered = _state()
    second = FILED_GOVERNANCE_INTEGRITY_ORDER[1]
    _run_function(reordered, second, evaluator, provider)
    assert reordered["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert reordered["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_EXECUTION_ORDER_INVALID"
    )

    evaluator = GovernanceIntegrityEvaluator(provider)
    duplicate = _state()
    first = FILED_GOVERNANCE_INTEGRITY_ORDER[0]
    _run_function(duplicate, first, evaluator, provider)
    _run_function(duplicate, first, evaluator, provider)
    assert duplicate["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert duplicate["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_EXECUTION_ORDER_INVALID"
    )


def test_unsigned_untrusted_tampered_and_replayed_evidence_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()

    unsigned_evaluator = GovernanceIntegrityEvaluator(provider)
    unsigned_evaluator.return_unsigned = True
    unsigned = _state()
    _run_function(
        unsigned,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        unsigned_evaluator,
        provider,
    )
    assert unsigned["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )

    untrusted_provider = GovernanceIntegrityProvider()
    untrusted_provider.governance_integrity_attestation_admitted = False
    untrusted_evaluator = GovernanceIntegrityEvaluator(untrusted_provider)
    untrusted = _state()
    _run_function(
        untrusted,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        untrusted_evaluator,
        untrusted_provider,
    )
    assert untrusted["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_PROVIDER_NOT_ADMITTED"
    )

    evaluator = GovernanceIntegrityEvaluator(provider)
    complete = _complete(evaluator, provider)
    complete["filed_governance_integrity_trace"][0]["evaluation_source"][
        "evaluation_time"
    ] += 1
    assert not verify_filed_governance_integrity(
        complete,
        evaluator=evaluator,
        attestation_provider=provider,
        require_hash_binding=False,
        **_trust(provider),
    )

    replay_evaluator = GovernanceIntegrityEvaluator(provider)
    replay = _state()
    first = FILED_GOVERNANCE_INTEGRITY_ORDER[0]
    second = FILED_GOVERNANCE_INTEGRITY_ORDER[1]
    _run_function(replay, first, replay_evaluator, provider)
    replay_evaluator.replay_source = deepcopy(
        replay["filed_governance_integrity_trace"][0]["evaluation_source"]
    )
    replay["evaluation_time"] += 1
    _run_function(replay, second, replay_evaluator, provider)
    assert replay["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert "BINDING_MISMATCH" in replay[
        "filed_governance_integrity_reason"
    ]


def test_revocation_and_rollback_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)

    revoked = _state()
    revoked["filed_governance_integrity_revocation_binding"] = (
        governance_integrity_revocation_binding(
            status="REVOKED",
            sequence=8,
        )
    )
    _run_function(
        revoked,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )
    assert revoked["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_REVOKED"
    )

    evaluator = GovernanceIntegrityEvaluator(provider)
    rollback = _state()
    _run_function(
        rollback,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )
    rollback["filed_governance_integrity_revocation_binding"] = (
        governance_integrity_revocation_binding(
            status="ACTIVE",
            sequence=6,
        )
    )
    _run_function(
        rollback,
        FILED_GOVERNANCE_INTEGRITY_ORDER[1],
        evaluator,
        provider,
    )
    assert rollback["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_REVOCATION_ROLLBACK"
    )


@pytest.mark.parametrize(
    "field",
    [
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_granted",
        "bypass_permitted",
    ],
)
def test_every_grant_or_bypass_attempt_fails_closed(field: str) -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    evaluator.determination_overrides[field] = True
    state = _state()

    _run_function(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )

    assert state["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert field.upper() in state["filed_governance_integrity_reason"]
    assert state[f"filed_governance_integrity_{field}"] is False


def test_evaluator_error_and_invalid_result_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    evaluator.raise_error = True
    state = _state()
    _run_function(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )
    assert "EVALUATOR_ERROR" in state["filed_governance_integrity_reason"]
    assert state["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )

    evaluator = GovernanceIntegrityEvaluator(provider)
    evaluator.result = "ALLOW"
    state = _state()
    _run_function(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )
    assert state["filed_governance_integrity_result"] == (
        GOVERNANCE_INTEGRITY_DENY
    )
    assert state["filed_governance_integrity_reason"].endswith(
        "_RESULT_INVALID"
    )


@pytest.mark.parametrize(
    "result",
    [GOVERNANCE_INTEGRITY_DENY, GOVERNANCE_INTEGRITY_ESCALATE],
)
def test_non_pass_results_never_grant_or_execute(result: str) -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    evaluator.result = result
    state = _state()
    _run_function(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator,
        provider,
    )

    assert state["filed_governance_integrity_result"] == result
    for field in (
        "authority_granted",
        "licence_granted",
        "execution_authority_granted",
        "effect_granted",
        "bypass_permitted",
    ):
        assert state[f"filed_governance_integrity_{field}"] is False


def test_hash_tamper_and_duplicate_hash_stage_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    original = _complete(evaluator, provider)

    tampered = deepcopy(original)
    function_stage = FILED_GOVERNANCE_INTEGRITY_STAGES[
        FILED_GOVERNANCE_INTEGRITY_ORDER[2]
    ]
    index = next(
        index
        for index, entry in enumerate(tampered["hash_chain"])
        if entry["stage"] == function_stage
    )
    tampered["hash_chain"][index]["payload_hash"] = "0" * 128
    assert not verify_filed_governance_integrity(
        tampered,
        evaluator=evaluator,
        attestation_provider=provider,
        **_trust(provider),
    )

    duplicate = deepcopy(original)
    _append_chain(
        duplicate,
        FILED_GOVERNANCE_INTEGRITY_STAGES[
            FILED_GOVERNANCE_INTEGRITY_ORDER[0]
        ],
        {"duplicate": True},
    )
    assert not verify_filed_governance_integrity(
        duplicate,
        evaluator=evaluator,
        attestation_provider=provider,
        **_trust(provider),
    )


def test_owner_pin_purpose_and_legacy_provider_fail_closed() -> None:
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    context = provider.hybrid_verification_context(allow_test_only=True)
    state = _state()
    _advance_three_p(
        state,
        FILED_GOVERNANCE_INTEGRITY_STAGES[
            FILED_GOVERNANCE_INTEGRITY_ORDER[0]
        ],
    )
    evaluate_filed_governance_integrity(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator=evaluator,
        attestation_provider=provider,
        attestation_trust_context=context,
        owner_pinned_context_digest="0" * 128,
    )
    assert state["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_OWNER_TRUST_PIN_INVALID"
    )

    wrong_purpose = GovernanceIntegrityEvaluator(provider)
    wrong_purpose.signing_purpose = "SBP_LEX_V2_WRONG_GOVERNANCE_PURPOSE"
    state = _state()
    _run_function(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        wrong_purpose,
        provider,
    )
    assert state["filed_governance_integrity_reason"].endswith(
        "_EVALUATION_ATTESTATION_INVALID"
    )

    class LegacyAdmittedProvider:
        algorithm = "Ed25519"
        governance_integrity_attestation_admitted = True

    state = _state()
    _advance_three_p(
        state,
        FILED_GOVERNANCE_INTEGRITY_STAGES[
            FILED_GOVERNANCE_INTEGRITY_ORDER[0]
        ],
    )
    evaluate_filed_governance_integrity(
        state,
        FILED_GOVERNANCE_INTEGRITY_ORDER[0],
        evaluator=GovernanceIntegrityEvaluator(provider),
        attestation_provider=LegacyAdmittedProvider(),
        **_trust(provider),
    )
    assert state["filed_governance_integrity_reason"] == (
        "FILED_GOVERNANCE_INTEGRITY_PROVIDER_NOT_ADMITTED"
    )
    assert not verify_filed_governance_integrity(
        _complete(GovernanceIntegrityEvaluator(provider), provider),
        evaluator=GovernanceIntegrityEvaluator(provider),
        attestation_provider=LegacyAdmittedProvider(),
        **_trust(provider),
    )
