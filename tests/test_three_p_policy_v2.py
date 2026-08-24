from __future__ import annotations

from copy import deepcopy

from sbp_lex.governance.three_p_policy_v2 import (
    ImplementationDefinedV2ThreePEvaluator,
    THREE_P_POLICY_CLASSIFICATION,
    THREE_P_POLICY_SCHEMA_ID,
    validate_three_p_policy,
)
from sbp_lex.security.integrity import GENESIS_HASH, canonical_integrity_hash
from sbp_lex.security.hybrid_signature import HybridMLDSA87Ed448SoftwareProvider


def _policy() -> dict:
    primitives = {}
    for primitive in ("P1", "P2", "P3"):
        primitives[primitive] = {
            "rules": [{
                "rule_id": f"{primitive}-external-rule",
                "evidence_type": f"{primitive}-evidence",
                "authority_id": "proposed-test-evidence-authority",
                "field": "policy_defined_measure",
                "comparator": "GTE",
                "threshold_id": "policy_defined_threshold",
            }],
            "thresholds": {"policy_defined_threshold": 10},
            "decision_logic": {"operator": "ALL", "required_rule_ids": [f"{primitive}-external-rule"]},
        }
    return {
        "schema_id": THREE_P_POLICY_SCHEMA_ID,
        "classification": THREE_P_POLICY_CLASSIFICATION,
        "policy_id": "AI_PROPOSED_TEST_ONLY_POLICY",
        "policy_version": "AI_PROPOSED_AWAITING_APPROVAL-1",
        "effective_from": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z",
        "authority": {"credential_id": "AI_PROPOSED_TEST_ONLY_CREDENTIAL", "evidence_authorities": ["proposed-test-evidence-authority"]},
        "lifecycle": {"state": "ACTIVE", "revision": 1, "supersedes": None, "revoked_at": None, "revocation_reason": None},
        "primitives": primitives,
        "fixtures": [{"fixture_id": "AI_PROPOSED_TEST_ONLY_FIXTURE", "input_digest": canonical_integrity_hash({"fixture": 1}), "expected": {"P1": "SATISFIED", "P2": "SATISFIED", "P3": "SATISFIED"}}],
    }


def _snapshot() -> dict:
    return {"evaluation_sequence": 1, "request_fingerprint": "request", "state_hash": GENESIS_HASH, "evaluation_time": "2026-06-01T00:00:00Z", "prior_three_p_digest": None}


def _provider() -> HybridMLDSA87Ed448SoftwareProvider:
    return HybridMLDSA87Ed448SoftwareProvider.generate(
        provider_id="TEST_ONLY:three-p-policy",
        three_p_attestation_admitted=True,
    )


def test_contract_requires_every_external_semantic_component() -> None:
    policy = _policy()
    assert validate_three_p_policy(policy) == ()
    for field in ("authority", "lifecycle", "primitives", "fixtures"):
        incomplete = deepcopy(policy)
        incomplete.pop(field)
        assert validate_three_p_policy(incomplete)


def test_absent_policy_fails_closed_for_all_primitives() -> None:
    evaluator = ImplementationDefinedV2ThreePEvaluator(policy=None, evidence_resolver=None, attestation_provider=_provider(), evaluator_id="adapter", evaluator_version="1")
    result = evaluator.evaluate(stage="three_p_core:test", snapshot=_snapshot())
    assert {item["result"] for item in result["determinations"].values()} == {"NOT_SATISFIED"}


def test_revoked_policy_fails_closed() -> None:
    policy = _policy()
    policy["lifecycle"]["state"] = "REVOKED"
    policy["lifecycle"]["revoked_at"] = "2026-05-01T00:00:00Z"
    policy["lifecycle"]["revocation_reason"] = "test-only revocation reason"
    evaluator = ImplementationDefinedV2ThreePEvaluator(policy=policy, evidence_resolver=lambda *_: None, attestation_provider=_provider(), evaluator_id="adapter", evaluator_version="1")
    result = evaluator.evaluate(stage="three_p_core:test", snapshot=_snapshot())
    assert all(item["result"] == "NOT_SATISFIED" for item in result["determinations"].values())


def test_supplied_policy_and_authorized_evidence_are_interpreted() -> None:
    def resolve(evidence_type: str, authority_id: str, snapshot: dict) -> dict:
        values = {"policy_defined_measure": 11}
        return {"evidence_id": evidence_type, "source": "proposed-test-source", "authority_id": authority_id, "values": values, "digest": canonical_integrity_hash(values)}

    evaluator = ImplementationDefinedV2ThreePEvaluator(policy=_policy(), evidence_resolver=resolve, attestation_provider=_provider(), evaluator_id="adapter", evaluator_version="1")
    result = evaluator.evaluate(stage="three_p_core:test", snapshot=_snapshot())
    assert all(item["result"] == "SATISFIED" for item in result["determinations"].values())


def test_indeterminate_evidence_fails_closed() -> None:
    evaluator = ImplementationDefinedV2ThreePEvaluator(policy=_policy(), evidence_resolver=lambda *_: None, attestation_provider=_provider(), evaluator_id="adapter", evaluator_version="1")
    result = evaluator.evaluate(stage="three_p_core:test", snapshot=_snapshot())
    assert all(item["result"] == "NOT_SATISFIED" for item in result["determinations"].values())


def test_evidence_resolver_error_fails_closed() -> None:
    def unavailable(*_: object) -> dict:
        raise RuntimeError("external evidence unavailable")

    evaluator = ImplementationDefinedV2ThreePEvaluator(policy=_policy(), evidence_resolver=unavailable, attestation_provider=_provider(), evaluator_id="adapter", evaluator_version="1")
    result = evaluator.evaluate(stage="three_p_core:test", snapshot=_snapshot())
    assert all(item["result"] == "NOT_SATISFIED" for item in result["determinations"].values())
