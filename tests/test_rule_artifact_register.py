from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.rules.rule_artifact_register import (
    ARTIFACT_ACTIVE,
    RULE_ARTIFACT_CLASSES,
    RULE_ARTIFACT_DENY,
    RULE_ARTIFACT_ESCALATE,
    RULE_ARTIFACT_PASS,
    RULE_ARTIFACT_SOURCE_ROLE,
    RULE_REGISTER_ADMISSION_STAGE,
    RULE_REGISTER_CONTRACT_ID,
    RULE_REGISTER_EVALUATOR_ROLE,
    RULE_REGISTER_REVALIDATION_STAGE,
    RULE_REGISTER_SCHEMA_STATUS,
    RULE_ARTIFACT_SIGNING_PURPOSE,
    evaluate_rule_artifact_register,
    verify_rule_artifact_register,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object,
    verify_legacy_non_effect_signed_object,
)


class RuleEvidenceProvider:
    def __init__(self, *, admitted: bool = True) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="RULE_ARTIFACT_TEST_ONLY_HYBRID",
            key_epoch=1,
        )
        self.rule_artifact_attestation_admitted = admitted

    def __getattr__(self, name):
        return getattr(self._provider, name)


class LegacyRuleEvidenceProvider:
    rule_artifact_attestation_admitted = True

    def __init__(self) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )

    def __getattr__(self, name):
        return getattr(self._provider, name)


def artifact(rule_class: str, index: int = 1) -> dict:
    credential_id = f"{rule_class}-source-authority"
    return {
        "rule_class": rule_class,
        "artifact_id": f"{rule_class}-artifact-{index}",
        "artifact_version": "1",
        "jurisdiction": "AU",
        "authority_credential": {
            "credential_id": credential_id,
            "authority_role": RULE_ARTIFACT_SOURCE_ROLE,
            "credential_digest": canonical_integrity_hash(
                {"credential_id": credential_id}
            ),
        },
        "provenance": {
            "source_id": f"{rule_class}-source-{index}",
            "source_locator": f"authority://AU/{rule_class}/{index}",
            "source_version": "1",
            "source_digest": canonical_integrity_hash(
                {"source": rule_class, "index": index}
            ),
            "issuing_authority_id": credential_id,
        },
        "effective_from": 1_600_000_000,
        "effective_until": 1_800_000_000,
        "status": ARTIFACT_ACTIVE,
        "revocation_sequence": 1,
        "artifact_digest": canonical_integrity_hash(
            {"artifact": rule_class, "index": index}
        ),
    }


class RuleArtifactEvaluatorFixture:
    evaluator_id = "rule-artifact-register-authority"
    evaluator_version = "1"
    authority_role = RULE_REGISTER_EVALUATOR_ROLE
    authority_credential_id = "rule-artifact-register-credential"

    def __init__(self, provider: RuleEvidenceProvider) -> None:
        self.provider = provider
        self.artifacts = [artifact(rule_class) for rule_class in RULE_ARTIFACT_CLASSES]
        self.conflicts: list[dict] = []
        self.cached_source: dict | None = None
        self.replay = False

    def evaluate_rule_artifacts(self, *, stage: str, snapshot: dict) -> dict:
        if self.replay and self.cached_source is not None:
            return deepcopy(self.cached_source)
        determination = {
            "result": RULE_ARTIFACT_ESCALATE if self.conflicts else RULE_ARTIFACT_PASS,
            "register_version": snapshot["register_version"],
            "artifacts": deepcopy(self.artifacts),
            "conflicts": deepcopy(self.conflicts),
            "universal_precedence_declared": False,
            "legal_interpretation_performed": False,
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
            "pipeline_bypass_permitted": False,
        }
        source = build_hybrid_signed_object(
            {
                "contract_id": RULE_REGISTER_CONTRACT_ID,
                "schema_status": RULE_REGISTER_SCHEMA_STATUS,
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["pre_evaluation_state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "register_version": snapshot["register_version"],
                "prior_register_digest": snapshot["prior_register_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
            purpose=RULE_ARTIFACT_SIGNING_PURPOSE,
        )
        self.cached_source = deepcopy(source)
        return source


class RuleArtifactRegisterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.owner_pins: dict[int, object] = {}

    def provider(self, *, admitted: bool = True) -> RuleEvidenceProvider:
        provider = RuleEvidenceProvider(admitted=admitted)
        self.owner_pins[id(provider)] = provider.hybrid_verification_context(
            allow_test_only=True
        )
        return provider

    def state(self) -> dict:
        request = {"request_id": "rule-register-request-1"}
        return {
            "request_fingerprint": canonical_integrity_hash(request),
            "state_hash": canonical_integrity_hash({"state": "pre-rule-register"}),
            "evaluation_time": 1_700_000_000,
            "rule_artifact_register_version": "rule-register-v1",
        }

    def evaluate(
        self,
        state,
        evaluator,
        provider,
        *,
        stage=RULE_REGISTER_ADMISSION_STAGE,
    ):
        context = self.owner_pins.get(id(provider))
        evaluate_rule_artifact_register(
            state,
            stage=stage,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest=(
                context.context_digest if context is not None else None
            ),
        )

    def verify(self, state, evaluator, provider, **kwargs) -> bool:
        context = self.owner_pins.get(id(provider))
        return verify_rule_artifact_register(
            state,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest=(
                context.context_digest if context is not None else None
            ),
            **kwargs,
        )

    def test_exact_four_classes_canonical_and_non_authorizing(self) -> None:
        provider = self.provider()
        evaluator = RuleArtifactEvaluatorFixture(provider)
        evaluator.artifacts.insert(2, artifact("statutory", 2))
        state = self.state()
        self.evaluate(state, evaluator, provider)

        self.assertEqual(state["rule_artifact_register_result"], RULE_ARTIFACT_PASS)
        self.assertEqual(
            {item["rule_class"] for item in state["rule_artifact_register_record"]["artifacts"]},
            set(RULE_ARTIFACT_CLASSES),
        )
        self.assertFalse(
            state["rule_artifact_register_universal_precedence_declared"]
        )
        self.assertFalse(
            state["rule_artifact_register_legal_interpretation_performed"]
        )
        self.assertTrue(
            self.verify(state, evaluator, provider)
        )

    def test_missing_duplicate_extra_and_noncanonical_artifacts_fail_closed(self) -> None:
        provider = self.provider()
        for mutation in (
            "missing",
            "duplicate",
            "cross_class_duplicate",
            "extra",
            "reordered",
            "extra_field",
        ):
            with self.subTest(mutation=mutation):
                evaluator = RuleArtifactEvaluatorFixture(provider)
                if mutation == "missing":
                    evaluator.artifacts.pop()
                elif mutation == "duplicate":
                    evaluator.artifacts.insert(1, deepcopy(evaluator.artifacts[0]))
                elif mutation == "cross_class_duplicate":
                    evaluator.artifacts[1]["artifact_id"] = evaluator.artifacts[0][
                        "artifact_id"
                    ]
                    evaluator.artifacts[1]["artifact_version"] = (
                        evaluator.artifacts[0]["artifact_version"]
                    )
                elif mutation == "extra":
                    extra = artifact("constitutional")
                    extra["rule_class"] = "institutional"
                    extra["artifact_id"] = "institutional-artifact"
                    evaluator.artifacts.append(extra)
                elif mutation == "reordered":
                    evaluator.artifacts.reverse()
                else:
                    evaluator.artifacts[0]["interpretation"] = "invented"
                state = self.state()
                self.evaluate(state, evaluator, provider)
                self.assertEqual(
                    state["rule_artifact_register_result"], RULE_ARTIFACT_DENY
                )

    def test_bad_provenance_credential_stale_and_revoked_fail_closed(self) -> None:
        provider = self.provider()
        mutations = ("provenance", "credential", "stale", "future", "revoked")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                evaluator = RuleArtifactEvaluatorFixture(provider)
                target = evaluator.artifacts[0]
                if mutation == "provenance":
                    target["provenance"]["source_digest"] = "bad"
                elif mutation == "credential":
                    target["authority_credential"]["credential_digest"] = "bad"
                elif mutation == "stale":
                    target["effective_until"] = 1_700_000_000
                elif mutation == "future":
                    target["effective_from"] = 1_700_000_001
                else:
                    target["status"] = "REVOKED"
                state = self.state()
                self.evaluate(state, evaluator, provider)
                self.assertEqual(
                    state["rule_artifact_register_result"], RULE_ARTIFACT_DENY
                )

    def test_unavailable_unadmitted_and_wrong_signature_fail_closed(self) -> None:
        signing_provider = self.provider()
        evaluator = RuleArtifactEvaluatorFixture(signing_provider)
        for candidate_evaluator, candidate_provider in (
            (None, signing_provider),
            (evaluator, None),
            (evaluator, self.provider(admitted=False)),
            (evaluator, self.provider()),
        ):
            with self.subTest(
                evaluator=candidate_evaluator, provider=candidate_provider
            ):
                state = self.state()
                self.evaluate(state, candidate_evaluator, candidate_provider)
                self.assertEqual(
                    state["rule_artifact_register_result"], RULE_ARTIFACT_DENY
                )

    def test_owner_pin_is_independent_and_legacy_cannot_enter_register(self) -> None:
        provider = self.provider()
        evaluator = RuleArtifactEvaluatorFixture(provider)

        missing_pin_state = self.state()
        evaluate_rule_artifact_register(
            missing_pin_state,
            stage=RULE_REGISTER_ADMISSION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=None,
            owner_pinned_context_digest=None,
        )
        self.assertEqual(
            missing_pin_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        )

        bad_digest_state = self.state()
        evaluate_rule_artifact_register(
            bad_digest_state,
            stage=RULE_REGISTER_ADMISSION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=self.owner_pins[id(provider)],
            owner_pinned_context_digest="0" * 128,
        )
        self.assertEqual(
            bad_digest_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        )

        wrong_provider = self.provider()
        wrong_pin = self.owner_pins[id(wrong_provider)]
        wrong_pin_state = self.state()
        evaluate_rule_artifact_register(
            wrong_pin_state,
            stage=RULE_REGISTER_ADMISSION_STAGE,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=wrong_pin,
            owner_pinned_context_digest=wrong_pin.context_digest,
        )
        self.assertEqual(
            wrong_pin_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_SIGNATURE_INVALID",
        )

        legacy = LegacyRuleEvidenceProvider()
        legacy_object = build_legacy_non_effect_signed_object(
            {"legacy_test_only_non_effect": True}, provider=legacy
        )
        self.assertTrue(
            verify_legacy_non_effect_signed_object(
                legacy_object, provider=legacy
            )
        )
        legacy_state = self.state()
        self.evaluate(legacy_state, evaluator, legacy)
        self.assertEqual(
            legacy_state["rule_artifact_register_result"], RULE_ARTIFACT_DENY
        )
        self.assertFalse(
            legacy_state["rule_artifact_register_effect_authority_granted"]
        )

    def test_unresolved_conflict_only_escalates_and_never_resolves(self) -> None:
        provider = self.provider()
        evaluator = RuleArtifactEvaluatorFixture(provider)
        evaluator.conflicts = [
            {
                "conflict_id": "conflict-1",
                "artifact_references": [
                    {
                        "rule_class": item["rule_class"],
                        "artifact_id": item["artifact_id"],
                        "artifact_version": item["artifact_version"],
                    }
                    for item in evaluator.artifacts[:2]
                ],
                "status": "UNRESOLVED",
                "escalation_required": True,
                "resolution_authority_credential": None,
                "resolution_digest": None,
            }
        ]
        state = self.state()
        self.evaluate(state, evaluator, provider)
        self.assertEqual(
            state["rule_artifact_register_result"], RULE_ARTIFACT_ESCALATE
        )
        self.assertTrue(
            self.verify(state, evaluator, provider)
        )

        resolved = RuleArtifactEvaluatorFixture(provider)
        resolved.conflicts = deepcopy(evaluator.conflicts)
        resolved.conflicts[0].update(
            {
                "status": "RESOLVED",
                "escalation_required": False,
                "resolution_authority_credential": {
                    "credential_id": "invented-resolution"
                },
                "resolution_digest": canonical_integrity_hash(
                    {"invented": "resolution"}
                ),
            }
        )
        resolved_state = self.state()
        self.evaluate(resolved_state, resolved, provider)
        self.assertEqual(
            resolved_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_CONFLICT_RESOLUTION_NOT_ADMITTED",
        )

    def test_tamper_replay_and_revocation_rollback_fail_closed(self) -> None:
        provider = self.provider()
        evaluator = RuleArtifactEvaluatorFixture(provider)
        state = self.state()
        self.evaluate(state, evaluator, provider)

        tampered = deepcopy(state)
        tampered["rule_artifact_register_trace"][0]["evaluation_source"][
            "determination"
        ]["artifacts"][0]["artifact_digest"] = "0" * 128
        tampered["rule_artifact_register_trace"][0]["evaluation_source_digest"] = (
            canonical_integrity_hash(
                tampered["rule_artifact_register_trace"][0]["evaluation_source"]
            )
        )
        tampered["rule_artifact_register_record"] = deepcopy(
            tampered["rule_artifact_register_trace"][0]
        )
        tampered["rule_artifact_register_digest"] = canonical_integrity_hash(
            tampered["rule_artifact_register_trace"]
        )
        self.assertFalse(
            self.verify(tampered, evaluator, provider)
        )

        replay_evaluator = RuleArtifactEvaluatorFixture(provider)
        replay_state = self.state()
        self.evaluate(replay_state, replay_evaluator, provider)
        replay_evaluator.replay = True
        self.evaluate(
            replay_state,
            replay_evaluator,
            provider,
            stage=RULE_REGISTER_REVALIDATION_STAGE,
        )
        self.assertEqual(
            replay_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_ATTESTATION_REPLAY",
        )

        rollback_evaluator = RuleArtifactEvaluatorFixture(provider)
        rollback_evaluator.artifacts[0]["revocation_sequence"] = 4
        rollback_state = self.state()
        self.evaluate(rollback_state, rollback_evaluator, provider)
        rollback_evaluator.artifacts[0]["revocation_sequence"] = 3
        self.evaluate(
            rollback_state,
            rollback_evaluator,
            provider,
            stage=RULE_REGISTER_REVALIDATION_STAGE,
        )
        self.assertEqual(
            rollback_state["rule_artifact_register_reason"],
            "RULE_ARTIFACT_REVOCATION_ROLLBACK",
        )


if __name__ == "__main__":
    unittest.main()
