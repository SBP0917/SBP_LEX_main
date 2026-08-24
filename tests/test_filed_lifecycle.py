from __future__ import annotations

from copy import deepcopy
import unittest

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.governance.filed_lifecycle import (
    AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
    CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION,
    FILED_LIFECYCLE_AUTHORITY_ROLE,
    FILED_LIFECYCLE_ATTESTATION_PURPOSE,
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_SCHEMA_STATUS,
    FILED_LIFECYCLE_STAGES,
    LIFECYCLE_DENY,
    LIFECYCLE_ESCALATE,
    LIFECYCLE_PASS,
    STRUCTURED_POST_AI_ERA_CONTINUITY,
    evaluate_filed_lifecycle,
    filed_lifecycle_hash_payload,
    verify_filed_lifecycle,
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


class LifecycleEvidenceProvider:
    token_signing_admitted = True

    def __init__(self) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
            MLDSA87PrivateKey.generate(),
            Ed448PrivateKey.generate(),
            provider_id="TEST_ONLY:FILED_LIFECYCLE",
            key_epoch=1,
            key_version="test-1",
        )
        self.lifecycle_attestation_admitted = True

    def __getattr__(self, name):
        return getattr(self._provider, name)


class LifecycleEvaluator:
    evaluator_id = "filed-lifecycle-evidence"
    evaluator_version = "1"
    authority_role = FILED_LIFECYCLE_AUTHORITY_ROLE
    authority_credential_id = "filed-lifecycle-evidence-credential"

    def __init__(self, provider: LifecycleEvidenceProvider) -> None:
        self.provider = provider
        self.calls = 0
        self.result = LIFECYCLE_PASS
        self.signing_purpose = FILED_LIFECYCLE_ATTESTATION_PURPOSE
        self.determination_overrides: dict[str, object] = {}
        self.extra_determination: dict[str, object] = {}
        self.return_unsigned = False
        self.replay_source: dict | None = None

    def _determination(self, engine: str, snapshot: dict) -> dict:
        determination = {
            "result": self.result,
            "transition_beyond_current_ai_paradigms_modelled": True,
            "full_lifecycle_governance_envelope_secured": True,
            "lawful_authority_continuity_preserved": True,
            "violent_or_coercive_interaction_prohibited": True,
            "bound_to_three_p": True,
            "bound_to_skg": True,
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
            "evidence_references": [
                {
                    "evidence_id": (
                        f"{FILED_LIFECYCLE_ENGINE_IDS[engine]}:"
                        f"{snapshot['evaluation_sequence']}"
                    ),
                    "source": "filed-lifecycle-contract-fixture",
                    "digest": canonical_integrity_hash(
                        {
                            "engine": engine,
                            "stage": snapshot["stage"],
                            "sequence": snapshot["evaluation_sequence"],
                        }
                    ),
                }
            ],
        }
        determination.update(self.determination_overrides)
        determination.update(self.extra_determination)
        return determination

    def _evaluate(self, engine: str, *, stage: str, snapshot: dict) -> dict:
        self.calls += 1
        if self.replay_source is not None:
            return deepcopy(self.replay_source)
        body = {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "authority_credential": {
                "credential_id": self.authority_credential_id,
                "authority_role": self.authority_role,
            },
            "lifecycle_engine": engine,
            "lifecycle_engine_id": FILED_LIFECYCLE_ENGINE_IDS[engine],
            "stage": stage,
            "evaluation_sequence": snapshot["evaluation_sequence"],
            "implementation_order_authority": (
                FILED_LIFECYCLE_ORDER_AUTHORITY
            ),
            "request_fingerprint": snapshot["request_fingerprint"],
            "pre_evaluation_state_hash": snapshot["state_hash"],
            "evaluation_time": snapshot["evaluation_time"],
            "prior_lifecycle_digest": snapshot["prior_lifecycle_digest"],
            "three_p_core_digest": snapshot["three_p_core_digest"],
            "three_p_trace_hash": snapshot["three_p_trace_hash"],
            "skg_digest": snapshot["skg_digest"],
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determination": self._determination(engine, snapshot),
        }
        if self.return_unsigned:
            return body
        return build_hybrid_signed_object(
            body,
            provider=self.provider,
            purpose=self.signing_purpose,
        )

    def evaluate_ai_obsolescence_lifecycle_supersession(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_civilisational_successor_intelligence_transition(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION,
            stage=stage,
            snapshot=snapshot,
        )

    def evaluate_structured_post_ai_era_continuity(
        self, *, stage: str, snapshot: dict
    ) -> dict:
        return self._evaluate(
            STRUCTURED_POST_AI_ERA_CONTINUITY,
            stage=stage,
            snapshot=snapshot,
        )


class FiledLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = LifecycleEvidenceProvider()
        self.evaluator = LifecycleEvaluator(self.provider)

    @staticmethod
    def trust(provider: LifecycleEvidenceProvider | None) -> dict:
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

    @staticmethod
    def _append_hash(state: dict, stage: str, payload: dict) -> None:
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

    def state(self) -> dict:
        three_p_digest = canonical_integrity_hash({"three_p": "PASS"})
        three_p_trace_hash = canonical_integrity_hash(
            {"three_p_trace": "current"}
        )
        skg_record = {
            "schema": "TEST_AUTHENTICATED_SKG_RECORD/1",
            "result": "PASS",
            "authority_source": "fixture",
        }
        state = {
            "request_fingerprint": canonical_integrity_hash(
                {"request": "filed-lifecycle"}
            ),
            "evaluation_time": 100,
            "three_p_core_result": "PASS",
            "three_p_core_digest": three_p_digest,
            "three_p_trace_hash": three_p_trace_hash,
            "three_p_trace": [
                {
                    "three_p_core_digest": three_p_digest,
                    "trace_hash": three_p_trace_hash,
                }
            ],
            "skg_authority_result": "PASS",
            "skg_authority_record": skg_record,
            "skg_authority_digest": canonical_integrity_hash(skg_record),
            "governance_result": "ALLOW",
            "filed_lifecycle_trace": [],
            "filed_lifecycle_results": {},
            "filed_lifecycle_digest": None,
            "filed_lifecycle_result": "",
            "filed_lifecycle_reason": "",
            "hash_chain": [],
            "state_hash": "",
        }
        self._append_hash(state, "governance:determination", {"result": "ALLOW"})
        return state

    def run_stage(
        self,
        state: dict,
        engine: str,
        *,
        evaluator: LifecycleEvaluator | None = None,
        provider: LifecycleEvidenceProvider | None = None,
    ) -> dict:
        evaluator = evaluator if evaluator is not None else self.evaluator
        provider = provider if provider is not None else self.provider
        stage = FILED_LIFECYCLE_STAGES[engine]
        self._append_hash(
            state,
            f"three_p_core:{stage}",
            {"three_p_core_digest": state["three_p_core_digest"]},
        )
        evaluate_filed_lifecycle(
            state,
            engine,
            evaluator=evaluator,
            attestation_provider=provider,
            **self.trust(provider),
        )
        self._append_hash(state, stage, filed_lifecycle_hash_payload(state))
        self._append_hash(
            state,
            f"three_p_core:{stage}:post",
            {"three_p_core_digest": state["three_p_core_digest"]},
        )
        return state

    def run_all(self, state: dict) -> dict:
        for engine in FILED_LIFECYCLE_ORDER:
            self.run_stage(state, engine)
        return state

    def test_exact_names_implementation_order_and_non_authorizing_records(
        self,
    ) -> None:
        self.assertEqual(
            FILED_LIFECYCLE_ORDER,
            (
                "AI Obsolescence Lifecycle & Supersession Engine",
                "Civilisational Successor Intelligence Transition Engine",
                "Structured Post-AI Era Continuity Engine",
            ),
        )
        self.assertIn("IMPLEMENTATION_DEFINED", FILED_LIFECYCLE_ORDER_AUTHORITY)
        self.assertIn("NOT_FILED_ORDER", FILED_LIFECYCLE_ORDER_AUTHORITY)
        self.assertIn(
            "IMPLEMENTATION_DEFINED_V2_MECHANICS",
            FILED_LIFECYCLE_SCHEMA_STATUS,
        )
        self.assertIn("NOT_FILED_SCHEMA", FILED_LIFECYCLE_SCHEMA_STATUS)

        state = self.run_all(self.state())

        self.assertTrue(
            verify_filed_lifecycle(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.trust(self.provider),
            )
        )
        self.assertEqual(
            [record["lifecycle_engine"] for record in state["filed_lifecycle_trace"]],
            list(FILED_LIFECYCLE_ORDER),
        )
        for record in state["filed_lifecycle_trace"]:
            self.assertEqual(record["result"], LIFECYCLE_PASS)
            self.assertIs(record["authority_granted"], False)
            self.assertIs(record["execution_authority_granted"], False)
            self.assertIs(record["licence_granted"], False)
            self.assertIs(record["governance_superseded"], False)
            determination = record["evaluation_source"]["determination"]
            self.assertIs(
                determination[
                    "transition_beyond_current_ai_paradigms_modelled"
                ],
                True,
            )
            self.assertIs(
                determination[
                    "full_lifecycle_governance_envelope_secured"
                ],
                True,
            )
            self.assertIs(
                determination["lawful_authority_continuity_preserved"], True
            )
            self.assertIs(
                determination["violent_or_coercive_interaction_prohibited"],
                True,
            )

    def test_missing_reordered_and_duplicate_evaluation_fail_closed(self) -> None:
        missing = self.state()
        evaluate_filed_lifecycle(
            missing,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=None,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(missing["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(
            missing["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_EVALUATOR_NOT_INJECTED",
        )

        reordered = self.state()
        evaluate_filed_lifecycle(
            reordered,
            FILED_LIFECYCLE_ORDER[1],
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(reordered["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(
            reordered["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_EXECUTION_ORDER_INVALID",
        )

        duplicated = self.run_stage(self.state(), FILED_LIFECYCLE_ORDER[0])
        evaluate_filed_lifecycle(
            duplicated,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(duplicated["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(
            duplicated["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_EXECUTION_ORDER_INVALID",
        )

    def test_current_three_p_skg_and_governance_are_mandatory(self) -> None:
        cases = {
            "three_p_result": ("three_p_core_result", "DENY"),
            "three_p_digest": ("three_p_core_digest", "0" * 128),
            "three_p_trace": ("three_p_trace", []),
            "skg_result": ("skg_authority_result", "DENY"),
            "skg_digest": ("skg_authority_digest", "0" * 128),
            "skg_record": ("skg_authority_record", {}),
            "governance": ("governance_result", "DENY"),
        }
        for label, (field, value) in cases.items():
            with self.subTest(label=label):
                evaluator = LifecycleEvaluator(self.provider)
                state = self.state()
                state[field] = value
                evaluate_filed_lifecycle(
                    state,
                    FILED_LIFECYCLE_ORDER[0],
                    evaluator=evaluator,
                    attestation_provider=self.provider,
                    **self.trust(self.provider),
                )
                self.assertEqual(state["filed_lifecycle_result"], LIFECYCLE_DENY)
                self.assertEqual(evaluator.calls, 0)

    def test_untrusted_unsigned_and_replayed_evidence_fail_closed(self) -> None:
        untrusted_provider = LifecycleEvidenceProvider()
        untrusted_provider.lifecycle_attestation_admitted = False
        untrusted_evaluator = LifecycleEvaluator(untrusted_provider)
        untrusted = self.state()
        evaluate_filed_lifecycle(
            untrusted,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=untrusted_evaluator,
            attestation_provider=untrusted_provider,
            **self.trust(untrusted_provider),
        )
        self.assertEqual(untrusted["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(untrusted_evaluator.calls, 0)

        unsigned_evaluator = LifecycleEvaluator(self.provider)
        unsigned_evaluator.return_unsigned = True
        unsigned = self.state()
        evaluate_filed_lifecycle(
            unsigned,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=unsigned_evaluator,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(unsigned["filed_lifecycle_result"], LIFECYCLE_DENY)

        replay_evaluator = LifecycleEvaluator(self.provider)
        replay = self.run_stage(
            self.state(),
            FILED_LIFECYCLE_ORDER[0],
            evaluator=replay_evaluator,
        )
        replay_evaluator.replay_source = deepcopy(
            replay["filed_lifecycle_trace"][0]["evaluation_source"]
        )
        stage = FILED_LIFECYCLE_STAGES[FILED_LIFECYCLE_ORDER[1]]
        self._append_hash(replay, f"three_p_core:{stage}", {"pre": True})
        evaluate_filed_lifecycle(
            replay,
            FILED_LIFECYCLE_ORDER[1],
            evaluator=replay_evaluator,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(replay["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertIn("EVALUATION_BINDING_MISMATCH", replay["filed_lifecycle_reason"])

    def test_non_authorizing_and_non_coercion_contract_is_strict(self) -> None:
        cases = {
            "unknown_result": {"result": "ALLOW"},
            "transition": {
                "transition_beyond_current_ai_paradigms_modelled": False
            },
            "lifecycle_envelope": {
                "full_lifecycle_governance_envelope_secured": False
            },
            "continuity": {"lawful_authority_continuity_preserved": False},
            "non_coercion": {
                "violent_or_coercive_interaction_prohibited": False
            },
            "three_p": {"bound_to_three_p": False},
            "skg": {"bound_to_skg": False},
            "authority": {"authority_granted": True},
            "execution": {"execution_authority_granted": True},
            "licence": {"licence_granted": True},
            "supersession": {"governance_superseded": True},
            "evidence": {"evidence_references": []},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label):
                evaluator = LifecycleEvaluator(self.provider)
                evaluator.determination_overrides = overrides
                state = self.state()
                evaluate_filed_lifecycle(
                    state,
                    FILED_LIFECYCLE_ORDER[0],
                    evaluator=evaluator,
                    attestation_provider=self.provider,
                    **self.trust(self.provider),
                )
                self.assertEqual(state["filed_lifecycle_result"], LIFECYCLE_DENY)
                record = state["filed_lifecycle_trace"][0]
                self.assertIs(record["authority_granted"], False)
                self.assertIs(record["execution_authority_granted"], False)
                self.assertIs(record["licence_granted"], False)
                self.assertIs(record["governance_superseded"], False)

        invented = LifecycleEvaluator(self.provider)
        invented.extra_determination = {"transition_threshold": 7}
        state = self.state()
        evaluate_filed_lifecycle(
            state,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=invented,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(state["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertIn("DETERMINATION_SHAPE_INVALID", state["filed_lifecycle_reason"])

    def test_deny_and_escalate_are_valid_non_authorizing_results(self) -> None:
        for result in (LIFECYCLE_DENY, LIFECYCLE_ESCALATE):
            with self.subTest(result=result):
                evaluator = LifecycleEvaluator(self.provider)
                evaluator.result = result
                evaluator.determination_overrides = {
                    "lawful_authority_continuity_preserved": False
                }
                state = self.state()
                evaluate_filed_lifecycle(
                    state,
                    FILED_LIFECYCLE_ORDER[0],
                    evaluator=evaluator,
                    attestation_provider=self.provider,
                    **self.trust(self.provider),
                )
                self.assertEqual(state["filed_lifecycle_result"], result)
                self.assertTrue(
                    state["filed_lifecycle_reason"].endswith(
                        "_EVALUATION_COMPLETED"
                    )
                )
                self.assertFalse(
                    verify_filed_lifecycle(
                        state,
                        evaluator=evaluator,
                        attestation_provider=self.provider,
                        require_hash_binding=False,
                        **self.trust(self.provider),
                    )
                )

    def test_prior_digest_tamper_prevents_progression(self) -> None:
        state = self.run_stage(self.state(), FILED_LIFECYCLE_ORDER[0])
        state["filed_lifecycle_digest"] = "0" * 128
        evaluate_filed_lifecycle(
            state,
            FILED_LIFECYCLE_ORDER[1],
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertEqual(state["filed_lifecycle_result"], LIFECYCLE_DENY)
        self.assertEqual(
            state["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_PRIOR_STATE_DIGEST_INVALID",
        )

    def test_trace_skg_and_hash_tamper_invalidate_verification(self) -> None:
        original = self.run_all(self.state())
        self.assertTrue(
            verify_filed_lifecycle(
                original,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.trust(self.provider),
            )
        )

        trace_tampered = deepcopy(original)
        trace_tampered["filed_lifecycle_trace"][0]["reason"] = "changed"
        self.assertFalse(
            verify_filed_lifecycle(
                trace_tampered,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.trust(self.provider),
            )
        )

        skg_tampered = deepcopy(original)
        skg_tampered["skg_authority_record"]["authority_source"] = "changed"
        self.assertFalse(
            verify_filed_lifecycle(
                skg_tampered,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.trust(self.provider),
            )
        )

        hash_tampered = deepcopy(original)
        lifecycle_index = next(
            index
            for index, entry in enumerate(hash_tampered["hash_chain"])
            if entry["stage"] == FILED_LIFECYCLE_STAGES[FILED_LIFECYCLE_ORDER[1]]
        )
        hash_tampered["hash_chain"][lifecycle_index]["stage"] = "changed"
        self.assertFalse(
            verify_filed_lifecycle(
                hash_tampered,
                evaluator=self.evaluator,
                attestation_provider=self.provider,
                **self.trust(self.provider),
            )
        )

    def test_identical_inputs_have_identical_verified_outcomes(self) -> None:
        first = self.run_all(self.state())
        second = self.run_all(self.state())
        self.assertEqual(
            first["filed_lifecycle_results"],
            second["filed_lifecycle_results"],
        )
        for state in (first, second):
            self.assertTrue(
                verify_filed_lifecycle(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.provider,
                    **self.trust(self.provider),
                )
            )

    def test_owner_pin_purpose_and_legacy_provider_fail_closed(self) -> None:
        state = self.state()
        trust = self.trust(self.provider)
        evaluate_filed_lifecycle(
            state,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=self.evaluator,
            attestation_provider=self.provider,
            attestation_trust_context=trust["attestation_trust_context"],
            owner_pinned_context_digest="0" * 128,
        )
        self.assertEqual(
            state["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_OWNER_TRUST_PIN_INVALID",
        )

        wrong_purpose = LifecycleEvaluator(self.provider)
        wrong_purpose.signing_purpose = "SBP_LEX_V2_WRONG_LIFECYCLE_PURPOSE"
        state = self.state()
        evaluate_filed_lifecycle(
            state,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=wrong_purpose,
            attestation_provider=self.provider,
            **self.trust(self.provider),
        )
        self.assertTrue(
            state["filed_lifecycle_reason"].endswith(
                "_EVALUATION_ATTESTATION_INVALID"
            )
        )

        class LegacyAdmittedProvider:
            algorithm = "Ed25519"
            lifecycle_attestation_admitted = True

        state = self.state()
        evaluate_filed_lifecycle(
            state,
            FILED_LIFECYCLE_ORDER[0],
            evaluator=self.evaluator,
            attestation_provider=LegacyAdmittedProvider(),
            **self.trust(self.provider),
        )
        self.assertEqual(
            state["filed_lifecycle_reason"],
            "FILED_LIFECYCLE_ATTESTATION_PROVIDER_NOT_ADMITTED",
        )
        complete = self.run_all(self.state())
        self.assertFalse(
            verify_filed_lifecycle(
                complete,
                evaluator=self.evaluator,
                attestation_provider=LegacyAdmittedProvider(),
                **self.trust(self.provider),
            )
        )


if __name__ == "__main__":
    unittest.main()
