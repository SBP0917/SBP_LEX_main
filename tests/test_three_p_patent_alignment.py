from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.governance.three_p_doctrine import (
    MECHANICALLY_CONSTRAINED_PROCESSES,
    THREE_P_ATTESTATION_PURPOSE,
    THREE_P_DEFINITIONS,
    evaluate_three_p_core,
    three_p_hash_payload,
    verify_three_p_core,
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
from sbp_lex.pipeline.runner import PipelineHybridTrustContexts, run_v2
from tests import test_controlled_local_adapter as controlled_local_adapter
from tests.test_foundational_public_pipeline import (
    _public_inputs,
    _run_arguments,
)


class RecordingThreePCoreEvaluator:
    evaluator_id = "patent-three-p-fixture"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "three-p-constitutional-credential"

    def __init__(
        self,
        provider: HybridMLDSA87Ed448SoftwareProvider,
        denied: str | None = None,
        *,
        include_evidence: bool = True,
    ) -> None:
        self.provider = provider
        self.denied = denied
        self.include_evidence = include_evidence
        self.calls: list[tuple[str, dict]] = []

    def evaluate(self, *, stage: str, snapshot: dict) -> dict:
        self.calls.append((stage, deepcopy(snapshot)))
        determinations = {
            primitive: {
                "result": (
                    "NOT_SATISFIED"
                    if primitive == self.denied
                    else "SATISFIED"
                ),
                "evidence_references": (
                    [
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
                    ]
                    if self.include_evidence
                    else []
                ),
            }
            for primitive in ("P1", "P2", "P3")
        }
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
                "determinations": determinations,
            },
            provider=self.provider,
            purpose=THREE_P_ATTESTATION_PURPOSE,
        )


class BareBooleanThreePCoreEvaluator:
    evaluator_id = "bare-boolean-three-p"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "bare-boolean-credential"

    def evaluate(self, *, stage: str, snapshot: dict) -> dict:
        return {"P1": True, "P2": True, "P3": True}


class ReplayingThreePCoreEvaluator(RecordingThreePCoreEvaluator):
    def __init__(self, provider: HybridMLDSA87Ed448SoftwareProvider) -> None:
        super().__init__(provider)
        self.cached_result: dict | None = None

    def evaluate(self, *, stage: str, snapshot: dict) -> dict:
        if self.cached_result is None:
            self.cached_result = super().evaluate(stage=stage, snapshot=snapshot)
        return deepcopy(self.cached_result)


class ThreePPatentAlignmentTests(unittest.TestCase):
    def provider(self) -> HybridMLDSA87Ed448SoftwareProvider:
        return HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="TEST_ONLY:THREE_P_PATENT_ALIGNMENT_HYBRID",
            three_p_attestation_admitted=True,
        )

    @staticmethod
    def trust_contexts(
        provider: HybridMLDSA87Ed448SoftwareProvider,
    ) -> PipelineHybridTrustContexts:
        context = provider.hybrid_verification_context(allow_test_only=True)
        return PipelineHybridTrustContexts(
            signature=context,
            signature_owner_pin=context.context_digest,
            three_p=context,
            three_p_owner_pin=context.context_digest,
        )

    @staticmethod
    def state(*, request_three_p_claim: dict | None = None) -> dict:
        payload = {}
        if request_three_p_claim is not None:
            payload["three_p_core"] = deepcopy(request_three_p_claim)
        return {
            "request_fingerprint": "f" * 128,
            "action": "review",
            "payload": payload,
            "context": {},
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "evaluation_time": 0,
            "hash_chain": [],
            "state_hash": "",
        }

    def evaluate(
        self,
        state: dict,
        *,
        evaluator: object | None,
        provider: HybridMLDSA87Ed448SoftwareProvider,
        trust_provider: HybridMLDSA87Ed448SoftwareProvider | None = None,
        stage: str = "ingress",
    ) -> dict:
        verifier = trust_provider if trust_provider is not None else provider
        contexts = self.trust_contexts(verifier)
        return evaluate_three_p_core(
            state,
            evaluator=evaluator,
            attestation_provider=verifier,
            stage=stage,
            trust_context=contexts.three_p,
            owner_pinned_context_digest=contexts.three_p_owner_pin,
        )

    def run_with_foundations(
        self,
        *,
        full_runtime: bool = False,
        request_three_p_claim: dict | None = None,
        **runtime_arguments: object,
    ) -> dict:
        foundation = controlled_local_adapter.ControlledLocalAdapterTests(
            "test_real_local_effect_requires_point_of_use_receipt"
        )
        foundation.setUp()
        request, signals, proof = _public_inputs(
            foundation,
            payload_update=(
                {"three_p_core": request_three_p_claim}
                if request_three_p_claim is not None
                else None
            ),
        )
        arguments = {
            "application_integrity_bundle": foundation.application_bundle,
            "foundational_request_dependencies": (
                foundation.foundational_dependencies
            ),
            "possession_proof": proof,
        }
        if full_runtime:
            arguments = _run_arguments(
                foundation,
                possession_proof=proof,
            )
        if runtime_arguments.get("three_p_attestation_provider") is not None:
            provider = runtime_arguments["three_p_attestation_provider"]
            arguments["signature_provider"] = provider
            arguments["hybrid_trust_contexts"] = self.trust_contexts(provider)
        arguments.update(runtime_arguments)
        try:
            return run_v2(request, signals, **arguments)
        finally:
            foundation.tearDown()

    def test_definitions_and_constrained_processes_are_exact(self) -> None:
        self.assertEqual(
            THREE_P_DEFINITIONS,
            {
                "P1": {
                    "name": "Planetary Stability Engine (PSE)",
                    "definition": (
                        "Non-negotiable ecological and planetary constraint "
                        "enforcement."
                    ),
                },
                "P2": {
                    "name": "Population Integrity Engine (PIE)",
                    "definition": (
                        "Human continuity, dignity, cohesion, and socio-economic "
                        "stability preservation."
                    ),
                },
                "P3": {
                    "name": "Permanent Sovereign Governance Cycle (PSGC)",
                    "definition": (
                        "Continuous rule validation, lawful recalibration, and "
                        "authority continuity loop."
                    ),
                },
            },
        )
        self.assertEqual(
            MECHANICALLY_CONSTRAINED_PROCESSES,
            (
                "optimisation",
                "modelling",
                "routing",
                "attestation",
                "licensing",
                "escalation",
                "execution",
                "lifecycle_governance",
                "obsolescence_modelling",
                "supersession",
            ),
        )

    def test_request_cannot_self_authorize_three_p(self) -> None:
        provider = self.provider()
        result = self.evaluate(
            self.state(
                request_three_p_claim={"P1": True, "P2": True, "P3": True}
            ),
            evaluator=None,
            provider=provider,
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(result["three_p_core_reason"], "3P_EVALUATOR_NOT_INJECTED")

    def test_any_primitive_denial_fails_closed_and_grants_no_authority(self) -> None:
        for primitive in ("P1", "P2", "P3"):
            with self.subTest(primitive=primitive):
                provider = self.provider()
                result = self.evaluate(
                    self.state(),
                    evaluator=RecordingThreePCoreEvaluator(
                        provider,
                        primitive,
                    ),
                    provider=provider,
                )
                self.assertEqual(result["three_p_core_result"], "DENY")
                self.assertFalse(
                    result["three_p_core_record"]["authority_granted"]
                )

    def test_p3_cycle_revalidates_with_current_history(self) -> None:
        provider = self.provider()
        evaluator = RecordingThreePCoreEvaluator(provider)
        state = self.state()
        stages = (
            "foundational_baseline",
            "ingress",
            "collective_attach:post",
            "root_of_trust:post",
            "governance:post",
            "execution:pre",
        )
        for stage in stages:
            self.evaluate(
                state,
                evaluator=evaluator,
                provider=provider,
                stage=stage,
            )

        observed_stages = [stage for stage, _ in evaluator.calls]
        self.assertEqual(observed_stages, list(stages))
        for index, (_, snapshot) in enumerate(evaluator.calls):
            self.assertEqual(len(snapshot["three_p_history"]), index)
            if index:
                self.assertIsNotNone(snapshot["prior_three_p_digest"])

    def test_bare_boolean_result_is_not_evidence(self) -> None:
        provider = self.provider()
        result = self.evaluate(
            self.state(),
            evaluator=BareBooleanThreePCoreEvaluator(),
            provider=provider,
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(
            result["three_p_core_reason"],
            "3P_EVALUATOR_RESULT_SHAPE_INVALID",
        )

    def test_signed_determination_without_evidence_fails_closed(self) -> None:
        provider = self.provider()
        result = self.evaluate(
            self.state(),
            evaluator=RecordingThreePCoreEvaluator(
                provider,
                include_evidence=False,
            ),
            provider=provider,
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(
            result["three_p_core_reason"],
            "3P_EVIDENCE_CONTRACT_INVALID",
        )

    def test_signed_evaluation_requires_separately_admitted_provider(self) -> None:
        signing_provider = self.provider()
        unadmitted_provider = HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="TEST_ONLY:THREE_P_UNADMITTED_HYBRID",
        )
        result = self.evaluate(
            self.state(),
            evaluator=RecordingThreePCoreEvaluator(signing_provider),
            provider=signing_provider,
            trust_provider=unadmitted_provider,
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(
            result["three_p_core_reason"],
            "3P_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED",
        )

    def test_admitted_provider_substitution_fails_signature_verification(self) -> None:
        signing_provider = self.provider()
        substituted_provider = self.provider()
        result = self.evaluate(
            self.state(),
            evaluator=RecordingThreePCoreEvaluator(signing_provider),
            provider=signing_provider,
            trust_provider=substituted_provider,
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(
            result["three_p_core_reason"],
            "3P_EVALUATION_ATTESTATION_INVALID",
        )

    def test_evaluation_replay_at_later_stage_fails_binding(self) -> None:
        provider = self.provider()
        state = self.state()
        evaluator = ReplayingThreePCoreEvaluator(provider)
        self.evaluate(
            state,
            evaluator=evaluator,
            provider=provider,
            stage="ingress",
        )
        result = self.evaluate(
            state,
            evaluator=evaluator,
            provider=provider,
            stage="later",
        )

        self.assertEqual(result["three_p_core_result"], "DENY")
        self.assertEqual(
            result["three_p_core_reason"],
            "3P_EVALUATION_BINDING_MISMATCH:stage",
        )

    def test_mutation_breaks_record_and_hash_binding(self) -> None:
        provider = self.provider()
        state = {
            "request_fingerprint": "f" * 128,
            "action": "review",
            "payload": {},
            "context": {},
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "evaluation_time": 0,
            "hash_chain": [],
            "state_hash": "",
        }
        evaluate_three_p_core(
            state,
            evaluator=RecordingThreePCoreEvaluator(provider),
            attestation_provider=provider,
            stage="ingress",
            trust_context=self.trust_contexts(provider).three_p,
            owner_pinned_context_digest=(
                self.trust_contexts(provider).three_p_owner_pin
            ),
        )
        entry = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="three_p_core:ingress",
            payload=three_p_hash_payload(state),
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]
        self.assertTrue(
            verify_three_p_core(
                state,
                attestation_provider=provider,
                trust_context=self.trust_contexts(provider).three_p,
                owner_pinned_context_digest=(
                    self.trust_contexts(provider).three_p_owner_pin
                ),
            )
        )

        state["three_p_core_record"]["primitives"][0]["definition"] = "changed"
        self.assertFalse(
            verify_three_p_core(
                state,
                attestation_provider=provider,
            )
        )

    def test_trace_splice_and_attestation_mutation_fail_closed(self) -> None:
        provider = self.provider()
        state = {
            "request_fingerprint": "f" * 128,
            "action": "review",
            "payload": {},
            "context": {},
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "evaluation_time": 0,
            "hash_chain": [],
            "state_hash": "",
        }
        evaluate_three_p_core(
            state,
            evaluator=RecordingThreePCoreEvaluator(provider),
            attestation_provider=provider,
            stage="ingress",
            trust_context=self.trust_contexts(provider).three_p,
            owner_pinned_context_digest=(
                self.trust_contexts(provider).three_p_owner_pin
            ),
        )
        entry = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="three_p_core:ingress",
            payload=three_p_hash_payload(state),
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

        trace_tampered = deepcopy(state)
        trace_tampered["three_p_trace"][0]["stage"] = "replayed"
        self.assertFalse(
            verify_three_p_core(
                trace_tampered,
                attestation_provider=provider,
                trust_context=self.trust_contexts(provider).three_p,
                owner_pinned_context_digest=(
                    self.trust_contexts(provider).three_p_owner_pin
                ),
            )
        )

        signature_tampered = deepcopy(state)
        signature_tampered["three_p_core_record"]["evaluation_source"][
            "stage"
        ] = "replayed"
        self.assertFalse(
            verify_three_p_core(
                signature_tampered,
                attestation_provider=provider,
                trust_context=self.trust_contexts(provider).three_p,
                owner_pinned_context_digest=(
                    self.trust_contexts(provider).three_p_owner_pin
                ),
            )
        )


if __name__ == "__main__":
    unittest.main()
