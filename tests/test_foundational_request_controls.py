from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import os
import unittest

from cryptography.hazmat.primitives import serialization

os.environ["SBP_LEX_IMPERSONATION_RUNTIME_MODE"] = "TEST_ONLY"

from sbp_lex.baseline.request_controls import (
    FoundationalRequestDependencies,
    digital_provenance_hash_payload,
    run_australian_minor_access_stage,
    run_authority_boundary_stage,
    run_digital_provenance_stage,
    run_impersonation_stage,
    run_sovereign_identity_stage,
    verify_digital_provenance_state,
    verify_foundational_request_controls,
)
from sbp_lex.compliance.australian_minor_access import (
    AGE_AT_LEAST_16,
    AGE_UNDER_16,
    RESULT_DENY,
    _clear_australian_minor_access_deployment_for_tests,
)
from sbp_lex.config.pipeline_config import FOUNDATIONAL_BASELINE_ORDER
from sbp_lex.identity.impersonation_protection import (
    AUTHORITY_BOUNDARY_COMPONENT,
    SOVEREIGN_IDENTITY_COMPONENT,
    _install_test_only_impersonation_deployment_pins,
    _reset_test_only_impersonation_composition_boundaries,
)
from sbp_lex.identity.sovereign_identity import verify_sovereign_identity
from sbp_lex.interface.authority_boundary import verify_authority_boundary
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import (
    build_legacy_non_effect_signed_object,
    build_signed_object,
)

from tests.test_australian_minor_access import Fixture as AustralianFixture
from tests.test_authority_bounded_interface import (
    AdmittedInterfaceProvider,
    SignedBoundaryEvaluator,
)
from tests import test_digital_provenance as _digital_provenance_fixtures
from tests import test_impersonation_protection as _impersonation_fixtures
from tests.test_impersonation_protection import (
    DurableReplayGuardFixture,
    LiveRegistryFixture,
    TEST_ONLY_FIXTURE_CLASS,
)
from tests.test_sovereign_identity import (
    IdentityEvidenceEvaluator,
    IdentityEvidenceProvider,
)

class CanonicalModuleUpstreamVerifier:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(
        self,
        *,
        component_id: str,
        receipt_provider: object,
        evaluator: object,
        attestation_provider: object,
        attestation_trust_context: object,
        owner_pinned_context_digest: str,
    ) -> None:
        self.component_id = component_id
        self.receipt_provider = receipt_provider
        self.evaluator = evaluator
        self.attestation_provider = attestation_provider
        self.attestation_trust_context = attestation_trust_context
        self.owner_pinned_context_digest = owner_pinned_context_digest
        self.verifier_id = f"canonical-{component_id}-verifier"
        self.verifier_version = "1"

    def verify_authenticated(
        self,
        *,
        state: dict,
        dependencies: object,
        expected_receipt: dict,
    ) -> dict | bool:
        if dependencies is not self.receipt_provider:
            return False
        if self.component_id == SOVEREIGN_IDENTITY_COMPONENT:
            verified = verify_sovereign_identity(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.attestation_provider,
                attestation_trust_context=self.attestation_trust_context,
                owner_pinned_context_digest=self.owner_pinned_context_digest,
            )
        else:
            verified = verify_authority_boundary(
                state,
                evaluator=self.evaluator,
                attestation_provider=self.attestation_provider,
                attestation_trust_context=self.attestation_trust_context,
                owner_pinned_context_digest=self.owner_pinned_context_digest,
            )
        return (
            build_legacy_non_effect_signed_object(
                deepcopy(expected_receipt), provider=self.receipt_provider
            )
            if verified
            else False
        )


class BridgeFixture:
    def __init__(self, *, age_result: str = AGE_AT_LEAST_16) -> None:
        self.identity_provider = IdentityEvidenceProvider()
        self.identity_evaluator = IdentityEvidenceEvaluator(
            self.identity_provider
        )
        self.authority_provider = AdmittedInterfaceProvider()
        self.authority_evaluator = SignedBoundaryEvaluator(
            self.authority_provider
        )
        self.identity_context = self.identity_provider.hybrid_verification_context(
            allow_test_only=True
        )
        self.authority_context = self.authority_provider.hybrid_verification_context(
            allow_test_only=True
        )

        self.impersonation = (
            _impersonation_fixtures.ImpersonationProtectionTests(
            methodName="test_valid_proof_passes_with_receipt_and_grants_nothing"
            )
        )
        self.impersonation.setUp()
        self.impersonation.now = 1_700_000_500
        self.impersonation.clock.now = self.impersonation.now
        self._install_integrated_impersonation_context()

        self.provenance = _digital_provenance_fixtures.DigitalProvenanceTests(
            methodName=(
                "test_exact_lineage_receipt_is_deterministic_and_non_authorizing"
            )
        )
        self.provenance.setUp()

        self.australian = AustralianFixture(age_result=age_result)
        self.australian.install()
        self.state = self._state()
        self.dependencies = FoundationalRequestDependencies(
            provenance_registry_snapshot=self.provenance.snapshot,
            provenance_trust_context=self.provenance.trust_context,
            sovereign_identity_evaluator=self.identity_evaluator,
            sovereign_identity_attestation_provider=self.identity_provider,
            authority_boundary_evaluator=self.authority_evaluator,
            authority_boundary_attestation_provider=self.authority_provider,
            impersonation_trust_context=self.impersonation.context,
            sovereign_identity_trust_context=self.identity_context,
            sovereign_identity_owner_pinned_context_digest=(
                self.identity_context.context_digest
            ),
            authority_boundary_trust_context=self.authority_context,
            authority_boundary_owner_pinned_context_digest=(
                self.authority_context.context_digest
            ),
        )

    def _install_integrated_impersonation_context(self) -> None:
        _reset_test_only_impersonation_composition_boundaries()
        self.impersonation.sovereign_verifier = (
            CanonicalModuleUpstreamVerifier(
                component_id=SOVEREIGN_IDENTITY_COMPONENT,
                receipt_provider=self.impersonation.sovereign_provider,
                evaluator=self.identity_evaluator,
                attestation_provider=self.identity_provider,
                attestation_trust_context=self.identity_context,
                owner_pinned_context_digest=self.identity_context.context_digest,
            )
        )
        self.impersonation.boundary_verifier = (
            CanonicalModuleUpstreamVerifier(
                component_id=AUTHORITY_BOUNDARY_COMPONENT,
                receipt_provider=self.impersonation.boundary_provider,
                evaluator=self.authority_evaluator,
                attestation_provider=self.authority_provider,
                attestation_trust_context=self.authority_context,
                owner_pinned_context_digest=self.authority_context.context_digest,
            )
        )
        payload = self.impersonation.context_payload()
        payload["sovereign_identity_verifier"]["hash_stage"] = (
            "impersonation_upstream:sovereign_identity"
        )
        payload["authority_boundary_verifier"]["hash_stage"] = (
            "impersonation_upstream:authority_boundary"
        )
        payload["valid_from_ms"] = self.impersonation.now - 10_000
        payload["valid_until_ms"] = self.impersonation.now + 10_000
        self.impersonation.context_record = build_legacy_non_effect_signed_object(
            payload,
            provider=self.impersonation.owner_provider,
        )
        self.impersonation.registry = LiveRegistryFixture(
            self.impersonation.context_record,
            self.impersonation.registry_provider,
        )
        self.impersonation.registry.valid_from_ms = (
            self.impersonation.now - 10_000
        )
        self.impersonation.registry.valid_until_ms = (
            self.impersonation.now + 10_000
        )
        self.impersonation.replay = DurableReplayGuardFixture(
            self.impersonation.context_record,
            self.impersonation.replay_provider,
        )
        _install_test_only_impersonation_deployment_pins(
            context_id=self.impersonation.context_record["context_id"],
            context_digest=self.impersonation.context_record["digest"],
            owner_public_key_hex=(
                self.impersonation.owner_provider.public_key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                ).hex()
            ),
        )
        self.impersonation.register_composition()
        self.impersonation.context = self.impersonation.make_context()

    def _state(self) -> dict:
        request_fingerprint = canonical_integrity_hash(
            {
                "schema_id": "SBP_LEX_V2_CANONICAL_PIPELINE_REQUEST_V1",
                "request_id": "foundational-request-1",
                "request_nonce": "nonce-1",
            }
        )
        ingress = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="state_construction",
            payload={"request_fingerprint": request_fingerprint},
        )
        biometric_digest = canonical_integrity_hash(
            {"external_biometric_attestation_reference": "attestation-1"}
        )
        return {
            "identity": {"subject_id": "subject-one"},
            "biometric_attestation_digest": biometric_digest,
            "identity_jurisdictions": ["AU"],
            "identity_access_grants": [
                {
                    "grant_id": "grant-au-review",
                    "jurisdiction": "AU",
                    "actions": ["review"],
                }
            ],
            "participant_id": "participant-one",
            "stakeholder_class": "regulators",
            "participant_role": "reviewer",
            "participant_mandate_id": "mandate-one",
            "action": "review",
            "requested_jurisdiction": "AU",
            "jurisdiction": "",
            "request_fingerprint": request_fingerprint,
            "evaluation_time": self.impersonation.now,
            "impersonation_session_id": "session-one",
            "impersonation_audience": "sbp-lex-v2",
            "impersonation_challenge": canonical_integrity_hash(
                {"challenge": "unique-one"}
            ),
            "subject_id": "subject-one",
            "session_id": "session-one",
            "service_id": "service-one",
            "request_nonce": "nonce-1",
            "digital_provenance_graph": self.provenance.graph(
                request_fingerprint=request_fingerprint
            ),
            "release_manifest_digest": (
                self.provenance.release_manifest_digest
            ),
            "runtime_measurement_digest": (
                self.provenance.runtime_measurement_digest
            ),
            "hash_chain": [ingress],
            "state_hash": ingress["hash"],
            "australian_minor_access_hash_binding_index": None,
            "australian_minor_access_hash_binding_hash": None,
        }

    def run_through_authority(self) -> dict:
        run_digital_provenance_stage(
            self.state, dependencies=self.dependencies
        )
        run_sovereign_identity_stage(
            self.state, dependencies=self.dependencies
        )
        run_authority_boundary_stage(
            self.state, dependencies=self.dependencies
        )
        return self.state

    def run_all(self) -> tuple[dict, dict]:
        self.run_through_authority()
        proof = self.impersonation.proof(self.state)
        run_impersonation_stage(
            self.state,
            dependencies=self.dependencies,
            possession_proof=proof,
        )
        run_australian_minor_access_stage(self.state)
        return self.state, proof

    def close(self) -> None:
        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        _reset_test_only_impersonation_composition_boundaries()


def _contains_exact(value: object, target: object) -> bool:
    if value == target:
        return True
    if type(value) is dict:
        return any(_contains_exact(item, target) for item in value.values())
    if type(value) in (list, tuple):
        return any(_contains_exact(item, target) for item in value)
    return False


class FoundationalRequestControlTests(unittest.TestCase):
    def tearDown(self) -> None:
        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        _reset_test_only_impersonation_composition_boundaries()

    def test_dependencies_are_frozen_and_snapshot_is_deep_copied(self) -> None:
        fixture = BridgeFixture()
        original = deepcopy(fixture.dependencies.provenance_registry_snapshot)
        fixture.provenance.snapshot["registry_version"] = "attacker-change"
        self.assertEqual(
            original, fixture.dependencies.provenance_registry_snapshot
        )
        with self.assertRaises(FrozenInstanceError):
            fixture.dependencies.provenance_trust_context = None

    def test_exact_control_order_no_allow_and_later_chain_revalidation(self) -> None:
        fixture = BridgeFixture()
        state, proof = fixture.run_all()
        stages = [entry["stage"] for entry in state["hash_chain"]]
        indices = [stages.index(stage) for stage in FOUNDATIONAL_BASELINE_ORDER]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(len(indices), len(set(indices)))
        self.assertTrue(
            verify_foundational_request_controls(
                state, dependencies=fixture.dependencies
            )
        )
        self.assertFalse(_contains_exact(state, proof))
        self.assertNotIn("possession_proof", state)
        self.assertNotIn(
            "ALLOW",
            {
                state["digital_provenance_result"],
                state["sovereign_identity_result"],
                state["authority_boundary_result"],
                state["impersonation_protection_result"],
                state["australian_minor_access"]["result"],
            },
        )
        later = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage="later_non_foundational_stage",
            payload={"result": "PASS"},
        )
        state["hash_chain"].append(later)
        state["state_hash"] = later["hash"]
        self.assertTrue(
            verify_foundational_request_controls(
                state, dependencies=fixture.dependencies
            )
        )

    def test_provenance_projection_payload_and_receipt_tamper(self) -> None:
        fixture = BridgeFixture()
        before = set(fixture.state)
        run_digital_provenance_stage(
            fixture.state, dependencies=fixture.dependencies
        )
        projection = {
            "digital_provenance_result",
            "digital_provenance_reason",
            "digital_provenance_digest",
            "digital_provenance_lineage_authenticated",
            "digital_provenance_verification_trace",
            "digital_provenance_verification_receipt",
            "digital_provenance_lineage_only",
        }
        self.assertEqual(set(fixture.state) - before, projection)
        self.assertEqual(
            {
                "contract_id",
                "stage",
                "result",
                "reason",
                "provenance_digest",
                "lineage_authenticated",
                "verification_trace_digest",
                "verification_receipt_digest",
                "lineage_only",
                "legal_truth_proven",
                "semantic_correctness_proven",
                "governance_allow_granted",
                "licence_granted",
                "execution_authority_granted",
                "effect_authority_granted",
                "pipeline_bypass_permitted",
            },
            set(digital_provenance_hash_payload(fixture.state)),
        )
        self.assertTrue(
            verify_digital_provenance_state(
                fixture.state, dependencies=fixture.dependencies
            )
        )
        fixture.state["digital_provenance_verification_receipt"][
            "signature"
        ] = "00"
        self.assertFalse(
            verify_digital_provenance_state(
                fixture.state, dependencies=fixture.dependencies
            )
        )

    def test_every_injected_dependency_fails_closed_when_missing(self) -> None:
        fields_and_runner = (
            ("provenance_registry_snapshot", "provenance"),
            ("provenance_trust_context", "provenance"),
            ("sovereign_identity_evaluator", "identity"),
            ("sovereign_identity_attestation_provider", "identity"),
            ("authority_boundary_evaluator", "authority"),
            ("authority_boundary_attestation_provider", "authority"),
            ("impersonation_trust_context", "impersonation"),
        )
        for field, runner in fields_and_runner:
            with self.subTest(field=field):
                fixture = BridgeFixture()
                values = {
                    name: getattr(fixture.dependencies, name)
                    for name in fixture.dependencies.__slots__
                }
                values[field] = None
                dependencies = FoundationalRequestDependencies(**values)
                if runner == "provenance":
                    run_digital_provenance_stage(
                        fixture.state, dependencies=dependencies
                    )
                    result = fixture.state["digital_provenance_result"]
                elif runner == "identity":
                    run_sovereign_identity_stage(
                        fixture.state, dependencies=dependencies
                    )
                    result = fixture.state["sovereign_identity_result"]
                elif runner == "authority":
                    run_authority_boundary_stage(
                        fixture.state, dependencies=dependencies
                    )
                    result = fixture.state["authority_boundary_result"]
                else:
                    fixture.run_through_authority()
                    proof = fixture.impersonation.proof(fixture.state)
                    run_impersonation_stage(
                        fixture.state,
                        dependencies=dependencies,
                        possession_proof=proof,
                    )
                    result = fixture.state["impersonation_protection_result"]
                self.assertNotEqual("ALLOW", result)
                self.assertIn(
                    result, {"DENY", "BOUNDARY_DENY", "ESCALATE"}
                )
                fixture.close()

    def test_every_injected_dependency_substitution_fails_closed(self) -> None:
        fields_and_runner = (
            ("provenance_registry_snapshot", "provenance"),
            ("provenance_trust_context", "provenance"),
            ("sovereign_identity_evaluator", "identity"),
            ("sovereign_identity_attestation_provider", "identity"),
            ("authority_boundary_evaluator", "authority"),
            ("authority_boundary_attestation_provider", "authority"),
            ("impersonation_trust_context", "impersonation"),
        )
        for field, runner in fields_and_runner:
            with self.subTest(field=field):
                fixture = BridgeFixture()
                try:
                    values = {
                        name: getattr(fixture.dependencies, name)
                        for name in fixture.dependencies.__slots__
                    }
                    if field == "provenance_registry_snapshot":
                        substituted = deepcopy(
                            values["provenance_registry_snapshot"]
                        )
                        substituted["registry_version"] = "substituted"
                    else:
                        substituted = object()
                    values[field] = substituted
                    dependencies = FoundationalRequestDependencies(**values)
                    if runner == "provenance":
                        run_digital_provenance_stage(
                            fixture.state, dependencies=dependencies
                        )
                        result = fixture.state["digital_provenance_result"]
                    elif runner == "identity":
                        run_sovereign_identity_stage(
                            fixture.state, dependencies=dependencies
                        )
                        result = fixture.state["sovereign_identity_result"]
                    elif runner == "authority":
                        run_authority_boundary_stage(
                            fixture.state, dependencies=dependencies
                        )
                        result = fixture.state["authority_boundary_result"]
                    else:
                        fixture.run_through_authority()
                        proof = fixture.impersonation.proof(fixture.state)
                        run_impersonation_stage(
                            fixture.state,
                            dependencies=dependencies,
                            possession_proof=proof,
                        )
                        result = fixture.state[
                            "impersonation_protection_result"
                        ]
                    self.assertIn(
                        result, {"DENY", "BOUNDARY_DENY", "ESCALATE"}
                    )
                    self.assertNotEqual("ALLOW", result)
                finally:
                    fixture.close()

    def test_missing_possession_proof_denies_and_is_not_retained(self) -> None:
        fixture = BridgeFixture()
        fixture.run_through_authority()
        run_impersonation_stage(
            fixture.state,
            dependencies=fixture.dependencies,
            possession_proof=None,
        )
        self.assertEqual(
            "DENY", fixture.state["impersonation_protection_result"]
        )
        self.assertNotIn("possession_proof", fixture.state)

    def test_tampered_possession_proof_denies_and_is_not_retained(self) -> None:
        fixture = BridgeFixture()
        fixture.run_through_authority()
        proof = fixture.impersonation.proof(fixture.state)
        proof["signature"] = "00"
        run_impersonation_stage(
            fixture.state,
            dependencies=fixture.dependencies,
            possession_proof=proof,
        )
        self.assertEqual(
            "DENY", fixture.state["impersonation_protection_result"]
        )
        self.assertFalse(_contains_exact(fixture.state, proof))
        self.assertNotIn("possession_proof", fixture.state)

    def test_duplicate_reorder_and_wrong_predecessor_fail_revalidation(self) -> None:
        cases = ("duplicate", "reorder", "predecessor")
        for case in cases:
            with self.subTest(case=case):
                fixture = BridgeFixture()
                state, _ = fixture.run_all()
                if case == "duplicate":
                    source = next(
                        entry
                        for entry in state["hash_chain"]
                        if entry["stage"] == FOUNDATIONAL_BASELINE_ORDER[0]
                    )
                    duplicate = build_hash_chain_entry(
                        previous_hash=state["state_hash"],
                        stage=source["stage"],
                        payload={"duplicate": source["payload_hash"]},
                    )
                    state["hash_chain"].append(duplicate)
                    state["state_hash"] = duplicate["hash"]
                elif case == "reorder":
                    state["hash_chain"][1], state["hash_chain"][2] = (
                        state["hash_chain"][2],
                        state["hash_chain"][1],
                    )
                else:
                    index = next(
                        index
                        for index, entry in enumerate(state["hash_chain"])
                        if entry["stage"] == FOUNDATIONAL_BASELINE_ORDER[2]
                    )
                    state["hash_chain"][index]["previous_hash"] = GENESIS_HASH
                self.assertFalse(
                    verify_foundational_request_controls(
                        state, dependencies=fixture.dependencies
                    )
                )
                fixture.close()

    def test_under_sixteen_is_a_verified_deny_not_an_allow(self) -> None:
        fixture = BridgeFixture(age_result=AGE_UNDER_16)
        state, _ = fixture.run_all()
        self.assertEqual(RESULT_DENY, state["australian_minor_access"]["result"])
        self.assertFalse(state["australian_minor_access"]["access_granted"])
        self.assertTrue(
            verify_foundational_request_controls(
                state, dependencies=fixture.dependencies
            )
        )


if __name__ == "__main__":
    unittest.main()
