from __future__ import annotations

import json
import os
import unittest
from copy import deepcopy
from dataclasses import replace
from hashlib import sha512
from pathlib import Path
from tempfile import TemporaryDirectory

os.environ["SBP_LEX_IMPERSONATION_RUNTIME_MODE"] = "TEST_ONLY"

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.audit.audit_ledger import verify_audit_record
from sbp_lex.baseline.application_startup import (
    APPLICATION_INTEGRITY_STARTUP_STAGE,
    ApplicationIntegrityRuntimeBundle,
    admit_application_startup,
    application_startup_hash_payload,
    verify_and_project_application_startup,
)
from sbp_lex.baseline.foundational_baseline import (
    bind_foundational_baseline_hash,
    evaluate_foundational_baseline,
    foundational_baseline_hash_payload,
)
from sbp_lex.execution.controlled_local_adapter import (
    ControlledLocalAdapter,
    LocalEffectHybridTrustContexts,
    LocalEffectCommand,
    LocalEffectError,
    LocalEffectInDoubtError,
    LocalEffectOutcome,
    LocalEffectResult,
    run_controlled_local_effect,
    verify_local_effect_receipt,
)
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.governance.three_p_doctrine import (
    THREE_P_ATTESTATION_PURPOSE,
    ThreePCoreEvaluator,
    evaluate_three_p_core,
    three_p_hash_payload,
)
from sbp_lex.governance.authority_provenance import (
    authority_provenance_hash_payload,
    evaluate_authority_provenance,
)
from sbp_lex.governance.filed_frameworks import (
    ABEGF,
    ABEGF_SUSPENSION_CONTROLS,
    AJ_SAAF,
    AJ_SAAF_RECALCULATION_TRIGGERS,
    FILED_FRAMEWORK_AUTHORITY_ROLE,
    FILED_FRAMEWORK_ATTESTATION_PURPOSE,
    FILED_FRAMEWORK_ORDER,
    FILED_FRAMEWORK_STAGES,
    GALA,
    PTODF,
    evaluate_filed_framework,
    filed_framework_hash_payload,
)
from sbp_lex.governance.skg_authority import (
    SKG_HASH_STAGE_PREFIX,
    evaluate_skg_authority,
    skg_authority_hash_payload,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_STAGES,
    evaluate_filed_lifecycle,
    filed_lifecycle_hash_payload,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_PASS,
    evaluate_filed_governance_integrity,
    filed_governance_integrity_hash_payload,
    governance_integrity_revocation_binding,
)
from sbp_lex.pipeline.runner import _finalize_audit
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import build_signed_object
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    PRODUCTION_DUAL_CUSTODY_CLASS,
    PRODUCTION_SIGNER,
    DualSignatureLaneCustody,
    HybridVerificationContext,
)
from sbp_lex.security.token_stack import issue_token
from sbp_lex.shared.state_builder import build_state
from sbp_lex.licensing.filed_licensing import (
    LICENCE_REVALIDATION_STAGE,
    LICENCE_ROOT_BINDING_STAGE,
    LICENCE_VALIDATION_STAGE,
)
from tests.licence_support import (
    PassingFiledLicenceEvaluator,
    append_filed_licence_evaluation,
    filed_licence_request_fields,
)
from tests.governance_support import (
    PassingFiledGovernanceIntegrityEvaluator,
    PassingFiledLifecycleEvaluator,
    PassingSKGAuthorityEvaluator,
)
from tests.test_application_integrity import ApplicationIntegrityTests
from tests.test_foundational_request_controls import BridgeFixture
from tests.authority_provenance_support import AuthorityProvenanceFixture


class BoundaryEvidenceProvider:
    """Synthetic external-custody double used only by this test module.

    The production-shaped context is necessary to exercise positive permit and
    dispatch mechanics.  It is not exported, admitted, or evidence of physical
    custody.
    """

    algorithm = HYBRID_SUITE_ID
    token_signing_admitted = True
    key_epoch = 1
    key_version = "1"
    signer_class = PRODUCTION_SIGNER

    def __init__(
        self,
        *,
        role: str,
        effect_authority: bool,
        three_p_attestation_admitted: bool,
        framework_attestation_admitted: bool = False,
        licence_attestation_admitted: bool = False,
        skg_attestation_admitted: bool = False,
        lifecycle_attestation_admitted: bool = False,
        governance_integrity_attestation_admitted: bool = False,
    ) -> None:
        self._mldsa87_private_key = MLDSA87PrivateKey.generate()
        self._ed448_private_key = Ed448PrivateKey.generate()
        self.provider_id = f"SYNTHETIC_EXTERNAL_CUSTODY_TEST_FIXTURE:{role}"
        self.custody_class = PRODUCTION_DUAL_CUSTODY_CLASS
        self.external_custody_admitted = True
        self.external_custody_admission_sha512 = sha512(
            f"controlled-local-test-fixture:{role}:aggregate".encode("utf-8")
        ).hexdigest()
        self.mldsa87_custody = DualSignatureLaneCustody(
            algorithm="ML-DSA-87",
            provider_id=f"SYNTHETIC_TEST_FIXTURE:{role}:ML-DSA-87",
            key_version=f"{self.key_version}:ml-dsa-87",
            key_epoch=self.key_epoch,
            rotation_epoch=self.key_epoch,
            custody_class="SYNTHETIC_NON_EXPORTABLE_TEST_FIXTURE_ML_DSA_87",
            custody_reference=f"SYNTHETIC:{role}:HSM:ML-DSA-87",
            signer_class=PRODUCTION_SIGNER,
            external_custody_admitted=True,
            custody_admission_sha512=sha512(
                f"controlled-local-test-fixture:{role}:ml-dsa-87".encode("utf-8")
            ).hexdigest(),
            non_exportable=True,
        )
        self.ed448_custody = DualSignatureLaneCustody(
            algorithm="Ed448",
            provider_id=f"SYNTHETIC_TEST_FIXTURE:{role}:ED448",
            key_version=f"{self.key_version}:ed448",
            key_epoch=self.key_epoch,
            rotation_epoch=self.key_epoch,
            custody_class="SYNTHETIC_NON_EXPORTABLE_TEST_FIXTURE_ED448",
            custody_reference=f"SYNTHETIC:{role}:HSM:ED448",
            signer_class=PRODUCTION_SIGNER,
            external_custody_admitted=True,
            custody_admission_sha512=sha512(
                f"controlled-local-test-fixture:{role}:ed448".encode("utf-8")
            ).hexdigest(),
            non_exportable=True,
        )
        self.effect_authority = effect_authority
        self.three_p_attestation_admitted = three_p_attestation_admitted
        self.framework_attestation_admitted = framework_attestation_admitted
        self.licence_attestation_admitted = licence_attestation_admitted
        self.skg_attestation_admitted = skg_attestation_admitted
        self.lifecycle_attestation_admitted = (
            lifecycle_attestation_admitted
        )
        self.governance_integrity_attestation_admitted = (
            governance_integrity_attestation_admitted
        )

    @property
    def key_id(self) -> str:
        return self.hybrid_verification_context().key_id

    def hybrid_verification_context(
        self, *, allow_test_only: bool = False
    ) -> HybridVerificationContext:
        return HybridVerificationContext(
            provider_id=self.provider_id,
            key_epoch=self.key_epoch,
            key_version=self.key_version,
            custody_class=self.custody_class,
            signer_class=self.signer_class,
            mldsa87_public_key=self._mldsa87_private_key.public_key(),
            ed448_public_key=self._ed448_private_key.public_key(),
            effect_authority=self.effect_authority,
            allow_test_only=False,
            external_custody_admitted=True,
            external_custody_admission_sha512=(
                self.external_custody_admission_sha512
            ),
            mldsa87_custody=self.mldsa87_custody,
            ed448_custody=self.ed448_custody,
        )

    def sign_hybrid_preimage(
        self,
        preimage: bytes,
        *,
        purpose: str,
        context_digest: str,
    ) -> tuple[bytes, bytes]:
        context = self.hybrid_verification_context()
        if context_digest != context.context_digest:
            raise ValueError("HYBRID_SIGNING_CONTEXT_MISMATCH")
        return (
            self._mldsa87_private_key.sign(preimage),
            self._ed448_private_key.sign(preimage),
        )


class PassingThreePEvidenceEvaluator(ThreePCoreEvaluator):
    evaluator_id = "three-p-local-evidence"
    evaluator_version = "1"
    authority_role = "CONSTITUTIONAL_3P_EVALUATOR"
    authority_credential_id = "three-p-local-evidence-credential"

    def __init__(self, provider: BoundaryEvidenceProvider) -> None:
        self._provider = provider

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
                                    f"{primitive}:"
                                    f"{snapshot['evaluation_sequence']}"
                                ),
                                "source": "controlled-local-evidence",
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
            provider=self._provider,
            purpose=THREE_P_ATTESTATION_PURPOSE,
        )


class PassingFiledFrameworkEvaluator:
    evaluator_id = "filed-framework-local-evidence"
    evaluator_version = "1"
    authority_role = FILED_FRAMEWORK_AUTHORITY_ROLE
    authority_credential_id = "filed-framework-local-evidence-credential"

    def __init__(self, provider: BoundaryEvidenceProvider) -> None:
        self._provider = provider

    @staticmethod
    def _evidence(framework: str, snapshot: dict) -> list[dict]:
        return [
            {
                "evidence_id": (
                    f"{framework}:{snapshot['evaluation_sequence']}"
                ),
                "source": "controlled-filed-framework-evidence",
                "digest": canonical_integrity_hash(
                    {
                        "framework": framework,
                        "stage": snapshot["stage"],
                        "sequence": snapshot["evaluation_sequence"],
                    }
                ),
            }
        ]

    def _signed(
        self,
        framework: str,
        stage: str,
        snapshot: dict,
        determination: dict,
    ) -> dict:
        return build_signed_object(
            {
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": self.authority_role,
                },
                "framework": framework,
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_framework_digest": snapshot[
                    "prior_framework_digest"
                ],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self._provider,
            purpose=FILED_FRAMEWORK_ATTESTATION_PURPOSE,
        )

    def evaluate_aj_saaf(self, *, stage: str, snapshot: dict) -> dict:
        return self._signed(
            AJ_SAAF,
            stage,
            snapshot,
            {
                "result": "PASS",
                "control_action": "PERMIT",
                "applicable_authorities": [snapshot["resolved_authority"]],
                "winning_authority": snapshot["resolved_authority"],
                "conflicts": [],
                "precedence_resolved": True,
                "escalation_route": None,
                "lawful_override_limits": ["no_override_outside_law"],
                "runtime_recalculation_triggers": list(
                    AJ_SAAF_RECALCULATION_TRIGGERS
                ),
                "evidence_references": self._evidence(AJ_SAAF, snapshot),
            },
        )

    def evaluate_ptodf(self, *, stage: str, snapshot: dict) -> dict:
        return self._signed(
            PTODF,
            stage,
            snapshot,
            {
                "result": "PASS",
                "required_procedural_steps": snapshot[
                    "required_procedural_steps"
                ],
                "evidentiary_sufficiency": True,
                "licence_state_action": "MAINTAIN",
                "evidence_references": self._evidence(PTODF, snapshot),
            },
        )

    def evaluate_gala(self, *, stage: str, snapshot: dict) -> dict:
        return self._signed(
            GALA,
            stage,
            snapshot,
            {
                "result": "PASS",
                "release_authorized": True,
                "certification_id": "gala-controlled-certification",
                "attestation_status": "ATTESTED",
                "revocation_status": "ACTIVE",
                "audit_packet_digest": snapshot["audit_packet_digest"],
                "evidence_references": self._evidence(GALA, snapshot),
            },
        )

    def evaluate_abegf(self, *, stage: str, snapshot: dict) -> dict:
        request = snapshot["autonomy_request"]
        return self._signed(
            ABEGF,
            stage,
            snapshot,
            {
                "result": "PASS",
                "autonomy_ceiling": snapshot["autonomy_ceiling"],
                "permitted_decision_domains": [
                    request["decision_domain"]
                ],
                "prohibited_actions": [],
                "maximum_self_directed_scope": request[
                    "self_directed_scope"
                ],
                "self_modification_allowed": False,
                "goal_expansion_allowed": False,
                "escalation_triggers": ["uncertainty_threshold"],
                "suspension_controls": list(ABEGF_SUSPENSION_CONTROLS),
                "cross_system_containment": {
                    "system_chaining_limited": True,
                    "cross_model_delegation_limited": True,
                    "cross_platform_interaction_limited": True,
                    "cross_vendor_interaction_limited": True,
                    "cross_jurisdiction_interaction_limited": True,
                },
                "emergency_rollback_available": True,
                "evidence_references": self._evidence(ABEGF, snapshot),
            },
        )


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def now_ms(self) -> int:
        return self.value


class UnavailableReceiptProvider(BoundaryEvidenceProvider):
    def sign_hybrid_preimage(
        self,
        preimage: bytes,
        *,
        purpose: str,
        context_digest: str,
    ) -> tuple[bytes, bytes]:
        raise RuntimeError("RECEIPT_SIGNER_UNAVAILABLE")


class DurableAppendHandler:
    action = "review"
    handler_id = "durable-append-v1"

    def __init__(self, output_path: Path) -> None:
        self.output_path = output_path
        self.invocations = 0

    def apply(self, command: LocalEffectCommand) -> LocalEffectResult:
        line = json.dumps(
            {
                "permit_id": command.permit_id,
                "effect_id": command.effect_id,
                "request_fingerprint": command.request_fingerprint,
                "action": command.action,
                "payload": command.payload,
                "current_candidate": command.current_candidate,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8") + b"\n"
        with self.output_path.open("ab", buffering=0) as stream:
            stream.write(line)
            os.fsync(stream.fileno())
        self.invocations += 1
        return LocalEffectResult(
            LocalEffectOutcome.SUCCESS,
            {
                "output_path_digest": sha512(
                    str(self.output_path).encode("utf-8")
                ).hexdigest(),
                "record_digest": sha512(line).hexdigest(),
            },
        )


class CapturingControlledLocalAdapter(ControlledLocalAdapter):
    captured_state: dict | None = None
    captured_permit: dict | None = None

    def dispatch(self, state: dict, permit: dict, **kwargs: object) -> dict:
        self.captured_state = deepcopy(state)
        self.captured_permit = deepcopy(permit)
        return super().dispatch(state, permit, **kwargs)


class ControlledLocalAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.effect_path = self.root / "effect.jsonl"
        self.journal_path = self.root / "adapter.sqlite3"
        self.clock = MutableClock(2_000_000_000_000)
        self.authority = BoundaryEvidenceProvider(
            role="authority",
            effect_authority=True,
            three_p_attestation_admitted=True,
            framework_attestation_admitted=True,
            licence_attestation_admitted=True,
            skg_attestation_admitted=True,
            lifecycle_attestation_admitted=True,
            governance_integrity_attestation_admitted=True,
        )
        self.receipt_provider = BoundaryEvidenceProvider(
            role="adapter",
            effect_authority=False,
            three_p_attestation_admitted=False,
        )
        self.authority_context = self.authority.hybrid_verification_context()
        self.authority_owner_pin = self.authority_context.context_digest
        self.receipt_context = (
            self.receipt_provider.hybrid_verification_context()
        )
        self.receipt_owner_pin = self.receipt_context.context_digest
        self.hybrid_trust_contexts = LocalEffectHybridTrustContexts(
            authority=self.authority_context,
            authority_owner_pin=self.authority_owner_pin,
            receipt=self.receipt_context,
            receipt_owner_pin=self.receipt_owner_pin,
            three_p=self.authority_context,
            three_p_owner_pin=self.authority_owner_pin,
            skg=self.authority_context,
            skg_owner_pin=self.authority_owner_pin,
            filed_framework=self.authority_context,
            filed_framework_owner_pin=self.authority_owner_pin,
            filed_licence=self.authority_context,
            filed_licence_owner_pin=self.authority_owner_pin,
            filed_lifecycle=self.authority_context,
            filed_lifecycle_owner_pin=self.authority_owner_pin,
            filed_governance_integrity=self.authority_context,
            filed_governance_integrity_owner_pin=self.authority_owner_pin,
        )
        self.evaluator = PassingThreePEvidenceEvaluator(self.authority)
        self.framework_evaluator = PassingFiledFrameworkEvaluator(
            self.authority
        )
        self.licence_evaluator = PassingFiledLicenceEvaluator(self.authority)
        self.skg_evaluator = PassingSKGAuthorityEvaluator(self.authority)
        self.lifecycle_evaluator = PassingFiledLifecycleEvaluator(
            self.authority
        )
        self.governance_integrity_evaluator = (
            PassingFiledGovernanceIntegrityEvaluator(self.authority)
        )
        self.application = ApplicationIntegrityTests(
            methodName=(
                "test_exact_release_passes_with_deterministic_trace_and_no_authority"
            )
        )
        self.application.setUp()
        self.application_bundle = ApplicationIntegrityRuntimeBundle(
            manifest=self.application.manifest,
            trusted_admission=self.application.admission,
            release_root=self.application.root,
            trust_context=self.application.context,
            fixed_context_id=self.application.context.context_id,
            owner_pinned_context_digest=(
                self.application.context.context_digest
            ),
        )
        self.application_result = admit_application_startup(
            self.application_bundle
        )
        self.foundation = BridgeFixture()
        self.foundation.provenance.release_manifest_digest = (
            self.application_result["manifest_digest"]
        )
        self.foundation.provenance.runtime_measurement_digest = (
            self.application_result["runtime_measurement_digest"]
        )
        self.foundation.state = self.foundation._state()
        self.authority_provenance = AuthorityProvenanceFixture.create(
            identity_provider=self.foundation.identity_provider,
            identity_evaluator=self.foundation.identity_evaluator,
            boundary_provider=self.foundation.authority_provider,
            boundary_evaluator=self.foundation.authority_evaluator,
            skg_provider=self.authority,
            skg_evaluator=self.skg_evaluator,
            observed_at=self.foundation.impersonation.now,
            resolved_authority="owner",
            class_id="CLASS_2",
            subclass_id="CLASS_2",
        )
        self.foundational_dependencies = replace(
            self.foundation.dependencies,
            authority_provenance_dependencies=(
                self.authority_provenance.dependencies
            ),
        )
        self.foundation.dependencies = self.foundational_dependencies
        self.handler = DurableAppendHandler(self.effect_path)
        self.adapter = CapturingControlledLocalAdapter(
            adapter_name="desktop-v2-controlled-local",
            journal_path=self.journal_path,
            max_permit_ttl_ms=1_000,
            receipt_provider=self.receipt_provider,
            handlers=[self.handler],
            clock=self.clock,
            skg_evaluator=self.skg_evaluator,
            skg_attestation_provider=self.authority,
            filed_framework_evaluator=self.framework_evaluator,
            filed_framework_attestation_provider=self.authority,
            filed_licence_evaluator=self.licence_evaluator,
            filed_licence_attestation_provider=self.authority,
            filed_lifecycle_evaluator=self.lifecycle_evaluator,
            filed_lifecycle_attestation_provider=self.authority,
            filed_governance_integrity_evaluator=(
                self.governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=self.authority,
            hybrid_trust_contexts=self.hybrid_trust_contexts,
        )

    def tearDown(self) -> None:
        self.foundation.close()
        self.application.doCleanups()
        self.temporary.cleanup()

    def evaluate_three_p_fixture(self, *args, **kwargs):
        kwargs.setdefault("trust_context", self.authority_context)
        kwargs.setdefault(
            "owner_pinned_context_digest", self.authority_owner_pin
        )
        return evaluate_three_p_core(*args, **kwargs)

    def evaluate_skg_fixture(self, *args, **kwargs):
        kwargs.setdefault(
            "attestation_trust_context", self.authority_context
        )
        kwargs.setdefault(
            "owner_pinned_context_digest", self.authority_owner_pin
        )
        return evaluate_skg_authority(*args, **kwargs)

    def evaluate_framework_fixture(self, *args, **kwargs):
        kwargs.setdefault(
            "attestation_trust_context", self.authority_context
        )
        kwargs.setdefault(
            "owner_pinned_context_digest", self.authority_owner_pin
        )
        return evaluate_filed_framework(*args, **kwargs)

    def evaluate_lifecycle_fixture(self, *args, **kwargs):
        kwargs.setdefault(
            "attestation_trust_context", self.authority_context
        )
        kwargs.setdefault(
            "owner_pinned_context_digest", self.authority_owner_pin
        )
        return evaluate_filed_lifecycle(*args, **kwargs)

    def evaluate_governance_integrity_fixture(self, *args, **kwargs):
        kwargs.setdefault(
            "attestation_trust_context", self.authority_context
        )
        kwargs.setdefault(
            "owner_pinned_context_digest", self.authority_owner_pin
        )
        return evaluate_filed_governance_integrity(*args, **kwargs)

    def issue_token_fixture(self, *args, **kwargs):
        kwargs.setdefault("three_p_trust_context", self.authority_context)
        kwargs.setdefault(
            "three_p_owner_pinned_context_digest",
            self.authority_owner_pin,
        )
        return issue_token(*args, **kwargs)

    def run_execution_gate_fixture(self, *args, **kwargs):
        kwargs.setdefault("signature_trust_context", self.authority_context)
        kwargs.setdefault(
            "signature_owner_pinned_context_digest", self.authority_owner_pin
        )
        for prefix in (
            "three_p",
            "skg",
            "filed_framework",
            "filed_licence",
            "filed_lifecycle",
            "filed_governance_integrity",
        ):
            trust_name = (
                f"{prefix}_attestation_trust_context"
                if prefix != "three_p"
                else "three_p_attestation_trust_context"
            )
            kwargs.setdefault(trust_name, self.authority_context)
            kwargs.setdefault(
                f"{prefix}_owner_pinned_context_digest",
                self.authority_owner_pin,
            )
        return run_execution_gate(*args, **kwargs)

    def request(self) -> dict:
        return {
            **filed_licence_request_fields(),
            "action": "review",
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "aj_saaf_operational_context": {
                "geographic_location": "AU",
                "deployment_context": "controlled-local",
                "data_origin": "AU",
                "subject_status": "owner",
                "regulatory_classification": "CLASS_2",
                "cross_border_data_movement": False,
            },
            "abegf_request": {
                "decision_domain": "review",
                "self_directed_scope": "local",
                "self_modification_requested": False,
                "goal_expansion_requested": False,
                "delegation_targets": [],
                "cross_platform_interactions": [],
                "cross_vendor_interactions": [],
                "cross_jurisdiction_interactions": [],
            },
            "anchors": {
                "procedural_truth": True,
                "sovereign_knowledge_graph": True,
                "digital_twin_network": True,
                "planetary_population_constraints": True,
            },
            "attestation": {"verified": True, "attested": True},
            "indexed_attestations": [
                {"verified": True, "source": "authority-a"}
            ],
            "output": {"result": "reviewed"},
            "payload": {
                "message": "governed local effect",
                "output": {"fact_verified_ratio": 1.0},
                "policy": {
                    "policy_id": "local-effect-policy",
                    "policy_version": "1",
                    "status": "ACTIVE",
                    "effective_from": 0,
                    "effective_until": 3_000_000_000,
                    "permitted_actions": ["review"],
                    "restricted_actions": [],
                },
            },
            "ap_acf_class": "CLASS_2",
            "ap_acf_subclass": "CLASS_2",
            "requested_autonomy_level": 20,
            "requested_system_mode": "supervised",
            "autonomy_ceiling": 30,
            "operational_environment": "controlled",
            "public_exposure": "limited",
            "operational_scope": "local",
            "environment_modifiers": {
                "human_proximity": "controlled",
                "geographic_isolation": "not-applicable",
                "operational_containment": "verified",
            },
            "deployment_restrictions": ["licensed-environment-only"],
            "deployment_scope": "licensed-local-scope",
            "license_profile": {
                "allowed_classes": ["CLASS_2"],
                "max_autonomy_level": 30,
            },
        }

    @staticmethod
    def append_chain(state: dict, stage: str, payload: dict) -> None:
        previous = (
            state["hash_chain"][-1]["hash"]
            if state["hash_chain"]
            else GENESIS_HASH
        )
        entry = build_hash_chain_entry(
            previous_hash=previous,
            stage=stage,
            payload=payload,
        )
        state["hash_chain"].append(entry)
        state["state_hash"] = entry["hash"]

    def verify_composite_audit(self, state: dict) -> bool:
        return verify_audit_record(
            state,
            skg_evaluator=self.skg_evaluator,
            skg_attestation_provider=self.authority,
            filed_lifecycle_evaluator=self.lifecycle_evaluator,
            filed_lifecycle_attestation_provider=self.authority,
            filed_governance_integrity_evaluator=(
                self.governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=self.authority,
            skg_attestation_trust_context=self.authority_context,
            skg_owner_pinned_context_digest=self.authority_owner_pin,
            filed_lifecycle_attestation_trust_context=self.authority_context,
            filed_lifecycle_owner_pinned_context_digest=(
                self.authority_owner_pin
            ),
            filed_governance_integrity_attestation_trust_context=(
                self.authority_context
            ),
            filed_governance_integrity_owner_pinned_context_digest=(
                self.authority_owner_pin
            ),
        )

    def foundational_runtime_arguments(self) -> dict:
        return {
            "application_integrity_bundle": self.application_bundle,
            "application_integrity_result": self.application_result,
            "foundational_request_dependencies": (
                self.foundational_dependencies
            ),
            "hybrid_trust_contexts": self.hybrid_trust_contexts,
        }

    def configure_authority_provenance_provider(
        self,
        *,
        skg_provider,
        skg_evaluator,
    ) -> None:
        self.authority_provenance = AuthorityProvenanceFixture.create(
            identity_provider=self.foundation.identity_provider,
            identity_evaluator=self.foundation.identity_evaluator,
            boundary_provider=self.foundation.authority_provider,
            boundary_evaluator=self.foundation.authority_evaluator,
            skg_provider=skg_provider,
            skg_evaluator=skg_evaluator,
            observed_at=self.foundation.impersonation.now,
            resolved_authority="owner",
            class_id="CLASS_2",
            subclass_id="CLASS_2",
        )
        self.foundational_dependencies = replace(
            self.foundation.dependencies,
            authority_provenance_dependencies=(
                self.authority_provenance.dependencies
            ),
        )
        self.foundation.dependencies = self.foundational_dependencies

    def ready_state(self) -> dict:
        state = build_state(self.request())
        state["filed_governance_integrity_revocation_binding"] = (
            governance_integrity_revocation_binding(
                status="ACTIVE",
                sequence=1,
            )
        )
        state.update(deepcopy(self.foundation.state))
        verify_and_project_application_startup(
            state,
            bundle=self.application_bundle,
            result=self.application_result,
        )
        state["release_manifest_digest"] = state[
            "application_integrity_manifest_digest"
        ]
        state["runtime_measurement_digest"] = state[
            "application_integrity_runtime_measurement_digest"
        ]
        state["hash_chain"] = []
        state["state_hash"] = GENESIS_HASH
        self.append_chain(
            state,
            APPLICATION_INTEGRITY_STARTUP_STAGE,
            application_startup_hash_payload(state),
        )
        self.append_chain(
            state,
            "state_construction",
            {"request_fingerprint": state["request_fingerprint"]},
        )
        self.foundation.state = state
        state, _ = self.foundation.run_all()
        self.evaluate_three_p_fixture(
            state,
            evaluator=self.evaluator,
            attestation_provider=self.authority,
            stage="foundational_baseline",
        )
        self.append_chain(
            state,
            "three_p_core:foundational_baseline",
            three_p_hash_payload(state),
        )
        evaluate_foundational_baseline(state)
        bind_foundational_baseline_hash(state)
        self.issue_token_fixture(
            state,
            token_name="foundational",
            issuer="foundational_baseline",
            issued_at_stage="foundational_baseline",
            payload=foundational_baseline_hash_payload(state),
            provider=self.authority,
            three_p_attestation_provider=self.authority,
        )
        self.evaluate_three_p_fixture(
            state,
            evaluator=self.evaluator,
            attestation_provider=self.authority,
            stage="ingress",
        )
        self.append_chain(
            state,
            "three_p_core:ingress",
            three_p_hash_payload(state),
        )
        evaluate_authority_provenance(
            state,
            dependencies=self.authority_provenance.dependencies,
        )
        self.append_chain(
            state,
            "authority_provenance:admission",
            authority_provenance_hash_payload(state),
        )
        self.issue_token_fixture(
            state,
            token_name="authority_provenance",
            issuer="authority_provenance",
            issued_at_stage="authority_provenance:admission",
            payload=authority_provenance_hash_payload(state),
            provider=self.authority,
            three_p_attestation_provider=self.authority,
        )
        state["financial_amount"] = None
        state["safety_profile"]["computed_tier"] = "LOW"
        state["corroboration_required"] = 2
        state["corroboration_met"] = True
        state["authority_first_result"] = "ALLOW"
        state["procedural_truth_result"] = "PASS"
        state["classification_result"] = "ALLOW"
        state["licensing_result"] = "ALLOW"
        state["governance_result"] = "ALLOW"
        state["domain_result"] = "pass"
        state["aurion15_result"] = "pass"
        state["current_candidate"] = {
            "type": "direct",
            "action": "review",
            "payload": deepcopy(state["payload"]),
        }
        state["collective_signals"] = {
            "request_fingerprint": state["request_fingerprint"],
            "intent_signal": "review",
            "risk_potential_signal": 0.1,
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
        state["collective_signal_status"] = "attached"

        token_contracts = [
            ("authority", "root_of_trust", "root_of_trust", {}),
            ("skg", "skg_authority", "skg_authority", {}),
            (
                "procedural_truth",
                "procedural_truth_engine",
                "procedural_truth",
                {},
            ),
            ("ptodf", "PTODF", "filed_framework:ptodf", {}),
            ("classification", "classification_engine", "classification", {}),
            ("licensing", "licensing_engine", "licensing", {}),
            ("aj_saaf", "AJ-SAAF", "filed_framework:aj_saaf", {}),
            ("gala", "GALA", "filed_framework:gala", {}),
            ("abegf", "ABEGF", "filed_framework:abegf", {}),
            *[
                (
                    FILED_LIFECYCLE_ENGINE_IDS[engine].lower(),
                    FILED_LIFECYCLE_ENGINE_IDS[engine],
                    FILED_LIFECYCLE_STAGES[engine],
                    {},
                )
                for engine in FILED_LIFECYCLE_ORDER
            ],
            *[
                (
                    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                        governance_function
                    ].lower(),
                    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                        governance_function
                    ],
                    FILED_GOVERNANCE_INTEGRITY_STAGES[
                        governance_function
                    ],
                    {},
                )
                for governance_function in (
                    FILED_GOVERNANCE_INTEGRITY_ORDER
                )
            ],
            ("governance", "governance_engine", "governance", {}),
            ("domain", "domain_wrap", "domain_wrap", {}),
            ("aurion", "aurion15_runtime", "aurion_runtime", {}),
            (
                "execution_boundary",
                "execution_gate",
                "execution_prep",
                {"boundary_clear": True},
            ),
            (
                "execution_attestation",
                "execution_gate",
                "execution_prep",
                {"attested_for_execution": True},
            ),
            (
                "consequentiality_threshold",
                "threshold_engine",
                "procedural_truth",
                {},
            ),
            (
                "corroboration_threshold",
                "threshold_engine",
                "procedural_truth",
                {},
            ),
        ]
        framework_by_token = {
            "aj_saaf": AJ_SAAF,
            "ptodf": PTODF,
            "gala": GALA,
            "abegf": ABEGF,
        }
        lifecycle_by_token = {
            FILED_LIFECYCLE_ENGINE_IDS[engine].lower(): engine
            for engine in FILED_LIFECYCLE_ORDER
        }
        governance_integrity_by_token = {
            FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                governance_function
            ].lower(): governance_function
            for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
        }
        for token_name, issuer, stage, payload in token_contracts:
            if token_name == "authority":
                append_filed_licence_evaluation(
                    state,
                    stage=LICENCE_ROOT_BINDING_STAGE,
                    evaluator=self.licence_evaluator,
                    provider=self.authority,
                )
                payload = {
                    "authority_first_result": state[
                        "authority_first_result"
                    ],
                    "authority_first_reason": state.get(
                        "authority_first_reason"
                    ),
                    "licence_id": state["licence_id"],
                    "license_tier": state["license_tier"],
                    "filed_licence_digest": state[
                        "filed_licence_digest"
                    ],
                    "licence_bindings_digest": canonical_integrity_hash(
                        state["filed_licence_record"][
                            "evaluation_snapshot"
                        ]["bindings"]
                    ),
                }
            elif token_name == "licensing":
                append_filed_licence_evaluation(
                    state,
                    stage=LICENCE_VALIDATION_STAGE,
                    evaluator=self.licence_evaluator,
                    provider=self.authority,
                )
                payload = {
                    "licensing_result": "ALLOW",
                    "licensing_reason": "license_valid",
                    "licence_id": state["licence_id"],
                    "license_tier": state["license_tier"],
                    "filed_licence_digest": state[
                        "filed_licence_digest"
                    ],
                    "licence_bindings_digest": canonical_integrity_hash(
                        state["filed_licence_record"][
                            "evaluation_snapshot"
                        ]["bindings"]
                    ),
                    "licence_revocation_status": state[
                        "licence_revocation_status"
                    ],
                    "licence_revocation_sequence": state[
                        "licence_revocation_sequence"
                    ],
                }
            framework = framework_by_token.get(token_name)
            lifecycle_engine = lifecycle_by_token.get(token_name)
            governance_integrity_function = (
                governance_integrity_by_token.get(token_name)
            )
            if token_name == "skg":
                skg_stage = (
                    f"{SKG_HASH_STAGE_PREFIX}"
                    "constitutional_authority_substrate"
                )
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=skg_stage,
                )
                self.append_chain(
                    state,
                    f"three_p_core:{skg_stage}",
                    three_p_hash_payload(state),
                )
                self.evaluate_skg_fixture(
                    state,
                    stage="constitutional_authority_substrate",
                    evaluator=self.skg_evaluator,
                    attestation_provider=self.authority,
                )
                self.append_chain(
                    state,
                    skg_stage,
                    skg_authority_hash_payload(state),
                )
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=f"{skg_stage}:post",
                )
                self.append_chain(
                    state,
                    f"three_p_core:{skg_stage}:post",
                    three_p_hash_payload(state),
                )
                payload = skg_authority_hash_payload(state)
            elif framework is not None:
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=FILED_FRAMEWORK_STAGES[framework],
                )
                self.append_chain(
                    state,
                    f"three_p_core:{FILED_FRAMEWORK_STAGES[framework]}",
                    three_p_hash_payload(state),
                )
                self.evaluate_framework_fixture(
                    state,
                    framework,
                    evaluator=self.framework_evaluator,
                    attestation_provider=self.authority,
                )
                self.append_chain(
                    state,
                    FILED_FRAMEWORK_STAGES[framework],
                    filed_framework_hash_payload(state),
                )
                evaluation_stage = (
                    f"{FILED_FRAMEWORK_STAGES[framework]}:post"
                )
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=evaluation_stage,
                )
                self.append_chain(
                    state,
                    f"three_p_core:{evaluation_stage}",
                    three_p_hash_payload(state),
                )
                record = state["filed_framework_trace"][-1]
                payload = {
                    "framework_result": record["result"],
                    "framework_record_digest": canonical_integrity_hash(
                        record
                    ),
                    "evaluation_source_digest": record[
                        "evaluation_source_digest"
                    ],
                    "execution_authority_granted": False,
                }
            elif lifecycle_engine is not None:
                lifecycle_stage = FILED_LIFECYCLE_STAGES[
                    lifecycle_engine
                ]
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=lifecycle_stage,
                )
                self.append_chain(
                    state,
                    f"three_p_core:{lifecycle_stage}",
                    three_p_hash_payload(state),
                )
                self.evaluate_lifecycle_fixture(
                    state,
                    lifecycle_engine,
                    evaluator=self.lifecycle_evaluator,
                    attestation_provider=self.authority,
                )
                self.append_chain(
                    state,
                    lifecycle_stage,
                    filed_lifecycle_hash_payload(state),
                )
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=f"{lifecycle_stage}:post",
                )
                self.append_chain(
                    state,
                    f"three_p_core:{lifecycle_stage}:post",
                    three_p_hash_payload(state),
                )
                payload = filed_lifecycle_hash_payload(state)
            elif governance_integrity_function is not None:
                integrity_stage = FILED_GOVERNANCE_INTEGRITY_STAGES[
                    governance_integrity_function
                ]
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=integrity_stage,
                )
                self.append_chain(
                    state,
                    f"three_p_core:{integrity_stage}",
                    three_p_hash_payload(state),
                )
                self.evaluate_governance_integrity_fixture(
                    state,
                    governance_integrity_function,
                    evaluator=self.governance_integrity_evaluator,
                    attestation_provider=self.authority,
                )
                self.append_chain(
                    state,
                    integrity_stage,
                    filed_governance_integrity_hash_payload(state),
                )
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=f"{integrity_stage}:post",
                )
                self.append_chain(
                    state,
                    f"three_p_core:{integrity_stage}:post",
                    three_p_hash_payload(state),
                )
                payload = filed_governance_integrity_hash_payload(state)
            else:
                evaluation_stage = f"token:{token_name}"
                self.evaluate_three_p_fixture(
                    state,
                    evaluator=self.evaluator,
                    attestation_provider=self.authority,
                    stage=evaluation_stage,
                )
                self.append_chain(
                    state,
                    f"three_p_core:{evaluation_stage}",
                    three_p_hash_payload(state),
                )
                if token_name == "governance":
                    payload = {
                        "governance_result": state["governance_result"],
                        "governance_reason": state.get(
                            "governance_reason"
                        ),
                        "governance_framework_results": {
                            framework: state[
                                "filed_framework_results"
                            ].get(framework)
                            for framework in (AJ_SAAF, GALA, ABEGF)
                        },
                        "filed_framework_digest": state[
                            "filed_framework_digest"
                        ],
                        "filed_lifecycle_results": {
                            engine: state["filed_lifecycle_results"].get(
                                engine
                            )
                            for engine in FILED_LIFECYCLE_ORDER
                        },
                        "filed_lifecycle_digest": state[
                            "filed_lifecycle_digest"
                        ],
                        "lifecycle_implementation_order_authority": (
                            FILED_LIFECYCLE_ORDER_AUTHORITY
                        ),
                        "filed_governance_integrity_result": (
                            GOVERNANCE_INTEGRITY_PASS
                        ),
                        "filed_governance_integrity_results": {
                            governance_function: state[
                                "filed_governance_integrity_results"
                            ].get(governance_function)
                            for governance_function in (
                                FILED_GOVERNANCE_INTEGRITY_ORDER
                            )
                        },
                        "filed_governance_integrity_digest": state[
                            "filed_governance_integrity_digest"
                        ],
                        "governance_integrity_implementation_order_authority": (
                            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                        ),
                        "filed_governance_integrity_revocation_status": (
                            state[
                                "filed_governance_integrity_revocation_binding"
                            ]["status"]
                        ),
                        "filed_governance_integrity_revocation_sequence": (
                            state[
                                "filed_governance_integrity_revocation_binding"
                            ]["sequence"]
                        ),
                        "filed_governance_integrity_revocation_digest": (
                            state[
                                "filed_governance_integrity_revocation_binding"
                            ]["digest"]
                        ),
                        "filed_governance_integrity_authority_granted": False,
                        "filed_governance_integrity_licence_granted": False,
                        "filed_governance_integrity_execution_authority_granted": False,
                        "filed_governance_integrity_effect_granted": False,
                        "filed_governance_integrity_bypass_permitted": False,
                    }
            self.issue_token_fixture(
                state,
                token_name=token_name,
                issuer=issuer,
                issued_at_stage=stage,
                payload=payload,
                provider=self.authority,
                three_p_attestation_provider=self.authority,
            )
        append_filed_licence_evaluation(
            state,
            stage=LICENCE_REVALIDATION_STAGE,
            evaluator=self.licence_evaluator,
            provider=self.authority,
        )
        self.evaluate_three_p_fixture(
            state,
            evaluator=self.evaluator,
            attestation_provider=self.authority,
            stage="execution_gate",
        )
        self.append_chain(
            state,
            "three_p_core:execution_gate",
            three_p_hash_payload(state),
        )
        self.append_chain(
            state,
            "token_stack",
            {"token_stack_digest": canonical_integrity_hash(state["tokens"])},
        )

        self.run_execution_gate_fixture(
            state,
            signature_provider=self.authority,
            three_p_attestation_provider=self.authority,
            skg_evaluator=self.skg_evaluator,
            skg_attestation_provider=self.authority,
            filed_framework_evaluator=self.framework_evaluator,
            filed_framework_attestation_provider=self.authority,
            filed_lifecycle_evaluator=self.lifecycle_evaluator,
            filed_lifecycle_attestation_provider=self.authority,
            filed_governance_integrity_evaluator=(
                self.governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=self.authority,
            filed_licence_evaluator=self.licence_evaluator,
            filed_licence_attestation_provider=self.authority,
            application_integrity_bundle=self.application_bundle,
            application_integrity_result=self.application_result,
            foundational_request_dependencies=(
                self.foundational_dependencies
            ),
        )
        self.assertEqual(state["execution_result"], "EXECUTE")
        self.assertEqual(state["decision"], "APPROVED")
        self.append_chain(
            state,
            "execution_gate",
            {
                "execution_result": state["execution_result"],
                "decision": state["decision"],
            },
        )
        self.evaluate_three_p_fixture(
            state,
            evaluator=self.evaluator,
            attestation_provider=self.authority,
            stage="execution_gate:post",
        )
        self.append_chain(
            state,
            "three_p_core:execution_gate:post",
            three_p_hash_payload(state),
        )
        return state

    def test_real_local_effect_requires_point_of_use_receipt(self) -> None:
        state = self.ready_state()
        run_controlled_local_effect(
            state,
            adapter=self.adapter,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            permit_ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )
        self.append_chain(
            state,
            "controlled_local_effect",
            {
                "effect_id": state["effect_id"],
                "permit_digest": state["effect_permit"]["digest"],
                "receipt_digest": state["effect_receipt"]["digest"],
                "effect_result": state["effect_result"],
            },
        )
        _finalize_audit(state)

        self.assertEqual(state["decision"], "APPROVED")
        self.assertEqual(state["execution_result"], "EXECUTE")
        self.assertEqual(state["effect_result"], "SUCCESS")
        self.assertEqual(self.handler.invocations, 1)
        records = self.effect_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(records), 1)
        self.assertEqual(json.loads(records[0])["effect_id"], state["effect_id"])
        self.assertTrue(
            verify_local_effect_receipt(
                state,
                receipt_provider=self.receipt_provider,
                receipt_trust_context=self.receipt_context,
                receipt_owner_pinned_context_digest=self.receipt_owner_pin,
            )
        )
        self.assertTrue(self.verify_composite_audit(state))
        self.assertEqual(
            state["audit_record"]["effect_receipt"],
            state["effect_receipt"],
        )

    def test_missing_adapter_blocks_without_effect(self) -> None:
        state = self.ready_state()
        with self.assertRaisesRegex(
            LocalEffectError,
            "CONTROLLED_LOCAL_ADAPTER_NOT_INJECTED",
        ):
            run_controlled_local_effect(
                state,
                adapter=None,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                permit_ttl_ms=500,
                **self.foundational_runtime_arguments(),
            )
        self.assertFalse(self.effect_path.exists())
        self.assertEqual(self.handler.invocations, 0)

    def test_replay_is_rejected_without_second_effect(self) -> None:
        state = self.ready_state()
        run_controlled_local_effect(
            state,
            adapter=self.adapter,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            permit_ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )

        with self.assertRaisesRegex(LocalEffectError, "EFFECT_PERMIT_REPLAYED"):
            self.adapter.dispatch(
                state,
                state["effect_permit"],
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 1)

    def test_expired_permit_is_rejected_without_effect(self) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=100,
            **self.foundational_runtime_arguments(),
        )
        self.clock.value += 100

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_PERMIT_EXPIRED_OR_TIME_INVALID",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 0)

    def test_revoked_permit_is_rejected_without_effect(self) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=100,
            **self.foundational_runtime_arguments(),
        )
        self.adapter.revoke(
            permit["permit_id"],
            reason={"code": "OWNER_REVOKED"},
        )

        with self.assertRaisesRegex(LocalEffectError, "EFFECT_PERMIT_REVOKED"):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 0)

    def test_filed_licence_revocation_between_permit_and_dispatch_blocks_effect(
        self,
    ) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )
        self.licence_evaluator.revocation_status = "REVOKED"
        self.licence_evaluator.revocation_sequence = 2

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_POINT_OF_USE_FILED_LICENCE_NOT_CURRENT",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )

        self.assertEqual(self.handler.invocations, 0)

    def test_lifecycle_change_after_claim_is_rechecked_before_effect(
        self,
    ) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )
        original_claim = self.adapter._claim_once

        def claim_then_mutate(
            claimed_permit: dict,
            *,
            claimed_at_ms: int,
        ) -> None:
            original_claim(
                claimed_permit,
                claimed_at_ms=claimed_at_ms,
            )
            ready_state["filed_lifecycle_trace"][-1][
                "governance_superseded"
            ] = True

        self.adapter._claim_once = claim_then_mutate

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_POINT_OF_USE_FILED_LIFECYCLE_INVALID",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )

        self.assertEqual(self.handler.invocations, 0)

    def test_governance_integrity_revocation_after_claim_blocks_effect(
        self,
    ) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )
        original_claim = self.adapter._claim_once

        def claim_then_revoke(
            claimed_permit: dict,
            *,
            claimed_at_ms: int,
        ) -> None:
            original_claim(
                claimed_permit,
                claimed_at_ms=claimed_at_ms,
            )
            ready_state[
                "filed_governance_integrity_revocation_binding"
            ] = governance_integrity_revocation_binding(
                status="REVOKED",
                sequence=2,
            )

        self.adapter._claim_once = claim_then_revoke

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_POINT_OF_USE_FILED_GOVERNANCE_INTEGRITY_INVALID",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )

        self.assertEqual(self.handler.invocations, 0)

    def test_missing_governance_integrity_token_blocks_permit(self) -> None:
        ready_state = self.ready_state()
        missing_token = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            FILED_GOVERNANCE_INTEGRITY_ORDER[0]
        ].lower()
        del ready_state["tokens"][missing_token]

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_PERMIT_(THREE_P|TOKEN_STACK)_INVALID",
        ):
            self.adapter.build_permit(
                ready_state,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                ttl_ms=500,
                **self.foundational_runtime_arguments(),
            )

        self.assertEqual(self.handler.invocations, 0)

    def test_bound_payload_mutation_is_rejected_without_effect(self) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=100,
            **self.foundational_runtime_arguments(),
        )
        ready_state["payload"]["message"] = "mutated"

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_POINT_OF_USE_THREE_P_INVALID",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 0)

    def test_foundational_mutation_at_point_of_use_is_rejected_without_effect(
        self,
    ) -> None:
        ready_state = self.ready_state()
        permit = self.adapter.build_permit(
            ready_state,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            ttl_ms=100,
            **self.foundational_runtime_arguments(),
        )
        ready_state["foundational_baseline_record"][
            "impersonation_protection_digest"
        ] = "f" * 128

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_POINT_OF_USE_FOUNDATIONAL_BASELINE_INVALID",
        ):
            self.adapter.dispatch(
                ready_state,
                permit,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 0)

    def test_non_effect_authority_cannot_mint_permit(self) -> None:
        ready_state = self.ready_state()
        non_authority = BoundaryEvidenceProvider(
            role="non-authority",
            effect_authority=False,
            three_p_attestation_admitted=True,
        )

        with self.assertRaisesRegex(
            LocalEffectError,
            "EFFECT_AUTHORITY_PROVIDER_NOT_ADMITTED",
        ):
            self.adapter.build_permit(
                ready_state,
                authority_provider=non_authority,
                three_p_attestation_provider=self.authority,
                ttl_ms=100,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 0)

    def test_receipt_failure_is_in_doubt_and_never_replayed(self) -> None:
        ready_state = self.ready_state()
        unavailable_receipt_provider = UnavailableReceiptProvider(
            role="unavailable-adapter",
            effect_authority=False,
            three_p_attestation_admitted=False,
        )
        adapter = ControlledLocalAdapter(
            adapter_name="desktop-v2-unavailable-receipt",
            journal_path=self.root / "unavailable-receipt.sqlite3",
            max_permit_ttl_ms=1_000,
            receipt_provider=unavailable_receipt_provider,
            handlers=[self.handler],
            clock=self.clock,
            skg_evaluator=self.skg_evaluator,
            skg_attestation_provider=self.authority,
            filed_framework_evaluator=self.framework_evaluator,
            filed_framework_attestation_provider=self.authority,
            filed_licence_evaluator=self.licence_evaluator,
            filed_licence_attestation_provider=self.authority,
            filed_lifecycle_evaluator=self.lifecycle_evaluator,
            filed_lifecycle_attestation_provider=self.authority,
            filed_governance_integrity_evaluator=(
                self.governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=self.authority,
        )

        with self.assertRaisesRegex(
            LocalEffectInDoubtError,
            "LOCAL_EFFECT_RECEIPT_UNAVAILABLE",
        ):
            run_controlled_local_effect(
                ready_state,
                adapter=adapter,
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                permit_ttl_ms=500,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 1)
        with self.assertRaisesRegex(LocalEffectError, "EFFECT_PERMIT_REPLAYED"):
            adapter.dispatch(
                ready_state,
                ready_state["effect_permit"],
                authority_provider=self.authority,
                three_p_attestation_provider=self.authority,
                **self.foundational_runtime_arguments(),
            )
        self.assertEqual(self.handler.invocations, 1)

    def test_effect_receipt_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        run_controlled_local_effect(
            state,
            adapter=self.adapter,
            authority_provider=self.authority,
            three_p_attestation_provider=self.authority,
            permit_ttl_ms=500,
            **self.foundational_runtime_arguments(),
        )
        self.append_chain(
            state,
            "controlled_local_effect",
            {
                "effect_id": state["effect_id"],
                "permit_digest": state["effect_permit"]["digest"],
                "receipt_digest": state["effect_receipt"]["digest"],
                "effect_result": state["effect_result"],
            },
        )
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["effect_receipt"]["outcome"] = "FAILED"
        self.assertFalse(self.verify_composite_audit(state))

    def test_filed_licence_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["filed_licence_trace"][-1]["evaluation_source"][
            "determination"
        ]["revocation_sequence"] = 99

        self.assertFalse(self.verify_composite_audit(state))

    def test_skg_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["skg_authority_trace"][-1]["evidence_references"][0][
            "digest"
        ] = "0" * 128

        self.assertFalse(self.verify_composite_audit(state))

    def test_foundational_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["foundational_baseline_record"][
            "authority_boundary_digest"
        ] = "0" * 128

        self.assertFalse(self.verify_composite_audit(state))

    def test_authority_provenance_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["authority_provenance_record"]["resolved_authority"][
            "authority_id"
        ] = "forged-authority"

        self.assertFalse(self.verify_composite_audit(state))

    def test_authenticated_audit_requires_live_verifier_dependencies(
        self,
    ) -> None:
        state = self.ready_state()
        _finalize_audit(state)

        self.assertFalse(verify_audit_record(state))
        self.assertTrue(self.verify_composite_audit(state))

    def test_lifecycle_tamper_invalidates_terminal_audit(self) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["filed_lifecycle_trace"][-1][
            "governance_superseded"
        ] = True

        self.assertFalse(self.verify_composite_audit(state))

    def test_governance_integrity_tamper_invalidates_terminal_audit(
        self,
    ) -> None:
        state = self.ready_state()
        _finalize_audit(state)
        self.assertTrue(self.verify_composite_audit(state))

        state["filed_governance_integrity_trace"][-1][
            "bypass_permitted"
        ] = True

        self.assertFalse(self.verify_composite_audit(state))


if __name__ == "__main__":
    unittest.main()
