from typing import Any, Dict

from .execution_gate import run_execution_gate
from sbp_lex.security.signature_provider import (
    HybridVerificationContext,
    SignatureProvider,
)
from sbp_lex.governance.three_p_doctrine import ThreePCoreEvaluator
from sbp_lex.governance.skg_authority import SKGAuthorityEvaluator
from sbp_lex.governance.filed_frameworks import FiledFrameworkEvaluator
from sbp_lex.governance.filed_lifecycle import FiledLifecycleEvaluator
from sbp_lex.governance.filed_governance_integrity import (
    FiledGovernanceIntegrityEvaluator,
)
from sbp_lex.licensing.filed_licensing import FiledLicenceEvaluator
from sbp_lex.baseline.application_startup import ApplicationIntegrityRuntimeBundle
from sbp_lex.baseline.request_controls import FoundationalRequestDependencies


class ExecutionEngine:
    """Compatibility wrapper for the response-controller pipeline."""

    name = "execution_engine"

    def __init__(
        self,
        signature_provider: SignatureProvider | None = None,
        signature_trust_context: HybridVerificationContext | None = None,
        signature_owner_pinned_context_digest: str | None = None,
        three_p_attestation_provider: SignatureProvider | None = None,
        three_p_attestation_trust_context: HybridVerificationContext | None = None,
        three_p_owner_pinned_context_digest: str | None = None,
        skg_evaluator: SKGAuthorityEvaluator | None = None,
        skg_attestation_provider: SignatureProvider | None = None,
        skg_attestation_trust_context: HybridVerificationContext | None = None,
        skg_owner_pinned_context_digest: str | None = None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
        filed_framework_attestation_provider: SignatureProvider | None = None,
        filed_framework_attestation_trust_context: (
            HybridVerificationContext | None
        ) = None,
        filed_framework_owner_pinned_context_digest: str | None = None,
        filed_licence_evaluator: FiledLicenceEvaluator | None = None,
        filed_licence_attestation_provider: SignatureProvider | None = None,
        filed_licence_attestation_trust_context: (
            HybridVerificationContext | None
        ) = None,
        filed_licence_owner_pinned_context_digest: str | None = None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
        filed_lifecycle_attestation_provider: SignatureProvider | None = None,
        filed_lifecycle_attestation_trust_context: (
            HybridVerificationContext | None
        ) = None,
        filed_lifecycle_owner_pinned_context_digest: str | None = None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ) = None,
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ) = None,
        filed_governance_integrity_attestation_trust_context: (
            HybridVerificationContext | None
        ) = None,
        filed_governance_integrity_owner_pinned_context_digest: str | None = None,
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
        application_integrity_result: dict[str, Any] | None = None,
        foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    ) -> None:
        self._signature_provider = signature_provider
        self._signature_trust_context = signature_trust_context
        self._signature_owner_pinned_context_digest = (
            signature_owner_pinned_context_digest
        )
        self._three_p_attestation_provider = three_p_attestation_provider
        self._three_p_attestation_trust_context = three_p_attestation_trust_context
        self._three_p_owner_pinned_context_digest = (
            three_p_owner_pinned_context_digest
        )
        self._skg_evaluator = skg_evaluator
        self._skg_attestation_provider = skg_attestation_provider
        self._skg_attestation_trust_context = skg_attestation_trust_context
        self._skg_owner_pinned_context_digest = skg_owner_pinned_context_digest
        self._filed_framework_evaluator = filed_framework_evaluator
        self._filed_framework_attestation_provider = (
            filed_framework_attestation_provider
        )
        self._filed_framework_attestation_trust_context = (
            filed_framework_attestation_trust_context
        )
        self._filed_framework_owner_pinned_context_digest = (
            filed_framework_owner_pinned_context_digest
        )
        self._filed_licence_evaluator = filed_licence_evaluator
        self._filed_licence_attestation_provider = (
            filed_licence_attestation_provider
        )
        self._filed_licence_attestation_trust_context = (
            filed_licence_attestation_trust_context
        )
        self._filed_licence_owner_pinned_context_digest = (
            filed_licence_owner_pinned_context_digest
        )
        self._filed_lifecycle_evaluator = filed_lifecycle_evaluator
        self._filed_lifecycle_attestation_provider = (
            filed_lifecycle_attestation_provider
        )
        self._filed_lifecycle_attestation_trust_context = (
            filed_lifecycle_attestation_trust_context
        )
        self._filed_lifecycle_owner_pinned_context_digest = (
            filed_lifecycle_owner_pinned_context_digest
        )
        self._filed_governance_integrity_evaluator = (
            filed_governance_integrity_evaluator
        )
        self._filed_governance_integrity_attestation_provider = (
            filed_governance_integrity_attestation_provider
        )
        self._filed_governance_integrity_attestation_trust_context = (
            filed_governance_integrity_attestation_trust_context
        )
        self._filed_governance_integrity_owner_pinned_context_digest = (
            filed_governance_integrity_owner_pinned_context_digest
        )
        self._application_integrity_bundle = application_integrity_bundle
        self._application_integrity_result = application_integrity_result
        self._foundational_request_dependencies = foundational_request_dependencies

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        return run_execution_gate(
            state,
            signature_provider=self._signature_provider,
            signature_trust_context=self._signature_trust_context,
            signature_owner_pinned_context_digest=(
                self._signature_owner_pinned_context_digest
            ),
            three_p_attestation_provider=self._three_p_attestation_provider,
            three_p_attestation_trust_context=(
                self._three_p_attestation_trust_context
            ),
            three_p_owner_pinned_context_digest=(
                self._three_p_owner_pinned_context_digest
            ),
            skg_evaluator=self._skg_evaluator,
            skg_attestation_provider=self._skg_attestation_provider,
            skg_attestation_trust_context=self._skg_attestation_trust_context,
            skg_owner_pinned_context_digest=(
                self._skg_owner_pinned_context_digest
            ),
            filed_framework_evaluator=self._filed_framework_evaluator,
            filed_framework_attestation_provider=(
                self._filed_framework_attestation_provider
            ),
            filed_framework_attestation_trust_context=(
                self._filed_framework_attestation_trust_context
            ),
            filed_framework_owner_pinned_context_digest=(
                self._filed_framework_owner_pinned_context_digest
            ),
            filed_licence_evaluator=self._filed_licence_evaluator,
            filed_licence_attestation_provider=(
                self._filed_licence_attestation_provider
            ),
            filed_licence_attestation_trust_context=(
                self._filed_licence_attestation_trust_context
            ),
            filed_licence_owner_pinned_context_digest=(
                self._filed_licence_owner_pinned_context_digest
            ),
            filed_lifecycle_evaluator=self._filed_lifecycle_evaluator,
            filed_lifecycle_attestation_provider=(
                self._filed_lifecycle_attestation_provider
            ),
            filed_lifecycle_attestation_trust_context=(
                self._filed_lifecycle_attestation_trust_context
            ),
            filed_lifecycle_owner_pinned_context_digest=(
                self._filed_lifecycle_owner_pinned_context_digest
            ),
            filed_governance_integrity_evaluator=(
                self._filed_governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=(
                self._filed_governance_integrity_attestation_provider
            ),
            filed_governance_integrity_attestation_trust_context=(
                self._filed_governance_integrity_attestation_trust_context
            ),
            filed_governance_integrity_owner_pinned_context_digest=(
                self._filed_governance_integrity_owner_pinned_context_digest
            ),
            application_integrity_bundle=self._application_integrity_bundle,
            application_integrity_result=self._application_integrity_result,
            foundational_request_dependencies=(
                self._foundational_request_dependencies
            ),
        )
