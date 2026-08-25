from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hmac
from typing import Dict, Any

from sbp_lex.shared.state_builder import build_state

from sbp_lex.baseline.application_startup import (
    APPLICATION_INTEGRITY_STARTUP_STAGE,
    ApplicationIntegrityRuntimeBundle,
    admit_application_startup,
    application_startup_hash_payload,
    verify_and_project_application_startup,
)
from sbp_lex.baseline.foundational_baseline import (
    FOUNDATIONAL_BASELINE_PASS,
    bind_foundational_baseline_hash,
    evaluate_foundational_baseline,
    foundational_baseline_hash_payload,
    verify_foundational_baseline,
)
from sbp_lex.baseline.request_controls import (
    FoundationalRequestDependencies,
    run_australian_minor_access_stage,
    run_authority_boundary_stage,
    run_digital_provenance_stage,
    run_impersonation_stage,
    run_sovereign_identity_stage,
    verify_foundational_request_controls,
)
from sbp_lex.compliance.australian_minor_access import (
    AUSTRALIAN_MINOR_ACCESS_STAGE,
    RESULT_NOT_APPLICABLE as AUSTRALIAN_MINOR_NOT_APPLICABLE,
    RESULT_PASS as AUSTRALIAN_MINOR_PASS,
)
from sbp_lex.identity.impersonation_protection import (
    IMPERSONATION_PASS,
    IMPERSONATION_PROTECTION_STAGE,
)
from sbp_lex.identity.sovereign_identity import (
    IDENTITY_ADMISSION_STAGE,
    IDENTITY_VERIFIED,
)
from sbp_lex.interface.authority_boundary import BOUNDARY_PASS
from sbp_lex.provenance.digital_provenance import ADMIT as PROVENANCE_ADMIT

from sbp_lex.collective.context_interface import attach_collective_signals

from sbp_lex.authority_first.anchor_validation_engine import anchor_validation_engine
from sbp_lex.authority_first.attestation_engine import attestation_engine
from sbp_lex.authority_first.attestation_consensus_engine import attestation_consensus_engine
from sbp_lex.authority_first.truth_anchor_engine import truth_anchor_engine
from sbp_lex.authority_first.truth_continuity_engine import truth_continuity_engine
from sbp_lex.authority_first.truth_expiry_engine import truth_expiry_engine
from sbp_lex.authority_first.truth_revocation_engine import truth_revocation_engine

from sbp_lex.classification.engine import ClassificationEngine
from sbp_lex.licensing.engine import LicensingEngine
from sbp_lex.licensing.filed_licensing import (
    LICENCE_ALLOW,
    LICENCE_REVALIDATION_STAGE,
    LICENCE_ROOT_BINDING_STAGE,
    FiledLicenceEvaluator,
    evaluate_filed_licence,
    filed_licence_hash_payload,
    invalidate_filed_licence,
)
from sbp_lex.governance.engine import GovernanceEngine
from sbp_lex.governance.authority_provenance import (
    AUTHORITY_PROVENANCE_PASS,
    AUTHORITY_PROVENANCE_STAGE,
    authority_provenance_hash_payload,
    evaluate_authority_provenance,
    verify_authority_provenance,
)
from sbp_lex.governance.procedural_truth_engine import evaluate_procedural_truth
from sbp_lex.governance.grc import (
    apply_grc,
    enforce_non_repeat_rule,
    build_deny_feedback,
    build_escalate_feedback,
)

from sbp_lex.config.thresholds import apply_financial_factor, apply_consequentiality_tier
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.aurion15.runtime.runner import run_aurion15
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.execution.controlled_local_adapter import (
    EffectAdapter,
)
from sbp_lex.execution.rust_authority_client import (
    RUST_AUTHORITY_ROUTE_NOT_ADMITTED,
    RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED,
    RustAuthorityRoute,
    RustAuthorityRouteInDoubt,
    RustAuthorityRouteUnavailable,
    RustAuthorityTerminalEvidence,
)
from sbp_lex.audit.engine import AuditEngine
from sbp_lex.audit.audit_ledger import record_audit
from sbp_lex.legacy_admission.runtime import (
    reconcile_legacy_comparisons,
    run_legacy_admission_phase,
)

from sbp_lex.security.token_stack import (
    get_required_threshold_tokens,
    issue_token,
)
from sbp_lex.security.signature_provider import (
    HybridVerificationContext,
    SignatureProvider,
    SignatureProviderUnavailable,
)
from sbp_lex.security.hybrid_signature import (
    HybridSignatureProvider,
    is_hybrid_provider,
)
from sbp_lex.security.authority_trust import (
    AUTHORITY_TRUST_ROLE_SKG,
    provider_matches_role,
    resolve_authority_trust_boundary,
    verify_pinned_signed_object,
)
from sbp_lex.governance.three_p_doctrine import (
    ThreePCoreEvaluator,
    evaluate_three_p_core,
    three_p_hash_payload,
    verify_three_p_core,
)


@dataclass(frozen=True, slots=True)
class PipelineHybridTrustContexts:
    """Caller-owned public trust pins for every active signed surface."""

    signature: HybridVerificationContext | None = None
    signature_owner_pin: str | None = None
    three_p: HybridVerificationContext | None = None
    three_p_owner_pin: str | None = None
    skg: HybridVerificationContext | None = None
    skg_owner_pin: str | None = None
    filed_framework: HybridVerificationContext | None = None
    filed_framework_owner_pin: str | None = None
    filed_licence: HybridVerificationContext | None = None
    filed_licence_owner_pin: str | None = None
    filed_lifecycle: HybridVerificationContext | None = None
    filed_lifecycle_owner_pin: str | None = None
    filed_governance_integrity: HybridVerificationContext | None = None
    filed_governance_integrity_owner_pin: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "signature",
            "three_p",
            "skg",
            "filed_framework",
            "filed_licence",
            "filed_lifecycle",
            "filed_governance_integrity",
        ):
            context = getattr(self, name)
            pin = getattr(self, f"{name}_owner_pin")
            if context is None and pin is None:
                continue
            if (
                not isinstance(context, HybridVerificationContext)
                or type(pin) is not str
                or not hmac.compare_digest(context.context_digest, pin)
            ):
                raise ValueError(f"PIPELINE_{name.upper()}_TRUST_PIN_INVALID")


def _pipeline_trust_pair(
    contexts: PipelineHybridTrustContexts | None,
    surface: str,
) -> tuple[HybridVerificationContext | None, str | None]:
    if not isinstance(contexts, PipelineHybridTrustContexts):
        return None, None
    return (
        getattr(contexts, surface),
        getattr(contexts, f"{surface}_owner_pin"),
    )


def _required_hybrid_stage_dependencies(
    provider: SignatureProvider | None,
    contexts: PipelineHybridTrustContexts | None,
    surface: str,
) -> tuple[HybridSignatureProvider, HybridVerificationContext, str]:
    trust_context, owner_pin = _pipeline_trust_pair(contexts, surface)
    if (
        not is_hybrid_provider(provider)
        or not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pin) is not str
    ):
        raise SignatureProviderUnavailable(
            f"{surface.upper()}_HYBRID_DEPENDENCIES_NOT_ADMITTED"
        )
    return provider, trust_context, owner_pin


from sbp_lex.governance.filed_frameworks import (
    ABEGF,
    AJ_SAAF,
    FILED_FRAMEWORK_STAGES,
    FRAMEWORK_ESCALATE,
    FRAMEWORK_PASS,
    GALA,
    GOVERNANCE_FRAMEWORK_ORDER,
    PTODF,
    FiledFrameworkEvaluator,
    evaluate_filed_framework,
    filed_framework_hash_payload,
)
from sbp_lex.governance.skg_authority import (
    SKG_AUTHORITY_ATTESTATION_PURPOSE,
    SKGAuthorityEvaluator,
    SKG_HASH_STAGE_PREFIX,
    SKG_PASS,
    evaluate_skg_authority,
    skg_authority_hash_payload,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_STAGES,
    LIFECYCLE_ESCALATE,
    LIFECYCLE_PASS,
    FiledLifecycleEvaluator,
    evaluate_filed_lifecycle,
    filed_lifecycle_hash_payload,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_ESCALATE,
    GOVERNANCE_INTEGRITY_PASS,
    FiledGovernanceIntegrityEvaluator,
    evaluate_filed_governance_integrity,
    filed_governance_integrity_hash_payload,
    verify_filed_governance_integrity,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.config.pipeline_config import (
    AURION_MAX_CANDIDATE_ATTEMPTS,
    AURION_REQUIRE_NEXT_CANDIDATE_RESULT,
    AURION_PASS_RESULT,
    AURION_ESCALATE_RESULT,
    GOVERNANCE_ALLOW,
    GOVERNANCE_DENY,
    GOVERNANCE_ESCALATE,
    PROCEDURAL_TRUTH_PASS,
    PROCEDURAL_TRUTH_ESCALATE,
    CLASSIFICATION_ALLOW,
    CLASSIFICATION_ESCALATE,
    LICENSING_ALLOW,
    LICENSING_ESCALATE,
    DOMAIN_PASS_RESULT,
    DOMAIN_ESCALATE_RESULT,
    AUTHORITY_BOUNDARY_ADMISSION_STAGE,
    DIGITAL_PROVENANCE_STAGE,
    FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
)

classification_engine = ClassificationEngine()
licensing_engine = LicensingEngine()
governance_engine = GovernanceEngine()
audit_engine = AuditEngine()


def _stable_hash(value: Any) -> str:
    return canonical_integrity_hash(value)


def _request_fingerprint(state: Dict[str, Any]) -> str:
    return _stable_hash(
        {
            "action": state.get("action"),
            "payload": state.get("payload"),
            "context": state.get("context"),
            "identity": state.get("identity"),
            "submitted_authority_claim": state.get(
                "submitted_authority_claim"
            ),
            "requested_jurisdiction": state.get("requested_jurisdiction"),
            "license_tier": state.get("license_tier"),
            "execution_rights": state.get("execution_rights"),
            "aj_saaf_operational_context": state.get(
                "aj_saaf_operational_context"
            ),
            "abegf_request": state.get("abegf_request"),
            "submitted_ap_acf_class": state.get(
                "submitted_ap_acf_class"
            ),
            "submitted_ap_acf_subclass": state.get(
                "submitted_ap_acf_subclass"
            ),
            "requested_autonomy_level": state.get("requested_autonomy_level"),
            "requested_system_mode": state.get("requested_system_mode"),
            "autonomy_ceiling": state.get("autonomy_ceiling"),
            "operational_environment": state.get("operational_environment"),
            "public_exposure": state.get("public_exposure"),
            "operational_scope": state.get("operational_scope"),
            "environment_modifiers": state.get("environment_modifiers"),
            "deployment_restrictions": state.get("deployment_restrictions"),
            "deployment_scope": state.get("deployment_scope"),
            "license_profile": state.get("license_profile"),
        }
    )


def _append_hash_chain(state: Dict[str, Any], stage: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("hash_chain", [])
    previous_hash = (
        state["hash_chain"][-1]["hash"] if state["hash_chain"] else GENESIS_HASH
    )
    entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=stage,
        payload=payload,
    )

    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]
    return state


def _apply_corroboration_evidence(
    state: Dict[str, Any],
    *,
    authority_provenance_dependencies: Any | None,
) -> Dict[str, Any]:
    required = state.get("corroboration_required")
    provenance_current = verify_authority_provenance(
        state,
        dependencies=authority_provenance_dependencies,
        require_hash_binding=True,
    )
    attestations = (
        state.get("authority_provenance_record", {}).get(
            "evidence_references"
        )
        if provenance_current
        else None
    )
    admitted_sources: set[str] = set()
    if type(required) is int and required > 0 and type(attestations) is list:
        for record in attestations:
            if type(record) is not dict:
                continue
            source = record.get("source")
            if type(source) is str and source and source == source.strip():
                admitted_sources.add(source)
    state["corroboration_evidence_count"] = len(admitted_sources)
    state["corroboration_evidence_digest"] = canonical_integrity_hash(
        sorted(admitted_sources)
    )
    state["corroboration_met"] = (
        type(required) is int
        and required > 0
        and len(admitted_sources) >= required
    )
    return state


def _engine_ok(result: Any) -> bool:
    return bool(getattr(result, "ok", False))


def _engine_detail(result: Any) -> str:
    return getattr(result, "detail", "engine_failed")


def _engine_data(result: Any) -> Any:
    return getattr(result, "data", None)


def _run_root_of_trust(
    state: Dict[str, Any],
    *,
    authority_provenance_dependencies: Any | None,
) -> Dict[str, Any]:
    state.setdefault("root_of_trust_trace", [])

    chain = [
        ("anchor_validation", anchor_validation_engine),
        ("attestation", attestation_engine),
        ("attestation_consensus", attestation_consensus_engine),
        ("truth_anchor", truth_anchor_engine),
        ("truth_continuity", truth_continuity_engine),
        ("truth_expiry", truth_expiry_engine),
        ("truth_revocation", truth_revocation_engine),
    ]

    for stage_name, fn in chain:
        result = fn(state)

        ok = _engine_ok(result)
        detail = _engine_detail(result)
        data = _engine_data(result)

        state["root_of_trust_trace"].append(
            {
                "engine": stage_name,
                "ok": ok,
                "detail": detail,
            }
        )

        _append_hash_chain(
            state,
            f"root_of_trust:{stage_name}",
            {
                "ok": ok,
                "detail": detail,
                "data": data,
            },
        )

        state[f"legacy_shadow_{stage_name}"] = data

    if verify_authority_provenance(
        state,
        dependencies=authority_provenance_dependencies,
        require_hash_binding=True,
    ):
        state["authority_first_result"] = "ALLOW"
        state["authority_first_reason"] = (
            "authenticated_authority_provenance_eligible"
        )
    else:
        state["authority_first_result"] = "DENY"
        state["authority_first_reason"] = (
            "authority_provenance_not_current_and_valid"
        )
    return state


def _issue_core_token(
    state: Dict[str, Any],
    signature_provider: SignatureProvider | None,
    three_p_attestation_provider: SignatureProvider | None,
    token_name: str,
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> Dict[str, Any]:
    three_p_context, three_p_pin = _pipeline_trust_pair(
        hybrid_trust_contexts, "three_p"
    )
    return issue_token(
        state,
        token_name=token_name,
        issuer=issuer,
        issued_at_stage=issued_at_stage,
        payload=payload,
        provider=signature_provider,
        three_p_attestation_provider=three_p_attestation_provider,
        three_p_trust_context=three_p_context,
        three_p_owner_pinned_context_digest=three_p_pin,
    )


def _finalize_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    state = reconcile_legacy_comparisons(state)
    legacy_observation_digest = canonical_integrity_hash(
        state.get("legacy_admission_trace", [])
    )
    legacy_reconciliation_digest = state.get(
        "legacy_admission_reconciliation_digest"
    )
    _append_hash_chain(
        state,
        "legacy_admission:reconciliation",
        {
            "legacy_admission_digest": legacy_observation_digest,
            "legacy_admission_reconciliation_digest": (
                legacy_reconciliation_digest
            ),
            "authority_effect": "NONE",
        },
    )
    state = audit_engine.execute(state)

    state["audit_record"] = {
        "request_fingerprint": state.get("request_fingerprint"),
        "decision": state.get("decision"),
        "execution_result": state.get("execution_result"),
        "execution_reason": state.get("execution_reason"),
        "governance_result": state.get("governance_result"),
        "governance_reason": state.get("governance_reason"),
        "state_hash": state.get("state_hash"),
        "governance_feedback": state.get("governance_feedback"),
        "application_integrity_result": state.get(
            "application_integrity_result"
        ),
        "application_integrity_result_digest": state.get(
            "application_integrity_result_digest"
        ),
        "application_integrity_receipt_digest": state.get(
            "application_integrity_receipt_digest"
        ),
        "application_integrity_manifest_digest": state.get(
            "application_integrity_manifest_digest"
        ),
        "application_integrity_runtime_measurement_digest": state.get(
            "application_integrity_runtime_measurement_digest"
        ),
        "application_integrity_trust_context_digest": state.get(
            "application_integrity_trust_context_digest"
        ),
        "digital_provenance_result": state.get(
            "digital_provenance_result"
        ),
        "digital_provenance_digest": state.get(
            "digital_provenance_digest"
        ),
        "digital_provenance_verification_receipt_digest": state.get(
            "digital_provenance_verification_receipt", {}
        ).get("digest"),
        "sovereign_identity_result": state.get(
            "sovereign_identity_result"
        ),
        "sovereign_identity_digest": state.get(
            "sovereign_identity_digest"
        ),
        "authority_boundary_result": state.get(
            "authority_boundary_result"
        ),
        "authority_boundary_digest": state.get(
            "authority_boundary_digest"
        ),
        "authority_boundary_trace_digest": state.get(
            "authority_boundary_trace_digest"
        ),
        "impersonation_protection_result": state.get(
            "impersonation_protection_result"
        ),
        "impersonation_protection_digest": state.get(
            "impersonation_protection_digest"
        ),
        "australian_minor_access": deepcopy(
            state.get("australian_minor_access", {})
        ),
        "foundational_baseline_record": deepcopy(
            state.get("foundational_baseline_record")
        ),
        "foundational_baseline_result": state.get(
            "foundational_baseline_result"
        ),
        "foundational_baseline_reason": state.get(
            "foundational_baseline_reason"
        ),
        "foundational_baseline_digest": state.get(
            "foundational_baseline_digest"
        ),
        "foundational_baseline_hash_binding_index": state.get(
            "foundational_baseline_hash_binding_index"
        ),
        "foundational_baseline_hash_binding_hash": state.get(
            "foundational_baseline_hash_binding_hash"
        ),
        "authority_provenance_trace": deepcopy(
            state.get("authority_provenance_trace", [])
        ),
        "authority_provenance_record": deepcopy(
            state.get("authority_provenance_record", {})
        ),
        "authority_provenance_result": state.get(
            "authority_provenance_result"
        ),
        "authority_provenance_reason": state.get(
            "authority_provenance_reason"
        ),
        "authority_provenance_digest": state.get(
            "authority_provenance_digest"
        ),
        "authority_provenance_trace_digest": state.get(
            "authority_provenance_trace_digest"
        ),
        "authority_provenance_trust_context_digest": state.get(
            "authority_provenance_trust_context_digest"
        ),
        "authority_provenance_clock_receipt_digest": state.get(
            "authority_provenance_clock_receipt_digest"
        ),
        "authority_provenance_registry_head_digest": state.get(
            "authority_provenance_registry_head_digest"
        ),
        "governance_policy_record": deepcopy(
            state.get("governance_policy_record", {})
        ),
        "governance_policy_digest": state.get(
            "governance_policy_digest"
        ),
        "hash_chain": deepcopy(state.get("hash_chain", [])),
        "three_p_core_record": deepcopy(state.get("three_p_core_record")),
        "three_p_core_digest": state.get("three_p_core_digest"),
        "three_p_trace_hash": state.get("three_p_trace_hash"),
        "three_p_trace": deepcopy(state.get("three_p_trace")),
        "skg_authority_trace": deepcopy(
            state.get("skg_authority_trace", [])
        ),
        "skg_authority_record": deepcopy(
            state.get("skg_authority_record")
        ),
        "skg_authority_digest": state.get("skg_authority_digest"),
        "skg_authority_trace_digest": state.get(
            "skg_authority_trace_digest"
        ),
        "skg_authority_result": state.get("skg_authority_result"),
        "skg_authority_reason": state.get("skg_authority_reason"),
        "skg_authority_granted": state.get("skg_authority_granted"),
        "skg_execution_authority_granted": state.get(
            "skg_execution_authority_granted"
        ),
        "skg_downstream_override_permitted": state.get(
            "skg_downstream_override_permitted"
        ),
        "filed_framework_digest": state.get("filed_framework_digest"),
        "filed_framework_trace": deepcopy(
            state.get("filed_framework_trace", [])
        ),
        "filed_framework_results": deepcopy(
            state.get("filed_framework_results", {})
        ),
        "gala_attestation": deepcopy(state.get("gala_attestation", {})),
        "filed_lifecycle_trace": deepcopy(
            state.get("filed_lifecycle_trace", [])
        ),
        "filed_lifecycle_results": deepcopy(
            state.get("filed_lifecycle_results", {})
        ),
        "filed_lifecycle_record": deepcopy(
            state.get("filed_lifecycle_record")
        ),
        "filed_lifecycle_result": state.get("filed_lifecycle_result"),
        "filed_lifecycle_reason": state.get("filed_lifecycle_reason"),
        "filed_lifecycle_digest": state.get("filed_lifecycle_digest"),
        "filed_governance_integrity_revocation_binding": deepcopy(
            state.get("filed_governance_integrity_revocation_binding", {})
        ),
        "filed_governance_integrity_trace": deepcopy(
            state.get("filed_governance_integrity_trace", [])
        ),
        "filed_governance_integrity_results": deepcopy(
            state.get("filed_governance_integrity_results", {})
        ),
        "filed_governance_integrity_record": deepcopy(
            state.get("filed_governance_integrity_record")
        ),
        "filed_governance_integrity_result": state.get(
            "filed_governance_integrity_result"
        ),
        "filed_governance_integrity_reason": state.get(
            "filed_governance_integrity_reason"
        ),
        "filed_governance_integrity_digest": state.get(
            "filed_governance_integrity_digest"
        ),
        "filed_governance_integrity_revocation_status": state.get(
            "filed_governance_integrity_revocation_binding", {}
        ).get("status"),
        "filed_governance_integrity_revocation_sequence": state.get(
            "filed_governance_integrity_revocation_binding", {}
        ).get("sequence"),
        "filed_governance_integrity_revocation_digest": state.get(
            "filed_governance_integrity_revocation_binding", {}
        ).get("digest"),
        "governance_integrity_implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
        "filed_governance_integrity_authority_granted": state.get(
            "filed_governance_integrity_authority_granted"
        ),
        "filed_governance_integrity_licence_granted": state.get(
            "filed_governance_integrity_licence_granted"
        ),
        "filed_governance_integrity_execution_authority_granted": state.get(
            "filed_governance_integrity_execution_authority_granted"
        ),
        "filed_governance_integrity_effect_granted": state.get(
            "filed_governance_integrity_effect_granted"
        ),
        "filed_governance_integrity_bypass_permitted": state.get(
            "filed_governance_integrity_bypass_permitted"
        ),
        "filed_licence_digest": state.get("filed_licence_digest"),
        "filed_licence_trace": deepcopy(
            state.get("filed_licence_trace", [])
        ),
        "filed_licence_record": deepcopy(
            state.get("filed_licence_record", {})
        ),
        "filed_licence_result": state.get("filed_licence_result"),
        "filed_licence_reason": state.get("filed_licence_reason"),
        "licence_id": state.get("licence_id"),
        "license_tier": state.get("license_tier"),
        "licence_bindings": deepcopy(
            state.get("filed_licence_record", {})
            .get("evaluation_snapshot", {})
            .get("bindings")
        ),
        "licence_invalidation_status": state.get(
            "licence_invalidation_status"
        ),
        "licence_execution_disabled": state.get(
            "licence_execution_disabled"
        ),
        "licence_invalidation_trace": deepcopy(
            state.get("licence_invalidation_trace", [])
        ),
        "licence_invalidation_digest": state.get(
            "licence_invalidation_digest"
        ),
        "licence_revocation_status": state.get("licence_revocation_status"),
        "licence_revocation_sequence": state.get(
            "licence_revocation_sequence"
        ),
        "legacy_admission_digest": legacy_observation_digest,
        "legacy_admission_reconciliation_digest": legacy_reconciliation_digest,
        "legacy_admission_comparison_summary": deepcopy(
            state.get("legacy_admission_comparison_summary", {})
        ),
        "legacy_admission_phase_results": state.get(
            "legacy_admission_phase_results", {}
        ),
        "effect_adapter_id": state.get("effect_adapter_id"),
        "effect_id": state.get("effect_id"),
        "effect_result": state.get("effect_result"),
        "effect_permit": deepcopy(state.get("effect_permit", {})),
        "effect_receipt": deepcopy(state.get("effect_receipt", {})),
        "effect_trace": deepcopy(state.get("effect_trace", [])),
        "rust_authority_route_status": state.get(
            "rust_authority_route_status"
        ),
        "rust_authority_terminal_validated": state.get(
            "rust_authority_terminal_validated"
        ),
        "rust_authority_terminal_evidence": deepcopy(
            state.get("rust_authority_terminal_evidence")
        ),
        "rust_authority_terminal_transcript": deepcopy(
            state.get("rust_authority_terminal_transcript")
        ),
        "controlled_local_adapter_classification": state.get(
            "controlled_local_adapter_classification"
        ),
    }
    state["audit_hash"] = _stable_hash(state["audit_record"])
    return record_audit(state)


def _deny_three_p(
    state: Dict[str, Any],
    stage: str,
) -> Dict[str, Any]:
    state = build_deny_feedback(
        state,
        denial_code="THREE_P_CORE_DENIAL",
        denial_reason=f"3P Core constitutional constraint failed at {stage}.",
        retry_eligible=True,
        required_change_for_retry=(
            "Provide an exact satisfied P1, P2, and P3 declaration and re-enter "
            "through the governed pathway."
        ),
        escalation_allowed=False,
        fallback_action_allowed=False,
        safe_state_required=True,
    )
    state["decision"] = "DENY"
    state["execution_result"] = "HALT"
    state["execution_reason"] = "three_p_core_denial"
    return state


def _deny_foundational(
    state: Dict[str, Any],
    *,
    stage: str,
    reason: str,
) -> Dict[str, Any]:
    state = build_deny_feedback(
        state,
        denial_code="FOUNDATIONAL_BASELINE_FAILURE",
        denial_reason=f"{stage}:{reason}",
        retry_eligible=True,
        required_change_for_retry=(
            "Re-enter through the complete foundational admission pathway "
            "with current deployment-authenticated evidence."
        ),
        escalation_allowed=False,
        fallback_action_allowed=False,
        safe_state_required=True,
    )
    state["foundational_failure_stage"] = stage
    state["foundational_failure_reason"] = reason
    state["decision"] = "DENY"
    state["execution_result"] = "HALT"
    state["execution_reason"] = "foundational_baseline_denial"
    return state


def _run_foundational_request_path(
    state: Dict[str, Any],
    *,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
    foundational_request_dependencies: FoundationalRequestDependencies | None,
    possession_proof: dict[str, Any] | None,
    three_p_evaluator: ThreePCoreEvaluator | None,
    three_p_attestation_provider: SignatureProvider | None,
    signature_provider: SignatureProvider | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None,
) -> tuple[Dict[str, Any], dict[str, Any] | None, bool]:
    if not isinstance(
        application_integrity_bundle, ApplicationIntegrityRuntimeBundle
    ):
        return (
            _deny_foundational(
                state,
                stage=APPLICATION_INTEGRITY_STARTUP_STAGE,
                reason="APPLICATION_INTEGRITY_RUNTIME_BUNDLE_NOT_INJECTED",
            ),
            None,
            True,
        )
    try:
        application_result = admit_application_startup(
            application_integrity_bundle
        )
        verify_and_project_application_startup(
            state,
            bundle=application_integrity_bundle,
            result=application_result,
        )
        _append_hash_chain(
            state,
            APPLICATION_INTEGRITY_STARTUP_STAGE,
            application_startup_hash_payload(state),
        )
    except Exception as exc:
        return (
            _deny_foundational(
                state,
                stage=APPLICATION_INTEGRITY_STARTUP_STAGE,
                reason=f"APPLICATION_INTEGRITY_STARTUP_REJECTED:{exc}",
            ),
            None,
            True,
        )

    state["release_manifest_digest"] = state.get(
        "application_integrity_manifest_digest"
    )
    state["runtime_measurement_digest"] = state.get(
        "application_integrity_runtime_measurement_digest"
    )
    _append_hash_chain(
        state,
        "state_construction",
        {
            "request_fingerprint": state.get("request_fingerprint"),
            "action": state.get("action"),
            "payload": state.get("payload"),
            "context": state.get("context"),
            "sources": state.get("sources"),
            "identity": state.get("identity"),
            "license_tier": state.get("license_tier"),
            "execution_rights": state.get("execution_rights"),
        },
    )

    if not isinstance(
        foundational_request_dependencies, FoundationalRequestDependencies
    ):
        return (
            _deny_foundational(
                state,
                stage="foundational_request_controls",
                reason="FOUNDATIONAL_REQUEST_DEPENDENCIES_NOT_INJECTED",
            ),
            application_result,
            True,
        )
    dependencies = foundational_request_dependencies
    controls = (
        (
            DIGITAL_PROVENANCE_STAGE,
            lambda: run_digital_provenance_stage(
                state, dependencies=dependencies
            ),
            lambda: state.get("digital_provenance_result")
            == PROVENANCE_ADMIT,
            lambda: state.get("digital_provenance_reason"),
        ),
        (
            IDENTITY_ADMISSION_STAGE,
            lambda: run_sovereign_identity_stage(
                state, dependencies=dependencies
            ),
            lambda: state.get("sovereign_identity_result")
            == IDENTITY_VERIFIED,
            lambda: state.get("sovereign_identity_reason"),
        ),
        (
            AUTHORITY_BOUNDARY_ADMISSION_STAGE,
            lambda: run_authority_boundary_stage(
                state, dependencies=dependencies
            ),
            lambda: state.get("authority_boundary_result") == BOUNDARY_PASS,
            lambda: state.get("authority_boundary_reason"),
        ),
        (
            IMPERSONATION_PROTECTION_STAGE,
            lambda: run_impersonation_stage(
                state,
                dependencies=dependencies,
                possession_proof=possession_proof,
            ),
            lambda: state.get("impersonation_protection_result")
            == IMPERSONATION_PASS,
            lambda: state.get("impersonation_protection_reason"),
        ),
        (
            AUSTRALIAN_MINOR_ACCESS_STAGE,
            lambda: run_australian_minor_access_stage(state),
            lambda: state.get("australian_minor_access", {}).get("result")
            in {AUSTRALIAN_MINOR_PASS, AUSTRALIAN_MINOR_NOT_APPLICABLE},
            lambda: state.get("australian_minor_access", {}).get("reason"),
        ),
    )
    for stage, run_control, accepted, failure_reason in controls:
        try:
            run_control()
            if accepted():
                continue
        except Exception:
            pass
        reason = failure_reason() or "FOUNDATIONAL_CONTROL_REJECTED"
        return (
            _deny_foundational(state, stage=stage, reason=str(reason)),
            application_result,
            True,
        )
    if not verify_foundational_request_controls(
        state,
        dependencies=dependencies,
    ):
        return (
            _deny_foundational(
                state,
                stage="foundational_request_controls",
                reason="FOUNDATIONAL_REQUEST_CONTROLS_REVALIDATION_FAILED",
            ),
            application_result,
            True,
        )

    state, terminal = _require_three_p(
        state,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, application_result, True
    state = evaluate_foundational_baseline(state)
    if state.get("foundational_baseline_result") == FOUNDATIONAL_BASELINE_PASS:
        try:
            bind_foundational_baseline_hash(state)
        except Exception:
            pass
    if not verify_foundational_baseline(state, require_hash_binding=True):
        return (
            _deny_foundational(
                state,
                stage=FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
                reason=str(
                    state.get(
                        "foundational_baseline_reason",
                        "FOUNDATIONAL_BASELINE_AGGREGATE_REJECTED",
                    )
                ),
            ),
            application_result,
            True,
        )
    state = _issue_core_token(
        state,
        signature_provider,
        three_p_attestation_provider,
        "foundational",
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        foundational_baseline_hash_payload(state),
        hybrid_trust_contexts,
    )
    return state, application_result, False


def _require_three_p(
    state: Dict[str, Any],
    stage: str,
    evaluator: ThreePCoreEvaluator | None,
    attestation_provider: SignatureProvider | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> tuple[Dict[str, Any], bool]:
    trust_context, owner_pin = _pipeline_trust_pair(
        hybrid_trust_contexts, "three_p"
    )
    state = evaluate_three_p_core(
        state,
        evaluator=evaluator,
        attestation_provider=attestation_provider,
        stage=stage,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    )
    _append_hash_chain(
        state,
        f"three_p_core:{stage}",
        three_p_hash_payload(state),
    )
    if verify_three_p_core(
        state,
        attestation_provider=attestation_provider,
        require_hash_binding=True,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    ):
        return state, False
    return _deny_three_p(state, stage), True


def _run_legacy_phase(
    state: Dict[str, Any],
    phase: str,
    *,
    run_id: str | None = None,
) -> tuple[Dict[str, Any], bool]:
    """Run an isolated initial-admission shadow lane with no authority effect."""

    before = len(state.get("legacy_admission_trace", []))
    completion_id = f"{phase}:{run_id}" if run_id is not None else phase
    try:
        state = run_legacy_admission_phase(state, phase, run_id=run_id)
    except Exception as exc:
        error_record = {
            "phase": phase,
            "run_id": run_id,
            "status": "SHADOW_INFRASTRUCTURE_ERROR",
            "detail": f"{type(exc).__name__}:{exc}",
            "authority_effect": "NONE",
        }
        state.setdefault("legacy_admission_infrastructure_errors", []).append(
            error_record
        )
        _append_hash_chain(
            state,
            f"legacy_admission:{completion_id}:infrastructure_error",
            error_record,
        )
        return state, False
    new_records = state.get("legacy_admission_trace", [])[before:]
    phase_record = state["legacy_admission_phase_results"][completion_id]
    _append_hash_chain(
        state,
        f"legacy_admission:{completion_id}",
        {
            "result": phase_record["result"],
            "authority_effect": phase_record["authority_effect"],
            "record_count": phase_record["record_count"],
            "trace_digest": canonical_integrity_hash(new_records),
        },
    )
    return state, False


def _run_filed_framework_stage(
    state: Dict[str, Any],
    framework: str,
    *,
    evaluator: FiledFrameworkEvaluator | None,
    attestation_provider: SignatureProvider | None,
    signature_provider: SignatureProvider | None,
    three_p_evaluator: ThreePCoreEvaluator | None,
    three_p_attestation_provider: SignatureProvider | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None,
) -> tuple[Dict[str, Any], bool]:
    stage = FILED_FRAMEWORK_STAGES[framework]
    state, terminal = _require_three_p(
        state,
        stage,
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True
    hybrid_provider, trust_context, owner_pin = (
        _required_hybrid_stage_dependencies(
            attestation_provider,
            hybrid_trust_contexts,
            "filed_framework",
        )
    )
    state = evaluate_filed_framework(
        state,
        framework,
        evaluator=evaluator,
        attestation_provider=hybrid_provider,
        attestation_trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    )
    _append_hash_chain(state, stage, filed_framework_hash_payload(state))
    state, terminal = _require_three_p(
        state,
        f"{stage}:post",
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True

    result = state.get("filed_framework_results", {}).get(framework)
    if result == FRAMEWORK_ESCALATE:
        state = build_escalate_feedback(
            state,
            denial_code=f"{framework.replace('-', '_')}_ESCALATION",
            denial_reason=state.get(
                "filed_framework_reason",
                f"{framework} escalation required.",
            ),
            safe_state_required=True,
        )
        state["decision"] = "ESCALATE"
        state["execution_result"] = "HALT"
        return state, True
    if result != FRAMEWORK_PASS:
        state = build_deny_feedback(
            state,
            denial_code=f"{framework.replace('-', '_')}_DENIAL",
            denial_reason=state.get(
                "filed_framework_reason",
                f"{framework} denied the governed pathway.",
            ),
            retry_eligible=True,
            required_change_for_retry=(
                f"Provide a materially changed request and valid {framework} "
                "evidence through the complete governed pathway."
            ),
            escalation_allowed=True,
            fallback_action_allowed=False,
            safe_state_required=True,
        )
        state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        return state, True

    token_name = {
        AJ_SAAF: "aj_saaf",
        "PTODF": "ptodf",
        "GALA": "gala",
        ABEGF: "abegf",
    }[framework]
    record = state["filed_framework_trace"][-1]
    state = _issue_core_token(
        state,
        signature_provider,
        three_p_attestation_provider,
        token_name,
        framework,
        stage,
        {
            "framework_result": result,
            "framework_record_digest": canonical_integrity_hash(record),
            "evaluation_source_digest": record.get(
                "evaluation_source_digest"
            ),
            "execution_authority_granted": False,
        },
        hybrid_trust_contexts,
    )
    return state, False


_SKG_TRAVERSAL_STAGE = "constitutional_authority_substrate"


def _run_skg_authority_stage(
    state: Dict[str, Any],
    *,
    evaluator: SKGAuthorityEvaluator | None,
    attestation_provider: SignatureProvider | None,
    signature_provider: SignatureProvider | None,
    three_p_evaluator: ThreePCoreEvaluator | None,
    three_p_attestation_provider: SignatureProvider | None,
    authority_provenance_dependencies: Any | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None,
) -> tuple[Dict[str, Any], bool]:
    stage = f"{SKG_HASH_STAGE_PREFIX}{_SKG_TRAVERSAL_STAGE}"
    state, terminal = _require_three_p(
        state,
        stage,
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True
    hybrid_provider, trust_context, owner_pin = (
        _required_hybrid_stage_dependencies(
            attestation_provider,
            hybrid_trust_contexts,
            "skg",
        )
    )
    state = evaluate_skg_authority(
        state,
        stage=_SKG_TRAVERSAL_STAGE,
        evaluator=evaluator,
        attestation_provider=hybrid_provider,
        attestation_trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    )
    trust_boundary = resolve_authority_trust_boundary(
        authority_provenance_dependencies
    )
    skg_pin = (
        trust_boundary.context.role_pin(AUTHORITY_TRUST_ROLE_SKG)
        if trust_boundary is not None
        else None
    )
    skg_source = state.get("skg_authority_record", {}).get(
        "evaluation_source"
    )
    if (
        skg_pin is None
        or not provider_matches_role(
            attestation_provider,
            dependencies=authority_provenance_dependencies,
            role=AUTHORITY_TRUST_ROLE_SKG,
        )
        or not verify_pinned_signed_object(
            skg_source,
            role_pin=skg_pin,
            purpose=SKG_AUTHORITY_ATTESTATION_PURPOSE,
        )
        or skg_source.get("evaluator_id") != skg_pin.evaluator_id
        or skg_source.get("evaluator_version") != skg_pin.evaluator_version
        or skg_source.get("authority_credential", {}).get("credential_id")
        != skg_pin.authority_credential_id
    ):
        state["skg_authority_result"] = "DENY"
        state["skg_authority_reason"] = "SKG_AUTHORITY_TRUST_PIN_INVALID"
    _append_hash_chain(state, stage, skg_authority_hash_payload(state))
    state, terminal = _require_three_p(
        state,
        f"{stage}:post",
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True
    if state.get("skg_authority_result") != SKG_PASS:
        state = build_deny_feedback(
            state,
            denial_code="SKG_AUTHORITY_DENIAL",
            denial_reason=state.get(
                "skg_authority_reason",
                "Authenticated SKG authority evaluation failed.",
            ),
            retry_eligible=True,
            required_change_for_retry=(
                "Provide a valid authenticated SKG authority evaluation "
                "through the complete governed pathway."
            ),
            escalation_allowed=True,
            fallback_action_allowed=False,
            safe_state_required=True,
        )
        state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        return state, True
    state = _issue_core_token(
        state,
        signature_provider,
        three_p_attestation_provider,
        "skg",
        "skg_authority",
        "skg_authority",
        skg_authority_hash_payload(state),
        hybrid_trust_contexts,
    )
    return state, False


def _run_filed_lifecycle_stage(
    state: Dict[str, Any],
    lifecycle_engine: str,
    *,
    evaluator: FiledLifecycleEvaluator | None,
    attestation_provider: SignatureProvider | None,
    signature_provider: SignatureProvider | None,
    three_p_evaluator: ThreePCoreEvaluator | None,
    three_p_attestation_provider: SignatureProvider | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None,
) -> tuple[Dict[str, Any], bool]:
    stage = FILED_LIFECYCLE_STAGES[lifecycle_engine]
    state, terminal = _require_three_p(
        state,
        stage,
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True
    hybrid_provider, trust_context, owner_pin = (
        _required_hybrid_stage_dependencies(
            attestation_provider,
            hybrid_trust_contexts,
            "filed_lifecycle",
        )
    )
    state = evaluate_filed_lifecycle(
        state,
        lifecycle_engine,
        evaluator=evaluator,
        attestation_provider=hybrid_provider,
        attestation_trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    )
    _append_hash_chain(state, stage, filed_lifecycle_hash_payload(state))
    state, terminal = _require_three_p(
        state,
        f"{stage}:post",
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True

    result = state.get("filed_lifecycle_results", {}).get(lifecycle_engine)
    if result != LIFECYCLE_PASS:
        if result == LIFECYCLE_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code=(
                    f"{FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]}_"
                    "ESCALATION"
                ),
                denial_reason=state.get(
                    "filed_lifecycle_reason",
                    "Filed lifecycle escalation required.",
                ),
                safe_state_required=True,
            )
            state["decision"] = "ESCALATE"
        else:
            state = build_deny_feedback(
                state,
                denial_code=(
                    f"{FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]}_DENIAL"
                ),
                denial_reason=state.get(
                    "filed_lifecycle_reason",
                    "Filed lifecycle evaluation failed.",
                ),
                retry_eligible=True,
                required_change_for_retry=(
                    "Provide valid signed lifecycle evidence through the "
                    "complete governed pathway."
                ),
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )
            state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        return state, True

    engine_id = FILED_LIFECYCLE_ENGINE_IDS[lifecycle_engine]
    state = _issue_core_token(
        state,
        signature_provider,
        three_p_attestation_provider,
        engine_id.lower(),
        engine_id,
        stage,
        filed_lifecycle_hash_payload(state),
        hybrid_trust_contexts,
    )
    return state, False


def _run_filed_governance_integrity_stage(
    state: Dict[str, Any],
    governance_function: str,
    *,
    evaluator: FiledGovernanceIntegrityEvaluator | None,
    attestation_provider: SignatureProvider | None,
    signature_provider: SignatureProvider | None,
    three_p_evaluator: ThreePCoreEvaluator | None,
    three_p_attestation_provider: SignatureProvider | None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None,
) -> tuple[Dict[str, Any], bool]:
    """Run one non-authorising filed-function veto evidence stage."""

    stage = FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
    state, terminal = _require_three_p(
        state,
        stage,
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True
    hybrid_provider, trust_context, owner_pin = (
        _required_hybrid_stage_dependencies(
            attestation_provider,
            hybrid_trust_contexts,
            "filed_governance_integrity",
        )
    )
    state = evaluate_filed_governance_integrity(
        state,
        governance_function,
        evaluator=evaluator,
        attestation_provider=hybrid_provider,
        attestation_trust_context=trust_context,
        owner_pinned_context_digest=owner_pin,
    )
    _append_hash_chain(
        state,
        stage,
        filed_governance_integrity_hash_payload(state),
    )
    state, terminal = _require_three_p(
        state,
        f"{stage}:post",
        three_p_evaluator,
        three_p_attestation_provider,
        hybrid_trust_contexts,
    )
    if terminal:
        return state, True

    result = state.get("filed_governance_integrity_results", {}).get(
        governance_function
    )
    function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
        governance_function
    ]
    if result != GOVERNANCE_INTEGRITY_PASS:
        if result == GOVERNANCE_INTEGRITY_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code=f"{function_id}_ESCALATION",
                denial_reason=state.get(
                    "filed_governance_integrity_reason",
                    "Filed governance-integrity escalation required.",
                ),
                safe_state_required=True,
            )
            state["decision"] = "ESCALATE"
        else:
            state = build_deny_feedback(
                state,
                denial_code=f"{function_id}_DENIAL",
                denial_reason=state.get(
                    "filed_governance_integrity_reason",
                    "Filed governance-integrity evaluation failed.",
                ),
                retry_eligible=True,
                required_change_for_retry=(
                    "Provide current signed evidence through the complete "
                    "governed pathway."
                ),
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )
            state["decision"] = "DENY"
        state["execution_result"] = "HALT"
        return state, True

    state = _issue_core_token(
        state,
        signature_provider,
        three_p_attestation_provider,
        function_id.lower(),
        function_id,
        stage,
        filed_governance_integrity_hash_payload(state),
        hybrid_trust_contexts,
    )
    return state, False


def _run_v2_core(
    input_data: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    *,
    signature_provider: SignatureProvider | None = None,
    three_p_evaluator: ThreePCoreEvaluator | None = None,
    three_p_attestation_provider: SignatureProvider | None = None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        SignatureProvider | None
    ) = None,
    filed_governance_integrity_revocation_binding: (
        dict[str, Any] | None
    ) = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
    foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    possession_proof: dict[str, Any] | None = None,
    effect_adapter: EffectAdapter | None = None,
    effect_permit_ttl_ms: int | None = None,
    rust_authority_route: RustAuthorityRoute | None = None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> Dict[str, Any]:
    try:
        state = build_state(input_data)

        state.setdefault("context", {})
        state.setdefault("payload", {})
        state.setdefault("tokens", {})
        state.setdefault("hash_chain", [])
        state.setdefault("audit_ledger", [])
        state.setdefault("last_denied_fingerprint", None)
        state.setdefault("financial_amount", 0.0)
        state["filed_governance_integrity_revocation_binding"] = deepcopy(
            filed_governance_integrity_revocation_binding
            if type(filed_governance_integrity_revocation_binding) is dict
            else {}
        )

        state["request_fingerprint"] = _request_fingerprint(state)
        state, application_integrity_result, terminal = (
            _run_foundational_request_path(
                state,
                application_integrity_bundle=application_integrity_bundle,
                foundational_request_dependencies=(
                    foundational_request_dependencies
                ),
                possession_proof=possession_proof,
                three_p_evaluator=three_p_evaluator,
                three_p_attestation_provider=three_p_attestation_provider,
                signature_provider=signature_provider,
                hybrid_trust_contexts=hybrid_trust_contexts,
            )
        )
        if terminal:
            return state

        state = evaluate_three_p_core(
            state,
            evaluator=three_p_evaluator,
            attestation_provider=three_p_attestation_provider,
            stage="ingress",
            trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[0],
            owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[1],
        )
        _append_hash_chain(
            state,
            "three_p_core:ingress",
            three_p_hash_payload(state),
        )
        if not verify_three_p_core(
            state,
            attestation_provider=three_p_attestation_provider,
            require_hash_binding=True,
            trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[0],
            owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[1],
        ):
            return _deny_three_p(state, "ingress")

        authority_provenance_dependencies = (
            foundational_request_dependencies.authority_provenance_dependencies
            if isinstance(
                foundational_request_dependencies,
                FoundationalRequestDependencies,
            )
            else None
        )
        state = evaluate_authority_provenance(
            state,
            dependencies=authority_provenance_dependencies,
        )
        if state.get("authority_provenance_result") == AUTHORITY_PROVENANCE_PASS:
            _append_hash_chain(
                state,
                AUTHORITY_PROVENANCE_STAGE,
                authority_provenance_hash_payload(state),
            )
        if not verify_authority_provenance(
            state,
            dependencies=authority_provenance_dependencies,
            require_hash_binding=True,
        ):
            state["decision"] = "DENY"
            state["execution_result"] = "HALT"
            state["execution_reason"] = "authority_provenance_denial"
            state["authority_first_result"] = "DENY"
            state["authority_first_reason"] = state.get(
                "authority_provenance_reason",
                "authority_provenance_not_current_and_valid",
            )
            return state
        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "authority_provenance",
            "authority_provenance",
            AUTHORITY_PROVENANCE_STAGE,
            authority_provenance_hash_payload(state),
            hybrid_trust_contexts,
        )

        state = enforce_non_repeat_rule(state)
        if state.get("governance_feedback", {}).get("status") == "DENY":
            state["decision"] = "DENY"
            _append_hash_chain(
                state,
                "grc:identical_denied_resubmission",
                state["governance_feedback"],
            )
            return state

        state, terminal = _require_three_p(
            state,
            "collective_attach",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = attach_collective_signals(state, pre_context_signals)
        _append_hash_chain(
            state,
            "collective_attach",
            {
                "collective_signal_status": state.get("collective_signal_status"),
                "collective_signals": state.get("collective_signals"),
            },
        )
        state, terminal = _require_three_p(
            state,
            "collective_attach:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        state, terminal = _run_legacy_phase(state, "collective")
        if terminal:
            return state

        state, terminal = _require_three_p(
            state,
            "root_of_trust",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = _run_root_of_trust(
            state,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
        )
        if state.get("authority_first_result") == "ALLOW":
            state = evaluate_filed_licence(
                state,
                stage=LICENCE_ROOT_BINDING_STAGE,
                evaluator=filed_licence_evaluator,
                attestation_provider=filed_licence_attestation_provider,
                trust_context=_pipeline_trust_pair(
                    hybrid_trust_contexts, "filed_licence"
                )[0],
                owner_pinned_context_digest=_pipeline_trust_pair(
                    hybrid_trust_contexts, "filed_licence"
                )[1],
            )
            _append_hash_chain(
                state,
                LICENCE_ROOT_BINDING_STAGE,
                filed_licence_hash_payload(state),
            )
            if state.get("filed_licence_result") != LICENCE_ALLOW:
                state["authority_first_result"] = "DENY"
                state["authority_first_reason"] = state.get(
                    "filed_licence_reason",
                    "filed_licence_root_binding_failed",
                )
        state, terminal = _require_three_p(
            state,
            "root_of_trust:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        if state.get("authority_first_result") != "ALLOW":
            state = build_deny_feedback(
                state,
                denial_code="AUTHORITY_FIRST_FAILURE",
                denial_reason=state.get("authority_first_reason", "Authority first validation failed."),
                retry_eligible=True,
                required_change_for_retry="Provide valid authority, attestation, and truth conditions.",
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )
            state["decision"] = "DENY"
            return state

        state, terminal = _run_legacy_phase(state, "authority")
        if terminal:
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "authority",
            "root_of_trust",
            "root_of_trust",
            {
                "authority_first_result": state.get("authority_first_result"),
                "authority_first_reason": state.get("authority_first_reason"),
                "licence_id": state.get("licence_id"),
                "license_tier": state.get("license_tier"),
                "filed_licence_digest": state.get("filed_licence_digest"),
                "licence_bindings_digest": canonical_integrity_hash(
                    state.get("filed_licence_record", {}).get(
                        "evaluation_snapshot", {}
                    ).get("bindings", {})
                ),
            },
            hybrid_trust_contexts,
        )

        state, terminal = _run_skg_authority_stage(
            state,
            evaluator=skg_evaluator,
            attestation_provider=skg_attestation_provider,
            signature_provider=signature_provider,
            three_p_evaluator=three_p_evaluator,
            three_p_attestation_provider=three_p_attestation_provider,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
            hybrid_trust_contexts=hybrid_trust_contexts,
        )
        if terminal:
            return state

        state, terminal = _require_three_p(
            state,
            "procedural_truth",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = evaluate_procedural_truth(state)
        state = apply_financial_factor(state)
        state = apply_consequentiality_tier(state)
        state = _apply_corroboration_evidence(
            state,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
        )

        _append_hash_chain(
            state,
            "procedural_truth",
            {
                "procedural_truth_result": state.get("procedural_truth_result"),
                "corroboration_required": state.get("corroboration_required"),
                "corroboration_met": state.get("corroboration_met"),
                "tier": state.get("safety_profile", {}).get("computed_tier"),
            },
        )
        state, terminal = _require_three_p(
            state,
            "procedural_truth:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        if state.get("procedural_truth_result") == PROCEDURAL_TRUTH_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="PROCEDURAL_TRUTH_ESCALATION",
                denial_reason="Procedural truth escalation required.",
                safe_state_required=True,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("procedural_truth_result") != PROCEDURAL_TRUTH_PASS:
            state = build_deny_feedback(
                state,
                denial_code="PROCEDURAL_TRUTH_FAILURE",
                denial_reason="Procedural truth validation failed.",
                retry_eligible=True,
                required_change_for_retry="Provide sufficient procedural truth and evidentiary sufficiency.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "procedural_truth",
            "procedural_truth_engine",
            "procedural_truth",
            {
                "procedural_truth_result": state.get("procedural_truth_result"),
                "corroboration_met": state.get("corroboration_met"),
                "corroboration_evidence_count": state.get(
                    "corroboration_evidence_count"
                ),
                "corroboration_evidence_digest": state.get(
                    "corroboration_evidence_digest"
                ),
            },
            hybrid_trust_contexts,
        )
        for threshold_token in get_required_threshold_tokens(state):
            state, terminal = _require_three_p(
                state,
                f"procedural_truth:{threshold_token}",
                three_p_evaluator,
                three_p_attestation_provider,
                hybrid_trust_contexts,
            )
            if terminal:
                return state
            state = _issue_core_token(
                state,
                signature_provider,
                three_p_attestation_provider,
                threshold_token,
                "threshold_engine",
                "procedural_truth",
                {},
                hybrid_trust_contexts,
            )

        state, terminal = _run_filed_framework_stage(
            state,
            PTODF,
            evaluator=filed_framework_evaluator,
            attestation_provider=filed_framework_attestation_provider,
            signature_provider=signature_provider,
            three_p_evaluator=three_p_evaluator,
            three_p_attestation_provider=three_p_attestation_provider,
            hybrid_trust_contexts=hybrid_trust_contexts,
        )
        if terminal:
            return state

        state, terminal = _require_three_p(
            state,
            "classification",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = classification_engine.execute(
            state,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
        )
        _append_hash_chain(
            state,
            "classification",
            {
                "classification_result": state.get("classification_result"),
                "classification_reason": state.get("classification_reason"),
            },
        )
        state, terminal = _require_three_p(
            state,
            "classification:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        if state.get("classification_result") == CLASSIFICATION_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="CLASSIFICATION_ESCALATION",
                denial_reason=state.get("classification_reason", "Classification escalation required."),
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("classification_result") != CLASSIFICATION_ALLOW:
            state = build_deny_feedback(
                state,
                denial_code="CLASSIFICATION_DENIAL",
                denial_reason=state.get("classification_reason", "Classification denied."),
                retry_eligible=True,
                required_change_for_retry="Adjust classification inputs and resubmit materially changed request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "classification",
            "classification_engine",
            "classification",
            {
                "classification_result": state.get("classification_result"),
                "classification_reason": state.get("classification_reason"),
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            "licensing",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = licensing_engine.execute(
            state,
            evaluator=filed_licence_evaluator,
            attestation_provider=filed_licence_attestation_provider,
            attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[0],
            owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[1],
        )
        _append_hash_chain(
            state,
            state.get("filed_licence_record", {}).get(
                "stage", "filed_licence:invalid"
            ),
            filed_licence_hash_payload(state),
        )
        _append_hash_chain(
            state,
            "licensing",
            {
                "licensing_result": state.get("licensing_result"),
                "licensing_reason": state.get("licensing_reason"),
                "licence_id": state.get("licence_id"),
                "license_tier": state.get("license_tier"),
                "filed_licence_digest": state.get("filed_licence_digest"),
                "licence_revocation_status": state.get(
                    "licence_revocation_status"
                ),
                "licence_revocation_sequence": state.get(
                    "licence_revocation_sequence"
                ),
            },
        )
        state, terminal = _require_three_p(
            state,
            "licensing:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        if state.get("licensing_result") == LICENSING_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="LICENSING_ESCALATION",
                denial_reason=state.get("licensing_reason", "Licensing escalation required."),
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("licensing_result") != LICENSING_ALLOW:
            state = build_deny_feedback(
                state,
                denial_code="LICENSING_DENIAL",
                denial_reason=state.get("licensing_reason", "Licensing denied."),
                retry_eligible=True,
                required_change_for_retry="Provide valid licence state or reduce scope/autonomy.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "licensing",
            "licensing_engine",
            "licensing",
            {
                "licensing_result": state.get("licensing_result"),
                "licensing_reason": state.get("licensing_reason"),
                "licence_id": state.get("licence_id"),
                "license_tier": state.get("license_tier"),
                "filed_licence_digest": state.get("filed_licence_digest"),
                "licence_bindings_digest": canonical_integrity_hash(
                    state["filed_licence_record"]["evaluation_snapshot"][
                        "bindings"
                    ]
                ),
                "licence_revocation_status": state.get(
                    "licence_revocation_status"
                ),
                "licence_revocation_sequence": state.get(
                    "licence_revocation_sequence"
                ),
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            "governance",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        state, terminal = _run_filed_framework_stage(
            state,
            AJ_SAAF,
            evaluator=filed_framework_evaluator,
            attestation_provider=filed_framework_attestation_provider,
            signature_provider=signature_provider,
            three_p_evaluator=three_p_evaluator,
            three_p_attestation_provider=three_p_attestation_provider,
            hybrid_trust_contexts=hybrid_trust_contexts,
        )
        if terminal:
            state["governance_result"] = (
                GOVERNANCE_ESCALATE
                if state.get("filed_framework_result") == FRAMEWORK_ESCALATE
                else GOVERNANCE_DENY
            )
            state["governance_reason"] = state.get(
                "filed_framework_reason",
                "aj_saaf_governance_component_failed",
            )
            _append_hash_chain(
                state,
                "governance",
                {
                    "governance_result": state.get("governance_result"),
                    "governance_reason": state.get("governance_reason"),
                    "filed_framework_results": state.get(
                        "filed_framework_results", {}
                    ),
                },
            )
            return apply_grc(state)

        state = governance_engine.execute(
            state,
            authority_provenance_dependencies=(
                authority_provenance_dependencies
            ),
        )
        _append_hash_chain(
            state,
            "governance:determination",
            {
                "governance_result": state.get("governance_result"),
                "governance_reason": state.get("governance_reason"),
                "ptodf_result": state.get(
                    "filed_framework_results", {}
                ).get(PTODF),
                "aj_saaf_result": state.get(
                    "filed_framework_results", {}
                ).get(AJ_SAAF),
            },
        )

        if state.get("governance_result") == GOVERNANCE_ESCALATE:
            _append_hash_chain(
                state,
                "governance",
                {
                    "governance_result": state.get("governance_result"),
                    "governance_reason": state.get("governance_reason"),
                    "filed_framework_results": state.get(
                        "filed_framework_results", {}
                    ),
                },
            )
            state = apply_grc(state)
            state["decision"] = "ESCALATE"
            return state

        if state.get("governance_result") != GOVERNANCE_ALLOW:
            _append_hash_chain(
                state,
                "governance",
                {
                    "governance_result": state.get("governance_result"),
                    "governance_reason": state.get("governance_reason"),
                    "filed_framework_results": state.get(
                        "filed_framework_results", {}
                    ),
                },
            )
            state = apply_grc(state)
            state["decision"] = "DENY"
            return state

        for framework in GOVERNANCE_FRAMEWORK_ORDER[1:]:
            state, terminal = _run_filed_framework_stage(
                state,
                framework,
                evaluator=filed_framework_evaluator,
                attestation_provider=filed_framework_attestation_provider,
                signature_provider=signature_provider,
                three_p_evaluator=three_p_evaluator,
                three_p_attestation_provider=three_p_attestation_provider,
                hybrid_trust_contexts=hybrid_trust_contexts,
            )
            if terminal:
                state["governance_result"] = (
                    GOVERNANCE_ESCALATE
                    if state.get("filed_framework_result")
                    == FRAMEWORK_ESCALATE
                    else GOVERNANCE_DENY
                )
                state["governance_reason"] = state.get(
                    "filed_framework_reason",
                    f"{framework.lower()}_governance_component_failed",
                )
                _append_hash_chain(
                    state,
                    "governance",
                    {
                        "governance_result": state.get(
                            "governance_result"
                        ),
                        "governance_reason": state.get(
                            "governance_reason"
                        ),
                        "filed_framework_results": state.get(
                            "filed_framework_results", {}
                        ),
                    },
                )
                return apply_grc(state)

        for lifecycle_engine in FILED_LIFECYCLE_ORDER:
            state, terminal = _run_filed_lifecycle_stage(
                state,
                lifecycle_engine,
                evaluator=filed_lifecycle_evaluator,
                attestation_provider=filed_lifecycle_attestation_provider,
                signature_provider=signature_provider,
                three_p_evaluator=three_p_evaluator,
                three_p_attestation_provider=three_p_attestation_provider,
                hybrid_trust_contexts=hybrid_trust_contexts,
            )
            if terminal:
                state["governance_result"] = (
                    GOVERNANCE_ESCALATE
                    if state.get("filed_lifecycle_result")
                    == LIFECYCLE_ESCALATE
                    else GOVERNANCE_DENY
                )
                state["governance_reason"] = state.get(
                    "filed_lifecycle_reason",
                    "filed_lifecycle_governance_component_failed",
                )
                _append_hash_chain(
                    state,
                    "governance",
                    {
                        "governance_result": state.get(
                            "governance_result"
                        ),
                        "governance_reason": state.get(
                            "governance_reason"
                        ),
                        "filed_framework_results": state.get(
                            "filed_framework_results", {}
                        ),
                        "filed_lifecycle_results": state.get(
                            "filed_lifecycle_results", {}
                        ),
                        "filed_lifecycle_digest": state.get(
                            "filed_lifecycle_digest"
                        ),
                    },
                )
                return apply_grc(state)

        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER:
            state, terminal = _run_filed_governance_integrity_stage(
                state,
                governance_function,
                evaluator=filed_governance_integrity_evaluator,
                attestation_provider=(
                    filed_governance_integrity_attestation_provider
                ),
                signature_provider=signature_provider,
                three_p_evaluator=three_p_evaluator,
                three_p_attestation_provider=three_p_attestation_provider,
                hybrid_trust_contexts=hybrid_trust_contexts,
            )
            if terminal:
                state["governance_result"] = (
                    GOVERNANCE_ESCALATE
                    if state.get("filed_governance_integrity_result")
                    == GOVERNANCE_INTEGRITY_ESCALATE
                    else GOVERNANCE_DENY
                )
                state["governance_reason"] = state.get(
                    "filed_governance_integrity_reason",
                    "filed_governance_integrity_function_failed",
                )
                _append_hash_chain(
                    state,
                    "governance",
                    {
                        "governance_result": state.get(
                            "governance_result"
                        ),
                        "governance_reason": state.get(
                            "governance_reason"
                        ),
                        "filed_governance_integrity_results": state.get(
                            "filed_governance_integrity_results", {}
                        ),
                        "filed_governance_integrity_digest": state.get(
                            "filed_governance_integrity_digest"
                        ),
                    },
                )
                return apply_grc(state)

        governance_gate_provider: SignatureProvider | None = (
            filed_governance_integrity_attestation_provider
        )
        governance_trust_context, governance_owner_pin = _pipeline_trust_pair(
            hybrid_trust_contexts, "filed_governance_integrity"
        )
        if not (
            is_hybrid_provider(
                filed_governance_integrity_attestation_provider
            )
            and governance_trust_context is not None
            and governance_owner_pin is not None
            and verify_filed_governance_integrity(
            state,
            evaluator=filed_governance_integrity_evaluator,
            attestation_provider=(
                filed_governance_integrity_attestation_provider
            ),
            attestation_trust_context=governance_trust_context,
            owner_pinned_context_digest=governance_owner_pin,
            require_hash_binding=True,
            )
        ):
            state["governance_result"] = GOVERNANCE_DENY
            state["governance_reason"] = (
                "filed_governance_integrity_verification_failed"
            )
            state["decision"] = "DENY"
            state["execution_result"] = "HALT"
            return state

        _append_hash_chain(
            state,
            "governance",
            {
                "governance_result": state.get("governance_result"),
                "governance_reason": state.get("governance_reason"),
                "filed_framework_results": state.get(
                    "filed_framework_results", {}
                ),
                "filed_framework_digest": state.get(
                    "filed_framework_digest"
                ),
                "filed_lifecycle_results": state.get(
                    "filed_lifecycle_results", {}
                ),
                "filed_lifecycle_digest": state.get(
                    "filed_lifecycle_digest"
                ),
                "lifecycle_implementation_order_authority": (
                    FILED_LIFECYCLE_ORDER_AUTHORITY
                ),
                "filed_governance_integrity_results": state.get(
                    "filed_governance_integrity_results", {}
                ),
                "filed_governance_integrity_digest": state.get(
                    "filed_governance_integrity_digest"
                ),
                "filed_governance_integrity_revocation_binding": state.get(
                    "filed_governance_integrity_revocation_binding", {}
                ),
                "governance_integrity_implementation_order_authority": (
                    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                ),
            },
        )

        state = apply_grc(state)
        state, terminal = _require_three_p(
            state,
            "governance:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        state, terminal = _run_legacy_phase(state, "governance")
        if terminal:
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "governance",
            "governance_engine",
            "governance",
            {
                "governance_result": state.get("governance_result"),
                "governance_reason": state.get("governance_reason"),
                "governance_framework_results": {
                    framework: state.get("filed_framework_results", {}).get(
                        framework
                    )
                    for framework in GOVERNANCE_FRAMEWORK_ORDER
                },
                "filed_framework_digest": state.get(
                    "filed_framework_digest"
                ),
                "filed_lifecycle_results": {
                    lifecycle_engine: state.get(
                        "filed_lifecycle_results", {}
                    ).get(lifecycle_engine)
                    for lifecycle_engine in FILED_LIFECYCLE_ORDER
                },
                "filed_lifecycle_digest": state.get(
                    "filed_lifecycle_digest"
                ),
                "lifecycle_implementation_order_authority": (
                    FILED_LIFECYCLE_ORDER_AUTHORITY
                ),
                "filed_governance_integrity_result": state.get(
                    "filed_governance_integrity_result"
                ),
                "filed_governance_integrity_results": {
                    governance_function: state.get(
                        "filed_governance_integrity_results", {}
                    ).get(governance_function)
                    for governance_function in (
                        FILED_GOVERNANCE_INTEGRITY_ORDER
                    )
                },
                "filed_governance_integrity_digest": state.get(
                    "filed_governance_integrity_digest"
                ),
                "governance_integrity_implementation_order_authority": (
                    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                ),
                "filed_governance_integrity_revocation_status": state.get(
                    "filed_governance_integrity_revocation_binding", {}
                ).get("status"),
                "filed_governance_integrity_revocation_sequence": state.get(
                    "filed_governance_integrity_revocation_binding", {}
                ).get("sequence"),
                "filed_governance_integrity_revocation_digest": state.get(
                    "filed_governance_integrity_revocation_binding", {}
                ).get("digest"),
                "filed_governance_integrity_authority_granted": False,
                "filed_governance_integrity_licence_granted": False,
                "filed_governance_integrity_execution_authority_granted": False,
                "filed_governance_integrity_effect_granted": False,
                "filed_governance_integrity_bypass_permitted": False,
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            "domain_wrap",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = run_domain_wrap(state)
        _append_hash_chain(
            state,
            "domain_wrap",
            {
                "domain_result": state.get("domain_result"),
            },
        )
        state, terminal = _require_three_p(
            state,
            "domain_wrap:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        if state.get("domain_result") == DOMAIN_ESCALATE_RESULT:
            state = build_escalate_feedback(
                state,
                denial_code="DOMAIN_ESCALATION",
                denial_reason="Domain escalation required.",
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("domain_result") != DOMAIN_PASS_RESULT:
            state = build_deny_feedback(
                state,
                denial_code="DOMAIN_DENIAL",
                denial_reason=f"Domain blocked pathway: {state.get('domain_result')}",
                retry_eligible=True,
                required_change_for_retry="Provide materially changed request, fallback request, or escalation request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state, terminal = _run_legacy_phase(state, "domain")
        if terminal:
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "domain",
            "domain_wrap",
            "domain_wrap",
            {
                "domain_result": state.get("domain_result"),
            },
            hybrid_trust_contexts,
        )

        aurion_attempts = 0
        while True:
            aurion_attempts += 1
            state, terminal = _require_three_p(
                state,
                f"aurion_runtime:{aurion_attempts}",
                three_p_evaluator,
                three_p_attestation_provider,
                hybrid_trust_contexts,
            )
            if terminal:
                return state
            state = run_aurion15(state)

            _append_hash_chain(
                state,
                f"aurion_runtime:{aurion_attempts}",
                {
                    "aurion15_result": state.get("aurion15_result"),
                    "candidate_attempt_count": state.get("candidate_attempt_count"),
                    "current_candidate": state.get("current_candidate"),
                },
            )
            state, terminal = _require_three_p(
                state,
                f"aurion_runtime:{aurion_attempts}:post",
                three_p_evaluator,
                three_p_attestation_provider,
                hybrid_trust_contexts,
            )
            if terminal:
                return state
            state, terminal = _run_legacy_phase(
                state,
                "candidate",
                run_id=str(aurion_attempts),
            )
            if terminal:
                return state

            if state.get("aurion15_result") == AURION_PASS_RESULT:
                break

            if state.get("aurion15_result") == AURION_ESCALATE_RESULT:
                state = build_escalate_feedback(
                    state,
                    denial_code="AURION_ESCALATION",
                    denial_reason="Aurion escalation required.",
                    safe_state_required=False,
                )
                state["decision"] = "ESCALATE"
                return state

            if (
                state.get("aurion15_result") == AURION_REQUIRE_NEXT_CANDIDATE_RESULT
                and aurion_attempts < AURION_MAX_CANDIDATE_ATTEMPTS
            ):
                continue

            state = build_deny_feedback(
                state,
                denial_code="AURION_RESOLUTION_FAILURE",
                denial_reason="Aurion could not resolve a valid pathway.",
                retry_eligible=True,
                required_change_for_retry="Provide materially changed request, fallback request, or escalation request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "aurion",
            "aurion15_runtime",
            "aurion_runtime",
            {
                "aurion15_result": state.get("aurion15_result"),
                "candidate_attempt_count": state.get("candidate_attempt_count"),
                "current_candidate": state.get("current_candidate"),
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            LICENCE_REVALIDATION_STAGE,
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = evaluate_filed_licence(
            state,
            stage=LICENCE_REVALIDATION_STAGE,
            evaluator=filed_licence_evaluator,
            attestation_provider=filed_licence_attestation_provider,
            trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[0],
            owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[1],
        )
        _append_hash_chain(
            state,
            LICENCE_REVALIDATION_STAGE,
            filed_licence_hash_payload(state),
        )
        state, terminal = _require_three_p(
            state,
            f"{LICENCE_REVALIDATION_STAGE}:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        if state.get("filed_licence_result") != LICENCE_ALLOW:
            state = invalidate_filed_licence(
                state,
                stage=LICENCE_REVALIDATION_STAGE,
                reason=state.get(
                    "filed_licence_reason",
                    "filed_licence_runtime_revalidation_failed",
                ),
            )
            licensing_reason = state.get("licensing_reason")
            state = build_deny_feedback(
                state,
                denial_code="LICENCE_RUNTIME_REVALIDATION_FAILURE",
                denial_reason=(
                    licensing_reason
                    if type(licensing_reason) is str
                    else "filed_licence_runtime_revalidation_failed"
                ),
                retry_eligible=True,
                required_change_for_retry=(
                    "Re-enter through the complete governed licence pathway."
                ),
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )
            state["decision"] = "DENY"
            state["execution_result"] = "HALT"
            return state

        state, terminal = _require_three_p(
            state,
            "execution_prep",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state, terminal = _run_legacy_phase(state, "pre_execution")
        if terminal:
            return state
        state, terminal = _require_three_p(
            state,
            "execution_prep:post_shadow",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "execution_boundary",
            "execution_gate",
            "execution_prep",
            {
                "boundary_clear": True,
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            "execution_prep:execution_attestation",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = _issue_core_token(
            state,
            signature_provider,
            three_p_attestation_provider,
            "execution_attestation",
            "execution_gate",
            "execution_prep",
            {
                "attested_for_execution": True,
            },
            hybrid_trust_contexts,
        )

        state, terminal = _require_three_p(
            state,
            "execution_gate",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state = run_execution_gate(
            state,
            signature_provider=signature_provider,
            signature_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "signature"
            )[0],
            signature_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "signature"
            )[1],
            three_p_attestation_provider=three_p_attestation_provider,
            three_p_attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[0],
            three_p_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[1],
            skg_evaluator=skg_evaluator,
            skg_attestation_provider=skg_attestation_provider,
            skg_attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "skg"
            )[0],
            skg_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "skg"
            )[1],
            filed_framework_evaluator=filed_framework_evaluator,
            filed_framework_attestation_provider=(
                filed_framework_attestation_provider
            ),
            filed_framework_attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_framework"
            )[0],
            filed_framework_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_framework"
            )[1],
            filed_lifecycle_evaluator=filed_lifecycle_evaluator,
            filed_lifecycle_attestation_provider=(
                filed_lifecycle_attestation_provider
            ),
            filed_lifecycle_attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_lifecycle"
            )[0],
            filed_lifecycle_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_lifecycle"
            )[1],
            filed_governance_integrity_evaluator=(
                filed_governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=(
                governance_gate_provider
            ),
            filed_governance_integrity_attestation_trust_context=(
                _pipeline_trust_pair(
                    hybrid_trust_contexts,
                    "filed_governance_integrity",
                )[0]
            ),
            filed_governance_integrity_owner_pinned_context_digest=(
                _pipeline_trust_pair(
                    hybrid_trust_contexts,
                    "filed_governance_integrity",
                )[1]
            ),
            filed_licence_evaluator=filed_licence_evaluator,
            filed_licence_attestation_provider=(
                filed_licence_attestation_provider
            ),
            filed_licence_attestation_trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[0],
            filed_licence_owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "filed_licence"
            )[1],
            application_integrity_bundle=application_integrity_bundle,
            application_integrity_result=application_integrity_result,
            foundational_request_dependencies=(
                foundational_request_dependencies
            ),
        )
        _append_hash_chain(
            state,
            "execution_gate",
            {
                "execution_result": state.get("execution_result"),
                "decision": state.get("decision"),
                "execution_reason": state.get("execution_reason"),
            },
        )
        state, terminal = _require_three_p(
            state,
            "execution_gate:post",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state

        if state.get("execution_result") != "EXECUTE":
            if state.get("decision") not in {"DENY", "ESCALATE"}:
                state = build_deny_feedback(
                    state,
                    denial_code="EXECUTION_GATE_FAILURE",
                    denial_reason="Execution gate halted the request.",
                    retry_eligible=False,
                    required_change_for_retry="Execution gate failure requires governed re-entry.",
                    escalation_allowed=True,
                    fallback_action_allowed=False,
                    safe_state_required=True,
                )
                state["decision"] = "DENY"
            return state

        if effect_adapter is not None or effect_permit_ttl_ms is not None:
            state["controlled_local_adapter_classification"] = (
                "ISOLATED_TEST_ONLY_NOT_LIVE"
            )
        if rust_authority_route is None:
            state["rust_authority_route_status"] = "NOT_ADMITTED"
            state["effect_result"] = "BLOCKED"
            state["execution_result"] = "HALT"
            state["decision"] = "DENY"
            state["execution_reason"] = RUST_AUTHORITY_ROUTE_NOT_ADMITTED
            state.setdefault("effect_trace", []).append(
                {
                    "event": "rust_authority_route_unavailable",
                    "reason": RUST_AUTHORITY_ROUTE_NOT_ADMITTED,
                    "authority_effect": "NONE",
                    "python_effect_handler_reachable": False,
                }
            )
        else:
            try:
                rust_terminal_evidence = rust_authority_route.execute(
                    deepcopy(state)
                )
                if type(rust_terminal_evidence) is not RustAuthorityTerminalEvidence:
                    raise RustAuthorityRouteInDoubt(
                        "RUST_AUTHORITY_TERMINAL_EVIDENCE_TYPE_REJECTED"
                    )
                terminal_record = rust_terminal_evidence.audit_record()
                if not terminal_record.get(
                    "complete_signed_terminal_transcript_validated"
                ):
                    raise RustAuthorityRouteInDoubt(
                        "RUST_AUTHORITY_TERMINAL_TRANSCRIPT_NOT_VALIDATED"
                    )
                if (
                    terminal_record.get("route_admission_state")
                    != RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED
                    or terminal_record.get("programme_success_eligible") is not False
                    or terminal_record.get("effect_authority_granted") is not False
                ):
                    raise RustAuthorityRouteInDoubt(
                        "RUST_AUTHORITY_ROUTE_ADMISSION_EVIDENCE_INVALID"
                    )
                state["rust_authority_route_status"] = (
                    RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED
                )
                state["rust_authority_terminal_evidence"] = terminal_record
                state["rust_authority_terminal_transcript"] = list(
                    rust_terminal_evidence.messages_for_diagnostics()
                )
                state["rust_authority_terminal_validated"] = True
                state["effect_adapter_id"] = rust_terminal_evidence.adapter_digest
                state["effect_id"] = rust_terminal_evidence.effect_digest
                state["effect_permit"] = {
                    "digest": rust_terminal_evidence.permit_digest,
                    "classification": "POST_CONSUMPTION_AUDIT_ONLY",
                }
                state["effect_receipt"] = {
                    "digest": rust_terminal_evidence.receipt_digest,
                    "classification": "RUST_TERMINAL_AUDIT_EVIDENCE",
                }
                state["effect_result"] = "BLOCKED"
                state["execution_result"] = "HALT"
                state["decision"] = "DENY"
                state["execution_reason"] = RUST_AUTHORITY_ROUTE_NOT_ADMITTED
                state.setdefault("effect_trace", []).append(
                    {
                        "event": "rust_authority_unadmitted_terminal_validated",
                        "reason": RUST_AUTHORITY_ROUTE_NOT_ADMITTED,
                        "reported_terminal_outcome": rust_terminal_evidence.outcome,
                        "authority_effect": "NONE_GRANTED",
                        "programme_success_eligible": False,
                        "python_effect_handler_reachable": False,
                    }
                )
            except RustAuthorityRouteUnavailable as exc:
                state["rust_authority_route_status"] = "NOT_ADMITTED"
                state["effect_result"] = "BLOCKED"
                state["execution_result"] = "HALT"
                state["decision"] = "DENY"
                state["execution_reason"] = str(exc)
                state.setdefault("effect_trace", []).append(
                    {
                        "event": "rust_authority_route_rejected_before_exchange",
                        "reason": str(exc),
                        "authority_effect": "NONE",
                        "python_effect_handler_reachable": False,
                    }
                )
            except Exception as exc:
                # Any failure after a route exchange begins is unknown.  The
                # pipeline cannot infer that no physical effect occurred.
                state["rust_authority_route_status"] = "TERMINAL_UNVERIFIED"
                state["rust_authority_terminal_validated"] = False
                state["effect_result"] = "UNKNOWN"
                state["execution_result"] = "HALT"
                state["decision"] = "ESCALATE"
                state["execution_reason"] = (
                    "RUST_AUTHORITY_TERMINAL_STATE_UNVERIFIED"
                )
                state.setdefault("effect_trace", []).append(
                    {
                        "event": "rust_authority_effect_in_doubt",
                        "reason": str(exc),
                        "authority_effect": "POSSIBLE_EFFECT_SLOT_SPENT",
                        "python_effect_handler_reachable": False,
                    }
                )
        _append_hash_chain(
            state,
            "rust_authority_effect",
            {
                "effect_adapter_id": state.get("effect_adapter_id"),
                "effect_id": state.get("effect_id"),
                "effect_permit_digest": state.get("effect_permit", {}).get(
                    "digest"
                ),
                "effect_receipt_digest": state.get("effect_receipt", {}).get(
                    "digest"
                ),
                "effect_result": state.get("effect_result"),
                "rust_authority_route_status": state.get(
                    "rust_authority_route_status"
                ),
                "rust_authority_terminal_validated": state.get(
                    "rust_authority_terminal_validated"
                ),
                "rust_authority_terminal_transcript_digest": state.get(
                    "rust_authority_terminal_evidence", {}
                ).get("terminal_transcript_digest"),
                "execution_result": state.get("execution_result"),
                "decision": state.get("decision"),
            },
        )
        if state.get("effect_result") != "SUCCESS":
            return state

        state, terminal = _require_three_p(
            state,
            "audit:pre",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        if terminal:
            return state
        state, terminal = _run_legacy_phase(state, "audit")
        if terminal:
            return state
        state = _finalize_audit(state)
        _append_hash_chain(
            state,
            "audit",
            {
                "audit_hash": state.get("audit_hash"),
                "ledger_entries": len(state.get("audit_ledger", [])),
            },
        )

        return state

    except SignatureProviderUnavailable as exc:
        candidate_state = locals().get("state")
        state = candidate_state if type(candidate_state) is dict else {}
        state.update(
            {
                "decision": "DENY",
                "execution_result": "HALT",
                "execution_reason": "signature_provider_unavailable",
                "signature_provider_status": "NOT_INJECTED_OR_NOT_ADMITTED",
                "error": str(exc),
            }
        )
        return state
    except Exception as exc:
        candidate_state = locals().get("state")
        state = candidate_state if type(candidate_state) is dict else {}
        state.update(
            {
                "decision": "DENY",
                "execution_result": "HALT",
                "execution_reason": "pipeline_runtime_error",
                "error": str(exc),
            }
        )
        return state


def run_v2_pipeline(
    input_data: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    *,
    signature_provider: SignatureProvider | None = None,
    three_p_evaluator: ThreePCoreEvaluator | None = None,
    three_p_attestation_provider: SignatureProvider | None = None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        SignatureProvider | None
    ) = None,
    filed_governance_integrity_revocation_binding: (
        dict[str, Any] | None
    ) = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
    foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    possession_proof: dict[str, Any] | None = None,
    effect_adapter: EffectAdapter | None = None,
    effect_permit_ttl_ms: int | None = None,
    rust_authority_route: RustAuthorityRoute | None = None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> Dict[str, Any]:
    return run_v2(
        input_data,
        pre_context_signals,
        signature_provider=signature_provider,
        three_p_evaluator=three_p_evaluator,
        three_p_attestation_provider=three_p_attestation_provider,
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_attestation_provider,
        filed_framework_evaluator=filed_framework_evaluator,
        filed_framework_attestation_provider=(
            filed_framework_attestation_provider
        ),
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        filed_governance_integrity_evaluator=(
            filed_governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        filed_governance_integrity_revocation_binding=(
            filed_governance_integrity_revocation_binding
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        application_integrity_bundle=application_integrity_bundle,
        foundational_request_dependencies=foundational_request_dependencies,
        possession_proof=possession_proof,
        effect_adapter=effect_adapter,
        effect_permit_ttl_ms=effect_permit_ttl_ms,
        rust_authority_route=rust_authority_route,
        hybrid_trust_contexts=hybrid_trust_contexts,
    )


def run_v2(
    input_data: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    *,
    signature_provider: SignatureProvider | None = None,
    three_p_evaluator: ThreePCoreEvaluator | None = None,
    three_p_attestation_provider: SignatureProvider | None = None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        SignatureProvider | None
    ) = None,
    filed_governance_integrity_revocation_binding: (
        dict[str, Any] | None
    ) = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
    foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    possession_proof: dict[str, Any] | None = None,
    effect_adapter: EffectAdapter | None = None,
    effect_permit_ttl_ms: int | None = None,
    rust_authority_route: RustAuthorityRoute | None = None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> Dict[str, Any]:
    """Run the single pipeline and force a terminal audit on every path."""

    state = _run_v2_core(
        input_data,
        pre_context_signals,
        signature_provider=signature_provider,
        three_p_evaluator=three_p_evaluator,
        three_p_attestation_provider=three_p_attestation_provider,
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_attestation_provider,
        filed_framework_evaluator=filed_framework_evaluator,
        filed_framework_attestation_provider=(
            filed_framework_attestation_provider
        ),
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        filed_governance_integrity_evaluator=(
            filed_governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        filed_governance_integrity_revocation_binding=(
            filed_governance_integrity_revocation_binding
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        application_integrity_bundle=application_integrity_bundle,
        foundational_request_dependencies=foundational_request_dependencies,
        possession_proof=possession_proof,
        effect_adapter=effect_adapter,
        effect_permit_ttl_ms=effect_permit_ttl_ms,
        rust_authority_route=rust_authority_route,
        hybrid_trust_contexts=hybrid_trust_contexts,
    )
    if type(state) is not dict:
        state = {
            "decision": "DENY",
            "execution_result": "HALT",
            "execution_reason": "pipeline_returned_invalid_state",
        }
    if state.get("decision") in {"DENY", "ESCALATE"} and not state.get(
        "execution_result"
    ):
        state["execution_result"] = "HALT"
    if not state.get("execution_reason"):
        feedback = state.get("governance_feedback", {})
        state["execution_reason"] = (
            feedback.get("denial_code")
            or state.get("aurion_reason")
            or state.get("domain_reason")
            or "terminal_without_execution"
        )
    state.setdefault("request_fingerprint", _stable_hash({"input": input_data}))
    state.setdefault("hash_chain", [])
    state.setdefault("audit_ledger", [])
    licence_was_activated = any(
        type(record) is dict
        and record.get("stage")
        in {LICENCE_ROOT_BINDING_STAGE, "filed_licence:validation"}
        and record.get("result") == LICENCE_ALLOW
        for record in state.get("filed_licence_trace", [])
    )
    terminal_failure = (
        state.get("decision") != "APPROVED"
        or state.get("execution_result") != "EXECUTE"
    )
    invalidation_bound = any(
        entry.get("stage") == "filed_licence:invalidation"
        for entry in state.get("hash_chain", [])
        if type(entry) is dict
    )
    if licence_was_activated and terminal_failure:
        state = invalidate_filed_licence(
            state,
            stage="terminal_governance_failure",
            reason=state.get(
                "execution_reason", "terminal_governance_failure"
            ),
        )
        if not invalidation_bound:
            _append_hash_chain(
                state,
                "filed_licence:invalidation",
                {
                    "licence_id": state.get("licence_id"),
                    "invalidation_status": state.get(
                        "licence_invalidation_status"
                    ),
                    "invalidation_digest": state.get(
                        "licence_invalidation_digest"
                    ),
                    "revocation_status": state.get(
                        "licence_revocation_status"
                    ),
                },
            )
    three_p_terminal_ready = bool(state.get("audit_hash"))
    if not state.get("audit_hash") and state.get("three_p_core_result") == "PASS":
        state, terminal = _require_three_p(
            state,
            "terminal_audit",
            three_p_evaluator,
            three_p_attestation_provider,
            hybrid_trust_contexts,
        )
        three_p_terminal_ready = not terminal
    if (
        three_p_terminal_ready
        and verify_three_p_core(
            state,
            attestation_provider=three_p_attestation_provider,
            require_hash_binding=True,
            trust_context=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[0],
            owner_pinned_context_digest=_pipeline_trust_pair(
                hybrid_trust_contexts, "three_p"
            )[1],
        )
        and "audit" not in state.get("legacy_admission_completed_phases", [])
    ):
        try:
            state, _ = _run_legacy_phase(state, "audit")
        except Exception as exc:
            state["decision"] = "DENY"
            state["execution_result"] = "HALT"
            state["execution_reason"] = "legacy_audit_runtime_error"
            state["legacy_audit_error"] = str(exc)
    if not state.get("audit_hash"):
        state = _finalize_audit(state)
        _append_hash_chain(
            state,
            "audit",
            {
                "audit_hash": state.get("audit_hash"),
                "ledger_entries": len(state.get("audit_ledger", [])),
                "terminal_decision": state.get("decision"),
            },
        )
    return state
