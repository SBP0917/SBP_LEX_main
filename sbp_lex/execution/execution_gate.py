from __future__ import annotations

from typing import Dict, Any, List

from sbp_lex.baseline.application_startup import (
    APPLICATION_STARTUP_STATE_FIELDS,
    ApplicationIntegrityRuntimeBundle,
    verify_and_project_application_startup,
)
from sbp_lex.baseline.foundational_baseline import (
    verify_foundational_baseline,
)
from sbp_lex.baseline.request_controls import (
    FoundationalRequestDependencies,
    verify_digital_provenance_state,
    verify_foundational_request_controls,
)
from sbp_lex.compliance.australian_minor_access import (
    verify_australian_minor_access,
)
from sbp_lex.config.pipeline_config import (
    GOVERNANCE_ALLOW,
    PROCEDURAL_TRUTH_PASS,
    DOMAIN_PASS_RESULT,
    AURION_PASS_RESULT,
    EXECUTION_RESULT_EXECUTE,
    EXECUTION_RESULT_HALT,
    EXECUTION_APPROVED,
    EXECUTION_DENIED,
    EXECUTION_ESCALATED,
)
from sbp_lex.security.token_stack import (
    verify_required_tokens,
    get_required_threshold_tokens,
)
from sbp_lex.security.signature_provider import (
    HybridVerificationContext,
    SignatureProvider,
)
from sbp_lex.security.integrity import verify_hash_chain_entries
from sbp_lex.governance.three_p_doctrine import verify_three_p_core
from sbp_lex.governance.authority_provenance import (
    verify_authority_provenance,
)
from sbp_lex.identity.sovereign_identity import verify_sovereign_identity
from sbp_lex.interface.authority_boundary import verify_authority_boundary
from sbp_lex.governance.skg_authority import (
    SKGAuthorityEvaluator,
    verify_skg_authority,
)
from sbp_lex.governance.filed_frameworks import (
    FiledFrameworkEvaluator,
    verify_filed_frameworks,
)
from sbp_lex.governance.filed_lifecycle import (
    FiledLifecycleEvaluator,
    verify_filed_lifecycle,
)
from sbp_lex.governance.filed_governance_integrity import (
    FiledGovernanceIntegrityEvaluator,
    verify_filed_governance_integrity,
)
from sbp_lex.licensing.filed_licensing import (
    FiledLicenceEvaluator,
    verify_filed_licence,
)


# ─────────────────────────────────────────────
# HASH-CHAIN VERIFICATION
# ─────────────────────────────────────────────

def verify_hash_chain(state: Dict[str, Any]) -> bool:
    return verify_hash_chain_entries(
        state.get("hash_chain"),
        state.get("state_hash"),
    )


# ─────────────────────────────────────────────
# TIER / THRESHOLD CONSISTENCY
# ─────────────────────────────────────────────

def verify_tier_consistency(state: Dict[str, Any]) -> bool:
    safety_profile = state.get("safety_profile", {})
    tier = safety_profile.get("computed_tier")

    if not tier:
        return False

    corroboration_required = state.get("corroboration_required")
    if corroboration_required is None:
        return False

    expected = {
        "LOW": 2,
        "MEDIUM": 3,
        "TOP": 5,
    }.get(tier)

    if expected is None:
        return False

    return corroboration_required == expected


# ─────────────────────────────────────────────
# COLLECTIVE SIGNAL CONSISTENCY
# ─────────────────────────────────────────────

def verify_collective_signal_consistency(state: Dict[str, Any]) -> bool:
    signals = state.get("collective_signals", {})

    if not signals:
        return False

    if signals.get("request_fingerprint") != state.get("request_fingerprint"):
        return False

    if "intent_signal" not in signals:
        return False

    if "risk_potential_signal" not in signals:
        return False

    if "authority_link_signal" not in signals:
        return False

    if "jurisdiction_signal" not in signals:
        return False

    if "dependency_signal" not in signals:
        return False

    if "policy_conflict_signal" not in signals:
        return False

    if "operational_context_signal" not in signals:
        return False

    if "precedence_signal" not in signals:
        return False

    policy_conflict_signal = signals.get("policy_conflict_signal", {})
    if policy_conflict_signal.get("conflicts_detected") is True:
        severity = policy_conflict_signal.get("severity", "LOW")
        if severity == "HIGH":
            return False

    return True


# ─────────────────────────────────────────────
# EXECUTION BOUNDARY / ATTESTATION CHECKS
# ─────────────────────────────────────────────

def verify_execution_boundary_clear(state: Dict[str, Any]) -> bool:
    token = state.get("tokens", {}).get("execution_boundary", {})
    return token.get("payload", {}).get("boundary_clear") is True


def verify_execution_attestation_clear(state: Dict[str, Any]) -> bool:
    token = state.get("tokens", {}).get("execution_attestation", {})
    return token.get("payload", {}).get("attested_for_execution") is True


# ─────────────────────────────────────────────
# TRACE HELPERS
# ─────────────────────────────────────────────

def _append_trace(
    state: Dict[str, Any],
    check: str,
    passed: bool,
    reason: str | None = None,
) -> None:
    state.setdefault("execution_trace", [])
    state["execution_trace"].append(
        {
            "check": check,
            "passed": passed,
            "reason": reason,
        }
    )


def _halt(
    state: Dict[str, Any],
    reason: str,
    decision: str = EXECUTION_DENIED,
) -> Dict[str, Any]:
    state["execution_result"] = EXECUTION_RESULT_HALT
    state["decision"] = decision
    state["execution_reason"] = reason
    return state


def _application_integrity_current_and_unchanged(
    state: Dict[str, Any],
    *,
    bundle: ApplicationIntegrityRuntimeBundle | None,
    result: dict[str, Any] | None,
) -> bool:
    if (
        type(bundle) is not ApplicationIntegrityRuntimeBundle
        or type(result) is not dict
    ):
        return False
    before = tuple(
        (field in state, state.get(field))
        for field in APPLICATION_STARTUP_STATE_FIELDS
    )
    verify_and_project_application_startup(
        state,
        bundle=bundle,
        result=result,
    )
    after = tuple(
        (field in state, state.get(field))
        for field in APPLICATION_STARTUP_STATE_FIELDS
    )
    return before == after


def _impersonation_control_current_and_valid(
    state: Dict[str, Any],
    dependencies: FoundationalRequestDependencies | None,
) -> bool:
    return (
        isinstance(dependencies, FoundationalRequestDependencies)
        and verify_foundational_request_controls(
            state,
            dependencies=dependencies,
        )
    )


def _run_foundational_execution_checks(
    state: Dict[str, Any],
    *,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
    application_integrity_result: dict[str, Any] | None,
    foundational_request_dependencies: FoundationalRequestDependencies | None,
) -> Dict[str, Any] | None:
    dependencies = foundational_request_dependencies
    checks = (
        (
            "application_integrity_current_and_valid",
            lambda: _application_integrity_current_and_unchanged(
                state,
                bundle=application_integrity_bundle,
                result=application_integrity_result,
            ),
        ),
        (
            "digital_provenance_authenticated",
            lambda: (
                isinstance(dependencies, FoundationalRequestDependencies)
                and verify_digital_provenance_state(
                    state,
                    dependencies=dependencies,
                )
            ),
        ),
        (
            "sovereign_identity_current_and_valid",
            lambda: (
                isinstance(dependencies, FoundationalRequestDependencies)
                and verify_sovereign_identity(
                    state,
                    evaluator=dependencies.sovereign_identity_evaluator,
                    attestation_provider=(
                        dependencies.sovereign_identity_attestation_provider
                    ),
                    attestation_trust_context=(
                        dependencies.sovereign_identity_trust_context
                    ),
                    owner_pinned_context_digest=(
                        dependencies.sovereign_identity_owner_pinned_context_digest
                    ),
                    require_hash_binding=True,
                )
            ),
        ),
        (
            "authority_boundary_current_and_valid",
            lambda: (
                isinstance(dependencies, FoundationalRequestDependencies)
                and verify_authority_boundary(
                    state,
                    evaluator=dependencies.authority_boundary_evaluator,
                    attestation_provider=(
                        dependencies.authority_boundary_attestation_provider
                    ),
                    attestation_trust_context=(
                        dependencies.authority_boundary_trust_context
                    ),
                    owner_pinned_context_digest=(
                        dependencies.authority_boundary_owner_pinned_context_digest
                    ),
                    require_hash_binding=True,
                )
            ),
        ),
        (
            "impersonation_protection_current_and_valid",
            lambda: _impersonation_control_current_and_valid(
                state,
                dependencies,
            ),
        ),
        (
            "australian_minor_access_current_and_valid",
            lambda: verify_australian_minor_access(state),
        ),
        (
            "foundational_request_controls_current_and_valid",
            lambda: (
                isinstance(dependencies, FoundationalRequestDependencies)
                and verify_foundational_request_controls(
                    state,
                    dependencies=dependencies,
                )
            ),
        ),
        (
            "foundational_baseline_digest_current_and_valid",
            lambda: verify_foundational_baseline(
                state,
                require_hash_binding=True,
            ),
        ),
    )
    for check, verifier in checks:
        try:
            passed = verifier() is True
        except Exception:
            passed = False
        failure_reason = f"{check}_failure"
        _append_trace(
            state,
            check,
            passed,
            None if passed else failure_reason,
        )
        if not passed:
            return _halt(state, failure_reason)
    return None


# ─────────────────────────────────────────────
# EXECUTION GATE
# ─────────────────────────────────────────────

def run_execution_gate(
    state: Dict[str, Any],
    *,
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
    filed_framework_attestation_trust_context: HybridVerificationContext | None = None,
    filed_framework_owner_pinned_context_digest: str | None = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    filed_licence_attestation_trust_context: HybridVerificationContext | None = None,
    filed_licence_owner_pinned_context_digest: str | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_attestation_trust_context: HybridVerificationContext | None = None,
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
) -> Dict[str, Any]:
    state.setdefault("execution_trace", [])

    # 1. hash-chain presence + integrity
    hash_chain_ok = verify_hash_chain(state)
    _append_trace(
        state,
        "hash_chain_presence_and_integrity",
        hash_chain_ok,
        None if hash_chain_ok else "Hash chain missing or broken.",
    )
    if not hash_chain_ok:
        return _halt(state, "hash_chain_failure", decision=EXECUTION_ESCALATED)

    foundational_failure = _run_foundational_execution_checks(
        state,
        application_integrity_bundle=application_integrity_bundle,
        application_integrity_result=application_integrity_result,
        foundational_request_dependencies=foundational_request_dependencies,
    )
    if foundational_failure is not None:
        return foundational_failure

    authority_provenance_ok = (
        isinstance(
            foundational_request_dependencies,
            FoundationalRequestDependencies,
        )
        and verify_authority_provenance(
            state,
            dependencies=(
                foundational_request_dependencies.authority_provenance_dependencies
            ),
            require_hash_binding=True,
        )
    )
    _append_trace(
        state,
        "authority_provenance_current_and_valid",
        authority_provenance_ok,
        None
        if authority_provenance_ok
        else "authority_provenance_current_and_valid_failure",
    )
    if not authority_provenance_ok:
        return _halt(
            state, "authority_provenance_current_and_valid_failure"
        )

    # Constitutional prerequisite: no downstream result can replace the 3P Core.
    three_p_ok = verify_three_p_core(
        state,
        attestation_provider=three_p_attestation_provider,
        trust_context=three_p_attestation_trust_context,
        owner_pinned_context_digest=three_p_owner_pinned_context_digest,
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "three_p_core_constitutional_constraint",
        three_p_ok,
        None if three_p_ok else "3P Core is absent, failed, mutated, or unbound.",
    )
    if not three_p_ok:
        return _halt(state, "three_p_core_failure")

    skg_ok = verify_skg_authority(
        state,
        evaluator=skg_evaluator,
        attestation_provider=skg_attestation_provider,
        attestation_trust_context=skg_attestation_trust_context,
        owner_pinned_context_digest=skg_owner_pinned_context_digest,
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "skg_authority_complete_and_valid",
        skg_ok,
        None
        if skg_ok
        else "SKG authority is absent, failed, mutated, untrusted, or unbound.",
    )
    if not skg_ok:
        return _halt(state, "skg_authority_failure")

    filed_licence_ok = verify_filed_licence(
        state,
        evaluator=filed_licence_evaluator,
        attestation_provider=filed_licence_attestation_provider,
        trust_context=filed_licence_attestation_trust_context,
        owner_pinned_context_digest=filed_licence_owner_pinned_context_digest,
        require_revalidation=True,
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "filed_four_tier_licence_current_and_valid",
        filed_licence_ok,
        None
        if filed_licence_ok
        else (
            "The filed licence tier, five bindings, invalidation state, or "
            "live revocation evidence is invalid."
        ),
    )
    if not filed_licence_ok:
        return _halt(state, "filed_licence_failure")

    filed_frameworks_ok = verify_filed_frameworks(
        state,
        evaluator=filed_framework_evaluator,
        attestation_provider=filed_framework_attestation_provider,
        attestation_trust_context=filed_framework_attestation_trust_context,
        owner_pinned_context_digest=filed_framework_owner_pinned_context_digest,
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "filed_frameworks_complete_and_valid",
        filed_frameworks_ok,
        None
        if filed_frameworks_ok
        else "AJ-SAAF, PTODF, GALA, and ABEGF are incomplete, invalid, or out of order.",
    )
    if not filed_frameworks_ok:
        return _halt(state, "filed_framework_traversal_failure")

    filed_lifecycle_ok = verify_filed_lifecycle(
        state,
        evaluator=filed_lifecycle_evaluator,
        attestation_provider=filed_lifecycle_attestation_provider,
        attestation_trust_context=filed_lifecycle_attestation_trust_context,
        owner_pinned_context_digest=filed_lifecycle_owner_pinned_context_digest,
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "filed_lifecycle_complete_and_valid",
        filed_lifecycle_ok,
        None
        if filed_lifecycle_ok
        else (
            "The three filed lifecycle contracts are incomplete, invalid, "
            "untrusted, unbound, or out of implementation-defined order."
        ),
    )
    if not filed_lifecycle_ok:
        return _halt(state, "filed_lifecycle_failure")

    filed_governance_integrity_ok = verify_filed_governance_integrity(
        state,
        evaluator=filed_governance_integrity_evaluator,
        attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        attestation_trust_context=(
            filed_governance_integrity_attestation_trust_context
        ),
        owner_pinned_context_digest=(
            filed_governance_integrity_owner_pinned_context_digest
        ),
        require_hash_binding=True,
    )
    _append_trace(
        state,
        "filed_governance_integrity_complete_and_valid",
        filed_governance_integrity_ok,
        None
        if filed_governance_integrity_ok
        else (
            "The five filed governance-integrity functions are incomplete, "
            "negative, invalid, untrusted, revoked, unbound, or reordered."
        ),
    )
    if not filed_governance_integrity_ok:
        return _halt(state, "filed_governance_integrity_failure")

    # 2. governance allow
    governance_ok = state.get("governance_result") == GOVERNANCE_ALLOW
    _append_trace(
        state,
        "governance_allow",
        governance_ok,
        None if governance_ok else "Governance result is not ALLOW.",
    )
    if not governance_ok:
        return _halt(state, "governance_not_allow")

    # 3. procedural truth pass
    procedural_truth_ok = state.get("procedural_truth_result") == PROCEDURAL_TRUTH_PASS
    _append_trace(
        state,
        "procedural_truth_pass",
        procedural_truth_ok,
        None if procedural_truth_ok else "Procedural truth result is not PASS.",
    )
    if not procedural_truth_ok:
        return _halt(state, "procedural_truth_not_pass")

    # 4. corroboration threshold satisfied
    corroboration_ok = bool(state.get("corroboration_met")) and verify_tier_consistency(state)
    _append_trace(
        state,
        "corroboration_threshold_satisfied",
        corroboration_ok,
        None if corroboration_ok else "Corroboration unmet or tier mismatch detected.",
    )
    if not corroboration_ok:
        return _halt(state, "corroboration_or_tier_failure")

    # 5. domain pass
    domain_ok = state.get("domain_result") == DOMAIN_PASS_RESULT
    _append_trace(
        state,
        "domain_pass",
        domain_ok,
        None if domain_ok else "Domain result is not pass.",
    )
    if not domain_ok:
        return _halt(state, "domain_not_pass")

    # 6. aurion pass
    aurion_ok = state.get("aurion15_result") == AURION_PASS_RESULT
    _append_trace(
        state,
        "aurion_pass",
        aurion_ok,
        None if aurion_ok else "Aurion result is not pass.",
    )
    if not aurion_ok:
        return _halt(state, "aurion_not_pass")

    # 7–12. token verification bundle
    required_threshold_tokens = get_required_threshold_tokens(state)
    state = verify_required_tokens(
        state,
        required_threshold_tokens=required_threshold_tokens,
        provider=signature_provider,
        require_effect_authority=True,
        trust_context=signature_trust_context,
        owner_pinned_context_digest=signature_owner_pinned_context_digest,
    )

    required_tokens_present_ok = len(state.get("token_verification_failures", [])) == 0
    _append_trace(
        state,
        "required_tokens_present_and_valid",
        required_tokens_present_ok,
        None if required_tokens_present_ok else f"Token failures: {state.get('token_verification_failures', [])}",
    )
    if not required_tokens_present_ok:
        return _halt(state, "token_stack_failure", decision=EXECUTION_ESCALATED)

    # 13. execution boundary clear
    execution_boundary_ok = verify_execution_boundary_clear(state)
    _append_trace(
        state,
        "execution_boundary_clear",
        execution_boundary_ok,
        None if execution_boundary_ok else "Execution boundary token is not clear.",
    )
    if not execution_boundary_ok:
        return _halt(state, "execution_boundary_failure", decision=EXECUTION_ESCALATED)

    # 14. execution attestation clear
    execution_attestation_ok = verify_execution_attestation_clear(state)
    _append_trace(
        state,
        "execution_attestation_clear",
        execution_attestation_ok,
        None if execution_attestation_ok else "Execution attestation token is not clear.",
    )
    if not execution_attestation_ok:
        return _halt(state, "execution_attestation_failure", decision=EXECUTION_ESCALATED)

    # 15. collective signal consistency
    collective_ok = verify_collective_signal_consistency(state)
    _append_trace(
        state,
        "collective_signal_consistency",
        collective_ok,
        None if collective_ok else "Collective signals are missing, mismatched, or contradictory.",
    )
    if not collective_ok:
        return _halt(state, "collective_signal_failure", decision=EXECUTION_ESCALATED)

    state["execution_result"] = EXECUTION_RESULT_EXECUTE
    state["decision"] = EXECUTION_APPROVED
    state["execution_reason"] = "execution_gate_passed"
    return state
