from typing import Any, Dict

from sbp_lex.licensing.filed_licensing import (
    LICENCE_ALLOW,
    LICENCE_VALIDATION_STAGE,
    FiledLicenceEvaluator,
    evaluate_filed_licence,
    invalidate_filed_licence,
)
from sbp_lex.security.signature_provider import (
    HybridVerificationContext,
    SignatureProvider,
)


def run_licensing(
    state: Dict[str, Any],
    *,
    evaluator: FiledLicenceEvaluator | None = None,
    attestation_provider: SignatureProvider | None = None,
    attestation_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> Dict[str, Any]:
    state.setdefault("licensing_trace", [])

    state = evaluate_filed_licence(
        state,
        stage=LICENCE_VALIDATION_STAGE,
        evaluator=evaluator,
        attestation_provider=attestation_provider,
        trust_context=attestation_trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if state.get("filed_licence_result") != LICENCE_ALLOW:
        state["licensing_result"] = state.get(
            "filed_licence_result", "DENY"
        )
        state["licensing_reason"] = state.get(
            "filed_licence_reason", "filed_licence_validation_failed"
        )
        return state

    license_profile = state.get("license_profile")
    ap_acf_class = state.get("ap_acf_class")
    requested_autonomy_level = state.get("requested_autonomy_level")

    state["licensing_trace"].append({
        "layer": "licensing",
        "status": "START"
    })

    if not license_profile:
        return invalidate_filed_licence(
            state,
            stage="licensing",
            reason="license_profile_missing",
        )

    allowed_classes = license_profile.get("allowed_classes", [])
    max_autonomy = license_profile.get("max_autonomy_level")

    if allowed_classes and ap_acf_class not in allowed_classes:
        return invalidate_filed_licence(
            state,
            stage="licensing",
            reason="class_not_permitted",
        )

    if max_autonomy is not None and requested_autonomy_level is not None:
        if float(requested_autonomy_level) > float(max_autonomy):
            return invalidate_filed_licence(
                state,
                stage="licensing",
                reason="autonomy_exceeds_license",
            )

    state["licensing_result"] = "ALLOW"
    state["licensing_reason"] = "license_valid"

    state["licensing_trace"].append({
        "layer": "licensing",
        "result": "ALLOW",
        "reason": "license_valid"
    })

    return state
