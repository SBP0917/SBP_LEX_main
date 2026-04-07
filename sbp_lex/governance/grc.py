from __future__ import annotations

from typing import Dict, Any


# ─────────────────────────────────────────────
# LOCKED DENIAL CODES
# ─────────────────────────────────────────────

DENIAL_CODES = [
    "AUTHORITY_FIRST_FAILURE",
    "PROCEDURAL_TRUTH_FAILURE",
    "PROCEDURAL_TRUTH_ESCALATION",
    "CLASSIFICATION_DENIAL",
    "CLASSIFICATION_ESCALATION",
    "LICENSING_DENIAL",
    "LICENSING_ESCALATION",
    "GOVERNANCE_DENIAL",
    "GOVERNANCE_ESCALATION",
    "DOMAIN_DENIAL",
    "DOMAIN_ESCALATION",
    "AURION_RESOLUTION_FAILURE",
    "AURION_ESCALATION",
    "EXECUTION_GATE_FAILURE",
    "IDENTICAL_DENIED_RESUBMISSION",
    "SYSTEM_EXCEPTION",
]


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _build_feedback(
    *,
    state: Dict[str, Any],
    status: str,
    denial_code: str,
    denial_reason: str,
    repeat_same_request_allowed: bool,
    retry_eligible: bool,
    required_change_for_retry: str,
    escalation_allowed: bool,
    fallback_action_allowed: bool,
    safe_state_required: bool,
) -> Dict[str, Any]:
    feedback = {
        "status": status,
        "denial_code": denial_code,
        "denial_reason": denial_reason,
        "repeat_same_request_allowed": repeat_same_request_allowed,
        "retry_eligible": retry_eligible,
        "required_change_for_retry": required_change_for_retry,
        "escalation_allowed": escalation_allowed,
        "fallback_action_allowed": fallback_action_allowed,
        "safe_state_required": safe_state_required,
        "request_fingerprint": state.get("request_fingerprint"),
    }
    state["governance_feedback"] = feedback
    return state


# ─────────────────────────────────────────────
# OUTPUT BUILDERS
# ─────────────────────────────────────────────

def build_allow_feedback(state: Dict[str, Any]) -> Dict[str, Any]:
    return _build_feedback(
        state=state,
        status="ALLOW",
        denial_code="",
        denial_reason="",
        repeat_same_request_allowed=False,
        retry_eligible=False,
        required_change_for_retry="",
        escalation_allowed=False,
        fallback_action_allowed=False,
        safe_state_required=False,
    )


def build_deny_feedback(
    state: Dict[str, Any],
    *,
    denial_code: str,
    denial_reason: str,
    retry_eligible: bool,
    required_change_for_retry: str,
    escalation_allowed: bool,
    fallback_action_allowed: bool,
    safe_state_required: bool,
) -> Dict[str, Any]:
    state["last_denied_fingerprint"] = state.get("request_fingerprint")

    return _build_feedback(
        state=state,
        status="DENY",
        denial_code=denial_code,
        denial_reason=denial_reason,
        repeat_same_request_allowed=False,
        retry_eligible=retry_eligible,
        required_change_for_retry=required_change_for_retry,
        escalation_allowed=escalation_allowed,
        fallback_action_allowed=fallback_action_allowed,
        safe_state_required=safe_state_required,
    )


def build_escalate_feedback(
    state: Dict[str, Any],
    *,
    denial_code: str,
    denial_reason: str,
    safe_state_required: bool,
) -> Dict[str, Any]:
    return _build_feedback(
        state=state,
        status="ESCALATE",
        denial_code=denial_code,
        denial_reason=denial_reason,
        repeat_same_request_allowed=False,
        retry_eligible=False,
        required_change_for_retry="Escalation pathway required.",
        escalation_allowed=True,
        fallback_action_allowed=True,
        safe_state_required=safe_state_required,
    )


# ─────────────────────────────────────────────
# NON-REPEAT CONTROL
# ─────────────────────────────────────────────

def identical_denied_resubmission(state: Dict[str, Any]) -> bool:
    return (
        state.get("request_fingerprint") is not None
        and state.get("last_denied_fingerprint") is not None
        and state.get("request_fingerprint") == state.get("last_denied_fingerprint")
    )


def enforce_non_repeat_rule(state: Dict[str, Any]) -> Dict[str, Any]:
    if identical_denied_resubmission(state):
        return build_deny_feedback(
            state,
            denial_code="IDENTICAL_DENIED_RESUBMISSION",
            denial_reason="Identical denied request must not be reprocessed.",
            retry_eligible=False,
            required_change_for_retry="Submit a materially changed request, fallback request, or escalation request.",
            escalation_allowed=True,
            fallback_action_allowed=True,
            safe_state_required=False,
        )
    return state


# ─────────────────────────────────────────────
# GOVERNED RESPONSE CONTROLLER
# ─────────────────────────────────────────────

def apply_grc(state: Dict[str, Any]) -> Dict[str, Any]:
    governance_result = state.get("governance_result")
    governance_reason = state.get("governance_reason", "")

    if governance_result == "ALLOW":
        return build_allow_feedback(state)

    if governance_result == "ESCALATE":
        return build_escalate_feedback(
            state,
            denial_code="GOVERNANCE_ESCALATION",
            denial_reason=governance_reason or "Governance escalation required.",
            safe_state_required=True,
        )

    return build_deny_feedback(
        state,
        denial_code="GOVERNANCE_DENIAL",
        denial_reason=governance_reason or "Governance denied.",
        retry_eligible=True,
        required_change_for_retry="Change authority, legality, scope, or invoke escalation.",
        escalation_allowed=True,
        fallback_action_allowed=True,
        safe_state_required=True,
)
