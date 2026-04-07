from __future__ import annotations

from typing import Dict, Any, List

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


# ─────────────────────────────────────────────
# HASH-CHAIN VERIFICATION
# ─────────────────────────────────────────────

def verify_hash_chain(state: Dict[str, Any]) -> bool:
    chain = state.get("hash_chain", [])
    if not chain:
        return False

    previous_hash = "GENESIS"

    for entry in chain:
        if entry.get("previous_hash") != previous_hash:
            return False

        if not entry.get("stage"):
            return False

        if not entry.get("payload_hash"):
            return False

        if not entry.get("hash"):
            return False

        previous_hash = entry["hash"]

    if state.get("state_hash") != chain[-1].get("hash"):
        return False

    return True


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
    payload = token.get("payload", {})
    token_payload = payload.get("payload", {})
    return token_payload.get("boundary_clear") is True


def verify_execution_attestation_clear(state: Dict[str, Any]) -> bool:
    token = state.get("tokens", {}).get("execution_attestation", {})
    payload = token.get("payload", {})
    token_payload = payload.get("payload", {})
    return token_payload.get("attested_for_execution") is True


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


# ─────────────────────────────────────────────
# EXECUTION GATE
# ─────────────────────────────────────────────

def run_execution_gate(state: Dict[str, Any]) -> Dict[str, Any]:
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
    state = verify_required_tokens(state, required_threshold_tokens=required_threshold_tokens)

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
