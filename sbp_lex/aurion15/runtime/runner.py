from __future__ import annotations

from typing import Dict, Any, List, Optional


# ─────────────────────────────────────────────
# SBP-LEX V6 — AURION RUNTIME (LOCKED)
# ─────────────────────────────────────────────

AURION_PASS = "pass"
AURION_FAIL = "fail"
AURION_ESCALATE = "escalate"
AURION_REQUIRE_NEXT = "require_next_candidate"


# ─────────────────────────────────────────────
# ENTRY
# ─────────────────────────────────────────────

def run_aurion15(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic pathway resolution loop (single step).
    """

    state.setdefault("aurion_trace", [])
    state.setdefault("candidate_queue", [])
    state.setdefault("candidate_attempt_count", 0)

    # ensure candidates exist
    if not state["candidate_queue"]:
        state["candidate_queue"] = _generate_candidates(state)

    candidate = _get_next_candidate(state)

    if not candidate:
        return _fail(state, "no_candidates_available")

    state["current_candidate"] = candidate
    state["candidate_attempt_count"] += 1

    evaluation = _evaluate_candidate(state, candidate)

    state["aurion_trace"].append(
        {
            "candidate": candidate,
            "evaluation": evaluation,
        }
    )

    # decision mapping
    if evaluation["result"] == "pass":
        state["aurion15_result"] = AURION_PASS
        return state

    if evaluation["result"] == "escalate":
        state["aurion15_result"] = AURION_ESCALATE
        state["aurion_reason"] = evaluation["reason"]
        return state

    if _has_remaining_candidates(state):
        state["aurion15_result"] = AURION_REQUIRE_NEXT
        return state

    return _fail(state, evaluation["reason"])


# ─────────────────────────────────────────────
# CANDIDATE GENERATION
# ─────────────────────────────────────────────

def _generate_candidates(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Deterministic candidate generation.
    """

    base_action = state.get("action")
    payload = state.get("payload", {})

    candidates = [
        {"type": "direct", "action": base_action, "payload": payload},
        {"type": "restricted", "action": base_action, "payload": payload},
        {"type": "minimal", "action": base_action, "payload": {}},
    ]

    return candidates


def _get_next_candidate(state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not state["candidate_queue"]:
        return None
    return state["candidate_queue"].pop(0)


def _has_remaining_candidates(state: Dict[str, Any]) -> bool:
    return len(state.get("candidate_queue", [])) > 0


# ─────────────────────────────────────────────
# CANDIDATE EVALUATION
# ─────────────────────────────────────────────

def _evaluate_candidate(state: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic evaluation based on:
    - domain result
    - governance
    - risk signals
    """

    # governance must already be allow
    if state.get("governance_result") != "ALLOW":
        return {"result": "fail", "reason": "governance_not_allow"}

    # domain must be pass
    if state.get("domain_result") != "pass":
        return {"result": "fail", "reason": "domain_not_pass"}

    # risk check
    signals = state.get("collective_signals", {})
    risk = signals.get("risk_potential_signal", 1.0)

    try:
        risk_value = float(risk)
    except Exception:
        return {"result": "fail", "reason": "invalid_risk_signal"}

    if risk_value >= 0.95:
        return {"result": "escalate", "reason": "extreme_risk_detected"}

    # candidate type filtering
    ctype = candidate.get("type")

    if ctype == "direct" and risk_value < 0.7:
        return {"result": "pass", "reason": "direct_path_valid"}

    if ctype == "restricted" and risk_value < 0.85:
        return {"result": "pass", "reason": "restricted_path_valid"}

    if ctype == "minimal":
        return {"result": "pass", "reason": "minimal_safe_path"}

    return {"result": "fail", "reason": "candidate_not_admissible"}


# ─────────────────────────────────────────────
# FAIL HANDLER
# ─────────────────────────────────────────────

def _fail(state: Dict[str, Any], reason: str) -> Dict[str, Any]:
    state["aurion15_result"] = AURION_FAIL
    state["aurion_reason"] = reason
    return state
