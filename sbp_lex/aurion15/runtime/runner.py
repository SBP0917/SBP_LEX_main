from typing import Dict, Any

from sbp_lex.aurion15.candidate.candidate_generator import generate_candidates
from sbp_lex.aurion15.candidate.candidate_ranker import rank_candidates
from sbp_lex.aurion15.candidate.runtime_constraint_controller import apply_runtime_constraints
from sbp_lex.aurion15.candidate.candidate_selector import select_candidate
from sbp_lex.aurion15.candidate.candidate_search_controller import candidate_search_required
from sbp_lex.governance.procedural_truth import compute_safety_tier


def run_aurion15(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("aurion15_trace", [])
    state.setdefault("candidate_attempt_count", 0)
    state.setdefault("safety_profile", {
        "human_safety": 0,
        "irreversibility": 0,
        "cascading_impact": 0,
        "financial_operational": 0,
        "computed_tier": None,
    })

    if not state.get("candidate_pathways"):
        state = generate_candidates(state)

    state = apply_runtime_constraints(state)
    state = rank_candidates(state)
    state = select_candidate(state)

    candidate = state.get("current_candidate")

    if not candidate:
        state["aurion15_result"] = "require_next_candidate"
        state["aurion15_trace"].append({
            "result": "require_next_candidate",
            "attempt": state.get("candidate_attempt_count", 0),
            "tier": state.get("safety_profile", {}).get("computed_tier"),
        })
        return state

    tier_recomputed = False

    mode = candidate.get("mode")
    if mode == "fallback":
        state["safety_profile"]["cascading_impact"] = max(
            int(state["safety_profile"].get("cascading_impact", 0)), 2
        )
        tier_recomputed = True

    if mode == "safe":
        state["safety_profile"]["irreversibility"] = max(
            int(state["safety_profile"].get("irreversibility", 0)), 1
        )
        tier_recomputed = True

    if tier_recomputed:
        state = compute_safety_tier(state)

    state["aurion15_trace"].append({
        "candidate": candidate,
        "result": "pass",
        "attempt": state.get("candidate_attempt_count", 0),
        "tier": state.get("safety_profile", {}).get("computed_tier"),
        "tier_recomputed": tier_recomputed,
    })

    state["best_candidate"] = candidate
    state["aurion15_result"] = "pass"

    if candidate_search_required(state):
        state["aurion15_trace"].append({
            "result": "search_exhausted",
            "attempt": state.get("candidate_attempt_count", 0),
            "tier": state.get("safety_profile", {}).get("computed_tier"),
        })

    return state
