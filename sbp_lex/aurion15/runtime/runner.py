from typing import Dict, Any

from sbp_lex.aurion15.candidate.candidate_generator import generate_candidates
from sbp_lex.aurion15.candidate.candidate_ranker import rank_candidates
from sbp_lex.aurion15.candidate.runtime_constraint_controller import apply_runtime_constraints
from sbp_lex.aurion15.candidate.candidate_selector import select_candidate
from sbp_lex.aurion15.candidate.candidate_search_controller import candidate_search_required


def run_aurion15(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("aurion15_trace", [])
    state.setdefault("candidate_attempt_count", 0)

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
        })
        return state

    state["aurion15_trace"].append({
        "candidate": candidate,
        "result": "pass",
        "attempt": state.get("candidate_attempt_count", 0)
    })

    state["best_candidate"] = candidate
    state["aurion15_result"] = "pass"

    if candidate_search_required(state):
        state["aurion15_trace"].append({
            "result": "search_exhausted",
            "attempt": state.get("candidate_attempt_count", 0),
        })

    return state
