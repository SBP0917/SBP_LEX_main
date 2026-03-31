from typing import Dict, Any
from sbp_lex.aurion15.candidate.candidate_selector import select_candidate


def run_aurion15(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("aurion15_trace", [])

    state = select_candidate(state)

    candidate = state.get("current_candidate")

    if not candidate:
        state["aurion15_result"] = "no_candidate"
        return state

    # simulate pathway success
    state["aurion15_trace"].append({
        "candidate": candidate,
        "result": "pass",
        "attempt": state.get("candidate_attempt_count", 0)
    })

    state["aurion15_result"] = "pass"
    return state
