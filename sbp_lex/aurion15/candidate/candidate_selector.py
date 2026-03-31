from typing import Dict, Any


def select_candidate(state: Dict[str, Any]) -> Dict[str, Any]:
    candidates = state.get("candidate_pathways", [])

    if not candidates:
        state["current_candidate"] = None
        return state

    idx = state.get("candidate_attempt_count", 0)

    if idx >= len(candidates):
        state["current_candidate"] = None
        return state

    state["current_candidate"] = candidates[idx]
    return state
