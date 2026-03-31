from typing import Dict, Any, List


def rank_candidates(state: Dict[str, Any]) -> Dict[str, Any]:
    candidates = state.get("candidate_pathways", [])

    def score(candidate: Dict[str, Any]) -> int:
        mode = candidate.get("mode")
        if mode == "primary":
            return 0
        if mode == "fallback":
            return 1
        if mode == "safe":
            return 2
        return 99

    state["candidate_pathways"] = sorted(candidates, key=score)
    return state
