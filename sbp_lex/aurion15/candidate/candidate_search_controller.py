from typing import Dict, Any


def candidate_search_required(state: Dict[str, Any]) -> bool:
    candidates = state.get("candidate_pathways", [])
    attempt = int(state.get("candidate_attempt_count", 0))
    return attempt >= len(candidates)
