from typing import Dict, Any


def generate_candidates(state: Dict[str, Any]) -> Dict[str, Any]:
    action = state.get("action")
    payload = state.get("payload") or {}

    if not action:
        state["candidate_pathways"] = []
        return state

    candidates = [
        {"name": f"{action}_primary", "payload": payload, "mode": "primary"},
        {"name": f"{action}_fallback", "payload": payload, "mode": "fallback"},
        {"name": f"{action}_safe", "payload": payload, "mode": "safe"},
    ]

    state["candidate_pathways"] = candidates
    return state
