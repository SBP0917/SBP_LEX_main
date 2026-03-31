from typing import Dict, Any


def apply_runtime_constraints(state: Dict[str, Any]) -> Dict[str, Any]:
    candidates = state.get("candidate_pathways", [])
    risk = state.get("risk_score")

    if risk is None:
        return state

    filtered = []
    for candidate in candidates:
        mode = candidate.get("mode")
        if float(risk) > 0.85 and mode == "primary":
            continue
        filtered.append(candidate)

    state["candidate_pathways"] = filtered
    return state
