from typing import Dict, Any


TIER_THRESHOLDS = {
    "LOW": 2,
    "MEDIUM": 3,
    "TOP": 5,
}


def compute_financial_factor(state: Dict[str, Any]) -> int:
    amount = float(state.get("financial_amount", 0))
    thresholds = state.get("financial_thresholds", {})

    low_max = thresholds.get("low_max", 499.99)
    medium_max = thresholds.get("medium_max", 49999.99)

    if amount <= low_max:
        return 1
    elif amount <= medium_max:
        return 2
    return 3


def compute_safety_tier(state: Dict[str, Any]) -> Dict[str, Any]:
    sp = state.get("safety_profile", {})

    hs = int(sp.get("human_safety", 0))
    ir = int(sp.get("irreversibility", 0))
    ci = int(sp.get("cascading_impact", 0))

    fo = compute_financial_factor(state)

    tier_value = max(hs, ir, ci, fo)

    if tier_value == 3:
        tier = "TOP"
    elif tier_value == 2:
        tier = "MEDIUM"
    else:
        tier = "LOW"

    sp["financial_operational"] = fo
    sp["computed_tier"] = tier

    state["safety_profile"] = sp
    state["corroboration_required"] = TIER_THRESHOLDS[tier]

    return state


def evaluate_procedural_truth(state: Dict[str, Any]) -> Dict[str, Any]:
    state = compute_safety_tier(state)

    required = state.get("corroboration_required", 2)

    sources = state.get("sources", [])

    verified = [
        s for s in sources
        if s.get("verified")
        and s.get("attested")
        and s.get("fresh")
        and s.get("consistent")
    ]

    count = len(verified)

    state["corroborated_sources"] = count
    state["corroboration_met"] = count >= required

    tier = state["safety_profile"]["computed_tier"]

    if count < required:
        if tier == "TOP":
            state["procedural_truth_result"] = "ESCALATE"
        elif tier == "MEDIUM":
            state["procedural_truth_result"] = "REFINE"
        else:
            state["procedural_truth_result"] = "REFINE"
    else:
        state["procedural_truth_result"] = "PASS"

    return state
