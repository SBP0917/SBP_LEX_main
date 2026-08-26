from __future__ import annotations

from types import MappingProxyType
from typing import Any, Dict, TypedDict, cast


class _FinancialThresholds(TypedDict):
    low_max: float
    medium_max: float
    currency: str


class _FailClosedDefaults(TypedDict):
    missing_safety_value: int
    missing_financial_amount: float
    unknown_tier: str
    unknown_corroboration_required: int


# ─────────────────────────────────────────────
# LOCKED V2 THRESHOLDS
# ─────────────────────────────────────────────

LOW_TIER = "LOW"
MEDIUM_TIER = "MEDIUM"
TOP_TIER = "TOP"

TIER_ORDER = MappingProxyType({
    LOW_TIER: 1,
    MEDIUM_TIER: 2,
    TOP_TIER: 3,
})

CORROBORATION_THRESHOLDS = MappingProxyType({
    LOW_TIER: 2,
    MEDIUM_TIER: 3,
    TOP_TIER: 5,
})

FINANCIAL_THRESHOLDS = cast(_FinancialThresholds, MappingProxyType({
    "low_max": 499.99,
    "medium_max": 49999.99,
    "currency": "AUD",
}))

FAIL_CLOSED_DEFAULTS = cast(_FailClosedDefaults, MappingProxyType({
    "missing_safety_value": 0,
    "missing_financial_amount": 0.0,
    "unknown_tier": TOP_TIER,
    "unknown_corroboration_required": 5,
}))


# ─────────────────────────────────────────────
# FACTOR HELPERS
# ─────────────────────────────────────────────

def clamp_factor(value: Any) -> int:
    """
    Clamp safety/consequence factors to the locked 0–3 range.
    Fail-closed behaviour:
    - invalid / missing -> 0
    - below 0 -> 0
    - above 3 -> 3
    """
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        return FAIL_CLOSED_DEFAULTS["missing_safety_value"]

    if ivalue < 0:
        return 0
    if ivalue > 3:
        return 3
    return ivalue


def compute_financial_operational_factor(amount: Any) -> int:
    """
    Map financial amount to the locked V2 financial/operational factor.
    """
    try:
        amount_value = float(amount)
    except (TypeError, ValueError):
        amount_value = FAIL_CLOSED_DEFAULTS["missing_financial_amount"]

    if amount_value <= FINANCIAL_THRESHOLDS["low_max"]:
        return 1
    if amount_value <= FINANCIAL_THRESHOLDS["medium_max"]:
        return 2
    return 3


# ─────────────────────────────────────────────
# TIER LOGIC
# ─────────────────────────────────────────────

def compute_tier_from_factors(
    human_safety: Any,
    irreversibility: Any,
    cascading_impact: Any,
    financial_operational: Any,
) -> str:
    """
    Locked rule:
    tier = max(HS, IR, CI, FO)
    """
    hs = clamp_factor(human_safety)
    ir = clamp_factor(irreversibility)
    ci = clamp_factor(cascading_impact)
    fo = clamp_factor(financial_operational)

    tier_value = max(hs, ir, ci, fo)

    if tier_value >= 3:
        return TOP_TIER
    if tier_value == 2:
        return MEDIUM_TIER
    return LOW_TIER


def get_corroboration_required(tier: str) -> int:
    """
    Return locked corroboration threshold for a tier.
    Fail-closed:
    unknown tier -> TOP requirement
    """
    return CORROBORATION_THRESHOLDS.get(
        tier,
        FAIL_CLOSED_DEFAULTS["unknown_corroboration_required"],
    )


def escalate_tier(current_tier: str, candidate_tier: str) -> str:
    """
    No silent downgrade rule:
    return the higher of the two tiers.
    """
    current_rank = TIER_ORDER.get(current_tier, TIER_ORDER[TOP_TIER])
    candidate_rank = TIER_ORDER.get(candidate_tier, TIER_ORDER[TOP_TIER])

    if candidate_rank > current_rank:
        return candidate_tier
    return current_tier


# ─────────────────────────────────────────────
# STATE HELPERS
# ─────────────────────────────────────────────

def ensure_safety_profile(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure the locked safety_profile exists.
    """
    state.setdefault(
        "safety_profile",
        {
            "human_safety": 0,
            "irreversibility": 0,
            "cascading_impact": 0,
            "financial_operational": 0,
            "computed_tier": None,
        },
    )
    return state


def apply_financial_factor(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute and apply financial_operational factor from financial_amount.
    """
    state = ensure_safety_profile(state)
    amount = state.get("financial_amount", FAIL_CLOSED_DEFAULTS["missing_financial_amount"])
    state["safety_profile"]["financial_operational"] = compute_financial_operational_factor(amount)
    return state


def apply_consequentiality_tier(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compute the locked consequentiality tier and corroboration threshold.
    Enforces no silent downgrade.
    """
    state = ensure_safety_profile(state)

    safety_profile = state["safety_profile"]

    candidate_tier = compute_tier_from_factors(
        human_safety=safety_profile.get("human_safety"),
        irreversibility=safety_profile.get("irreversibility"),
        cascading_impact=safety_profile.get("cascading_impact"),
        financial_operational=safety_profile.get("financial_operational"),
    )

    current_tier = safety_profile.get("computed_tier")
    if current_tier:
        locked_tier = escalate_tier(current_tier, candidate_tier)
    else:
        locked_tier = candidate_tier

    safety_profile["computed_tier"] = locked_tier
    state["corroboration_required"] = get_corroboration_required(locked_tier)

    return state


def build_threshold_snapshot(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Small snapshot for audit / trace / hashing.
    """
    state = ensure_safety_profile(state)

    return {
        "tier": state["safety_profile"].get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "financial_thresholds": dict(FINANCIAL_THRESHOLDS),
        "corroboration_thresholds": dict(CORROBORATION_THRESHOLDS),
  }
