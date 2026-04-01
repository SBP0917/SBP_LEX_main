from .legal_domain import LegalDomain
from .sovereign_domain import SovereignDomain
from .risk_domain import RiskDomain
from .operational_domain import OperationalDomain
from sbp_lex.governance.procedural_truth import compute_safety_tier


DOMAINS = [
    SovereignDomain(),
    LegalDomain(),
    RiskDomain(),
    OperationalDomain(),
]


def run_domain_wrap(state):
    state["tier_recomputed"] = False

    for domain in DOMAINS:
        result = domain.execute(state)

        if state.get("tier_recomputed"):
            state = compute_safety_tier(state)

        if result != "pass":
            state["domain_result"] = result
            return state

    state["domain_result"] = "pass"
    return state
