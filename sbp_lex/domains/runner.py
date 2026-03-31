from .legal_domain import LegalDomain
from .sovereign_domain import SovereignDomain
from .risk_domain import RiskDomain
from .operational_domain import OperationalDomain


DOMAINS = [
    SovereignDomain(),
    LegalDomain(),
    RiskDomain(),
    OperationalDomain(),
]


def run_domain_wrap(state):
    for domain in DOMAINS:
        result = domain.execute(state)

        if result != "pass":
            state["domain_result"] = result
            return state

    state["domain_result"] = "pass"
    return state
