from typing import Dict, Any

from sbp_lex.shared.state_builder import build_state
from sbp_lex.classification.engine import ClassificationEngine
from sbp_lex.licensing.engine import LicensingEngine
from sbp_lex.governance.engine import GovernanceEngine
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.response_controller.controller import stop


classification_engine = ClassificationEngine()
licensing_engine = LicensingEngine()
governance_engine = GovernanceEngine()


def run_pipeline(input_data: Dict[str, Any]) -> Dict[str, Any]:
    state = build_state(input_data)

    state = classification_engine.execute(state)
    if state.get("classification_result") != "ALLOW":
        return stop(state)

    state = licensing_engine.execute(state)
    if state.get("licensing_result") != "ALLOW":
        return stop(state)

    state = governance_engine.execute(state)
    if state.get("governance_result") != "ALLOW":
        return stop(state)

    state = run_domain_wrap(state)
    if state.get("domain_result") != "pass":
        return stop(state)

    return state
