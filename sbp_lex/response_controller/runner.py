from typing import Dict, Any

from sbp_lex.shared.state_builder import build_state
from sbp_lex.classification.engine import ClassificationEngine
from sbp_lex.licensing.engine import LicensingEngine
from sbp_lex.response_controller.controller import stop


classification_engine = ClassificationEngine()
licensing_engine = LicensingEngine()


def run_pipeline(input_data: Dict[str, Any]) -> Dict[str, Any]:
    state = build_state(input_data)

    state = classification_engine.execute(state)
    if state.get("classification_result") != "ALLOW":
        return stop(state)

    state = licensing_engine.execute(state)
    if state.get("licensing_result") != "ALLOW":
        return stop(state)

    return state
