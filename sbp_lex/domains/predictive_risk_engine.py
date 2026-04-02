from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class PredictiveRiskEngine(AurionEngine):
    name = "predictive_risk_engine"
    stage = 4
    depends_on = [
        "risk_detection_engine",
        "crisis_recognition_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        risk_score = state.get("risk_score", 0.0)
        crisis_status = state.get("crisis_recognition_status")

        predictive_indicators = payload.get(
            "predictive_risk_indicators",
            current_candidate.get("predictive_risk_indicators", []),
        )

        predictive_score = payload.get(
            "predictive_risk_score",
            current_candidate.get("predictive_risk_score", 0.0),
        )

        try:
            predictive_score = float(predictive_score)
        except (TypeError, ValueError):
            predictive_score = 0.0

        if not isinstance(predictive_indicators, list):
            predictive_indicators = []

        predicted_risk = (
            risk_score >= 0.6
            or crisis_status == "crisis_detected"
            or predictive_score >= 0.65
            or len(predictive_indicators) >= 2
        )

        state["predictive_risk_status"] = "predicted_risk" if predicted_risk else "stable_projection"
        state["predictive_risk_score"] = predictive_score
        state["predictive_risk_indicators"] = predictive_indicators

        if predicted_risk:
            state["candidate_action"] = "refine_candidate"
        else:
            state["candidate_action"] = "pass"

        return state


aurion_registry.register(PredictiveRiskEngine())
