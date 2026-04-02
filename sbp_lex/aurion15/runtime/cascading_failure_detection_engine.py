from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class CascadingFailureDetectionEngine(AurionEngine):
    name = "cascading_failure_detection_engine"
    stage = 4
    depends_on = [
        "predictive_risk_engine",
        "crisis_recognition_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        predictive_risk_status = state.get("predictive_risk_status")
        crisis_status = state.get("crisis_recognition_status")

        cascade_indicators = payload.get(
            "cascade_indicators",
            current_candidate.get("cascade_indicators", []),
        )

        cascade_score = payload.get(
            "cascade_score",
            current_candidate.get("cascade_score", 0.0),
        )

        try:
            cascade_score = float(cascade_score)
        except (TypeError, ValueError):
            cascade_score = 0.0

        if not isinstance(cascade_indicators, list):
            cascade_indicators = []

        cascade_detected = (
            predictive_risk_status == "predicted_risk"
            or crisis_status == "crisis_detected"
            or cascade_score >= 0.7
            or len(cascade_indicators) >= 2
        )

        state["cascading_failure_status"] = (
            "cascade_detected" if cascade_detected else "stable_system"
        )

        state["cascade_score"] = cascade_score
        state["cascade_indicators"] = cascade_indicators

        if cascade_detected:
            state["candidate_action"] = "refine_candidate"
        else:
            state["candidate_action"] = "pass"

        return state


aurion_registry.register(CascadingFailureDetectionEngine())
