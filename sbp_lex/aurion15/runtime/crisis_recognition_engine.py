"""Crisis recognition engine imported from SBP0917/SBP."""

from typing import Any, Dict

from .base_engine import AurionEngine
from .registry import aurion_registry


class CrisisRecognitionEngine(AurionEngine):
    name = "crisis_recognition_engine"
    stage = 4
    depends_on = ["risk_detection_engine"]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}
        risk_level = state.get("risk_level")

        crisis_indicators = payload.get(
            "crisis_indicators",
            current_candidate.get("crisis_indicators", []),
        )
        crisis_score = payload.get(
            "crisis_score",
            current_candidate.get("crisis_score", 0.0),
        )

        if not isinstance(crisis_indicators, list):
            crisis_indicators = []

        try:
            crisis_score = float(crisis_score)
        except (TypeError, ValueError):
            crisis_score = 0.0

        crisis_detected = (
            risk_level in ["high", "critical"]
            or crisis_score >= 0.7
            or len(crisis_indicators) >= 2
        )

        state["crisis_recognition_status"] = (
            "crisis_detected" if crisis_detected else "stable"
        )
        state["crisis_score"] = crisis_score
        state["crisis_indicators"] = crisis_indicators
        state["candidate_action"] = "refine_candidate" if crisis_detected else "pass"
        return state


aurion_registry.register(CrisisRecognitionEngine())
