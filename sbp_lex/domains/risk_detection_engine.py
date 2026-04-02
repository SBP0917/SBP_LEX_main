from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class RiskDetectionEngine(AurionEngine):
    name = "risk_detection_engine"
    stage = 4
    depends_on = [
        "execution_gate_engine",
        "autonomy_boundary_engine",
        "escalation_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        risk_score = state.get(
            "risk_score",
            payload.get("risk_score", current_candidate.get("risk_score", 0.0)),
        )

        boundary_status = state.get("boundary_status")
        escalation_required = state.get("escalation_required", False)
        candidate_result = state.get("candidate_result")

        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError):
            risk_score = 0.0

        if risk_score >= 0.85:
            risk_level = "critical"
        elif risk_score >= 0.65:
            risk_level = "high"
        elif risk_score >= 0.35:
            risk_level = "medium"
        else:
            risk_level = "low"

        risk_detected = (
            candidate_result in ["allow", "allow_reduced", "allow_fallback"]
            and boundary_status not in ["violation", "breach", "blocked"]
            and escalation_required is False
        )

        state["risk_detection_status"] = "detected" if risk_detected else "blocked"
        state["risk_score"] = risk_score
        state["risk_level"] = risk_level

        if risk_detected:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "require_next_candidate"

        return state


aurion_registry.register(RiskDetectionEngine())
