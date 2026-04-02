from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class DemographicMonitoringEngine(AurionEngine):
    name = "demographic_monitoring_engine"
    stage = 5
    depends_on = [
        "societal_stability_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        societal_stability_status = state.get("societal_stability_status")

        demographic_stability_score = payload.get(
            "demographic_stability_score",
            current_candidate.get("demographic_stability_score", 0.0),
        )

        demographic_shift_flags = payload.get(
            "demographic_shift_flags",
            current_candidate.get("demographic_shift_flags", []),
        )

        try:
            demographic_stability_score = float(demographic_stability_score)
        except (TypeError, ValueError):
            demographic_stability_score = 0.0

        if not isinstance(demographic_shift_flags, list):
            demographic_shift_flags = []

        stable = (
            societal_stability_status == "stable"
            and demographic_stability_score >= 0.7
            and len(demographic_shift_flags) == 0
        )

        state["demographic_monitoring_status"] = "stable" if stable else "shift_detected"
        state["demographic_stability_score"] = demographic_stability_score
        state["demographic_shift_flags"] = demographic_shift_flags

        if stable:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(DemographicMonitoringEngine())
