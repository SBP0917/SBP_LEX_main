from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class SocietalStabilityEngine(AurionEngine):
    name = "societal_stability_engine"
    stage = 5
    depends_on = [
        "economic_signal_engine",
        "institutional_integrity_engine",
        "strategic_conflict_detection_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        economic_signal_status = state.get("economic_signal_status")
        institutional_integrity_status = state.get("institutional_integrity_status")
        strategic_conflict_status = state.get("strategic_conflict_detection_status")

        societal_stability_score = payload.get(
            "societal_stability_score",
            current_candidate.get("societal_stability_score", 0.0),
        )

        societal_disruption_flags = payload.get(
            "societal_disruption_flags",
            current_candidate.get("societal_disruption_flags", []),
        )

        try:
            societal_stability_score = float(societal_stability_score)
        except (TypeError, ValueError):
            societal_stability_score = 0.0

        if not isinstance(societal_disruption_flags, list):
            societal_disruption_flags = []

        stable = (
            economic_signal_status == "stable"
            and institutional_integrity_status == "sound"
            and strategic_conflict_status != "conflict_detected"
            and societal_stability_score >= 0.7
            and len(societal_disruption_flags) == 0
        )

        state["societal_stability_status"] = "stable" if stable else "unstable"
        state["societal_stability_score"] = societal_stability_score
        state["societal_disruption_flags"] = societal_disruption_flags

        if stable:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(SocietalStabilityEngine())
