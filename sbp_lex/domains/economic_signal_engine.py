from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class EconomicSignalEngine(AurionEngine):
    name = "economic_signal_engine"
    stage = 5
    depends_on = [
        "risk_detection_engine",
        "resource_allocation_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        economic_signal_score = payload.get(
            "economic_signal_score",
            current_candidate.get("economic_signal_score", 0.0),
        )

        economic_indicators = payload.get(
            "economic_indicators",
            current_candidate.get("economic_indicators", []),
        )

        risk_level = state.get("risk_level")

        try:
            economic_signal_score = float(economic_signal_score)
        except (TypeError, ValueError):
            economic_signal_score = 0.0

        if not isinstance(economic_indicators, list):
            economic_indicators = []

        stable_signal = (
            risk_level not in ["critical"]
            and economic_signal_score >= 0.6
            and len(economic_indicators) <= 3
        )

        state["economic_signal_status"] = "stable" if stable_signal else "volatile"
        state["economic_signal_score"] = economic_signal_score
        state["economic_indicators"] = economic_indicators

        if stable_signal:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(EconomicSignalEngine())
