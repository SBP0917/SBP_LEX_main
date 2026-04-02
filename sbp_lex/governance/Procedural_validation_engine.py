from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class ProceduralValidationEngine(AurionEngine):
    name = "procedural_validation_engine"
    stage = 1
    depends_on = []

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        procedural_truth_status = (
            state.get("procedural_truth_status")
            or state.get("truth_state")
            or state.get("governance_reason")
        )

        state["aurion15_procedural_truth_status"] = procedural_truth_status

        if procedural_truth_status in {"invalid", "failed", "procedural_failure"}:
            state["status"] = "require_next_candidate"
            state["candidate_result"] = "deny"
            return state

        state["status"] = "pass"
        return state


aurion_registry.register(ProceduralValidationEngine())
