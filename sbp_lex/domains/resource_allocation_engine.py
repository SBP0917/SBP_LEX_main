from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class ResourceAllocationEngine(AurionEngine):
    name = "resource_allocation_engine"
    stage = 6
    depends_on = [
        "economic_signal_engine",
        "societal_stability_engine",
        "ecological_constraint_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        economic_status = state.get("economic_signal_status")
        societal_status = state.get("societal_stability_status")
        ecological_status = state.get("ecological_constraint_status")

        resource_availability_score = payload.get(
            "resource_availability_score",
            current_candidate.get("resource_availability_score", 0.0),
        )

        resource_constraints = payload.get(
            "resource_constraints",
            current_candidate.get("resource_constraints", []),
        )

        try:
            resource_availability_score = float(resource_availability_score)
        except (TypeError, ValueError):
            resource_availability_score = 0.0

        if not isinstance(resource_constraints, list):
            resource_constraints = []

        resources_available = (
            economic_status == "stable"
            and societal_status == "stable"
            and ecological_status == "within_limits"
            and resource_availability_score >= 0.7
            and len(resource_constraints) == 0
        )

        state["resource_allocation_status"] = (
            "available" if resources_available else "constrained"
        )

        state["resource_availability_score"] = resource_availability_score
        state["resource_constraints"] = resource_constraints

        if resources_available:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(ResourceAllocationEngine())
