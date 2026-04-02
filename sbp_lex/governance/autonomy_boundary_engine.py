from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class AutonomyBoundaryEngine(AurionEngine):
    name = "autonomy_boundary_engine"
    stage = 1
    depends_on = []

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        boundary_status = state.get("boundary_status")

        state["aurion15_boundary_status"] = boundary_status

        if boundary_status in {"breached", "invalid", "blocked"}:
            state["status"] = "redefine_candidate"
            return state

        state["status"] = "pass"
        return state


aurion_registry.register(AutonomyBoundaryEngine())
