from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class AuthorityResolutionEngine(AurionEngine):
    name = "authority_resolution_engine"
    stage = 1
    depends_on = ["jurisdiction_determination_engine"]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        resolved_authority = state.get("resolved_authority") or state.get("authority")
        jurisdiction = state.get("aurion15_jurisdiction") or state.get("jurisdiction")

        if not resolved_authority and not jurisdiction:
            state["status"] = "escalate"
            state["aurion_reason"] = "missing_authority_context"
            return state

        state["aurion15_resolved_authority"] = resolved_authority or jurisdiction
        state["status"] = "pass"
        return state


aurion_registry.register(AuthorityResolutionEngine())
