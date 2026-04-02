from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class GovernanceRoutingEngine(AurionEngine):
    name = "governance_routing_engine"
    stage = 3
    depends_on = [
        "jurisdiction_engine",
        "authority_resolution_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        jurisdiction = (
            state.get("aurion15_jurisdiction")
            or state.get("jurisdiction")
        )

        resolved_authority = (
            state.get("aurion15_resolved_authority")
            or state.get("resolved_authority")
            or state.get("authority")
        )

        governance_trace = state.get("governance_trace", []) or []

        route_valid = bool(jurisdiction) and bool(resolved_authority)

        state["governance_routing_status"] = "routed" if route_valid else "unrouted"
        state["governance_route"] = {
            "jurisdiction": jurisdiction,
            "resolved_authority": resolved_authority,
            "governance_trace": governance_trace,
        }

        if route_valid:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "escalate"

        return state


aurion_registry.register(GovernanceRoutingEngine())
