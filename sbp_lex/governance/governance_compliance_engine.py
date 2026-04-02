from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class GovernanceComplianceEngine(AurionEngine):
    name = "governance_compliance_engine"
    stage = 3
    depends_on = [
        "governance_routing_engine",
        "legitimacy_engine",
        "attestation_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        governance_result = state.get("governance_result")
        governance_reason = state.get("governance_reason")
        route_status = state.get("governance_routing_status")
        legitimacy_status = state.get("legitimacy_status") or state.get("aurion15_legitimacy_status")
        attestation_status = state.get("attestation_status") or state.get("aurion15_attestation_status")

        compliant = (
            governance_result not in ["deny", "escalate"]
            and route_status == "routed"
            and legitimacy_status not in ["invalid", "failed", "illegitimate", None]
            and attestation_status not in ["invalid", "failed", "missing", None]
        )

        state["governance_compliance_status"] = "compliant" if compliant else "non_compliant"
        state["governance_compliance_context"] = {
            "governance_result": governance_result,
            "governance_reason": governance_reason,
            "route_status": route_status,
            "legitimacy_status": legitimacy_status,
            "attestation_status": attestation_status,
        }

        if compliant:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "require_next_candidate"

        return state


aurion_registry.register(GovernanceComplianceEngine())
