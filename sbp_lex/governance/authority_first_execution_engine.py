from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class AuthorityFirstExecutionEngine(AurionEngine):
    name = "authority_first_execution_engine"
    stage = 6
    depends_on = [
        "authority_resolution_engine",
        "execution_gate_engine",
        "governance_compliance_engine",
        "legal_conflict_resolution_engine",
        "decision_integrity_engine",
        "policy_simulation_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        resolved_authority = (
            state.get("aurion15_resolved_authority")
            or state.get("resolved_authority")
            or state.get("authority")
        )

        candidate_result = state.get("candidate_result")
        governance_compliance_status = state.get("governance_compliance_status")
        legal_conflict_resolution_status = state.get("legal_conflict_resolution_status")
        decision_integrity_status = state.get("decision_integrity_status")
        policy_simulation_status = state.get("policy_simulation_status")

        executable = (
            bool(resolved_authority)
            and candidate_result in ["allow", "allow_reduced", "allow_fallback"]
            and governance_compliance_status == "compliant"
            and legal_conflict_resolution_status == "resolved"
            and decision_integrity_status == "sound"
            and policy_simulation_status == "viable"
        )

        state["authority_first_execution_status"] = (
            "approved" if executable else "blocked"
        )

        state["authority_first_execution_context"] = {
            "resolved_authority": resolved_authority,
            "candidate_result": candidate_result,
            "governance_compliance_status": governance_compliance_status,
            "legal_conflict_resolution_status": legal_conflict_resolution_status,
            "decision_integrity_status": decision_integrity_status,
            "policy_simulation_status": policy_simulation_status,
        }

        if executable:
            state["candidate_action"] = "pass"
            state["aurion15_result"] = candidate_result
        else:
            state["candidate_action"] = "escalate"
            state["aurion15_result"] = "authority_first_execution_blocked"

        return state


aurion_registry.register(AuthorityFirstExecutionEngine())
