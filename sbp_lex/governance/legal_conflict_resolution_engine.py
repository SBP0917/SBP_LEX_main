"""Legal conflict resolution engine imported from SBP0917/SBP."""

from typing import Any, Dict

from .base_engine import AurionEngine
from .registry import aurion_registry


class LegalConflictResolutionEngine(AurionEngine):
    name = "legal_conflict_resolution_engine"
    stage = 3
    depends_on = [
        "jurisdiction_engine",
        "authority_resolution_engine",
        "governance_compliance_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        jurisdiction = state.get("aurion15_jurisdiction") or state.get("jurisdiction")
        resolved_authority = (
            state.get("aurion15_resolved_authority")
            or state.get("resolved_authority")
            or state.get("authority")
        )
        governance_compliance_status = state.get("governance_compliance_status")
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        declared_conflicts = payload.get(
            "legal_conflicts",
            current_candidate.get("legal_conflicts", []),
        )
        if not isinstance(declared_conflicts, list):
            declared_conflicts = []

        resolvable = (
            bool(jurisdiction)
            and bool(resolved_authority)
            and governance_compliance_status == "compliant"
            and len(declared_conflicts) == 0
        )

        state["legal_conflict_resolution_status"] = (
            "resolved" if resolvable else "unresolved"
        )
        state["legal_conflict_resolution_context"] = {
            "jurisdiction": jurisdiction,
            "resolved_authority": resolved_authority,
            "governance_compliance_status": governance_compliance_status,
            "legal_conflicts": declared_conflicts,
            "legal_conflict_count": len(declared_conflicts),
        }
        state["candidate_action"] = "pass" if resolvable else "redefine_candidate"
        return state


aurion_registry.register(LegalConflictResolutionEngine())
