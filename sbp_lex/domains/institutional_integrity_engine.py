from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class InstitutionalIntegrityEngine(AurionEngine):
    name = "institutional_integrity_engine"
    stage = 5
    depends_on = [
        "legitimacy_engine",
        "attestation_engine",
        "governance_compliance_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:

        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        legitimacy_status = state.get("legitimacy_status")
        attestation_status = state.get("attestation_status")
        governance_compliance = state.get("governance_compliance_status")

        institutional_integrity_score = payload.get(
            "institutional_integrity_score",
            current_candidate.get("institutional_integrity_score", 0.0),
        )

        corruption_flags = payload.get(
            "institutional_corruption_flags",
            current_candidate.get("institutional_corruption_flags", []),
        )

        try:
            institutional_integrity_score = float(institutional_integrity_score)
        except (TypeError, ValueError):
            institutional_integrity_score = 0.0

        if not isinstance(corruption_flags, list):
            corruption_flags = []

        institution_valid = (
            legitimacy_status not in ["invalid", "failed"]
            and attestation_status not in ["invalid", "failed"]
            and governance_compliance == "compliant"
            and institutional_integrity_score >= 0.7
            and len(corruption_flags) == 0
        )

        state["institutional_integrity_status"] = (
            "sound" if institution_valid else "compromised"
        )

        state["institutional_integrity_score"] = institutional_integrity_score
        state["institutional_corruption_flags"] = corruption_flags

        if institution_valid:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(InstitutionalIntegrityEngine())
