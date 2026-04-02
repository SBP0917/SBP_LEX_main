from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class DecisionIntegrityEngine(AurionEngine):
    name = "decision_integrity_engine"
    stage = 2
    depends_on = [
        "legitimacy_engine",
        "attestation_engine",
        "evidence_sufficiency_engine",
        "evidence_corroboration_engine",
        "output_discipline_engine",
        "procedural_truth_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:

        legitimacy_status = state.get("legitimacy_status")
        attestation_status = state.get("attestation_status")

        evidence_status = state.get("evidence_sufficiency_status")
        corroboration_status = state.get("evidence_corroboration_status")
        discipline_status = state.get("output_discipline_status")

        procedural_truth = state.get("aurion_procedural_truth_status")

        decision_integrity = (
            legitimacy_status not in ["invalid", "failed", None]
            and attestation_status not in ["invalid", "failed", None]
            and evidence_status == "sufficient"
            and corroboration_status == "corroborated"
            and discipline_status == "disciplined"
            and procedural_truth in ["true", "conclusive", "general_pass"]
        )

        state["decision_integrity_status"] = "sound" if decision_integrity else "unsound"

        if decision_integrity:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "require_next_candidate"

        return state


aurion_registry.register(DecisionIntegrityEngine())
