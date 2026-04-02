from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class InformationIntegrityEngine(AurionEngine):
    name = "information_integrity_engine"
    stage = 2
    depends_on = ["procedural_validation_engine", "evidence_sufficiency_engine"]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        information_integrity_score = payload.get(
            "information_integrity_score",
            current_candidate.get("information_integrity_score", 0.0),
        )
        contradiction_count = payload.get(
            "contradiction_count",
            current_candidate.get("contradiction_count", 0),
        )
        tamper_flags = payload.get(
            "tamper_flags",
            current_candidate.get("tamper_flags", []),
        )

        try:
            information_integrity_score = float(information_integrity_score)
        except (TypeError, ValueError):
            information_integrity_score = 0.0

        try:
            contradiction_count = int(contradiction_count)
        except (TypeError, ValueError):
            contradiction_count = 0

        if not isinstance(tamper_flags, list):
            tamper_flags = []

        verified = (
            information_integrity_score >= 0.7
            and contradiction_count == 0
            and len(tamper_flags) == 0
        )

        state["information_integrity_status"] = "verified" if verified else "degraded"
        state["information_integrity_score"] = information_integrity_score
        state["contradiction_count"] = contradiction_count
        state["tamper_flags"] = tamper_flags

        if verified:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(InformationIntegrityEngine())
