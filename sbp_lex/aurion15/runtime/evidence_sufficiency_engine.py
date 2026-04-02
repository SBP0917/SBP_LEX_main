from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class EvidenceSufficiencyEngine(AurionEngine):
    name = "evidence_sufficiency_engine"
    stage = 2
    depends_on = ["procedural_validation_engine"]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        evidence_count = payload.get(
            "evidence_count",
            current_candidate.get("evidence_count", 0),
        )
        evidence_quality = payload.get(
            "evidence_quality",
            current_candidate.get("evidence_quality", 0.0),
        )
        evidence_sources = payload.get(
            "evidence_sources",
            current_candidate.get("evidence_sources", []),
        )

        try:
            evidence_count = int(evidence_count)
        except (TypeError, ValueError):
            evidence_count = 0

        try:
            evidence_quality = float(evidence_quality)
        except (TypeError, ValueError):
            evidence_quality = 0.0

        if not isinstance(evidence_sources, list):
            evidence_sources = []

        sufficient = (
            evidence_count >= 1
            and evidence_quality >= 0.5
            and len(evidence_sources) >= 1
        )

        state["evidence_sufficiency_status"] = "sufficient" if sufficient else "insufficient"
        state["evidence_count"] = evidence_count
        state["evidence_quality"] = evidence_quality
        state["evidence_sources"] = evidence_sources

        if sufficient:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(EvidenceSufficiencyEngine())
