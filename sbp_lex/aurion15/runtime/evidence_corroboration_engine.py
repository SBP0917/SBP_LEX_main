from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class EvidenceCorroborationEngine(AurionEngine):
    name = "evidence_corroboration_engine"
    stage = 2
    depends_on = [
        "evidence_sufficiency_engine",
        "information_integrity_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        corroboration_sources = payload.get(
            "corroboration_sources",
            current_candidate.get("corroboration_sources", []),
        )

        corroboration_score = payload.get(
            "corroboration_score",
            current_candidate.get("corroboration_score", 0.0),
        )

        try:
            corroboration_score = float(corroboration_score)
        except (TypeError, ValueError):
            corroboration_score = 0.0

        if not isinstance(corroboration_sources, list):
            corroboration_sources = []

        corroborated = (
            len(corroboration_sources) >= 2
            and corroboration_score >= 0.6
        )

        state["evidence_corroboration_status"] = (
            "corroborated" if corroborated else "uncorroborated"
        )

        state["corroboration_sources"] = corroboration_sources
        state["corroboration_score"] = corroboration_score

        if corroborated:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(EvidenceCorroborationEngine())
