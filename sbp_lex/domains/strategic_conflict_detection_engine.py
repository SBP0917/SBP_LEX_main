from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class StrategicConflictDetectionEngine(AurionEngine):
    name = "strategic_conflict_detection_engine"
    stage = 5
    depends_on = [
        "jurisdiction_engine",
        "authority_resolution_engine",
        "risk_detection_engine",
        "institutional_integrity_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:

        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        jurisdiction = (
            state.get("aurion15_jurisdiction")
            or state.get("jurisdiction")
        )

        resolved_authority = (
            state.get("aurion15_resolved_authority")
            or state.get("resolved_authority")
            or state.get("authority")
        )

        risk_level = state.get("risk_level")
        institutional_integrity_status = state.get("institutional_integrity_status")

        strategic_conflict_score = payload.get(
            "strategic_conflict_score",
            current_candidate.get("strategic_conflict_score", 0.0),
        )

        strategic_conflict_flags = payload.get(
            "strategic_conflict_flags",
            current_candidate.get("strategic_conflict_flags", []),
        )

        try:
            strategic_conflict_score = float(strategic_conflict_score)
        except (TypeError, ValueError):
            strategic_conflict_score = 0.0

        if not isinstance(strategic_conflict_flags, list):
            strategic_conflict_flags = []

        conflict_detected = (
            bool(jurisdiction)
            and bool(resolved_authority)
            and (
                risk_level in ["high", "critical"]
                or institutional_integrity_status == "compromised"
                or strategic_conflict_score >= 0.7
                or len(strategic_conflict_flags) >= 1
            )
        )

        state["strategic_conflict_detection_status"] = (
            "conflict_detected" if conflict_detected else "stable"
        )

        state["strategic_conflict_score"] = strategic_conflict_score
        state["strategic_conflict_flags"] = strategic_conflict_flags

        if conflict_detected:
            state["candidate_action"] = "refine_candidate"
        else:
            state["candidate_action"] = "pass"

        return state


aurion_registry.register(StrategicConflictDetectionEngine())
