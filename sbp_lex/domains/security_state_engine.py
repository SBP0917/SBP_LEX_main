from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class SecurityStateEngine(AurionEngine):
    name = "security_state_engine"
    stage = 4
    depends_on = [
        "attestation_engine",
        "system_interdependency_engine",
        "cascading_failure_detection_engine",
    ]

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        payload = state.get("payload", {}) or {}
        current_candidate = state.get("current_candidate", {}) or {}

        attestation_status = state.get("attestation_status") or state.get("aurion15_attestation_status")
        system_interdependency_status = state.get("system_interdependency_status")
        cascading_failure_status = state.get("cascading_failure_status")

        security_state_score = payload.get(
            "security_state_score",
            current_candidate.get("security_state_score", 0.0),
        )

        security_flags = payload.get(
            "security_flags",
            current_candidate.get("security_flags", []),
        )

        try:
            security_state_score = float(security_state_score)
        except (TypeError, ValueError):
            security_state_score = 0.0

        if not isinstance(security_flags, list):
            security_flags = []

        secure = (
            attestation_status not in ["invalid", "failed", "missing", None]
            and system_interdependency_status != "interdependent_risk"
            and cascading_failure_status != "cascade_detected"
            and security_state_score >= 0.7
            and len(security_flags) == 0
        )

        state["security_state_status"] = "secure" if secure else "insecure"
        state["security_state_score"] = security_state_score
        state["security_flags"] = security_flags

        if secure:
            state["candidate_action"] = "pass"
        else:
            state["candidate_action"] = "refine_candidate"

        return state


aurion_registry.register(SecurityStateEngine())
