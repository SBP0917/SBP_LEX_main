from typing import Dict, Any
from .base_engine import AurionEngine
from .registry import aurion_registry


class LegitimacyVerificationEngine(AurionEngine):
    name = "legitimacy_verification_engine"
    stage = 1
    depends_on = []

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        legitimacy_status = state.get("legitimacy_status")

        state["aurion15_legitimacy_status"] = legitimacy_status

        if legitimacy_status in {"invalid", "failed", "illegitimate"}:
            state["status"] = "require_next_candidate"
            return state

        state["status"] = "pass"
        return state


aurion_registry.register(LegitimacyVerificationEngine())
