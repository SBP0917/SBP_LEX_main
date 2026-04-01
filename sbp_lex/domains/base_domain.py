from typing import Dict, Any, List


ALLOWED_DOMAIN_RESULTS = {
    "pass",
    "refine_candidate",
    "redefine_candidate",
    "require_next_candidate",
    "escalate",
}


class DomainEngine:
    name = "base_domain"
    reads: List[str] = []
    writes: List[str] = []

    def execute(self, state: Dict[str, Any]) -> str:
        raise NotImplementedError("Domain must implement execute()")

    def _escalate_tier_if_needed(self, state: Dict[str, Any], factor: str, value: int) -> None:
        safety_profile = state.setdefault("safety_profile", {
            "human_safety": 0,
            "irreversibility": 0,
            "cascading_impact": 0,
            "financial_operational": 0,
            "computed_tier": None,
        })

        current = int(safety_profile.get(factor, 0))
        if value > current:
            safety_profile[factor] = value
            state["tier_recomputed"] = True

    def _finalise_result(self, state: Dict[str, Any], result: str) -> str:
        if result not in ALLOWED_DOMAIN_RESULTS:
            raise ValueError(f"{self.name} returned invalid result: {result}")

        state.setdefault("domain_trace", [])

        entry = {
            "domain": self.name,
            "result": result,
            "attempt": state.get("candidate_attempt_count", 0),
            "tier": state.get("safety_profile", {}).get("computed_tier"),
            "tier_recomputed": bool(state.get("tier_recomputed", False)),
        }

        state["domain_trace"].append(entry)
        state["candidate_action"] = result

        return result
