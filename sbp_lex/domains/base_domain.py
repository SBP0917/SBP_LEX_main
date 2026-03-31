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

    def _finalise_result(self, state: Dict[str, Any], result: str) -> str:
        if result not in ALLOWED_DOMAIN_RESULTS:
            raise ValueError(f"{self.name} returned invalid result: {result}")

        state.setdefault("domain_trace", [])

        entry = {
            "domain": self.name,
            "result": result,
            "attempt": state.get("candidate_attempt_count", 0),
        }

        state["domain_trace"].append(entry)
        state["candidate_action"] = result

        return result
