from .base_domain import DomainEngine


class RiskDomain(DomainEngine):
    name = "risk_domain"
    reads = ["risk_score", "candidate"]
    writes = ["candidate_action"]

    def execute(self, state):
        candidate = state.get("candidate")
        risk = state.get("risk_score")

        if not candidate:
            return self._finalise_result(state, "require_next_candidate")

        if risk is None:
            return self._finalise_result(state, "refine_candidate")

        risk = float(risk)

        if risk > 0.85:
            self._escalate_tier_if_needed(state, "cascading_impact", 3)
            return self._finalise_result(state, "escalate")

        if risk > 0.60:
            self._escalate_tier_if_needed(state, "cascading_impact", 2)
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
