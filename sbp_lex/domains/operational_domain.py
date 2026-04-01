from .base_domain import DomainEngine


class OperationalDomain(DomainEngine):
    name = "operational_domain"
    reads = ["candidate", "operational_environment"]
    writes = ["candidate_action"]

    def execute(self, state):
        candidate = state.get("candidate")
        env = state.get("operational_environment")

        if not candidate:
            return self._finalise_result(state, "require_next_candidate")

        if not env:
            return self._finalise_result(state, "refine_candidate")

        constraints = env.get("constraints", [])
        human_proximity = env.get("human_proximity")

        if human_proximity in ["direct", "live", "close"]:
            self._escalate_tier_if_needed(state, "human_safety", 3)

        if "restricted" in constraints:
            self._escalate_tier_if_needed(state, "irreversibility", 3)
            return self._finalise_result(state, "escalate")

        if "limited" in constraints:
            self._escalate_tier_if_needed(state, "irreversibility", 2)
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
