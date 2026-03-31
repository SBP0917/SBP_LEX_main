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

        if "restricted" in constraints:
            return self._finalise_result(state, "escalate")

        if "limited" in constraints:
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
