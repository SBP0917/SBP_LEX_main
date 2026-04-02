from .base_domain import DomainEngine

class OperationalDomain(DomainEngine):
    name = "operational_domain"
    reads = ["candidate", "action", "payload"]
    writes = ["candidate_action"]

    def execute(self, state):
        candidate = state.get("candidate")
        action = state.get("action")
        payload = state.get("payload")

        if not candidate:
            return self._finalise_result(state, "require_next_candidate")

        if not action:
            return self._finalise_result(state, "refine_candidate")

        if payload is None:
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
