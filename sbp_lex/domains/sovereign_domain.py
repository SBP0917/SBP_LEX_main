from .base_domain import DomainEngine


class SovereignDomain(DomainEngine):
    name = "sovereign_domain"
    reads = ["authority", "jurisdiction", "candidate"]
    writes = ["candidate_action"]

    def execute(self, state):
        candidate = state.get("candidate")
        authority = state.get("authority")
        jurisdiction = state.get("jurisdiction")

        if not candidate:
            return self._finalise_result(state, "require_next_candidate")

        if not authority or not jurisdiction:
            return self._finalise_result(state, "escalate")

        c = str(candidate).lower()

        if "override_authority" in c:
            return self._finalise_result(state, "escalate")

        if "cross_jurisdiction" in c:
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
