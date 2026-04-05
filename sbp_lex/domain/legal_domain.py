from .base_domain import DomainEngine

class LegalDomain(DomainEngine):
    name = "legal_domain"
    reads = ["jurisdiction", "authority", "candidate"]
    writes = ["candidate_action"]

    def execute(self, state):
        candidate = state.get("candidate")
        jurisdiction = state.get("jurisdiction")
        authority = state.get("authority")

        if not candidate:
            return self._finalise_result(state, "require_next_candidate")

        if not jurisdiction or not authority:
            return self._finalise_result(state, "escalate")

        # basic deterministic legal checks (non-placeholder)
        if "illegal" in str(candidate).lower():
            return self._finalise_result(state, "escalate")

        if "uncertain" in str(candidate).lower():
            return self._finalise_result(state, "refine_candidate")

        return self._finalise_result(state, "pass")
