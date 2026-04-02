"""
Candidate Loop Controller

Controls continuous candidate pathway execution for Aurion-15.

Responsibilities
----------------
• manage candidate lifecycle (A → B → C → …)
• enforce continuous search (no dead stops)
• integrate runner with generator and queue
• respect runtime constraints via external controller

Rules
-----
• search does not terminate on denial
• must always attempt to find lawful pathway
• escalation only when fallback is rejected OR constraints exceeded
"""

from typing import Dict, Any


class CandidateLoopController:
    def __init__(self, search_controller, runner, constraint_controller):
        self.search = search_controller
        self.runner = runner
        self.constraints = constraint_controller

    def run(self, request_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        state.setdefault("candidate_attempt_count", 0)
        state.setdefault("best_candidate_result", None)

        self.constraints.start(state)

        while True:
            # Enforce runtime + attempt limits
            if self.constraints.should_stop(state):
                state["aurion15_result"] = "escalate"
                return state

            # Get next candidate (A, B, C...)
            candidate = self.search.get_next_candidate(state)

            if not candidate:
                state["aurion15_result"] = "escalate"
                return state

            state["current_candidate"] = candidate

            # Run Aurion pipeline
            state = self.runner.run(state)

            action = state.get("candidate_action")
            result = state.get("aurion15_result") or state.get("candidate_result")

            # SUCCESS PATH
            if action == "pass" and result in [
                "allow",
                "allow_reduced",
                "allow_fallback",
            ]:
                state["aurion15_result"] = result
                return state

            # REFINEMENT (same candidate evolves)
            if action == "refine_candidate":
                continue

            # REDEFINE (new version of same pathway)
            if action == "redefine_candidate":
                state["candidate_attempt_count"] += 1
                self.search.redefine_candidate(state)
                continue

            # NEXT candidate (B, C, D...)
            if action == "require_next_candidate":
                state["candidate_attempt_count"] += 1
                continue

            # ESCALATION condition
            if action == "escalate":
                state["aurion15_result"] = "escalate"
                return state
