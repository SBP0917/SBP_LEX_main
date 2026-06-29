"""
Execution Gate Engine

Determines whether an action is permitted to execute based on the
procedural truth state produced by the PTODF engine.
"""

from .base_engine import BaseEngine
from .registry import register
from sbp_lex.types import EngineResult


@register("execution_gate_engine")
def execution_gate_engine(context: dict) -> EngineResult:
    engine = ExecutionGateEngine()
    return engine.run(context)


class ExecutionGateEngine(BaseEngine):
    name = "execution_gate_engine"

    def _get_action_class(self, context: dict) -> str:
        payload = context.get("payload", {}) or {}
        action_class = (
            context.get("action_class")
            or payload.get("action_class")
            or payload.get("risk_class")
            or "general"
        )
        return str(action_class).strip().lower()

    def run(self, context: dict) -> EngineResult:
        procedural_truth = context.get("procedural_truth", {}) or {}

        truth_state = procedural_truth.get("truth_state", "false")
        verified = procedural_truth.get("fact_verified_percentage", "00.000%")
        uncertainty = procedural_truth.get("uncertainty_percentage", "100.000%")
        assurance_tier = procedural_truth.get("assurance_tier", "general")
        action_class = self._get_action_class(context)

        if truth_state == "true":
            return self._result(
                ok=True,
                detail="execution_allowed_five_nines_truth",
                execution_state="approved",
                autonomy_ceiling=1.0,
                verified=verified,
                uncertainty=uncertainty,
                truth_state=truth_state,
                assurance_tier=assurance_tier,
            )

        if truth_state == "conclusive":
            if action_class in [
                "financial",
                "critical",
                "transport",
                "evidentiary",
                "safety_critical",
            ]:
                return self._result(
                    ok=False,
                    detail="execution_blocked_conclusive_state_for_critical_action",
                    execution_state="denied",
                    autonomy_ceiling=0.0,
                    verified=verified,
                    uncertainty=uncertainty,
                    truth_state=truth_state,
                    assurance_tier=assurance_tier,
                )

            return self._result(
                ok=True,
                detail="execution_allowed_conclusive_state_with_limited_autonomy",
                execution_state="conditional",
                autonomy_ceiling=0.5,
                verified=verified,
                uncertainty=uncertainty,
                truth_state=truth_state,
                assurance_tier=assurance_tier,
            )

        if truth_state == "general_pass":
            if action_class != "general":
                return self._result(
                    ok=False,
                    detail="execution_blocked_general_pass_outside_general_workflow",
                    execution_state="denied",
                    autonomy_ceiling=0.0,
                    verified=verified,
                    uncertainty=uncertainty,
                    truth_state=truth_state,
                    assurance_tier=assurance_tier,
                )

            return self._result(
                ok=True,
                detail="execution_allowed_general_workflow_state",
                execution_state="limited_general",
                autonomy_ceiling=0.5,
                verified=verified,
                uncertainty=uncertainty,
                truth_state=truth_state,
                assurance_tier=assurance_tier,
            )

        return self._result(
            ok=False,
            detail="execution_blocked_truth_threshold_not_met",
            execution_state="denied",
            autonomy_ceiling=0.0,
            verified=verified,
            uncertainty=uncertainty,
            truth_state=truth_state,
            assurance_tier=assurance_tier,
        )

    def _result(
        self,
        *,
        ok: bool,
        detail: str,
        execution_state: str,
        autonomy_ceiling: float,
        verified: str,
        uncertainty: str,
        truth_state: str,
        assurance_tier: str,
    ) -> EngineResult:
        return EngineResult(
            ok=ok,
            name=self.name,
            detail=detail,
            data={
                "execution_gate": {
                    "execution_state": execution_state,
                    "autonomy_ceiling": autonomy_ceiling,
                    "verification": verified,
                    "uncertainty": uncertainty,
                    "truth_state": truth_state,
                    "assurance_tier": assurance_tier,
                }
            },
        )
