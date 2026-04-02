"""
Execution Gate Engine

Purpose
-------
Determines whether an action is permitted to execute based on the
procedural truth state produced by the PTODF engine.

Decision Logic
--------------
true
    Full execution permission.

conclusive
    Conditional execution with reduced autonomy ceiling.

general_pass
    Allowed only for low-risk general workflow actions.

false
    Execution denied.

Autonomy Control
----------------
true → 100% autonomy
conclusive → 50% autonomy ceiling
general_pass → limited general workflow autonomy
false → 0% autonomy

Critical Action Protection
--------------------------
Actions classified as financial, safety-critical, evidentiary,
or transport control require a "true" five-nines truth state.
"""

from .base_engine import BaseEngine
from .registry import register
from ...types import EngineResult


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
            return EngineResult(
                ok=True,
                name=self.name,
                detail="execution_allowed_five_nines_truth",
                data={
                    "execution_gate": {
                        "execution_state": "approved",
                        "autonomy_ceiling": 1.0,
                        "verification": verified,
                        "uncertainty": uncertainty,
                        "truth_state": truth_state,
                        "assurance_tier": assurance_tier,
                    }
                },
            )

        if truth_state == "conclusive":
            if action_class in ["financial", "critical", "transport", "evidentiary", "safety_critical"]:
                return EngineResult(
                    ok=False,
                    name=self.name,
                    detail="execution_blocked_conclusive_state_for_critical_action",
                    data={
                        "execution_gate": {
                            "execution_state": "denied",
                            "autonomy_ceiling": 0.0,
                            "verification": verified,
                            "uncertainty": uncertainty,
                            "truth_state": truth_state,
                            "assurance_tier": assurance_tier,
                        }
                    },
                )

            return EngineResult(
                ok=True,
                name=self.name,
                detail="execution_allowed_conclusive_state_with_limited_autonomy",
                data={
                    "execution_gate": {
                        "execution_state": "conditional",
                        "autonomy_ceiling": 0.5,
                        "verification": verified,
                        "uncertainty": uncertainty,
                        "truth_state": truth_state,
                        "assurance_tier": assurance_tier,
                    }
                },
            )

        if truth_state == "general_pass":
            if action_class != "general":
                return EngineResult(
                    ok=False,
                    name=self.name,
                    detail="execution_blocked_general_pass_outside_general_workflow",
                    data={
                        "execution_gate": {
                            "execution_state": "denied",
                            "autonomy_ceiling": 0.0,
                            "verification": verified,
                            "uncertainty": uncertainty,
                            "truth_state": truth_state,
                            "assurance_tier": assurance_tier,
                        }
                    },
                )

            return EngineResult(
                ok=True,
                name=self.name,
                detail="execution_allowed_general_workflow_state",
                data={
                    "execution_gate": {
                        "execution_state": "limited_general",
                        "autonomy_ceiling": 0.5,
                        "verification": verified,
                        "uncertainty": uncertainty,
                        "truth_state": truth_state,
                        "assurance_tier": assurance_tier,
                    }
                },
            )

        return EngineResult(
            ok=False,
            name=self.name,
            detail="execution_blocked_truth_threshold_not_met",
            data={
                "execution_gate": {
                    "execution_state": "denied",
                    "autonomy_ceiling": 0.0,
                    "verification": verified,
                    "uncertainty": uncertainty,
                    "truth_state": truth_state,
                    "assurance_tier": assurance_tier,
                }
            },
        )                    "verification": verified,
                    "uncertainty": uncertainty,
                    "truth_state": truth_state,
                    "assurance_tier": assurance_tier,
                },
            )

        # GENERAL PASS = only for general workflow
        if truth_state == "general_pass":
            if action_class != "general":
                return EngineResult(
                    ok=False,
                    name=self.name,
                    detail="execution_blocked_general_pass_outside_general_workflow",
                    data={
                        "execution_state": "denied",
                        "autonomy_ceiling": 0.0,
                        "verification": verified,
                        "uncertainty": uncertainty,
                        "truth_state": truth_state,
                        "assurance_tier": assurance_tier,
                    },
                )

            return EngineResult(
                ok=True,
                name=self.name,
                detail="execution_allowed_general_workflow_state",
                data={
                    "execution_state": "limited_general",
                    "autonomy_ceiling": 0.5,
                    "verification": verified,
                    "uncertainty": uncertainty,
                    "truth_state": truth_state,
                    "assurance_tier": assurance_tier,
                },
            )

        # FALSE = deny
        return EngineResult(
            ok=False,
            name=self.name,
            detail="execution_blocked_truth_threshold_not_met",
            data={
                "execution_state": "denied",
                "autonomy_ceiling": 0.0,
                "verification": verified,
                "uncertainty": uncertainty,
                "truth_state": truth_state,
                "assurance_tier": assurance_tier,
            },
        )
