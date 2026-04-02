"""
Decision Token Engine

Purpose
-------
Generates the decision claims that will be embedded into the SBP-LEX
execution token.

Token Claims
------------
truth_state
assurance_tier
fact_verified_ratio
fact_verified_percentage
uncertainty_ratio
uncertainty_percentage
required_threshold_ratio
required_threshold_percentage
execution_state
autonomy_ceiling

Function
--------
Provides a verifiable record of the procedural truth result and
execution decision that downstream systems must respect.
"""

from .base_engine import BaseEngine
from .registry import register
from ...types import EngineResult


@register("decision_token_engine")
def decision_token_engine(context: dict) -> EngineResult:
    engine = DecisionTokenEngine()
    return engine.run(context)


class DecisionTokenEngine(BaseEngine):
    name = "decision_token_engine"

    def run(self, context: dict) -> EngineResult:
        procedural_truth = context.get("procedural_truth", {}) or {}
        execution_gate = context.get("execution_gate", {}) or {}

        token_claims = {
            "truth_state": procedural_truth.get("truth_state", "false"),
            "assurance_tier": procedural_truth.get("assurance_tier", "general"),
            "fact_verified_ratio": procedural_truth.get("fact_verified_ratio", 0.0),
            "fact_verified_percentage": procedural_truth.get("fact_verified_percentage", "00.000%"),
            "uncertainty_ratio": procedural_truth.get("uncertainty_ratio", 1.0),
            "uncertainty_percentage": procedural_truth.get("uncertainty_percentage", "100.000%"),
            "required_threshold_ratio": procedural_truth.get("required_threshold_ratio", 0.0),
            "required_threshold_percentage": procedural_truth.get("required_threshold_percentage", "00.000%"),
            "execution_state": execution_gate.get("execution_state", "denied"),
            "autonomy_ceiling": execution_gate.get("autonomy_ceiling", 0.0),
        }

        return EngineResult(
            ok=True,
            name=self.name,
            detail="decision_token_claims_prepared",
            data={"decision_token_claims": token_claims},
        )
