"""
Runtime Revalidation Engine

Purpose
-------
Ensures the decision token has not become invalid between the
time it was issued and the time execution occurs.

Validation Checks
-----------------
Truth state consistency
Assurance tier consistency
Verification percentage integrity
Uncertainty value integrity

Failure Conditions
------------------
If the token values differ from the current procedural truth state,
execution is immediately blocked.

Role
----
Prevents token replay, tampering, or downgrade of verification state
after the decision phase.
"""

from .base_engine import BaseEngine
from .registry import register
from ...types import EngineResult


@register("runtime_revalidation_engine")
def runtime_revalidation_engine(context: dict) -> EngineResult:
    engine = RuntimeRevalidationEngine()
    return engine.run(context)


class RuntimeRevalidationEngine(BaseEngine):
    name = "runtime_revalidation_engine"

    def run(self, context: dict) -> EngineResult:
        procedural_truth = context.get("procedural_truth", {}) or {}
        decision_token_claims = context.get("decision_token_claims", {}) or {}

        current_truth_state = procedural_truth.get("truth_state")
        token_truth_state = decision_token_claims.get("truth_state")

        current_assurance_tier = procedural_truth.get("assurance_tier")
        token_assurance_tier = decision_token_claims.get("assurance_tier")

        current_verified = procedural_truth.get("fact_verified_percentage")
        token_verified = decision_token_claims.get("fact_verified_percentage")

        current_uncertainty = procedural_truth.get("uncertainty_percentage")
        token_uncertainty = decision_token_claims.get("uncertainty_percentage")

        if token_truth_state and token_truth_state != current_truth_state:
            return EngineResult(
                ok=False,
                name=self.name,
                detail="runtime_revalidation_failed_truth_state_mismatch",
                data={
                    "runtime_revalidation": {
                        "current_truth_state": current_truth_state,
                        "token_truth_state": token_truth_state,
                    }
                },
            )

        if token_assurance_tier and token_assurance_tier != current_assurance_tier:
            return EngineResult(
                ok=False,
                name=self.name,
                detail="runtime_revalidation_failed_assurance_tier_mismatch",
                data={
                    "runtime_revalidation": {
                        "current_assurance_tier": current_assurance_tier,
                        "token_assurance_tier": token_assurance_tier,
                    }
                },
            )

        if token_verified and token_verified != current_verified:
            return EngineResult(
                ok=False,
                name=self.name,
                detail="runtime_revalidation_failed_verification_percentage_mismatch",
                data={
                    "runtime_revalidation": {
                        "current_fact_verified_percentage": current_verified,
                        "token_fact_verified_percentage": token_verified,
                    }
                },
            )

        if token_uncertainty and token_uncertainty != current_uncertainty:
            return EngineResult(
                ok=False,
                name=self.name,
                detail="runtime_revalidation_failed_uncertainty_percentage_mismatch",
                data={
                    "runtime_revalidation": {
                        "current_uncertainty_percentage": current_uncertainty,
                        "token_uncertainty_percentage": token_uncertainty,
                    }
                },
            )

        return EngineResult(
            ok=True,
            name=self.name,
            detail="runtime_revalidation_passed",
            data={
                "runtime_revalidation": {
                    "revalidated_truth_state": current_truth_state,
                    "revalidated_assurance_tier": current_assurance_tier,
                    "revalidated_fact_verified_percentage": current_verified,
                    "revalidated_uncertainty_percentage": current_uncertainty,
                }
            },
        )
