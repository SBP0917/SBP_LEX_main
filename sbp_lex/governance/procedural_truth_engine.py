"""
Procedural Truth & Output Discipline Framework (PTODF)

Purpose
-------
Evaluates the verified factual certainty of AI output before it is allowed
to proceed through the SBP-LEX decision pipeline.

Operation
---------
The engine evaluates the fact_verified_ratio of an output and attempts
re-verification within a bounded search window.

Search Behaviour
----------------
Maximum evaluation window: 3 seconds
Maximum re-evaluation attempts: 12

Truth States
------------
true
    ≥ 99.999% verified factual certainty.

conclusive
    ≥ 98.500% verified certainty.

general_pass
    ≥ 95.000% verified certainty (general automation tier only).

false
    Verification threshold not met.

Assurance Tiers
---------------
critical
    Requires 99.999% certainty.

medium
    Allows "conclusive" state ≥ 98.500%.

general
    Allows general workflow state ≥ 95.000%.

Output
------
Returns a structured truth state along with the calculated uncertainty
percentage for downstream governance and execution engines.
"""

import time
from .base_engine import BaseEngine
from .registry import register
from sbp_lex.types import EngineResult

# PTODF thresholds
PTODF_CRITICAL_TRUE_THRESHOLD = 0.99999   # 99.999%
PTODF_MEDIUM_CONCLUSIVE_THRESHOLD = 0.985 # 98.500%
PTODF_GENERAL_THRESHOLD = 0.95            # 95.000%

PTODF_MAX_REEVALUATIONS = 12
PTODF_MAX_SEARCH_TIME = 3


@register("procedural_truth_engine")
def procedural_truth_engine(context: dict) -> EngineResult:
    engine = ProceduralTruthEngine()
    return engine.run(context)


class ProceduralTruthEngine(BaseEngine):
    name = "procedural_truth_engine"

    def _get_fact_verified_ratio(self, payload: dict) -> float:
        output = payload.get("output", {}) or {}
        ratio = output.get("fact_verified_ratio", 0.0)

        try:
            ratio = float(ratio)
        except (TypeError, ValueError):
            ratio = 0.0

        if ratio < 0.0:
            return 0.0
        if ratio > 1.0:
            return 1.0
        return ratio

    def _get_assurance_tier(self, context: dict) -> str:
        payload = context.get("payload", {}) or {}
        tier = context.get("assurance_tier") or payload.get("assurance_tier") or "general"
        tier = str(tier).strip().lower()

        if tier in ["critical", "highest", "extreme", "safety_critical"]:
            return "critical"
        if tier in ["medium", "moderate", "high_impact"]:
            return "medium"
        return "general"

    def run(self, context: dict) -> EngineResult:
        payload = context.get("payload", {}) or {}
        assurance_tier = self._get_assurance_tier(context)

        record = {
            "assurance_tier": assurance_tier,
            "critical_true_threshold_ratio": PTODF_CRITICAL_TRUE_THRESHOLD,
            "critical_true_threshold_percentage": "99.999%",
            "medium_conclusive_threshold_ratio": PTODF_MEDIUM_CONCLUSIVE_THRESHOLD,
            "medium_conclusive_threshold_percentage": "98.500%",
            "general_threshold_ratio": PTODF_GENERAL_THRESHOLD,
            "general_threshold_percentage": "95.000%",
            "max_reevaluations": PTODF_MAX_REEVALUATIONS,
            "max_search_time_seconds": PTODF_MAX_SEARCH_TIME,
            "attempts": 0,
            "fact_verified_ratio": 0.0,
            "fact_verified_percentage": "00.000%",
            "uncertainty_ratio": 1.0,
            "uncertainty_percentage": "100.000%",
            "truth_state": "false",
            "procedural_truth_status": "false",
            "procedural_truth_tier": "false",
            "procedural_confidence": 0.0,
            "general_pass_95": False,
            "conclusive_98_5": False,
            "deterministic_99_999": False,
            "required_threshold_ratio": 0.0,
            "required_threshold_percentage": "00.000%",
        }

        if assurance_tier == "critical":
            record["required_threshold_ratio"] = PTODF_CRITICAL_TRUE_THRESHOLD
            record["required_threshold_percentage"] = "99.999%"
        elif assurance_tier == "medium":
            record["required_threshold_ratio"] = PTODF_MEDIUM_CONCLUSIVE_THRESHOLD
            record["required_threshold_percentage"] = "98.500%"
        else:
            record["required_threshold_ratio"] = PTODF_GENERAL_THRESHOLD
            record["required_threshold_percentage"] = "95.000%"

        start_time = time.time()

        while True:
            fact_verified_ratio = self._get_fact_verified_ratio(payload)
            uncertainty_ratio = 1.0 - fact_verified_ratio

            record["attempts"] += 1
            record["fact_verified_ratio"] = fact_verified_ratio
            record["fact_verified_percentage"] = f"{fact_verified_ratio * 100:.3f}%"
            record["uncertainty_ratio"] = uncertainty_ratio
            record["uncertainty_percentage"] = f"{uncertainty_ratio * 100:.3f}%"
            record["procedural_confidence"] = fact_verified_ratio

            record["general_pass_95"] = fact_verified_ratio >= PTODF_GENERAL_THRESHOLD
            record["conclusive_98_5"] = fact_verified_ratio >= PTODF_MEDIUM_CONCLUSIVE_THRESHOLD
            record["deterministic_99_999"] = fact_verified_ratio >= PTODF_CRITICAL_TRUE_THRESHOLD

            if record["deterministic_99_999"]:
                record["truth_state"] = "true"
                record["procedural_truth_status"] = "true"
                record["procedural_truth_tier"] = "true"
                return EngineResult(
                    ok=True,
                    name=self.name,
                    detail="five_nines_true_state",
                    data={"procedural_truth": record},
                )

            if record["conclusive_98_5"]:
                record["truth_state"] = "conclusive"
                record["procedural_truth_status"] = "conclusive"
                record["procedural_truth_tier"] = "conclusive"

                if assurance_tier in ["medium", "general"]:
                    return EngineResult(
                        ok=True,
                        name=self.name,
                        detail="conclusive_state",
                        data={"procedural_truth": record},
                    )

            if record["general_pass_95"]:
                record["truth_state"] = "general_pass"
                record["procedural_truth_status"] = "general_pass"
                record["procedural_truth_tier"] = "general_pass"

                if assurance_tier == "general":
                    return EngineResult(
                        ok=True,
                        name=self.name,
                        detail="general_workflow_state",
                        data={"procedural_truth": record},
                    )

            elapsed = time.time() - start_time
            if record["attempts"] >= PTODF_MAX_REEVALUATIONS:
                break
            if elapsed >= PTODF_MAX_SEARCH_TIME:
                break

            payload = context.get("payload", {}) or {}

        record["truth_state"] = "false"
        record["procedural_truth_status"] = "false"
        record["procedural_truth_tier"] = "false"

        return EngineResult(
            ok=False,
            name=self.name,
            detail="ptodf_threshold_not_met_for_assurance_tier",
            data={"procedural_truth": record},
        )


def evaluate_procedural_truth(state: dict) -> dict:
    result = procedural_truth_engine(state)
    procedural_truth = result.data.get("procedural_truth", {})

    state["procedural_truth"] = procedural_truth
    state["procedural_truth_result"] = "PASS" if result.ok else "FAIL"
    state["procedural_truth_reason"] = result.detail
    state["procedural_truth_status"] = procedural_truth.get("procedural_truth_status")
    state["procedural_truth_tier"] = procedural_truth.get("procedural_truth_tier")
    return state
