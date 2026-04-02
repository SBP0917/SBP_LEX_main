from sbp_lex.types import EngineResult
from .registry import register


@register("jurisdiction_drift")
def jurisdiction_drift_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction", {})
    baseline_jurisdiction = payload.get("baseline_jurisdiction", {})
    action = payload.get("action")

    current_country = jurisdiction.get("country")
    baseline_country = baseline_jurisdiction.get("country")

    drift_detected = current_country != baseline_country

    record = {
        "action": action,
        "current_country": current_country,
        "baseline_country": baseline_country,
        "drift_detected": drift_detected
    }

    if drift_detected:
        return EngineResult(
            ok=False,
            name="jurisdiction_drift",
            detail="Jurisdiction drift detected",
            data={"jurisdiction_drift": record}
        )

    return EngineResult(
        ok=True,
        name="jurisdiction_drift",
        detail="Jurisdiction consistent",
        data={"jurisdiction_drift": record}
    )
