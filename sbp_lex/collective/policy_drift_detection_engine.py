from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json


@register("policy_drift_detection")
def policy_drift_detection_engine(payload: dict) -> EngineResult:
    policy = payload.get("policy", {})
    baseline_policy = payload.get("baseline_policy", {})
    action = payload.get("action")

    current_hash = hashlib.sha512(
        json.dumps(policy, sort_keys=True).encode()
    ).hexdigest()

    baseline_hash = hashlib.sha512(
        json.dumps(baseline_policy, sort_keys=True).encode()
    ).hexdigest()

    drift_detected = current_hash != baseline_hash

    record = {
        "action": action,
        "current_policy_hash": current_hash,
        "baseline_policy_hash": baseline_hash,
        "drift_detected": drift_detected,
    }

    if drift_detected:
        return EngineResult(
            ok=False,
            name="policy_drift_detection",
            detail="Policy drift detected",
            data={"policy_drift": record},
        )

    return EngineResult(
        ok=True,
        name="policy_drift_detection",
        detail="No policy drift detected",
        data={"policy_drift": record},
    )
