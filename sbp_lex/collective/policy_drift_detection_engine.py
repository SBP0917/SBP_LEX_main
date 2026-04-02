from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json


@register("policy_drift_detection")
def policy_drift_detection_engine(payload: dict) -> EngineResult:
    policy = payload.get("policy", {})
    baseline_policy = payload.get("baseline_policy", {})
    action = payload.get("action")

    current_hash = hashlib.sha256(
        json.dumps(policy, sort_keys=True).encode()
    ).hexdigest()

    baseline_hash = hashlib.sha256(
        json.dumps(baseline_policy, sort_keys=True).encode()
    ).hexdigest()

    drift_detected = current_hash != baseline_hash

    record = {
        "action":
