from sbp_lex.types import EngineResult
from .registry import register
import time


@register("decision_expiry")
def decision_expiry_engine(payload: dict) -> EngineResult:
    decision_token = payload.get("decision_token", {})
    action = payload.get("action")

    issued_at = decision_token.get("timestamp")
    expires_in = decision_token.get("expires_in", 300)
    now = int(time.time())

    record = {
        "action": action,
        "token_present": bool(decision_token),
        "issued_at": issued_at,
        "expires_in": expires_in,
        "current_time": now,
        "expired": False
    }

    if not record["token_present"]:
        return EngineResult(
            ok=False,
            name="decision_expiry",
            detail="Decision token missing
