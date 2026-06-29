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
        "expired": False,
    }

    if not record["token_present"]:
        return EngineResult(
            ok=False,
            name="decision_expiry",
            detail="Decision token missing",
            data={"decision_expiry": record},
        )

    if issued_at is None:
        return EngineResult(
            ok=False,
            name="decision_expiry",
            detail="Decision token timestamp missing",
            data={"decision_expiry": record},
        )

    try:
        issued_at_int = int(issued_at)
        expires_in_int = int(expires_in)
    except (TypeError, ValueError):
        return EngineResult(
            ok=False,
            name="decision_expiry",
            detail="Decision token expiry fields malformed",
            data={"decision_expiry": record},
        )

    record["expired"] = now > issued_at_int + expires_in_int
    if record["expired"]:
        return EngineResult(
            ok=False,
            name="decision_expiry",
            detail="Decision token expired",
            data={"decision_expiry": record},
        )

    return EngineResult(
        ok=True,
        name="decision_expiry",
        detail="Decision token within expiry window",
        data={"decision_expiry": record},
    )
