from sbp_lex.types import EngineResult
from .registry import register
import time


@register("truth_expiry")
def truth_expiry_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    truth_anchor = payload.get("truth_anchor", {})

    issued_at = truth_anchor.get("timestamp")
    expires_in = truth_anchor.get("expires_in", 300)
    now = int(time.time())

    record = {
        "action": action,
        "truth_anchor_present": bool(truth_anchor),
        "issued_at": issued_at,
        "expires_in": expires_in,
        "current_time": now,
        "expired": False
    }

    if not record["truth_anchor_present"]:
        return EngineResult(
            ok=False,
            name="truth_expiry",
            detail="Truth anchor missing",
            data={"truth_expiry": record}
        )

    if issued_at is None:
        return EngineResult(
            ok=False,
            name="truth_expiry",
            detail="Truth anchor timestamp missing",
            data={"truth_expiry": record}
        )

    record["expired"] = now > (issued_at + expires_in)

    if record["expired"]:
        return EngineResult(
            ok=False,
            name="truth_expiry",
            detail="Truth anchor expired",
            data={"truth_expiry": record}
        )

    return EngineResult(
        ok=True,
        name="truth_expiry",
        detail="Truth anchor valid within expiry window",
        data={"truth_expiry": record}
    )
