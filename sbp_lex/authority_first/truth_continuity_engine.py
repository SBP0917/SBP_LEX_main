from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json
import time


@register("truth_continuity")
def truth_continuity_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    previous_anchor = payload.get("previous_truth_anchor")
    current_anchor = payload.get("truth_anchor")

    record = {
        "action": action,
        "previous_anchor_present": previous_anchor is not None,
        "current_anchor_present": current_anchor is not None,
        "continuity_hash": None,
        "continuity_valid": False
    }

    if current_anchor is None:
        return EngineResult(
            ok=False,
            name="truth_continuity",
            detail="Current truth anchor missing",
            data={"truth_continuity": record}
        )

    continuity_material = {
        "previous_anchor": previous_anchor,
        "current_anchor": current_anchor,
        "timestamp": int(time.time())
    }

    continuity_hash = hashlib.sha512(
        json.dumps(continuity_material, sort_keys=True).encode()
    ).hexdigest()

    record["continuity_hash"] = continuity_hash
    record["continuity_valid"] = True

    return EngineResult(
        ok=True,
        name="truth_continuity",
        detail="Truth continuity chain established",
        data={"truth_continuity": record}
    )
