from sbp_lex.types import EngineResult
from .registry import register
import time


@register("permanent_sovereign_governance_cycle")
def permanent_sovereign_governance_cycle_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    anchors = payload.get("anchors", {})
    decision_token = payload.get("decision_token")

    cycle_record = {
        "timestamp": int(time.time()),
        "action": action,
        "jurisdiction_present": jurisdiction is not None,
        "authority_present": authority is not None,
        "anchors_present": bool(anchors),
        "decision_token_present": decision_token is not None,
        "cycle_valid": False,
    }

    cycle_record["cycle_valid"] = all([
        cycle_record["jurisdiction_present"],
        cycle_record["authority_present"],
        cycle_record["anchors_present"],
        cycle_record["decision_token_present"],
    ])

    if not cycle_record["cycle_valid"]:
        return EngineResult(
            ok=False,
            name="permanent_sovereign_governance_cycle",
            detail="Permanent sovereign governance cycle incomplete",
            data={"governance_cycle": cycle_record}
        )

    return EngineResult(
        ok=True,
        name="permanent_sovereign_governance_cycle",
        detail="Permanent sovereign governance cycle validated",
        data={"governance_cycle": cycle_record}
    )
