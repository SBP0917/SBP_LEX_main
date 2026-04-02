from sbp_lex.types import EngineResult
from .registry import register


@register("governance_confidence")
def governance_confidence_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    anchors = payload.get("anchors")
    decision_token = payload.get("decision_token")
    action = payload.get("action")

    score = 0
    total = 4

    if jurisdiction:
        score += 1
    if authority:
        score += 1
    if anchors:
        score += 1
    if decision_token:
        score += 1

    confidence = score / total

    record = {
        "action": action,
        "jurisdiction_present": jurisdiction is not None,
        "authority_present": authority is not None,
        "anchors_present": anchors is not None,
        "decision_token_present": decision_token is not None,
        "confidence_score": confidence
    }

    if confidence < 1.0:
        return EngineResult(
            ok=False,
            name="governance_confidence",
            detail="Governance confidence insufficient",
            data={"governance_confidence": record}
        )

    return EngineResult(
        ok=True,
        name="governance_confidence",
        detail="Governance confidence verified",
        data={"governance_confidence": record}
        )
