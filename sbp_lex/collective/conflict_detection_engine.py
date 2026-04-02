# sbp_lex/engines/aurion15/conflict_detection_engine.py


from sbp_lex.types import EngineResult
from .registry import register

@register("conflict_detection")
def conflict_detection_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    precedence = payload.get("precedence")
    action = payload.get("action")

    conflicts = []

    if not jurisdiction:
        conflicts.append("Missing jurisdiction")

    if not authority:
        conflicts.append("Missing authority")

    if not precedence:
        conflicts.append("Missing precedence result")

    if jurisdiction and authority:
        country = jurisdiction.get("country")
        primary = authority.get("primary_authority")

        if country == "AU" and primary == "US Federal Authority":
            conflicts.append("Jurisdiction-authority mismatch: AU vs US")
        elif country == "US" and primary == "Australian Federal Authority":
            conflicts.append("Jurisdiction-authority mismatch: US vs AU")
        elif country == "EU" and primary not in ["European Commission", "Member State Authority", None]:
            conflicts.append("Jurisdiction-authority mismatch: EU routing conflict")

    if precedence:
        if precedence.get("escalation_required") and precedence.get("winning_authority") is not None:
            conflicts.append("Escalation conflict: winning authority set while escalation required")

    result = {
        "conflict_found": len(conflicts) > 0,
        "conflicts": conflicts,
        "action": action
    }

    if result["conflict_found"]:
        return EngineResult(
            ok=False,
            name="conflict_detection",
            detail="Governance conflict detected",
            data=result
        )

    return EngineResult(
        ok=True,
        name="conflict_detection",
        detail="No governance conflicts detected",
        data=result
    )
