from sbp_lex.types import EngineResult
from .registry import register


@register("escalation")
def escalation_engine(payload: dict) -> EngineResult:
    conflict = payload.get("conflict_detection", {})
    precedence = payload.get("precedence", {})
    action = payload.get("action")
    authority = payload.get("authority")

    conflict_found = conflict.get("conflict_found", False)
    conflicts = conflict.get("conflicts", [])
    escalation_required = precedence.get("escalation_required", False)

    escalation_record = {
        "action": action,
        "authority": authority,
        "conflict_found": conflict_found,
        "conflicts": conflicts,
        "escalation_required": escalation_required,
        "escalation_target": None,
    }

    if conflict_found or escalation_required:
        escalation_record["escalation_target"] = "supervisory_authority"

        return EngineResult(
            ok=False,
            name="escalation",
            detail="Escalation required",
            data={"escalation": escalation_record}
        )

    return EngineResult(
        ok=True,
        name="escalation",
        detail="No escalation required",
        data={"escalation": escalation_record}
    )
