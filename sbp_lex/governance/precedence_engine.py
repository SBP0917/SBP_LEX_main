# sbp_lex/engines/aurion15/precedence_engine.py

from sbp_lex.types import EngineResult
from .registry import register


@register("precedence")
def precedence_engine(payload: dict) -> EngineResult:
    authority = payload.get("authority")
    action = payload.get("action")

    if not authority:
        return EngineResult(
            ok=False,
            name="precedence",
            detail="No authority provided"
        )

    primary = authority.get("primary_authority")
    secondary = authority.get("secondary_authority")
    escalation_required = authority.get("escalation_required", False)

    precedence = {
        "winning_authority": None,
        "fallback_authority": secondary,
        "escalation_required": escalation_required,
        "action": action
    }

    if escalation_required:
        precedence["winning_authority"] = None
    elif primary:
        precedence["winning_authority"] = primary
    elif secondary:
        precedence["winning_authority"] = secondary

    if not precedence["winning_authority"] and not escalation_required:
        return EngineResult(
            ok=False,
            name="precedence",
            detail="No governing authority determined"
        )

    return EngineResult(
        ok=True,
        name="precedence",
        detail="Authority precedence resolved",
        data={
            "precedence": precedence,
            "action": action
        }
    )
