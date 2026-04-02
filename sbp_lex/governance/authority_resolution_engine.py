from sbp_lex.types import EngineResult
from .registry import register


@register("authority_resolution")
def authority_resolution_engine(payload: dict) -> EngineResult:

    jurisdiction = payload.get("jurisdiction")
    action = payload.get("action")

    if not jurisdiction:
        return EngineResult(
            ok=False,
            name="authority_resolution",
            detail="No jurisdiction provided"
        )

    authority = {
        "primary_authority": None,
        "secondary_authority": None,
        "escalation_required": False
    }

    country = jurisdiction.get("country")

    if country == "AU":
        authority["primary_authority"] = "Australian Federal Authority"
        authority["secondary_authority"] = "State Authority"

    elif country == "US":
        authority["primary_authority"] = "US Federal Authority"
        authority["secondary_authority"] = "State Authority"

    elif country == "EU":
        authority["primary_authority"] = "European Commission"
        authority["secondary_authority"] = "Member State Authority"

    else:
        authority["primary_authority"] = "External Sovereign Authority"
        authority["escalation_required"] = True

    return EngineResult(
        ok=True,
        name="authority_resolution",
        detail="Authority resolved",
        data={
            "authority": authority,
            "action": action
        }
    )
