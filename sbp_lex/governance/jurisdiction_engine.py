from sbp_lex.types import EngineResult
from .registry import register


@register("jurisdiction_determination")
def jurisdiction_engine(payload: dict) -> EngineResult:

    user_country = payload.get("country")
    user_region = payload.get("region")
    action = payload.get("action")

    if not user_country:
        return EngineResult(
            ok=False,
            name="jurisdiction_determination",
            detail="No country provided"
        )

    jurisdiction = {
        "country": user_country,
        "region": user_region,
        "legal_framework": None
    }

    if user_country == "AU":
        jurisdiction["legal_framework"] = "Australia Federal Law"

    elif user_country == "US":
        jurisdiction["legal_framework"] = "United States Federal Law"

    elif user_country == "EU":
        jurisdiction["legal_framework"] = "EU Regulatory Framework"

    else:
        jurisdiction["legal_framework"] = "Unknown / External Jurisdiction"

    return EngineResult(
        ok=True,
        name="jurisdiction_determination",
        detail="Jurisdiction determined",
        data={
            "jurisdiction": jurisdiction,
            "action": action
        }
    )
