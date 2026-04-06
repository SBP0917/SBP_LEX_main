from sbp_lex.types import EngineResult
from .registry import register


@register("jurisdiction_verification")
def jurisdiction_verification_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")

    if not jurisdiction:
        return EngineResult(
            ok=False,
            name="jurisdiction_verification",
            detail="Jurisdiction missing"
        )

    country = jurisdiction.get("country")
    region = jurisdiction.get("region")
    authority_primary = authority.get("primary_authority") if authority else None

    verification = {
        "country": country,
        "region": region,
        "authority": authority_primary
    }

    if not country:
        return EngineResult(
            ok=False,
            name="jurisdiction_verification",
            detail="Invalid jurisdiction: country not specified",
            data=verification
        )

    return EngineResult(
        ok=True,
        name="jurisdiction_verification",
        detail="Jurisdiction verified",
        data=verification
    )
