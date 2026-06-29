from sbp_lex.types import EngineResult
from .registry import register


@register("digital_twin_network")
def digital_twin_network_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction", {})
    action = payload.get("action")
    twin_data = payload.get("digital_twin", {})

    country = jurisdiction.get("country")
    region = jurisdiction.get("region")

    if not country:
        return EngineResult(
            ok=False,
            name="digital_twin_network",
            detail="Jurisdiction country missing",
        )

    twin_record = {
        "country": country,
        "region": region,
        "action": action,
        "twin_available": twin_data.get("available", False),
        "twin_verified": twin_data.get("verified", False),
        "network_bound": True,
    }

    if not twin_record["twin_available"]:
        return EngineResult(
            ok=False,
            name="digital_twin_network",
            detail="Digital twin unavailable",
            data={"digital_twin_network": twin_record},
        )

    if not twin_record["twin_verified"]:
        return EngineResult(
            ok=False,
            name="digital_twin_network",
            detail="Digital twin not verified",
            data={"digital_twin_network": twin_record},
        )

    return EngineResult(
        ok=True,
        name="digital_twin_network",
        detail="Digital twin network resolved",
        data={"digital_twin_network": twin_record},
    )
