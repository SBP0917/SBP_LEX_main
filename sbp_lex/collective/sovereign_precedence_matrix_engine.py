from sbp_lex.types import EngineResult
from .registry import register


@register("sovereign_precedence_matrix")
def sovereign_precedence_matrix_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction", {})
    authority = payload.get("authority", {})
    action = payload.get("action")

    country = jurisdiction.get("country")
    regional = authority.get("regional_authority")
    national = authority.get("national_authority")
    international = authority.get("international_authority")

    precedence_order = []

    if national:
        precedence_order.append(national)

    if regional:
        precedence_order.append(regional)

    if international:
        precedence_order.append(international)

    record = {
        "country": country,
        "action": action,
        "precedence_order": precedence_order,
        "precedence_established": len(precedence_order) > 0
    }

    if not record["precedence_established"]:
        return EngineResult(
            ok=False,
            name="sovereign_precedence_matrix",
            detail="No sovereign precedence determined",
            data={"precedence_matrix": record}
        )

    return EngineResult(
        ok=True,
        name="sovereign_precedence_matrix",
        detail="Sovereign precedence matrix resolved",
        data={"precedence_matrix": record}
    )
