from sbp_lex.types import EngineResult
from .registry import register


@register("authority_confidence")
def authority_confidence_engine(payload: dict) -> EngineResult:
    authority = payload.get("authority", {})
    jurisdiction = payload.get("jurisdiction")
    action = payload.get("action")

    signals = [
        authority.get("primary_authority"),
        authority.get("secondary_authority"),
        authority.get("regulator"),
        jurisdiction
    ]

    score = sum(1 for s in signals if s) / len(signals)

    record = {
        "action": action,
        "authority_signals_present": sum(1 for s in signals if s),
        "authority_signals_total": len(signals),
        "confidence_score": score
    }

    if score < 0.75:
        return EngineResult(
            ok=False,
            name="authority_confidence",
            detail="Authority confidence insufficient",
            data={"authority_confidence": record}
        )

    return EngineResult(
        ok=True,
        name="authority_confidence",
        detail="Authority confidence validated",
        data={"authority_confidence": record}
    )
