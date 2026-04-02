from sbp_lex.types import EngineResult
from .registry import register


@register("supervisory_override")
def supervisory_override_engine(payload: dict) -> EngineResult:
    override = payload.get("override", {})
    decision_token = payload.get("decision_token")
    action = payload.get("action")

    override_requested = override.get("requested", False)
    override_authorized = override.get("authorized", False)
    override_reason = override.get("reason")

    record = {
        "action": action,
        "token_present": decision_token is not None,
        "override_requested": override_requested,
        "override_authorized": override_authorized,
        "override_reason": override_reason,
    }

    if not record["token_present"]:
        return EngineResult(
            ok=False,
            name="supervisory_override",
            detail="Missing decision token",
            data={"supervisory_override": record}
        )

    if override_requested and not override_authorized:
        return EngineResult(
            ok=False,
            name="supervisory_override",
            detail="Supervisory override requested but not authorized",
            data={"supervisory_override": record}
        )

    return EngineResult(
        ok=True,
        name="supervisory_override",
        detail="Supervisory override state valid",
        data={"supervisory_override": record}
    )
