from sbp_lex.types import EngineResult
from .registry import register


@register("authority_revocation")
def authority_revocation_engine(payload: dict) -> EngineResult:
    authority = payload.get("authority", {})
    decision_token = payload.get("decision_token")
    revocation_list = payload.get("revocation_list", [])
    action = payload.get("action")

    primary_authority = authority.get("primary_authority")

    record = {
        "action": action,
        "authority": primary_authority,
        "token_present": decision_token is not None,
        "revoked": primary_authority in revocation_list
    }

    if not record["token_present"]:
        return EngineResult(
            ok=False,
            name="authority_revocation",
            detail="Execution blocked: missing decision token",
            data={"authority_revocation": record}
        )

    if record["revoked"]:
        return EngineResult(
            ok=False,
            name="authority_revocation",
            detail="Authority revoked",
            data={"authority_revocation": record}
        )

    return EngineResult(
        ok=True,
        name="authority_revocation",
        detail="Authority revocation check passed",
        data={"authority_revocation": record}
    )
