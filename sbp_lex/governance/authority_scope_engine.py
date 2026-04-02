from sbp_lex.types import EngineResult
from .registry import register


@register("authority_scope")
def authority_scope_engine(payload: dict) -> EngineResult:
    authority = payload.get("authority", {})
    action = payload.get("action")
    scope = authority.get("authorized_scope", [])

    record = {
        "action": action,
        "authorized_scope": scope,
        "action_within_scope": action in scope if scope else False
    }

    if not scope:
        return EngineResult(
            ok=False,
            name="authority_scope",
            detail="Authority scope not defined",
            data={"authority_scope": record}
        )

    if not record["action_within_scope"]:
        return EngineResult(
            ok=False,
            name="authority_scope",
            detail="Action outside authority scope",
            data={"authority_scope": record}
        )

    return EngineResult(
        ok=True,
        name="authority_scope",
        detail="Authority scope validated",
        data={"authority_scope": record}
    )
