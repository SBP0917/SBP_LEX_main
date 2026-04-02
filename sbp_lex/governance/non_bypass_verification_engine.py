from sbp_lex.types import EngineResult
from .registry import register


@register("non_bypass_verification")
def non_bypass_verification_engine(payload: dict) -> EngineResult:
    decision_token = payload.get("decision_token")
    execution_request = payload.get("execution_request", {})
    action = payload.get("action")

    token_present = decision_token is not None
    token_hash = decision_token.get("token_hash") if token_present else None
    bound_action = decision_token.get("action") if token_present else None

    verification = {
        "token_present": token_present,
        "token_hash": token_hash,
        "action_matches_token": bound_action == action if token_present else False,
        "execution_path_bound": execution_request.get("token_required", False) is True,
    }

    if not verification["token_present"]:
        return EngineResult(
            ok=False,
            name="non_bypass_verification",
            detail="No decision token present",
            data=verification
        )

    if not verification["action_matches_token"]:
        return EngineResult(
            ok=False,
            name="non_bypass_verification",
            detail="Decision token does not match action",
            data=verification
        )

    if not verification["execution_path_bound"]:
        return EngineResult(
            ok=False,
            name="non_bypass_verification",
            detail="Execution path not bound to token enforcement",
            data=verification
        )

    return EngineResult(
        ok=True,
        name="non_bypass_verification",
        detail="Non-bypass conditions verified",
        data=verification
    )
