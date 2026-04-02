from sbp_lex.types import EngineResult
from .registry import register


@register("execution_boundary")
def execution_boundary_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    policy = payload.get("policy", {})
    decision_token = payload.get("decision_token")

    allowed_scope = policy.get("allowed_scope", [])
    restricted_scope = policy.get("restricted_scope", [])

    record = {
        "action": action,
        "token_present": decision_token is not None,
        "within_allowed_scope": action in allowed_scope if allowed_scope else True,
        "within_restricted_scope": action in restricted_scope,
    }

    if not record["token_present"]:
        return EngineResult(
            ok=False,
            name="execution_boundary",
            detail="Execution blocked: no decision token",
            data={"execution_boundary": record}
        )

    if record["within_restricted_scope"]:
        return EngineResult(
            ok=False,
            name="execution_boundary",
            detail="Execution blocked: restricted scope",
            data={"execution_boundary": record}
        )

    if not record["within_allowed_scope"]:
        return EngineResult(
            ok=False,
            name="execution_boundary",
            detail="Execution outside allowed scope",
            data={"execution_boundary": record}
        )

    return EngineResult(
        ok=True,
        name="execution_boundary",
        detail="Execution boundary validated",
        data={"execution_boundary": record}
    )
