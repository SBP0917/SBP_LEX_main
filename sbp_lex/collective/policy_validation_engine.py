from sbp_lex.types import EngineResult
from .registry import register


@register("policy_validation")
def policy_validation_engine(payload: dict) -> EngineResult:
    policy = payload.get("policy")
    action = payload.get("action")
    authority = payload.get("authority")

    if not policy:
        return EngineResult(
            ok=False,
            name="policy_validation",
            detail="No policy provided"
        )

    allowed_actions = policy.get("allowed_actions", [])
    restricted_actions = policy.get("restricted_actions", [])

    if action in restricted_actions:
        return EngineResult(
            ok=False,
            name="policy_validation",
            detail="Action restricted by policy",
            data={"action": action}
        )

    if allowed_actions and action not in allowed_actions:
        return EngineResult(
            ok=False,
            name="policy_validation",
            detail="Action not permitted under policy",
            data={"action": action}
        )

    return EngineResult(
        ok=True,
        name="policy_validation",
        detail="Policy validation successful",
        data={
            "action": action,
            "authority": authority
        }
    )
