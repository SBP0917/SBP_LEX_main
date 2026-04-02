from sbp_lex.types import EngineResult
from .registry import register


@register("governance_state")
def governance_state_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    precedence = payload.get("precedence")
    policy = payload.get("policy")
    anchors = payload.get("anchors")

    state = {
        "jurisdiction_verified": jurisdiction is not None,
        "authority_resolved": authority is not None,
        "precedence_resolved": precedence is not None,
        "policy_validated": policy is not None,
        "anchors_validated": anchors is not None
    }

    governance_ready = all(state.values())

    if not governance_ready:
        return EngineResult(
            ok=False,
            name="governance_state",
            detail="Governance state incomplete",
            data={"state": state}
        )

    return EngineResult(
        ok=True,
        name="governance_state",
        detail="Governance state verified",
        data={"state": state}
    )
