from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json


@register("governance_integrity")
def governance_integrity_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction")
    authority = payload.get("authority")
    policy = payload.get("policy")
    anchors = payload.get("anchors")
    decision_token = payload.get("decision_token")
    action = payload.get("action")

    integrity_material = {
        "jurisdiction": jurisdiction,
        "authority": authority,
        "policy": policy,
        "anchors": anchors,
        "decision_token": decision_token
    }

    integrity_hash = hashlib.sha256(
        json.dumps(integrity_material, sort_keys=True).encode()
    ).hexdigest()

    record = {
        "action": action,
        "jurisdiction_present": jurisdiction is not None,
        "authority_present": authority is not None,
        "policy_present": policy is not None,
        "anchors_present": anchors is not None,
        "decision_token_present": decision_token is not None,
        "integrity_hash": integrity_hash
    }

    if not all([
        record["jurisdiction_present"],
        record["authority_present"],
        record["policy_present"],
        record["anchors_present"],
        record["decision_token_present"]
    ]):
        return EngineResult(
            ok=False,
            name="governance_integrity",
            detail="Governance integrity validation failed",
            data={"governance_integrity": record}
        )

    return EngineResult(
        ok=True,
        name="governance_integrity",
        detail="Governance integrity validated",
        data={"governance_integrity": record}
    )
