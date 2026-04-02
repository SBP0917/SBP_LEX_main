from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import time


@register("audit")
def audit_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    authority = payload.get("authority")
    jurisdiction = payload.get("jurisdiction")
    precedence = payload.get("precedence")
    attestation = payload.get("attestation")
    anchor_validation = payload.get("anchor_validation")

    timestamp = int(time.time())

    audit_string = (
        f"{timestamp}|{action}|{authority}|{jurisdiction}|"
        f"{precedence}|{attestation}|{anchor_validation}"
    )

    audit_hash = hashlib.sha256(audit_string.encode()).hexdigest()

    audit_record = {
        "timestamp": timestamp,
        "action": action,
        "authority": authority,
        "jurisdiction": jurisdiction,
        "precedence": precedence,
        "attestation": attestation,
        "anchor_validation": anchor_validation,
        "audit_hash": audit_hash
    }

    return EngineResult(
        ok=True,
        name="audit",
        detail="Governance audit record created",
        data={"audit_record": audit_record}
    )
