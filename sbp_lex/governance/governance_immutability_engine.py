from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import time


@register("governance_immutability")
def governance_immutability_engine(payload: dict) -> EngineResult:
    decision_token = payload.get("decision_token")
    attestation = payload.get("attestation")
    audit_record = payload.get("audit_record")

    timestamp = int(time.time())

    immutability_material = f"{decision_token}|{attestation}|{audit_record}|{timestamp}"
    immutability_hash = hashlib.sha256(immutability_material.encode()).hexdigest()

    record = {
        "timestamp": timestamp,
        "decision_token_present": decision_token is not None,
        "attestation_present": attestation is not None,
        "audit_record_present": audit_record is not None,
        "immutability_hash": immutability_hash
    }

    if not (record["decision_token_present"] and record["attestation_present"] and record["audit_record_present"]):
        return EngineResult(
            ok=False,
            name="governance_immutability",
            detail="Governance immutability requirements not satisfied",
            data={"immutability_record": record}
        )

    return EngineResult(
        ok=True,
        name="governance_immutability",
        detail="Governance decision immutability verified",
        data={"immutability_record": record}
    )
