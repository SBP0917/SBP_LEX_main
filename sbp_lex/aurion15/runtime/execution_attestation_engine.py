from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import time


@register("execution_attestation")
def execution_attestation_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    authority_chain = payload.get("authority_chain")
    jurisdiction = payload.get("jurisdiction")
    anchor_validation = payload.get("anchor_validation")

    timestamp = int(time.time())

    attestation_material = f"{action}|{authority_chain}|{jurisdiction}|{anchor_validation}|{timestamp}"
    attestation_hash = hashlib.sha256(attestation_material.encode()).hexdigest()

    record = {
        "timestamp": timestamp,
        "action": action,
        "authority_chain": authority_chain,
        "jurisdiction": jurisdiction,
        "anchor_validation": anchor_validation,
        "execution_attestation_hash": attestation_hash
    }

    return EngineResult(
        ok=True,
        name="execution_attestation",
        detail="Execution authorization attested",
        data={"execution_attestation": record}
    )
