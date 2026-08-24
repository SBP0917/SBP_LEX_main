from sbp_lex.types import EngineResult
from .registry import register
import hashlib


@register("authority_attestation")
def authority_attestation_engine(payload: dict) -> EngineResult:
    authority_chain = payload.get("authority_chain")
    jurisdiction = payload.get("jurisdiction")
    action = payload.get("action")

    if not authority_chain:
        return EngineResult(
            ok=False,
            name="authority_attestation",
            detail="Authority chain missing"
        )

    timestamp = int(payload.get("evaluation_time", 0))

    attestation_string = f"{authority_chain}|{jurisdiction}|{action}|{timestamp}"
    attestation_hash = hashlib.sha512(attestation_string.encode()).hexdigest()

    record = {
        "timestamp": timestamp,
        "authority_chain": authority_chain,
        "jurisdiction": jurisdiction,
        "action": action,
        "authority_attestation_hash": attestation_hash
    }

    return EngineResult(
        ok=True,
        name="authority_attestation",
        detail="Authority legitimacy attested",
        data={"authority_attestation": record}
    )
