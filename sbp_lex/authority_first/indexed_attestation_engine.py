from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json
import time


@indexed = None
@register("indexed_attestation")
def indexed_attestation_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    output = payload.get("output", {})
    attestations = payload.get("indexed_attestations", [])

    if len(attestations) == 0:
        return EngineResult(
            ok=False,
            name="indexed_attestation",
            detail="No indexed attestations provided"
        )

    normalized_attestations = []

    for attestation in attestations:
        normalized_attestations.append({
            "source_id": attestation.get("source_id"),
            "source_type": attestation.get("source_type"),
            "attestation_hash": attestation.get("attestation_hash"),
            "verified": attestation.get("verified", False),
            "timestamp": attestation.get("timestamp"),
        })

    verified_count = sum(
        1 for item in normalized_attestations if item.get("verified") is True
    )

    record_material = {
        "action": action,
        "output": output,
        "indexed_attestations": normalized_attestations,
        "timestamp": int(time.time()),
    }

    record_hash = hashlib.sha256(
        json.dumps(record_material, sort_keys=True).encode()
    ).hexdigest()

    record = {
        "action": action,
        "attestation_count": len(normalized_attestations),
        "verified_attestation_count": verified_count,
        "all_attestations_verified": verified_count == len(normalized_attestations),
        "indexed_attestation_hash": record_hash,
        "indexed_attestations": normalized_attestations,
    }

    if not record["all_attestations_verified"]:
        return EngineResult(
            ok=False,
            name="indexed_attestation",
            detail="Indexed attestation verification failed",
            data={"indexed_attestation": record}
