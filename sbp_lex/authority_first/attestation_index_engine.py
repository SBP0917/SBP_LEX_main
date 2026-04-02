from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json
import time


@register("attestation_index")
def attestation_index_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    attestations = payload.get("indexed_attestations", [])

    if not attestations:
        return EngineResult(
            ok=False,
            name="attestation_index",
            detail="No attestations supplied for indexing"
        )

    indexed_records = []

    for att in attestations:
        material = {
            "source_id": att.get("source_id"),
            "source_type": att.get("source_type"),
            "attestation_hash": att.get("attestation_hash"),
            "timestamp": att.get("timestamp"),
        }

        index_hash = hashlib.sha256(
            json.dumps(material, sort_keys=True).encode()
        ).hexdigest()

        indexed_records.append({
            "index_hash": index_hash,
            "material": material
        })

    index_record = {
        "action": action,
        "indexed_count": len(indexed_records),
        "indexed_records": indexed_records,
        "timestamp": int(time.time())
    }

    return EngineResult(
        ok=True,
        name="attestation_index",
        detail="Indexed attestation records generated",
        data={"attestation_index": index_record}
    )
