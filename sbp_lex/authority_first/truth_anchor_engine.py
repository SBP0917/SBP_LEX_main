from sbp_lex.types import EngineResult
from .registry import register
import hashlib
import json
import time


@register("truth_anchor")
def truth_anchor_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    output = payload.get("output", {})
    attestations = payload.get("indexed_attestations", [])

    if not attestations:
        return EngineResult(
            ok=False,
            name="truth_anchor",
            detail="No indexed attestations available for truth anchoring"
        )

    anchor_material = {
        "action": action,
        "output": output,
        "attestation_sources": attestations,
        "timestamp": int(time.time())
    }

    anchor_hash = hashlib.sha512(
        json.dumps(anchor_material, sort_keys=True).encode()
    ).hexdigest()

    record = {
        "action": action,
        "attestation_count": len(attestations),
        "truth_anchor_hash": anchor_hash,
        "truth_anchor_created": True,
        "timestamp": anchor_material["timestamp"],
        "expires_in": 300,
    }

    return EngineResult(
        ok=True,
        name="truth_anchor",
        detail="Truth anchor generated from indexed attestations",
        data=record
    )
