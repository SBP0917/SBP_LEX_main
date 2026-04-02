from sbp_lex.types import EngineResult
from .registry import register


@register("attestation_consensus")
def attestation_consensus_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    attestations = payload.get("indexed_attestations", [])

    if not attestations:
        return EngineResult(
            ok=False,
            name="attestation_consensus",
            detail="No attestations available for consensus evaluation"
        )

    total = len(attestations)
    verified = sum(1 for a in attestations if a.get("verified") is True)

    consensus_ratio = verified / total if total > 0 else 0.0

    record = {
        "action": action,
        "attestation_count": total,
        "verified_count": verified,
        "consensus_ratio": consensus_ratio,
        "consensus_valid": False,
    }

    if consensus_ratio < 0.99999:
        return EngineResult(
            ok=False,
            name="attestation_consensus",
            detail="Attestation consensus below PTODF threshold",
            data={"attestation_consensus": record}
        )

    record["consensus_valid"] = True

    return EngineResult(
        ok=True,
        name="attestation_consensus",
        detail="Attestation consensus verified",
        data={"attestation_consensus": record}
    )
