from sbp_lex.types import EngineResult
from .registry import register


@register("attestation")
def attestation_engine(payload: dict) -> EngineResult:
    attestation = payload.get("attestation")

    if not attestation:
        return EngineResult(
            ok=False,
            name="attestation",
            detail="No attestation provided"
        )

    if isinstance(attestation, dict):
        verified = attestation.get("verified", False)
        attested = attestation.get("attested", True)

        if not verified or not attested:
            return EngineResult(
                ok=False,
                name="attestation",
                detail="Attestation validation failed",
                data={
                    "verified": verified,
                    "attested": attested,
                }
            )

        return EngineResult(
            ok=True,
            name="attestation",
            detail="Attestation validated",
            data=attestation
        )

    return EngineResult(
        ok=True,
        name="attestation",
        detail="Attestation present",
        data={"attestation": attestation}
    )
