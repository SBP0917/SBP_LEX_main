from sbp_lex.types import EngineResult
from .registry import register


@register("truth_revocation")
def truth_revocation_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    truth_anchor = payload.get("truth_anchor")
    revocation_index = payload.get("revoked_truth_anchors", [])

    anchor_hash = None
    revoked = False

    if truth_anchor:
        anchor_hash = truth_anchor.get("truth_anchor_hash")
        revoked = anchor_hash in revocation_index

    record = {
        "action": action,
        "truth_anchor_present": truth_anchor is not None,
        "truth_anchor_hash": anchor_hash,
        "revoked": revoked
    }

    if not truth_anchor:
        return EngineResult(
            ok=False,
            name="truth_revocation",
            detail="Truth anchor missing",
            data={"truth_revocation": record}
        )

    if revoked:
        return EngineResult(
            ok=False,
            name="truth_revocation",
            detail="Truth anchor revoked",
            data={"truth_revocation": record}
        )

    return EngineResult(
        ok=True,
        name="truth_revocation",
        detail="Truth anchor valid and not revoked",
        data={"truth_revocation": record}
    )
