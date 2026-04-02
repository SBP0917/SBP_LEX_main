from sbp_lex.types import EngineResult
from .registry import register


@register("output_discipline")
def output_discipline_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    output = payload.get("output", {})
    decision_token = payload.get("decision_token")
    procedural_truth = payload.get("procedural_truth", {})

    contains_unverified_content = output.get("contains_unverified_content", True)
    contains_speculative_content = output.get("contains_speculative_content", True)
    contains_unauthorized_inference = output.get("contains_unauthorized_inference", True)
    passes_ptodf = procedural_truth.get("passes_ptodf", False)

    record = {
        "action": action,
        "decision_token_present": decision_token is not None,
        "passes_ptodf": passes_ptodf,
        "contains_unverified_content": contains_unverified_content,
        "contains_speculative_content": contains_speculative_content,
        "contains_unauthorized_inference": contains_unauthorized_inference,
        "output_disciplined": False,
    }

    if decision_token is None:
        return EngineResult(
            ok=False,
            name="output_discipline",
            detail="Output discipline failed: no decision token present",
            data={"output_discipline": record}
        )

    if not passes_ptodf:
        return EngineResult(
            ok=False,
            name="output_discipline",
            detail="Output discipline failed: PTODF not satisfied",
            data={"output_discipline": record}
        )

    if contains_unverified_content:
        return EngineResult(
            ok=False,
            name="output_discipline",
            detail="Output discipline failed: unverified content detected",
            data={"output_discipline": record}
        )

    if contains_speculative_content:
        return EngineResult(
            ok=False,
            name="output_discipline",
            detail="Output discipline failed: speculative content detected",
            data={"output_discipline": record}
        )

    if contains_unauthorized_inference:
        return EngineResult(
            ok=False,
            name="output_discipline",
            detail="Output discipline failed: unauthorized inference detected",
            data={"output_discipline": record}
        )

    record["output_disciplined"] = True

    return EngineResult(
        ok=True,
        name="output_discipline",
        detail="Output discipline verified",
        data={"output_discipline": record}
    )
