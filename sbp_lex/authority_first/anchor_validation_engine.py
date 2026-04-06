from sbp_lex.shared.types import EngineResult
from .registry import register


@register("anchor_validation")
def anchor_validation_engine(payload: dict) -> EngineResult:
    anchors = payload.get("anchors")
    action = payload.get("action")

    if not anchors:
        return EngineResult(
            ok=False,
            name="anchor_validation",
            detail="No anchors provided"
        )

    required_anchors = [
        "procedural_truth",
        "sovereign_knowledge_graph",
        "digital_twin_network",
        "planetary_population_constraints"
    ]

    missing = []

    for anchor in required_anchors:
        if anchor not in anchors or anchors.get(anchor) is not True:
            missing.append(anchor)

    if missing:
        return EngineResult(
            ok=False,
            name="anchor_validation",
            detail="Anchor validation failed",
            data={"missing_anchors": missing}
        )

    return EngineResult(
        ok=True,
        name="anchor_validation",
        detail="All governance anchors validated",
        data={"action": action}
    )
