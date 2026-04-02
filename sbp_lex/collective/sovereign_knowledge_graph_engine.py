from sbp_lex.types import EngineResult
from .registry import register


@register("sovereign_knowledge_graph")
def sovereign_knowledge_graph_engine(payload: dict) -> EngineResult:
    jurisdiction = payload.get("jurisdiction", {})
    authority = payload.get("authority", {})
    action = payload.get("action")

    country = jurisdiction.get("country")
    region = jurisdiction.get("region")
    primary_authority = authority.get("primary_authority")

    if not country:
        return EngineResult(
            ok=False,
            name="sovereign_knowledge_graph",
            detail="Jurisdiction country missing"
        )

    graph_record = {
        "country": country,
        "region": region,
        "primary_authority": primary_authority,
        "action": action,
        "graph_resolved": True
    }

    return EngineResult(
        ok=True,
        name="sovereign_knowledge_graph",
        detail="Sovereign knowledge graph resolved",
        data={"sovereign_knowledge_graph": graph_record}
    )
