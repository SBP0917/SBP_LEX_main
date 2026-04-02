from sbp_lex.types import EngineResult
from .registry import register


@register("planetary_population_constraints")
def planetary_population_constraints_engine(payload: dict) -> EngineResult:
    action = payload.get("action")
    constraints = payload.get("constraints", {})

    environmental_safe = constraints.get("environmental_safe", False)
    population_safe = constraints.get("population_safe", False)
    resource_safe = constraints.get("resource_safe", False)

    record = {
        "action": action,
        "environmental_safe": environmental_safe,
        "population_safe": population_safe,
        "resource_safe": resource_safe
    }

    if not environmental_safe:
        return EngineResult(
            ok=False,
            name="planetary_population_constraints",
            detail="Environmental constraint failed",
            data={"constraints_record": record}
        )

    if not population_safe:
        return EngineResult(
            ok=False,
            name="planetary_population_constraints",
            detail="Population integrity constraint failed",
            data={"constraints_record": record}
        )

    if not resource_safe:
        return EngineResult(
            ok=False,
            name="planetary_population_constraints",
            detail="Resource constraint failed",
            data={"constraints_record": record}
        )

    return EngineResult(
        ok=True,
        name="planetary_population_constraints",
        detail="Planetary and population constraints validated",
        data={"constraints_record": record}
    )
