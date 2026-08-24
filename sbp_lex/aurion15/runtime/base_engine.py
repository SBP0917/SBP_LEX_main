from sbp_lex.types import EngineResult
from sbp_lex.aurion15.core.base_engine import AurionEngine


class BaseEngine:
    name = "base_engine"

    def run(self, context: dict) -> EngineResult:
        return EngineResult(
            ok=False,
            name=self.name,
            detail="Engine run method not implemented",
        )


__all__ = ["AurionEngine", "BaseEngine"]
