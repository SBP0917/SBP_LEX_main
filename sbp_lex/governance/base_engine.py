from sbp_lex.types import EngineResult


class BaseEngine:
    name = "base_engine"

    def run(self, context: dict) -> EngineResult:
        return EngineResult(
            ok=False,
            name=self.name,
            detail="Engine run method not implemented",
        )
