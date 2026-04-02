from sbp_lex.types import EngineResult

class BaseEngine:

    name = "base"

    def run(self, payload: dict) -> EngineResult:
        return EngineResult(
            ok=True,
            name=self.name,
            detail="Base engine executed",
            data=payload
        )
