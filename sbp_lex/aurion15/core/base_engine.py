from __future__ import annotations

from typing import Any, Dict, List

from sbp_lex.types import EngineResult


class AurionEngine:
    """Common deterministic contract for class-based Aurion engines."""

    name = "base_engine"
    stage = 0
    depends_on: List[str] = []

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError("Aurion engines must implement execute(state)")


class BaseEngine:
    """Legacy EngineResult contract retained for function-style adapters."""

    name = "base"

    def run(self, payload: dict) -> EngineResult:
        return EngineResult(
            ok=True,
            name=self.name,
            detail="Base engine executed",
            data=payload,
        )
