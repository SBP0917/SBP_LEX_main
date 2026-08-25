from collections.abc import Callable
from typing import TypeVar

from sbp_lex.aurion15.core.registry import aurion_registry
from sbp_lex.shared.types import EngineResult


RuntimeEngine = Callable[[dict[str, object]], EngineResult]
_RuntimeEngineT = TypeVar("_RuntimeEngineT", bound=RuntimeEngine)

ENGINE_REGISTRY: dict[str, RuntimeEngine] = {}


def register(name: str) -> Callable[[_RuntimeEngineT], _RuntimeEngineT]:
    def decorator(fn: _RuntimeEngineT) -> _RuntimeEngineT:
        ENGINE_REGISTRY[name] = fn
        return fn

    return decorator


__all__ = ["ENGINE_REGISTRY", "aurion_registry", "register"]
