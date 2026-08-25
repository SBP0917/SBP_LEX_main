from collections.abc import Callable

from sbp_lex.aurion15.core.registry import aurion_registry

ENGINE_REGISTRY: dict[str, Callable[..., object]] = {}


def register(name: str):
    def decorator(fn):
        ENGINE_REGISTRY[name] = fn
        return fn

    return decorator


__all__ = ["ENGINE_REGISTRY", "aurion_registry", "register"]
