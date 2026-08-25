from collections.abc import Callable

ENGINE_REGISTRY: dict[str, Callable[..., object]] = {}


def register(name: str):
    def decorator(fn):
        ENGINE_REGISTRY[name] = fn
        return fn

    return decorator
