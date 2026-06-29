ENGINE_REGISTRY = {}


def register(name: str):
    def decorator(fn):
        ENGINE_REGISTRY[name] = fn
        return fn

    return decorator
