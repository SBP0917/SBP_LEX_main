from __future__ import annotations

from typing import Dict, Iterable, List, Set

from .base_engine import AurionEngine


class AurionRegistry:
    """Shared registry for Aurion engines distributed across V2 packages."""

    def __init__(self) -> None:
        self._engines: Dict[str, AurionEngine] = {}
        self._aliases: Dict[str, str] = {}

    def register(self, engine: AurionEngine) -> None:
        if not isinstance(engine, AurionEngine):
            raise TypeError("Registered Aurion engines must inherit AurionEngine")
        if not engine.name or engine.name == "base_engine":
            raise ValueError("Aurion engines must declare a unique name")
        if engine.name in self._engines:
            existing = self._engines[engine.name]
            if type(existing) is type(engine):
                return
            raise ValueError(f"Engine already registered: {engine.name}")
        self._engines[engine.name] = engine

    def register_alias(self, alias: str, engine_name: str) -> None:
        if alias in self._engines:
            raise ValueError(f"Alias conflicts with registered engine: {alias}")
        existing = self._aliases.get(alias)
        if existing is not None and existing != engine_name:
            raise ValueError(f"Alias already registered: {alias}")
        self._aliases[alias] = engine_name

    def resolve_name(self, name: str) -> str:
        return self._aliases.get(name, name)

    def get(self, name: str) -> AurionEngine:
        resolved = self.resolve_name(name)
        if resolved not in self._engines:
            raise KeyError(f"Engine not registered: {name}")
        return self._engines[resolved]

    def all(self) -> List[AurionEngine]:
        return list(self._engines.values())

    def names(self) -> List[str]:
        return sorted(self._engines)

    def stage_ordered(self) -> List[AurionEngine]:
        """Return a stable inspection order without claiming dependency safety."""
        return sorted(
            self._engines.values(),
            key=lambda engine: (getattr(engine, "stage", 0), engine.name),
        )

    def unresolved_dependencies(
        self,
        provided: Iterable[str] = (),
    ) -> Dict[str, List[str]]:
        supplied = {self.resolve_name(name) for name in provided}
        available = set(self._engines) | supplied
        unresolved: Dict[str, List[str]] = {}

        for engine in self._engines.values():
            missing = sorted(
                dependency
                for dependency in getattr(engine, "depends_on", [])
                if self.resolve_name(dependency) not in available
            )
            if missing:
                unresolved[engine.name] = missing

        return unresolved

    def dependency_cycles(self, provided: Iterable[str] = ()) -> List[List[str]]:
        """Report strongly connected groups requiring convergence handling."""
        supplied = {self.resolve_name(name) for name in provided}
        graph = {
            name: [
                self.resolve_name(dependency)
                for dependency in getattr(engine, "depends_on", [])
                if self.resolve_name(dependency) in self._engines
                and self.resolve_name(dependency) not in supplied
            ]
            for name, engine in self._engines.items()
        }

        index = 0
        indices: Dict[str, int] = {}
        lowlinks: Dict[str, int] = {}
        stack: List[str] = []
        on_stack: Set[str] = set()
        components: List[List[str]] = []

        def connect(name: str) -> None:
            nonlocal index
            indices[name] = index
            lowlinks[name] = index
            index += 1
            stack.append(name)
            on_stack.add(name)

            for dependency in graph[name]:
                if dependency not in indices:
                    connect(dependency)
                    lowlinks[name] = min(lowlinks[name], lowlinks[dependency])
                elif dependency in on_stack:
                    lowlinks[name] = min(lowlinks[name], indices[dependency])

            if lowlinks[name] != indices[name]:
                return

            component: List[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == name:
                    break

            component.sort()
            if len(component) > 1 or name in graph[name]:
                components.append(component)

        for engine_name in sorted(graph):
            if engine_name not in indices:
                connect(engine_name)

        return sorted(components)


aurion_registry = AurionRegistry()
