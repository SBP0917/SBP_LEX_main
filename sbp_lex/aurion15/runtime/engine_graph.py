from __future__ import annotations

import hashlib
import json
import math
from copy import deepcopy
from decimal import Decimal
from typing import Any, Iterable

from sbp_lex.aurion15.core.catalog import (
    EXTERNAL_ENGINE_DEPENDENCIES,
    load_aurion_catalog,
)
from sbp_lex.aurion15.core.contracts import (
    ENGINE_CONTRACTS,
    KNOWN_CONVERGENCE_FIELDS,
    validate_engine_contracts,
)
from sbp_lex.aurion15.core.registry import AurionRegistry


MAX_CONVERGENCE_ITERATIONS = 8
_ALLOW_ACTIONS = {None, "", "allow", "pass"}
_REFINE_ACTIONS = {
    "blocked",
    "deny",
    "fail",
    "invalid",
    "redefine_candidate",
    "refine_candidate",
    "require_next_candidate",
}
_ESCALATE_ACTIONS = {"escalate"}


class EngineGraphError(RuntimeError):
    pass


def _normalise(value: Any) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EngineGraphError("ENGINE_GRAPH_NONFINITE_NUMBER")
        # Existing engines calculate with floats.  Decision projections cross
        # the digest boundary as exact decimal strings, never JSON floats.
        return {"decimal": format(Decimal(str(value)).normalize(), "f")}
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise EngineGraphError("ENGINE_GRAPH_NONSTRING_KEY")
        return {key: _normalise(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_normalise(item) for item in value]
    raise EngineGraphError(f"ENGINE_GRAPH_UNSUPPORTED_VALUE:{type(value).__name__}")


def _digest(value: Any) -> str:
    encoded = json.dumps(
        _normalise(value),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha512(encoded).hexdigest()


def _strong_components(registry: AurionRegistry) -> list[tuple[str, ...]]:
    graph = {
        engine.name: tuple(
            registry.resolve_name(dependency)
            for dependency in engine.depends_on
            if registry.resolve_name(dependency) in set(registry.names())
        )
        for engine in registry.all()
    }
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[tuple[str, ...]] = []

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
        members: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            members.append(member)
            if member == name:
                break
        components.append(tuple(sorted(members)))

    for name in sorted(graph):
        if name not in indices:
            connect(name)
    return components


def _execution_components(registry: AurionRegistry) -> list[tuple[str, ...]]:
    components = _strong_components(registry)
    by_name = {
        name: index for index, component in enumerate(components) for name in component
    }
    dependencies: dict[int, set[int]] = {index: set() for index in range(len(components))}
    for engine in registry.all():
        current = by_name[engine.name]
        for dependency in engine.depends_on:
            resolved = registry.resolve_name(dependency)
            if resolved in by_name and by_name[resolved] != current:
                dependencies[current].add(by_name[resolved])

    def component_key(index: int) -> tuple[int, str]:
        return min(
            (registry.get(name).stage, name) for name in components[index]
        )

    remaining = set(dependencies)
    ordered: list[tuple[str, ...]] = []
    while remaining:
        ready = sorted(
            (index for index in remaining if not (dependencies[index] & remaining)),
            key=component_key,
        )
        if not ready:
            raise EngineGraphError("ENGINE_GRAPH_CONDENSATION_CYCLE")
        for index in ready:
            ordered.append(
                tuple(
                    sorted(
                        components[index],
                        key=lambda name: (registry.get(name).stage, name),
                    )
                )
            )
            remaining.remove(index)
    return ordered


def _decision(engine_name: str, state: dict[str, Any]) -> str | None:
    writes = ENGINE_CONTRACTS[engine_name].writes
    field = next(
        (
            candidate
            for candidate in ("candidate_action", "candidate_result", "status")
            if candidate in writes
        ),
        None,
    )
    if field is None:
        return None
    value = state.get(field)
    if value is None:
        return None
    return str(value).strip().lower()


def _invoke_engine(
    state: dict[str, Any],
    registry: AurionRegistry,
    engine_name: str,
    *,
    component_iteration: int,
) -> tuple[str | None, dict[str, Any]]:
    engine = registry.get(engine_name)
    contract = ENGINE_CONTRACTS[engine_name]
    if contract.external_effects or not contract.pure:
        raise EngineGraphError(f"ENGINE_NOT_ADMITTED_AS_PURE:{engine_name}")
    decision_field = next(
        (
            candidate
            for candidate in ("candidate_action", "candidate_result", "status")
            if candidate in contract.writes
        ),
        None,
    )
    if decision_field is not None:
        state.pop(decision_field, None)
    before = deepcopy(state)
    result = engine.execute(state)
    if result is not state:
        raise EngineGraphError(f"ENGINE_REPLACED_CANONICAL_STATE:{engine_name}")
    missing = object()
    changed = sorted(
        key
        for key in set(before) | set(state)
        if before.get(key, missing) != state.get(key, missing)
    )
    undeclared = sorted(set(changed) - set(contract.writes))
    if undeclared:
        raise EngineGraphError(
            f"ENGINE_UNDECLARED_WRITE:{engine_name}:{','.join(undeclared)}"
        )
    action = _decision(engine_name, state)
    record = {
        "engine": engine_name,
        "stage": engine.stage,
        "component_iteration": component_iteration,
        "changed_fields": changed,
        "declared_writes": sorted(contract.writes),
        "decision": action,
        "post_state_digest": _digest({key: state.get(key) for key in sorted(contract.writes)}),
    }
    return action, record


def _convergence_projection(
    component: Iterable[str], state: dict[str, Any]
) -> dict[str, Any]:
    projection: dict[str, Any] = {}
    for engine_name in component:
        fields = KNOWN_CONVERGENCE_FIELDS.get(engine_name)
        if fields is None:
            raise EngineGraphError(
                f"ENGINE_CYCLE_WITHOUT_DECLARED_PROJECTION:{engine_name}"
            )
        projection[engine_name] = {field: state.get(field) for field in fields}
    return projection


def run_registered_engine_graph(
    state: dict[str, Any],
    *,
    max_convergence_iterations: int = MAX_CONVERGENCE_ITERATIONS,
) -> dict[str, Any]:
    """Run every admitted class engine once or in its bounded SCC loop."""

    if type(state) is not dict:
        raise EngineGraphError("ENGINE_GRAPH_STATE_NOT_EXACT_DICT")
    if type(max_convergence_iterations) is not int or max_convergence_iterations < 2:
        raise EngineGraphError("ENGINE_GRAPH_CONVERGENCE_BOUND_INVALID")
    registry = load_aurion_catalog()
    unresolved = registry.unresolved_dependencies(EXTERNAL_ENGINE_DEPENDENCIES)
    if unresolved:
        raise EngineGraphError(f"ENGINE_GRAPH_UNRESOLVED_DEPENDENCIES:{unresolved}")
    validate_engine_contracts(set(registry.names()))

    for field in sorted(
        {field for contract in ENGINE_CONTRACTS.values() for field in contract.writes}
    ):
        state.pop(field, None)
    state["engine_graph_trace"] = []
    state["engine_convergence_trace"] = []
    final_actions: dict[str, str | None] = {}

    for component in _execution_components(registry):
        cyclic = len(component) > 1 or any(
            registry.resolve_name(dependency) == component[0]
            for dependency in registry.get(component[0]).depends_on
        )
        if not cyclic:
            action, record = _invoke_engine(
                state, registry, component[0], component_iteration=1
            )
            final_actions[component[0]] = action
            state["engine_graph_trace"].append(record)
            continue

        previous_digest: str | None = None
        converged = False
        for iteration in range(1, max_convergence_iterations + 1):
            iteration_actions: dict[str, str | None] = {}
            for engine_name in component:
                action, record = _invoke_engine(
                    state, registry, engine_name, component_iteration=iteration
                )
                iteration_actions[engine_name] = action
                state["engine_graph_trace"].append(record)
            projection_digest = _digest(_convergence_projection(component, state))
            state["engine_convergence_trace"].append(
                {
                    "component": list(component),
                    "iteration": iteration,
                    "projection_digest": projection_digest,
                    "matches_previous": projection_digest == previous_digest,
                }
            )
            if projection_digest == previous_digest:
                converged = True
                final_actions.update(iteration_actions)
                break
            previous_digest = projection_digest
        if not converged:
            raise EngineGraphError(
                "ENGINE_GRAPH_CONVERGENCE_BOUND_EXCEEDED:" + ",".join(component)
            )

    unknown = sorted(
        f"{name}={action}"
        for name, action in final_actions.items()
        if action not in _ALLOW_ACTIONS | _REFINE_ACTIONS | _ESCALATE_ACTIONS
    )
    escalations = sorted(
        name for name, action in final_actions.items() if action in _ESCALATE_ACTIONS
    )
    refinements = sorted(
        name for name, action in final_actions.items() if action in _REFINE_ACTIONS
    )
    state["engine_graph_actions"] = {
        name: action for name, action in sorted(final_actions.items())
    }
    if unknown:
        state["engine_graph_result"] = "invalid"
        state["engine_graph_reason"] = "unknown_engine_decision:" + ",".join(unknown)
    elif escalations:
        state["engine_graph_result"] = "escalate"
        state["engine_graph_reason"] = "engine_escalation:" + ",".join(escalations)
    elif refinements:
        state["engine_graph_result"] = "refine_candidate"
        state["engine_graph_reason"] = "engine_refinement:" + ",".join(refinements)
    else:
        state["engine_graph_result"] = "pass"
        state["engine_graph_reason"] = "all_registered_engines_passed"
    state["engine_graph_digest"] = _digest(
        {
            "actions": state["engine_graph_actions"],
            "convergence": state["engine_convergence_trace"],
            "result": state["engine_graph_result"],
        }
    )
    return state
