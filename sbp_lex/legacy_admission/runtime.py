from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from typing import Any

from sbp_lex.security.integrity import canonical_integrity_hash

from .contracts import (
    LEGACY_ENGINE_CONTRACTS,
    LegacyEngineContract,
    validate_legacy_contracts,
)


_ACTIVE_OUTCOMES: dict[str, dict[str, str]] = {
    "authority_first_result": {"ALLOW": "PASS", "DENY": "DENY"},
    "collective_signal_status": {"attached": "PASS", "unattached": "DENY"},
    "governance_result": {
        "ALLOW": "PASS",
        "DENY": "DENY",
        "ESCALATE": "ESCALATE",
    },
    "domain_result": {
        "pass": "PASS",
        "deny": "DENY",
        "escalate": "ESCALATE",
    },
    "aurion15_result": {
        "pass": "PASS",
        "allow": "PASS",
        "allow_reduced": "PASS",
        "allow_fallback": "PASS",
        "deny": "DENY",
        "escalate": "ESCALATE",
        "require_next_candidate": "INCOMPLETE",
    },
    "execution_result": {"EXECUTE": "PASS", "HALT": "DENY"},
    "decision": {
        "APPROVED": "PASS",
        "ALLOW": "PASS",
        "DENY": "DENY",
        "ESCALATE": "ESCALATE",
    },
}


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _triggered(value: Any) -> bool:
    if type(value) is bool:
        return value
    return _present(value)


def _compatibility_view(state: dict[str, Any]) -> dict[str, Any]:
    """Build an isolated view solely from canonical active state."""

    view = deepcopy(state)
    request_payload = state.get("payload")
    if isinstance(request_payload, dict):
        for key, value in request_payload.items():
            view.setdefault(key, deepcopy(value))

    context = state.get("context")
    if isinstance(context, dict):
        for key, value in context.items():
            view.setdefault(key, deepcopy(value))

    jurisdiction = view.get("jurisdiction")
    if isinstance(jurisdiction, str) and jurisdiction:
        view["jurisdiction"] = {
            "country": jurisdiction,
            "region": view.get("region"),
        }
        view.setdefault("country", jurisdiction)
    elif isinstance(jurisdiction, dict):
        view.setdefault("country", jurisdiction.get("country"))
        view.setdefault("region", jurisdiction.get("region"))

    authority = view.get("authority")
    view["legacy_authority_supplied"] = isinstance(authority, dict) and bool(
        authority
    )
    if not isinstance(authority, dict):
        resolved = state.get("resolved_authority")
        authority = {"primary_authority": resolved} if resolved else {}
        view["authority"] = authority
    if isinstance(authority, dict):
        view.setdefault("authorized_scope", authority.get("authorized_scope"))
        view["sovereign_precedence_available"] = any(
            _present(authority.get(field))
            for field in (
                "national_authority",
                "regional_authority",
                "international_authority",
            )
        )

    signals = state.get("collective_signals")
    if isinstance(signals, dict):
        for key, value in signals.items():
            view.setdefault(key, deepcopy(value))

    view.setdefault("candidate", deepcopy(state.get("current_candidate")))
    view.setdefault("risk_score", view.get("risk_potential_signal"))
    view.setdefault("evaluation_time", state.get("evaluation_time", 0))
    return view


def _applicable(contract: LegacyEngineContract, view: dict[str, Any]) -> bool:
    if not contract.trigger_inputs:
        return True
    return all(_triggered(view.get(field)) for field in contract.trigger_inputs)


def _invoke(
    contract: LegacyEngineContract,
    view: dict[str, Any],
) -> tuple[bool, str, dict[str, Any]]:
    module = import_module(contract.module)
    target = getattr(module, contract.callable_name)
    local = {key: deepcopy(view.get(key)) for key in contract.reads}
    initial = deepcopy(local)

    if contract.kind == "engine_result_function":
        result = target(local)
        if local != initial:
            raise TypeError("LEGACY_ENGINE_MUTATED_INPUT_VIEW")
        ok = getattr(result, "ok", None)
        if type(ok) is not bool:
            raise TypeError("LEGACY_RESULT_OK_NOT_BOOL")
        detail = getattr(result, "detail", None)
        if type(detail) is not str or not detail:
            raise TypeError("LEGACY_RESULT_DETAIL_INVALID")
        data = getattr(result, "data", None)
        if type(data) is not dict:
            raise TypeError("LEGACY_RESULT_DATA_NOT_DICT")
        return ok, detail, deepcopy(data)

    if contract.kind == "state_function":
        before_keys = set(local)
        result = target(local)
        if result is not local:
            raise TypeError("LEGACY_STATE_FUNCTION_REPLACED_STATE")
        deleted = sorted(before_keys - set(local))
        if deleted:
            raise TypeError(f"LEGACY_STATE_FUNCTION_DELETED_KEYS:{deleted}")
        changed = {
            key: deepcopy(local[key])
            for key in sorted(set(local) | set(view))
            if key in local and local.get(key) != view.get(key)
        }
        undeclared = sorted(set(changed) - set(contract.isolated_outputs))
        if undeclared:
            raise TypeError(f"LEGACY_UNDECLARED_ISOLATED_OUTPUTS:{undeclared}")
        return True, "legacy_state_function_executed", {"state_delta": changed}

    if contract.kind == "state_predicate":
        result = target(local)
        if local != initial:
            raise TypeError("LEGACY_PREDICATE_MUTATED_INPUT_VIEW")
        if type(result) is not bool:
            raise TypeError("LEGACY_PREDICATE_NOT_BOOL")
        return result, "legacy_state_predicate_evaluated", {"predicate": result}

    if contract.kind == "domain_class":
        instance = target()
        result = instance.execute(local)
        if type(result) is not str:
            raise TypeError("LEGACY_DOMAIN_RESULT_NOT_STR")
        changed_keys = {
            key
            for key in set(local) | set(initial)
            if local.get(key) != initial.get(key)
        }
        undeclared = sorted(changed_keys - set(contract.isolated_outputs))
        if undeclared:
            raise TypeError(f"LEGACY_UNDECLARED_ISOLATED_OUTPUTS:{undeclared}")
        return result.lower() == "pass", result, {
            "candidate_action": deepcopy(local.get("candidate_action"))
        }

    if contract.kind == "authority_resolver":
        result = target.resolve(deepcopy(local.get("context", {})))
        if type(result) is not dict:
            raise TypeError("LEGACY_AUTHORITY_RESOLVER_NOT_DICT")
        return True, "legacy_authority_resolver_executed", deepcopy(result)

    if contract.kind in {"controller", "quarantined_source"}:
        raise TypeError("LEGACY_TARGET_NOT_ADMITTED_FOR_EXECUTION")

    raise TypeError(f"LEGACY_KIND_UNKNOWN:{contract.kind}")


def _pending_comparison(contract: LegacyEngineContract) -> dict[str, Any]:
    if contract.comparison_target is None:
        return {
            "adapter": contract.comparison_adapter,
            "target": None,
            "status": "UNMAPPED_ACTIVE_EQUIVALENT",
        }
    return {
        "adapter": contract.comparison_adapter,
        "target": contract.comparison_target,
        "status": "PENDING_ACTIVE_RESULT",
    }


def _completion_id(
    state: dict[str, Any],
    phase: str,
    run_id: str | None,
) -> str:
    if run_id is not None:
        return f"{phase}:{run_id}"
    if phase == "candidate":
        return f"candidate:{state.get('candidate_attempt_count', 0)}"
    return phase


def run_legacy_admission_phase(
    state: dict[str, Any],
    phase: str,
    *,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Run one isolated shadow phase without decision authority or shared writes."""

    if type(state) is not dict:
        raise TypeError("LEGACY_ADMISSION_STATE_NOT_DICT")
    validate_legacy_contracts()
    contracts = tuple(
        contract for contract in LEGACY_ENGINE_CONTRACTS if contract.phase == phase
    )
    if not contracts:
        raise ValueError(f"LEGACY_ADMISSION_PHASE_UNKNOWN:{phase}")

    state.setdefault("legacy_admission_trace", [])
    state.setdefault("legacy_admission_completed_phases", [])
    completion_id = _completion_id(state, phase, run_id)
    if completion_id in state["legacy_admission_completed_phases"]:
        return state

    view = _compatibility_view(state)
    statuses: list[str] = []
    completed_engine_ids: set[str] = set()
    for contract in contracts:
        record: dict[str, Any] = {
            "engine_id": contract.engine_id,
            "phase": contract.phase,
            "run_id": run_id,
            "position": contract.position,
            "role": contract.role,
            "promotion_candidate_role": contract.promotion_candidate_role,
            "promotion_evidence": list(contract.promotion_evidence),
            "failure_policy": contract.failure_policy,
            "reads": list(contract.reads),
            "output_contract": contract.output_contract,
            "isolated_outputs": list(contract.isolated_outputs),
            "allowed_writes": list(contract.allowed_writes),
            "dependencies": list(contract.dependencies),
            "applicability": contract.applicability,
            "authority_granted": False,
            "source_path": contract.source_path,
        }
        unmet_dependencies = sorted(
            dependency
            for dependency in contract.dependencies
            if dependency not in completed_engine_ids
        )
        if unmet_dependencies:
            record.update(
                {
                    "status": "CONTRACT_FAILURE",
                    "ok": None,
                    "detail": f"legacy_dependencies_unmet:{unmet_dependencies}",
                    "data_digest": canonical_integrity_hash({}),
                    "comparison": _pending_comparison(contract),
                }
            )
        elif not contract.runnable:
            record.update(
                {
                    "status": "QUARANTINED",
                    "ok": None,
                    "detail": "legacy_source_not_importable_or_deterministic",
                    "data_digest": canonical_integrity_hash({}),
                    "comparison": _pending_comparison(contract),
                }
            )
        elif not _applicable(contract, view):
            record.update(
                {
                    "status": "NOT_APPLICABLE",
                    "ok": None,
                    "detail": "trusted_trigger_inputs_absent",
                    "data_digest": canonical_integrity_hash({}),
                    "comparison": _pending_comparison(contract),
                }
            )
        elif not contract.deterministic:
            record.update(
                {
                    "status": "SHADOW_BLOCKED",
                    "ok": None,
                    "detail": "legacy_nondeterministic_implementation_not_admitted",
                    "data_digest": canonical_integrity_hash({}),
                    "comparison": _pending_comparison(contract),
                }
            )
        else:
            try:
                ok, detail, data = _invoke(contract, view)
                data_digest = canonical_integrity_hash(data)
                record.update(
                    {
                        "status": "PASS" if ok else "FAIL",
                        "ok": ok,
                        "detail": detail,
                        "data_digest": data_digest,
                        "comparison": _pending_comparison(contract),
                    }
                )
            except Exception as exc:
                record.update(
                    {
                        "status": "ERROR",
                        "ok": None,
                        "detail": f"LEGACY_ENGINE_ERROR:{type(exc).__name__}:{exc}",
                        "data_digest": canonical_integrity_hash({}),
                        "comparison": _pending_comparison(contract),
                    }
                )
        statuses.append(record["status"])
        state["legacy_admission_trace"].append(record)
        completed_engine_ids.add(contract.engine_id)

    state.setdefault("legacy_admission_phase_results", {})[completion_id] = {
        "result": "SHADOW_RECORDED",
        "authority_effect": "NONE",
        "record_count": len(contracts),
        "statuses": statuses,
    }
    state["legacy_admission_completed_phases"].append(completion_id)
    return state


def _active_outcome(target: str, value: Any) -> str | None:
    if value is None or value == "":
        return None
    mapping = _ACTIVE_OUTCOMES.get(target)
    if mapping is None or type(value) is not str:
        return "UNMAPPED"
    return mapping.get(value, "UNMAPPED")


def _reconcile_record(
    record: dict[str, Any],
    contract: LegacyEngineContract,
    state: dict[str, Any],
) -> dict[str, Any]:
    target = contract.comparison_target
    if target is None:
        return _pending_comparison(contract)
    active_value = state.get(target)
    active_outcome = _active_outcome(target, active_value)
    if contract.comparison_adapter.startswith("unverified:"):
        status = "INCOMPARABLE_UNVERIFIED_ADAPTER"
    elif active_outcome is None:
        status = "ACTIVE_RESULT_NOT_REACHED"
    elif active_outcome in {"UNMAPPED", "INCOMPLETE", "ESCALATE"}:
        status = "INCOMPARABLE"
    elif type(record.get("ok")) is not bool:
        status = "LEGACY_RESULT_NOT_COMPARABLE"
    else:
        legacy_outcome = "PASS" if record["ok"] else "DENY"
        status = "AGREE" if legacy_outcome == active_outcome else "DISAGREE"
    return {
        "adapter": contract.comparison_adapter,
        "target": target,
        "status": status,
        "active_value": active_value,
        "active_outcome": active_outcome,
        "legacy_ok": record.get("ok"),
    }


def reconcile_legacy_comparisons(state: dict[str, Any]) -> dict[str, Any]:
    """Compare shadow observations only after active graph results are available."""

    contracts = {contract.engine_id: contract for contract in LEGACY_ENGINE_CONTRACTS}
    counts: dict[str, int] = {}
    reconciliations: list[dict[str, Any]] = []
    for record in state.get("legacy_admission_trace", []):
        contract = contracts.get(record.get("engine_id"))
        if contract is None:
            comparison = {"status": "CONTRACT_NOT_FOUND"}
        else:
            comparison = _reconcile_record(record, contract, state)
        reconciliations.append(
            {
                "engine_id": record.get("engine_id"),
                "phase": record.get("phase"),
                "run_id": record.get("run_id"),
                "observation_digest": canonical_integrity_hash(record),
                "comparison": comparison,
                "authority_effect": "NONE",
            }
        )
        status = comparison["status"]
        counts[status] = counts.get(status, 0) + 1
    state["legacy_admission_reconciliation_trace"] = reconciliations
    state["legacy_admission_comparison_summary"] = counts
    state["legacy_admission_reconciliation_digest"] = canonical_integrity_hash(
        reconciliations
    )
    return state
