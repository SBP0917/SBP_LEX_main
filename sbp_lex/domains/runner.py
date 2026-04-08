from __future__ import annotations

from typing import Dict, Any, List


# ─────────────────────────────────────────────
# SBP-LEX V6 DOMAIN WRAP RUNNER (LOCKED)
# ─────────────────────────────────────────────

DOMAIN_ORDER: List[str] = [
    "legal_domain",
    "sovereign_domain",
    "operational_domain",
    "risk_domain",
]


def run_domain_wrap(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Deterministic domain admissibility runner.

    Domain Wrap answers:
    can this governance-cleared request proceed in actual context?
    """

    state.setdefault("domain_trace", [])

    checks = [
        ("legal_domain", _check_legal_domain(state)),
        ("sovereign_domain", _check_sovereign_domain(state)),
        ("operational_domain", _check_operational_domain(state)),
        ("risk_domain", _check_risk_domain(state)),
    ]

    for domain_name, result in checks:
        state["domain_trace"].append(
            {
                "domain": domain_name,
                "result": result["result"],
                "reason": result["reason"],
            }
        )

        if result["result"] == "escalate":
            state["domain_result"] = "escalate"
            state["domain_reason"] = result["reason"]
            return state

        if result["result"] == "fail":
            state["domain_result"] = "fail"
            state["domain_reason"] = result["reason"]
            return state

    state["domain_result"] = "pass"
    state["domain_reason"] = "domain_wrap_valid"
    return state


# ─────────────────────────────────────────────
# DOMAIN CHECKS
# ─────────────────────────────────────────────

def _check_legal_domain(state: Dict[str, Any]) -> Dict[str, str]:
    governance_result = state.get("governance_result")
    if governance_result != "ALLOW":
        return {
            "result": "fail",
            "reason": "governance_not_allow",
        }

    return {
        "result": "pass",
        "reason": "legal_domain_valid",
    }


def _check_sovereign_domain(state: Dict[str, Any]) -> Dict[str, str]:
    signals = state.get("collective_signals", {})
    precedence_signal = signals.get("precedence_signal", {})
    jurisdiction_signal = signals.get("jurisdiction_signal", {})

    if not precedence_signal:
        return {
            "result": "fail",
            "reason": "precedence_signal_missing",
        }

    if not jurisdiction_signal:
        return {
            "result": "fail",
            "reason": "jurisdiction_signal_missing",
        }

    return {
        "result": "pass",
        "reason": "sovereign_domain_valid",
    }


def _check_operational_domain(state: Dict[str, Any]) -> Dict[str, str]:
    signals = state.get("collective_signals", {})
    operational_signal = signals.get("operational_context_signal", {})
    dependency_signal = signals.get("dependency_signal", {})

    if not operational_signal:
        return {
            "result": "fail",
            "reason": "operational_context_signal_missing",
        }

    system_state = operational_signal.get("system_state", "CRITICAL")
    if system_state == "CRITICAL":
        return {
            "result": "escalate",
            "reason": "critical_operational_state",
        }

    if not dependency_signal:
        return {
            "result": "fail",
            "reason": "dependency_signal_missing",
        }

    if dependency_signal.get("risk_level") == "HIGH":
        return {
            "result": "escalate",
            "reason": "high_dependency_risk",
        }

    return {
        "result": "pass",
        "reason": "operational_domain_valid",
    }


def _check_risk_domain(state: Dict[str, Any]) -> Dict[str, str]:
    signals = state.get("collective_signals", {})
    policy_conflict_signal = signals.get("policy_conflict_signal", {})
    risk_potential_signal = signals.get("risk_potential_signal", 1.0)

    if policy_conflict_signal.get("conflicts_detected") is True:
        severity = policy_conflict_signal.get("severity", "LOW")
        if severity == "HIGH":
            return {
                "result": "escalate",
                "reason": "high_policy_conflict_detected",
            }
        if severity == "MEDIUM":
            return {
                "result": "fail",
                "reason": "medium_policy_conflict_detected",
            }

    try:
        risk_value = float(risk_potential_signal)
    except (TypeError, ValueError):
        return {
            "result": "fail",
            "reason": "invalid_risk_potential_signal",
        }

    if risk_value >= 0.90:
        return {
            "result": "escalate",
            "reason": "risk_potential_too_high",
        }

    return {
        "result": "pass",
        "reason": "risk_domain_valid",
    }
