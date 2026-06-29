from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


def attach_collective_signals(
    state: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    signals = deepcopy(pre_context_signals or {})

    state["collective_signals"] = {
        "request_fingerprint": state.get("request_fingerprint"),
        "intent_signal": signals.get("intent_signal", state.get("intent_signal", "")),
        "risk_potential_signal": signals.get(
            "risk_potential_signal",
            state.get("risk_potential_signal", 0.0),
        ),
        "authority_link_signal": signals.get(
            "authority_link_signal",
            state.get("authority_link_signal", {}),
        ),
        "jurisdiction_signal": signals.get(
            "jurisdiction_signal",
            state.get("jurisdiction_signal", {}),
        ),
        "dependency_signal": signals.get(
            "dependency_signal",
            state.get("dependency_signal", {}),
        ),
        "policy_conflict_signal": signals.get(
            "policy_conflict_signal",
            state.get("policy_conflict_signal", {}),
        ),
        "operational_context_signal": signals.get(
            "operational_context_signal",
            state.get("operational_context_signal", {}),
        ),
        "precedence_signal": signals.get(
            "precedence_signal",
            state.get("precedence_signal", {}),
        ),
    }
    state["collective_signal_status"] = "attached"
    return state
