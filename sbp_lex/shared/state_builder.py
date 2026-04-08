from __future__ import annotations

from copy import deepcopy
from typing import Dict, Any, Optional

from sbp_lex.config.security_config import build_security_config
from sbp_lex.config.pipeline_config import build_pipeline_config
from sbp_lex.config.thresholds import (
    ensure_safety_profile,
    apply_financial_factor,
    apply_consequentiality_tier,
)


# ─────────────────────────────────────────────
# SBP-LEX V6 STATE BUILDER (LOCKED)
# ─────────────────────────────────────────────

def build_state(input_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Construct the canonical V6 state object.

    This is the only supported entry construction point for pipeline state.
    It:
    - normalises incoming request data
    - applies locked defaults
    - attaches config snapshots
    - prepares all mandatory state keys
    """

    source = deepcopy(input_data or {})

    state: Dict[str, Any] = {
        # Request identity / raw request
        "request_fingerprint": None,
        "action": source.get("action", ""),
        "payload": deepcopy(source.get("payload", {})),
        "context": deepcopy(source.get("context", {})),

        # Authority / jurisdiction
        "resolved_authority": source.get("resolved_authority", ""),
        "jurisdiction": source.get("jurisdiction", ""),

        # Optional raw supporting inputs
        "sources": deepcopy(source.get("sources", [])),
        "financial_amount": source.get("financial_amount", 0.0),

        # Collective
        "collective_signals": {},
        "collective_signal_status": "unattached",

        # Safety / consequentiality
        "safety_profile": deepcopy(
            source.get(
                "safety_profile",
                {
                    "human_safety": 0,
                    "irreversibility": 0,
                    "cascading_impact": 0,
                    "financial_operational": 0,
                    "computed_tier": None,
                },
            )
        ),
        "corroboration_required": None,
        "corroboration_met": False,

        # Root of Trust / Authority First
        "authority_first_result": "",
        "authority_first_reason": "",

        # Procedural truth
        "procedural_truth_result": "",

        # Classification
        "classification_result": "",
        "classification_reason": "",

        # Licensing
        "licensing_result": "",
        "licensing_reason": "",

        # Governance
        "governance_result": "",
        "governance_reason": "",
        "governance_feedback": {},

        # Domain / Aurion / Execution
        "domain_result": "",
        "aurion15_result": "",
        "candidate_attempt_count": 0,
        "current_candidate": {},
        "execution_result": "",
        "execution_reason": "",
        "decision": "",

        # Tokens / verification
        "tokens": {},
        "token_stack_valid": False,
        "token_verification_failures": [],
        "token_trace": [],

        # Hashing / integrity
        "hash_chain": [],
        "state_hash": "",

        # Audit
        "audit_trace": [],
        "audit_record": {},
        "audit_hash": "",
        "audit_ledger": [],

        # GRC / re-entry control
        "last_denied_fingerprint": source.get("last_denied_fingerprint"),

        # Optional threshold flags
        "autonomy_boundary_required": bool(source.get("autonomy_boundary_required", False)),
        "escalation_threshold_required": bool(source.get("escalation_threshold_required", False)),

        # Config snapshots
        "security_config": build_security_config(),
        "pipeline_config": build_pipeline_config(),
    }

    # Carry through optional pre-existing fields if present
    optional_passthrough_fields = [
        "anchors",
        "attestation",
        "attestation_consensus",
        "truth_anchor",
        "truth_continuity",
        "truth_expiry",
        "truth_revocation",
        "authority_link_signal",
        "jurisdiction_signal",
        "dependency_signal",
        "policy_conflict_signal",
        "operational_context_signal",
        "precedence_signal",
        "intent_signal",
        "risk_potential_signal",
    ]

    for field in optional_passthrough_fields:
        if field in source:
            state[field] = deepcopy(source[field])

    # Ensure locked safety structure exists
    state = ensure_safety_profile(state)

    # Apply locked financial + tier defaults up front
    state = apply_financial_factor(state)
    state = apply_consequentiality_tier(state)

    return state
