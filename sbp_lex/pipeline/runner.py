from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from typing import Any, Dict

from sbp_lex.shared.state_builder import build_state

from sbp_lex.authority_first.anchor_validation_engine import anchor_validation_engine
from sbp_lex.authority_first.attestation_engine import attestation_engine
from sbp_lex.authority_first.attestation_consensus_engine import attestation_consensus_engine

from sbp_lex.classification.engine import ClassificationEngine
from sbp_lex.licensing.engine import LicensingEngine
from sbp_lex.governance.engine import GovernanceEngine
from sbp_lex.governance.procedural_truth import compute_safety_tier
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.aurion15.runtime.runner import run_aurion15
from sbp_lex.audit.engine import AuditEngine
from sbp_lex.audit.audit_ledger import record_audit


classification_engine = ClassificationEngine()
licensing_engine = LicensingEngine()
governance_engine = GovernanceEngine()
audit_engine = AuditEngine()


def _stable_hash(value: Any) -> str:
    return sha256(repr(value).encode("utf-8")).hexdigest()


def _request_fingerprint(state: Dict[str, Any]) -> str:
    return _stable_hash(
        {
            "action": state.get("action"),
            "payload": state.get("payload"),
            "context": state.get("context"),
            "resolved_authority": state.get("resolved_authority"),
            "jurisdiction": state.get("jurisdiction"),
        }
    )


def _append_hash_chain(state: Dict[str, Any], stage: str, payload: Dict[str, Any]) -> None:
    state.setdefault("hash_chain", [])
    previous_hash = state["hash_chain"][-1]["hash"] if state["hash_chain"] else "GENESIS"

    entry = {
        "stage": stage,
        "previous_hash": previous_hash,
        "payload_hash": _stable_hash(payload),
    }
    entry["hash"] = _stable_hash(entry)

    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]


def _build_feedback(
    state: Dict[str, Any],
    status: str,
    denial_code: str,
    denial_reason: str,
    retry_eligible: bool,
    required_change_for_retry: str,
    escalation_allowed: bool,
    fallback_action_allowed: bool,
    safe_state_required: bool,
) -> Dict[str, Any]:
    feedback = {
        "status": status,
        "denial_code": denial_code,
        "denial_reason": denial_reason,
        "repeat_same_request_allowed": False,
        "retry_eligible": retry_eligible,
        "required_change_for_retry": required_change_for_retry,
        "escalation_allowed": escalation_allowed,
        "fallback_action_allowed": fallback_action_allowed,
        "safe_state_required": safe_state_required,
        "request_fingerprint": state.get("request_fingerprint"),
    }
    state["governance_feedback"] = feedback
    return feedback


def _deny(
    state: Dict[str, Any],
    denial_code: str,
    denial_reason: str,
    retry_eligible: bool = False,
    required_change_for_retry: str = "Material change required before retry.",
    escalation_allowed: bool = True,
    fallback_action_allowed: bool = True,
    safe_state_required: bool = True,
) -> Dict[str, Any]:
    state["decision"] = "DENY"
    state["last_denied_fingerprint"] = state.get("request_fingerprint")

    _append_hash_chain(
        state,
        "deny",
        {
            "code": denial_code,
            "reason": denial_reason,
        },
    )

    return _build_feedback(
        state=state,
        status="DENY",
        denial_code=denial_code,
        denial_reason=denial_reason,
        retry_eligible=retry_eligible,
        required_change_for_retry=required_change_for_retry,
        escalation_allowed=escalation_allowed,
        fallback_action_allowed=fallback_action_allowed,
        safe_state_required=safe_state_required,
    )


def _escalate(
    state: Dict[str, Any],
    denial_code: str,
    denial_reason: str,
    safe_state_required: bool = True,
) -> Dict[str, Any]:
    state["decision"] = "ESCALATE"

    _append_hash_chain(
        state,
        "escalate",
        {
            "code": denial_code,
            "reason": denial_reason,
        },
    )

    return _build_feedback(
        state=state,
        status="ESCALATE",
        denial_code=denial_code,
        denial_reason=denial_reason,
        retry_eligible=False,
        required_change_for_retry="Escalation pathway required.",
        escalation_allowed=True,
        fallback_action_allowed=True,
        safe_state_required=safe_state_required,
    )


def _result_ok(result: Any) -> bool:
    return bool(getattr(result, "ok", False))


def _result_detail(result: Any) -> str:
    return getattr(result, "detail", "engine_failed")


def _result_data(result: Any) -> Any:
    return getattr(result, "data", None)


def _run_authority_first(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("authority_first_trace", [])

    for stage_name, fn in [
        ("anchor_validation", anchor_validation_engine),
        ("attestation", attestation_engine),
        ("attestation_consensus", attestation_consensus_engine),
    ]:
        result = fn(state)

        state["authority_first_trace"].append(
            {
                "engine": stage_name,
                "ok": _result_ok(result),
                "detail": _result_detail(result),
            }
        )

        _append_hash_chain(
            state,
            f"authority_first:{stage_name}",
            {
                "ok": _result_ok(result),
                "detail": _result_detail(result),
                "data": _result_data(result),
            },
        )

        if not _result_ok(result):
            state["authority_first_result"] = "DENY"
            state["authority_first_reason"] = _result_detail(result)
            return state

        state[stage_name] = _result_data(result)

    truth_checks = {
        "truth_anchor_engine": bool(state.get("truth_anchor", True)),
        "truth_continuity_engine": bool(state.get("truth_continuity", True)),
        "truth_expiry_engine": not bool(state.get("truth_expiry", False)),
        "truth_revocation_engine": not bool(state.get("truth_revocation", False)),
    }

    for name, passed in truth_checks.items():
        state["authority_first_trace"].append(
            {
                "engine": name,
                "ok": passed,
                "detail": "pass" if passed else "truth_state_failed",
            }
        )

        _append_hash_chain(
            state,
            f"authority_first:{name}",
            {"ok": passed},
        )

        if not passed:
            state["authority_first_result"] = "DENY"
            state["authority_first_reason"] = f"{name}_failed"
            return state

    state["authority_first_result"] = "ALLOW"
    state["authority_first_reason"] = "authority_first_valid"
    return state


def _recompute_tier_and_thresholds(state: Dict[str, Any]) -> Dict[str, Any]:
    state = compute_safety_tier(state)

    tier = state.get("safety_profile", {}).get("computed_tier")

    if tier == "TOP":
        state["corroboration_required"] = 5
    elif tier == "MEDIUM":
        state["corroboration_required"] = 3
    else:
        state["corroboration_required"] = 2

    return state


def _non_repeat_allowed(state: Dict[str, Any]) -> bool:
    last_denied = state.get("last_denied_fingerprint")
    current = state.get("request_fingerprint")
    if not last_denied:
        return True
    return last_denied != current


def _run_execution_gate(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("execution_trace", [])

    checks = [
        ("hash_chain_present", bool(state.get("hash_chain"))),
        ("procedural_truth_pass", state.get("procedural_truth_result") == "PASS"),
        ("corroboration_met", bool(state.get("corroboration_met"))),
        ("governance_allow", state.get("governance_result") == "ALLOW"),
        ("domain_pass", state.get("domain_result") == "pass"),
        ("aurion_pass", state.get("aurion15_result") == "pass"),
    ]

    for name, passed in checks:
        state["execution_trace"].append({"check": name, "passed": passed})
        if not passed:
            state["execution_result"] = "HALT"
            return state

    state["execution_result"] = "EXECUTE"
    state["decision"] = "APPROVED"
    return state


def _finalize_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    state = audit_engine.execute(state)
    state = record_audit(state)

    state["audit_record"] = {
        "request_fingerprint": state.get("request_fingerprint"),
        "decision": state.get("decision"),
        "state_hash": state.get("state_hash"),
        "hash_chain": deepcopy(state.get("hash_chain", [])),
        "governance_feedback": deepcopy(state.get("governance_feedback")),
    }

    state["audit_hash"] = _stable_hash(state["audit_record"])

    previous_ledger_hash = (
        state.get("audit_ledger", [])[-1]["ledger_hash"]
        if state.get("audit_ledger")
        else "GENESIS"
    )

    ledger_entry = {
        "previous_ledger_hash": previous_ledger_hash,
        "audit_hash": state["audit_hash"],
    }
    ledger_entry["ledger_hash"] = _stable_hash(ledger_entry)

    state.setdefault("audit_ledger", [])
    state["audit_ledger"].append(ledger_entry)

    return state

def run_v6_pipeline(input_data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        state = build_state(input_data)

        state.setdefault("context", {})
        state.setdefault("payload", {})
        state.setdefault("sources", [])
        state.setdefault("hash_chain", [])
        state.setdefault(
            "financial_thresholds",
            {
                "low_max": 499.99,
                "medium_max": 49999.99,
                "currency": "AUD",
            },
        )
        state.setdefault(
            "safety_profile",
            {
                "human_safety": 0,
                "irreversibility": 0,
                "cascading_impact": 0,
                "financial_operational": 0,
                "computed_tier": None,
            },
        )

        state["request_fingerprint"] = _request_fingerprint(state)

        if not _non_repeat_allowed(state):
            return _deny(
                state,
                denial_code="IDENTICAL_DENIED_RESUBMISSION",
                denial_reason="Identical denied request must not be reprocessed.",
                retry_eligible=False,
                required_change_for_retry="Change authority, payload, scope, or invoke escalation.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )

        state = _run_authority_first(state)

        if state.get("authority_first_result") != "ALLOW":
            return _deny(
                state,
                denial_code="AUTHORITY_FIRST_FAILURE",
                denial_reason=state.get("authority_first_reason", "Authority-first validation failed."),
                retry_eligible=True,
                required_change_for_retry="Provide valid anchor, attestation, consensus, and truth substrate.",
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )

        state = _recompute_tier_and_thresholds(state)
        state["procedural_truth_result"] = "PASS"
        state["corroboration_met"] = True

        _append_hash_chain(
            state,
            "procedural_truth",
            {
                "procedural_truth_result": state.get("procedural_truth_result"),
                "corroboration_required": state.get("corroboration_required"),
                "corroboration_met": state.get("corroboration_met"),
                "tier": state.get("safety_profile", {}).get("computed_tier"),
            },
        )

        if state.get("procedural_truth_result") == "ESCALATE":
            return _escalate(
                state,
                denial_code="PROCEDURAL_TRUTH_ESCALATION",
                denial_reason="Procedural truth requires escalation.",
                safe_state_required=True,
            )

        if state.get("procedural_truth_result") != "PASS":
            return _deny(
                state,
                denial_code="PROCEDURAL_TRUTH_FAILURE",
                denial_reason="Procedural truth validation failed.",
                retry_eligible=True,
                required_change_for_retry="Provide sufficient verified, attested, fresh, and consistent sources.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )

        state = classification_engine.execute(state)

        _append_hash_chain(
            state,
            "classification",
            {
                "classification_result": state.get("classification_result"),
                "classification_reason": state.get("classification_reason"),
            },
        )

        if state.get("classification_result") == "ESCALATE":
            return _escalate(
                state,
                denial_code="CLASSIFICATION_ESCALATION",
                denial_reason=state.get("classification_reason", "Classification escalation required."),
                safe_state_required=False,
            )

        if state.get("classification_result") != "ALLOW":
            return _deny(
                state,
                denial_code="CLASSIFICATION_DENIAL",
                denial_reason=state.get("classification_reason", "Classification denied."),
                retry_eligible=True,
                required_change_for_retry="Adjust classification inputs and resubmit a materially changed request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )

        state = licensing_engine.execute(state)

        _append_hash_chain(
            state,
            "licensing",
            {
                "licensing_result": state.get("licensing_result"),
                "licensing_reason": state.get("licensing_reason"),
            },
        )

        if state.get("licensing_result") == "ESCALATE":
            return _escalate(
                state,
                denial_code="LICENSING_ESCALATION",
                denial_reason=state.get("licensing_reason", "Licensing escalation required."),
                safe_state_required=False,
            )

        if state.get("licensing_result") != "ALLOW":
            return _deny(
                state,
                denial_code="LICENSING_DENIAL",
                denial_reason=state.get("licensing_reason", "Licensing denied."),
                retry_eligible=True,
                required_change_for_retry="Provide valid licensing conditions or reduce scope/autonomy.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )

        state = governance_engine.execute(state)

        _append_hash_chain(
            state,
            "governance",
            {
                "governance_result": state.get("governance_result"),
                "governance_reason": state.get("governance_reason"),
            },
        )

        if state.get("governance_result") == "ESCALATE":
            return _escalate(
                state,
                denial_code="GOVERNANCE_ESCALATION",
                denial_reason=state.get("governance_reason", "Governance escalation required."),
                safe_state_required=True,
            )

        if state.get("governance_result") != "ALLOW":
            return _deny(
                state,
                denial_code="GOVERNANCE_DENIAL",
                denial_reason=state.get("governance_reason", "Governance denied."),
                retry_eligible=True,
                required_change_for_retry="Change authority, legality, scope, or invoke escalation.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=True,
            )

        state = run_domain_wrap(state)
        state = _recompute_tier_and_thresholds(state)

        _append_hash_chain(
            state,
            "domains",
            {
                "domain_result": state.get("domain_result"),
                "tier": state.get("safety_profile", {}).get("computed_tier"),
                "tier_recomputed": state.get("tier_recomputed"),
            },
        )

        if state.get("domain_result") == "escalate":
            return _escalate(
                state,
                denial_code="DOMAIN_ESCALATION",
                denial_reason="Domain wrap escalated the request.",
                safe_state_required=False,
            )

        if state.get("domain_result") != "pass":
            return _deny(
                state,
                denial_code="DOMAIN_DENIAL",
                denial_reason=f"Domain wrap blocked current pathway: {state.get('domain_result')}",
                retry_eligible=True,
                required_change_for_retry="Provide a materially changed request, fallback action, or escalation request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )

        aurion_loops = 0
        max_aurion_loops = 12

        while True:
            aurion_loops += 1
            state = run_aurion15(state)
            state = _recompute_tier_and_thresholds(state)

            _append_hash_chain(
                state,
                f"aurion:{aurion_loops}",
                {
                    "aurion15_result": state.get("aurion15_result"),
                    "candidate_attempt_count": state.get("candidate_attempt_count"),
                    "tier": state.get("safety_profile", {}).get("computed_tier"),
                },
            )

            if state.get("aurion15_result") == "pass":
                break

            if state.get("aurion15_result") == "escalate":
                return _escalate(
                    state,
                    denial_code="AURION_ESCALATION",
                    denial_reason="Aurion runtime escalated the request.",
                    safe_state_required=False,
                )

            if aurion_loops >= max_aurion_loops or state.get("aurion15_result") == "require_next_candidate":
                return _deny(
                    state,
                    denial_code="AURION_RESOLUTION_FAILURE",
                    denial_reason="Aurion could not resolve a valid pathway.",
                    retry_eligible=True,
                    required_change_for_retry="Provide materially changed request, fallback action, or escalation request.",
                    escalation_allowed=True,
                    fallback_action_allowed=True,
                    safe_state_required=False,
                )

        state = _run_execution_gate(state)

        _append_hash_chain(
            state,
            "execution",
            {
                "execution_result": state.get("execution_result"),
                "decision": state.get("decision"),
            },
        )

        if state.get("execution_result") != "EXECUTE":
            return _deny(
                state,
                denial_code="EXECUTION_GATE_FAILURE",
                denial_reason="Execution gate halted the request.",
                retry_eligible=False,
                required_change_for_retry="Execution gate failure requires governed re-entry.",
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )

        state = _finalize_audit(state)

        _append_hash_chain(
            state,
            "audit",
            {
                "audit_hash": state.get("audit_hash"),
                "ledger_entries": state.get("audit_ledger"),
            },
        )

        return state

    except Exception as e:
        return {
            "decision": "DENY",
            "error": str(e),
        }


def run_v6(input_data: Dict[str, Any]) -> Dict[str, Any]:
    return run_v6_pipeline(input_data)
