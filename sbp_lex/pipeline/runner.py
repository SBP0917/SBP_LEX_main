from __future__ import annotations

from hashlib import sha256
from typing import Dict, Any

from sbp_lex.shared.state_builder import build_state

from sbp_lex.collective.context_interface import attach_collective_signals

from sbp_lex.authority_first.anchor_validation_engine import anchor_validation_engine
from sbp_lex.authority_first.attestation_engine import attestation_engine
from sbp_lex.authority_first.attestation_consensus_engine import attestation_consensus_engine
from sbp_lex.authority_first.truth_anchor_engine import truth_anchor_engine
from sbp_lex.authority_first.truth_continuity_engine import truth_continuity_engine
from sbp_lex.authority_first.truth_expiry_engine import truth_expiry_engine
from sbp_lex.authority_first.truth_revocation_engine import truth_revocation_engine

from sbp_lex.classification.engine import ClassificationEngine
from sbp_lex.licensing.engine import LicensingEngine
from sbp_lex.governance.engine import GovernanceEngine
from sbp_lex.governance.procedural_truth_engine import evaluate_procedural_truth
from sbp_lex.governance.grc import (
    apply_grc,
    enforce_non_repeat_rule,
    build_deny_feedback,
    build_escalate_feedback,
)

from sbp_lex.config.thresholds import apply_financial_factor, apply_consequentiality_tier
from sbp_lex.domains.runner import run_domain_wrap
from sbp_lex.aurion15.runtime.runner import run_aurion15
from sbp_lex.execution.execution_gate import run_execution_gate
from sbp_lex.audit.engine import AuditEngine
from sbp_lex.audit.audit_ledger import record_audit

from sbp_lex.security.token_stack import issue_token
from sbp_lex.config.pipeline_config import (
    AURION_MAX_CANDIDATE_ATTEMPTS,
    AURION_REQUIRE_NEXT_CANDIDATE_RESULT,
    AURION_PASS_RESULT,
    AURION_ESCALATE_RESULT,
    GOVERNANCE_ALLOW,
    GOVERNANCE_DENY,
    GOVERNANCE_ESCALATE,
    PROCEDURAL_TRUTH_PASS,
    PROCEDURAL_TRUTH_ESCALATE,
    CLASSIFICATION_ALLOW,
    CLASSIFICATION_ESCALATE,
    LICENSING_ALLOW,
    LICENSING_ESCALATE,
    DOMAIN_PASS_RESULT,
    DOMAIN_ESCALATE_RESULT,
)

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


def _append_hash_chain(state: Dict[str, Any], stage: str, payload: Dict[str, Any]) -> Dict[str, Any]:
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
    return state


def _engine_ok(result: Any) -> bool:
    return bool(getattr(result, "ok", False))


def _engine_detail(result: Any) -> str:
    return getattr(result, "detail", "engine_failed")


def _engine_data(result: Any) -> Any:
    return getattr(result, "data", None)


def _run_root_of_trust(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("root_of_trust_trace", [])

    chain = [
        ("anchor_validation", anchor_validation_engine),
        ("attestation", attestation_engine),
        ("attestation_consensus", attestation_consensus_engine),
        ("truth_anchor", truth_anchor_engine),
        ("truth_continuity", truth_continuity_engine),
        ("truth_expiry", truth_expiry_engine),
        ("truth_revocation", truth_revocation_engine),
    ]

    for stage_name, fn in chain:
        result = fn(state)

        ok = _engine_ok(result)
        detail = _engine_detail(result)
        data = _engine_data(result)

        state["root_of_trust_trace"].append(
            {
                "engine": stage_name,
                "ok": ok,
                "detail": detail,
            }
        )

        _append_hash_chain(
            state,
            f"root_of_trust:{stage_name}",
            {
                "ok": ok,
                "detail": detail,
                "data": data,
            },
        )

        if not ok:
            state["authority_first_result"] = "DENY"
            state["authority_first_reason"] = detail
            return state

        state[stage_name] = data

    state["authority_first_result"] = "ALLOW"
    state["authority_first_reason"] = "root_of_trust_valid"
    return state


def _issue_core_token(
    state: Dict[str, Any],
    token_name: str,
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    return issue_token(
        state,
        token_name=token_name,
        issuer=issuer,
        issued_at_stage=issued_at_stage,
        payload=payload,
        key_id=f"{issuer}_root",
    )


def _finalize_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    state = audit_engine.execute(state)
    state = record_audit(state)

    state["audit_record"] = {
        "request_fingerprint": state.get("request_fingerprint"),
        "decision": state.get("decision"),
        "state_hash": state.get("state_hash"),
        "governance_feedback": state.get("governance_feedback"),
        "hash_chain": state.get("hash_chain", []),
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


def run_v6(input_data: Dict[str, Any], pre_context_signals: Dict[str, Any] | None = None) -> Dict[str, Any]:
    try:
        state = build_state(input_data)

        state.setdefault("context", {})
        state.setdefault("payload", {})
        state.setdefault("tokens", {})
        state.setdefault("hash_chain", [])
        state.setdefault("audit_ledger", [])
        state.setdefault("last_denied_fingerprint", None)
        state.setdefault("financial_amount", 0.0)

        state["request_fingerprint"] = _request_fingerprint(state)

        state = enforce_non_repeat_rule(state)
        if state.get("governance_feedback", {}).get("status") == "DENY":
            state["decision"] = "DENY"
            _append_hash_chain(
                state,
                "grc:identical_denied_resubmission",
                state["governance_feedback"],
            )
            return state

        state = attach_collective_signals(state, pre_context_signals)
        _append_hash_chain(
            state,
            "collective_attach",
            {
                "collective_signal_status": state.get("collective_signal_status"),
                "collective_signals": state.get("collective_signals"),
            },
        )

        state = _run_root_of_trust(state)
        if state.get("authority_first_result") != "ALLOW":
            state = build_deny_feedback(
                state,
                denial_code="AUTHORITY_FIRST_FAILURE",
                denial_reason=state.get("authority_first_reason", "Authority first validation failed."),
                retry_eligible=True,
                required_change_for_retry="Provide valid authority, attestation, and truth conditions.",
                escalation_allowed=True,
                fallback_action_allowed=False,
                safe_state_required=True,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "authority",
            "root_of_trust",
            "root_of_trust",
            {
                "authority_first_result": state.get("authority_first_result"),
                "authority_first_reason": state.get("authority_first_reason"),
            },
        )

        state = evaluate_procedural_truth(state)
        state = apply_financial_factor(state)
        state = apply_consequentiality_tier(state)

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

        if state.get("procedural_truth_result") == PROCEDURAL_TRUTH_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="PROCEDURAL_TRUTH_ESCALATION",
                denial_reason="Procedural truth escalation required.",
                safe_state_required=True,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("procedural_truth_result") != PROCEDURAL_TRUTH_PASS:
            state = build_deny_feedback(
                state,
                denial_code="PROCEDURAL_TRUTH_FAILURE",
                denial_reason="Procedural truth validation failed.",
                retry_eligible=True,
                required_change_for_retry="Provide sufficient procedural truth and evidentiary sufficiency.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "procedural_truth",
            "procedural_truth_engine",
            "procedural_truth",
            {
                "procedural_truth_result": state.get("procedural_truth_result"),
                "corroboration_met": state.get("corroboration_met"),
            },
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

        if state.get("classification_result") == CLASSIFICATION_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="CLASSIFICATION_ESCALATION",
                denial_reason=state.get("classification_reason", "Classification escalation required."),
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("classification_result") != CLASSIFICATION_ALLOW:
            state = build_deny_feedback(
                state,
                denial_code="CLASSIFICATION_DENIAL",
                denial_reason=state.get("classification_reason", "Classification denied."),
                retry_eligible=True,
                required_change_for_retry="Adjust classification inputs and resubmit materially changed request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "classification",
            "classification_engine",
            "classification",
            {
                "classification_result": state.get("classification_result"),
                "classification_reason": state.get("classification_reason"),
            },
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

        if state.get("licensing_result") == LICENSING_ESCALATE:
            state = build_escalate_feedback(
                state,
                denial_code="LICENSING_ESCALATION",
                denial_reason=state.get("licensing_reason", "Licensing escalation required."),
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("licensing_result") != LICENSING_ALLOW:
            state = build_deny_feedback(
                state,
                denial_code="LICENSING_DENIAL",
                denial_reason=state.get("licensing_reason", "Licensing denied."),
                retry_eligible=True,
                required_change_for_retry="Provide valid licence state or reduce scope/autonomy.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "licensing",
            "licensing_engine",
            "licensing",
            {
                "licensing_result": state.get("licensing_result"),
                "licensing_reason": state.get("licensing_reason"),
            },
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

        state = apply_grc(state)

        if state.get("governance_result") == GOVERNANCE_ESCALATE:
            state["decision"] = "ESCALATE"
            return state

        if state.get("governance_result") != GOVERNANCE_ALLOW:
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "governance",
            "governance_engine",
            "governance",
            {
                "governance_result": state.get("governance_result"),
                "governance_reason": state.get("governance_reason"),
            },
        )

        state = run_domain_wrap(state)
        _append_hash_chain(
            state,
            "domain_wrap",
            {
                "domain_result": state.get("domain_result"),
            },
        )

        if state.get("domain_result") == DOMAIN_ESCALATE_RESULT:
            state = build_escalate_feedback(
                state,
                denial_code="DOMAIN_ESCALATION",
                denial_reason="Domain escalation required.",
                safe_state_required=False,
            )
            state["decision"] = "ESCALATE"
            return state

        if state.get("domain_result") != DOMAIN_PASS_RESULT:
            state = build_deny_feedback(
                state,
                denial_code="DOMAIN_DENIAL",
                denial_reason=f"Domain blocked pathway: {state.get('domain_result')}",
                retry_eligible=True,
                required_change_for_retry="Provide materially changed request, fallback request, or escalation request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "domain",
            "domain_wrap",
            "domain_wrap",
            {
                "domain_result": state.get("domain_result"),
            },
        )

        aurion_attempts = 0
        while True:
            aurion_attempts += 1
            state = run_aurion15(state)

            _append_hash_chain(
                state,
                f"aurion_runtime:{aurion_attempts}",
                {
                    "aurion15_result": state.get("aurion15_result"),
                    "candidate_attempt_count": state.get("candidate_attempt_count"),
                    "current_candidate": state.get("current_candidate"),
                },
            )

            if state.get("aurion15_result") == AURION_PASS_RESULT:
                break

            if state.get("aurion15_result") == AURION_ESCALATE_RESULT:
                state = build_escalate_feedback(
                    state,
                    denial_code="AURION_ESCALATION",
                    denial_reason="Aurion escalation required.",
                    safe_state_required=False,
                )
                state["decision"] = "ESCALATE"
                return state

            if (
                state.get("aurion15_result") == AURION_REQUIRE_NEXT_CANDIDATE_RESULT
                and aurion_attempts < AURION_MAX_CANDIDATE_ATTEMPTS
            ):
                continue

            state = build_deny_feedback(
                state,
                denial_code="AURION_RESOLUTION_FAILURE",
                denial_reason="Aurion could not resolve a valid pathway.",
                retry_eligible=True,
                required_change_for_retry="Provide materially changed request, fallback request, or escalation request.",
                escalation_allowed=True,
                fallback_action_allowed=True,
                safe_state_required=False,
            )
            state["decision"] = "DENY"
            return state

        state = _issue_core_token(
            state,
            "aurion",
            "aurion15_runtime",
            "aurion_runtime",
            {
                "aurion15_result": state.get("aurion15_result"),
                "candidate_attempt_count": state.get("candidate_attempt_count"),
                "current_candidate": state.get("current_candidate"),
            },
        )

        state = _issue_core_token(
            state,
            "execution_boundary",
            "execution_gate",
            "execution_prep",
            {
                "boundary_clear": True,
            },
        )

        state = _issue_core_token(
            state,
            "execution_attestation",
            "execution_gate",
            "execution_prep",
            {
                "attested_for_execution": True,
            },
        )

        state = run_execution_gate(state)
        _append_hash_chain(
            state,
            "execution_gate",
            {
                "execution_result": state.get("execution_result"),
                "decision": state.get("decision"),
                "execution_reason": state.get("execution_reason"),
            },
        )

        if state.get("execution_result") != "EXECUTE":
            if state.get("decision") not in {"DENY", "ESCALATE"}:
                state = build_deny_feedback(
                    state,
                    denial_code="EXECUTION_GATE_FAILURE",
                    denial_reason="Execution gate halted the request.",
                    retry_eligible=False,
                    required_change_for_retry="Execution gate failure requires governed re-entry.",
                    escalation_allowed=True,
                    fallback_action_allowed=False,
                    safe_state_required=True,
                )
                state["decision"] = "DENY"
            return state

        state = _finalize_audit(state)
        _append_hash_chain(
            state,
            "audit",
            {
                "audit_hash": state.get("audit_hash"),
                "ledger_entries": len(state.get("audit_ledger", [])),
            },
        )

        return {
 
