from __future__ import annotations

import hashlib
from typing import Dict, Any

from wire_protocol.v2.python import sbp_lex_wire_v2 as wire_v2

from sbp_lex.governance.filed_lifecycle import (
    FiledLifecycleEvaluator,
    verify_filed_lifecycle,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FiledGovernanceIntegrityEvaluator,
    verify_filed_governance_integrity,
)
from sbp_lex.governance.skg_authority import (
    SKGAuthorityEvaluator,
    verify_skg_authority,
)
from sbp_lex.security.hybrid_signature import (
    HybridSignatureProvider,
    HybridVerificationContext,
)
from sbp_lex.execution.rust_authority_client import (
    RUST_AUTHORITY_ROUTE_NOT_ADMITTED,
    RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED,
)
from sbp_lex.baseline.foundational_baseline import (
    verify_foundational_baseline,
)

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)


# ─────────────────────────────────────────────
# SBP-LEX V2 AUDIT LEDGER (LOCKED)
# ─────────────────────────────────────────────

def record_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Append audit record to immutable ledger chain.
    """

    state.setdefault("audit_ledger", [])

    audit_record = state.get("audit_record", {})
    audit_hash = state.get("audit_hash")

    if not audit_record or not audit_hash:
        return state

    previous_ledger_hash = (
        state["audit_ledger"][-1]["ledger_hash"]
        if state["audit_ledger"]
        else GENESIS_HASH
    )

    entry = {
        "previous_ledger_hash": previous_ledger_hash,
        "audit_hash": audit_hash,
    }

    entry["ledger_hash"] = _compute_digest(entry)

    state["audit_ledger"].append(entry)

    return state


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _compute_digest(payload: Dict[str, Any]) -> str:
    return canonical_integrity_hash(payload)


def verify_audit_record(
    state: Dict[str, Any],
    *,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: HybridSignatureProvider | None = None,
    skg_attestation_trust_context: HybridVerificationContext | None = None,
    skg_owner_pinned_context_digest: str | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: HybridSignatureProvider | None = None,
    filed_lifecycle_attestation_trust_context: (
        HybridVerificationContext | None
    ) = None,
    filed_lifecycle_owner_pinned_context_digest: str | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        HybridSignatureProvider | None
    ) = None,
    filed_governance_integrity_attestation_trust_context: (
        HybridVerificationContext | None
    ) = None,
    filed_governance_integrity_owner_pinned_context_digest: str | None = None,
) -> bool:
    audit_record = state.get("audit_record")
    audit_hash = state.get("audit_hash")
    if (
        type(audit_record) is not dict
        or not audit_record
        or not is_sha512(audit_hash)
        or canonical_integrity_hash(audit_record) != audit_hash
    ):
        return False
    audited_chain = audit_record.get("hash_chain")
    audited_state_hash = audit_record.get("state_hash")
    live_chain = state.get("hash_chain")
    live_state_hash = state.get("state_hash")
    if (
        type(audited_chain) is not list
        or type(live_chain) is not list
        or not verify_hash_chain_entries(
            audited_chain,
            audited_state_hash,
        )
        or not verify_hash_chain_entries(live_chain, live_state_hash)
        or len(live_chain) < len(audited_chain)
        or live_chain[: len(audited_chain)] != audited_chain
    ):
        return False
    for field in (
        "request_fingerprint",
        "decision",
        "execution_result",
        "execution_reason",
        "governance_result",
        "governance_reason",
        "governance_feedback",
    ):
        if audit_record.get(field) != state.get(field):
            return False
    for field in (
        "application_integrity_result",
        "application_integrity_result_digest",
        "application_integrity_receipt_digest",
        "application_integrity_manifest_digest",
        "application_integrity_runtime_measurement_digest",
        "application_integrity_trust_context_digest",
        "digital_provenance_result",
        "digital_provenance_digest",
        "sovereign_identity_result",
        "sovereign_identity_digest",
        "authority_boundary_result",
        "authority_boundary_digest",
        "authority_boundary_trace_digest",
        "impersonation_protection_result",
        "impersonation_protection_digest",
        "foundational_baseline_result",
        "foundational_baseline_reason",
        "foundational_baseline_digest",
        "foundational_baseline_hash_binding_index",
        "foundational_baseline_hash_binding_hash",
    ):
        if audit_record.get(field) != state.get(field):
            return False
    provenance_receipt = state.get(
        "digital_provenance_verification_receipt"
    )
    provenance_receipt_digest = (
        provenance_receipt.get("digest")
        if type(provenance_receipt) is dict
        else None
    )
    if (
        audit_record.get(
            "digital_provenance_verification_receipt_digest"
        )
        != provenance_receipt_digest
        or audit_record.get("australian_minor_access")
        != state.get("australian_minor_access")
        or audit_record.get("foundational_baseline_record")
        != state.get("foundational_baseline_record")
    ):
        return False
    if state.get("foundational_baseline_result") == "PASS" and not (
        verify_foundational_baseline(state, require_hash_binding=True)
    ):
        return False
    provenance_fields = (
        "authority_provenance_result",
        "authority_provenance_reason",
        "authority_provenance_digest",
        "authority_provenance_trace_digest",
        "authority_provenance_trust_context_digest",
        "authority_provenance_clock_receipt_digest",
        "authority_provenance_registry_head_digest",
        "governance_policy_digest",
    )
    if any(
        audit_record.get(field) != state.get(field)
        for field in provenance_fields
    ):
        return False
    provenance_trace = state.get("authority_provenance_trace")
    provenance_record = state.get("authority_provenance_record")
    if (
        audit_record.get("authority_provenance_trace") != provenance_trace
        or audit_record.get("authority_provenance_record")
        != provenance_record
        or audit_record.get("governance_policy_record")
        != state.get("governance_policy_record")
    ):
        return False
    if state.get("authority_provenance_result") == "PASS" and (
        type(provenance_trace) is not list
        or len(provenance_trace) != 1
        or type(provenance_record) is not dict
        or provenance_record != provenance_trace[0]
        or canonical_integrity_hash(provenance_record)
        != state.get("authority_provenance_digest")
        or canonical_integrity_hash(provenance_trace)
        != state.get("authority_provenance_trace_digest")
        or any(
            provenance_record.get(field) is not False
            for field in (
                "authority_granted",
                "licence_granted",
                "execution_authority_granted",
                "effect_authority_granted",
                "pipeline_bypass_permitted",
                "downstream_override_permitted",
            )
        )
    ):
        return False
    if audit_record.get("three_p_core_digest") != state.get("three_p_core_digest"):
        return False
    if audit_record.get("three_p_trace_hash") != state.get("three_p_trace_hash"):
        return False
    if audit_record.get("three_p_trace") != state.get("three_p_trace"):
        return False
    skg_trace = state.get("skg_authority_trace", [])
    if type(skg_trace) is not list:
        return False
    expected_skg_record = (
        skg_trace[-1]
        if skg_trace
        else state.get("skg_authority_record")
    )
    expected_skg_digest = (
        canonical_integrity_hash(expected_skg_record)
        if skg_trace
        else None
    )
    expected_skg_trace_digest = (
        canonical_integrity_hash(skg_trace) if skg_trace else None
    )
    if audit_record.get("skg_authority_trace") != skg_trace:
        return False
    if audit_record.get("skg_authority_record") != expected_skg_record:
        return False
    if state.get("skg_authority_record") != expected_skg_record:
        return False
    if audit_record.get("skg_authority_digest") != expected_skg_digest:
        return False
    if state.get("skg_authority_digest") != expected_skg_digest:
        return False
    if (
        audit_record.get("skg_authority_trace_digest")
        != expected_skg_trace_digest
        or state.get("skg_authority_trace_digest")
        != expected_skg_trace_digest
    ):
        return False
    if skg_trace:
        if state.get("skg_authority_result") not in {"PASS", "DENY"}:
            return False
        if state.get("skg_authority_result") == "PASS" and (
            not isinstance(
                skg_attestation_trust_context,
                HybridVerificationContext,
            )
            or type(skg_owner_pinned_context_digest) is not str
            or not verify_skg_authority(
                state,
                evaluator=skg_evaluator,
                attestation_provider=skg_attestation_provider,
                attestation_trust_context=skg_attestation_trust_context,
                owner_pinned_context_digest=skg_owner_pinned_context_digest,
                require_hash_binding=True,
            )
        ):
            return False
    for field in (
        "skg_authority_result",
        "skg_authority_reason",
        "skg_authority_granted",
        "skg_execution_authority_granted",
        "skg_downstream_override_permitted",
    ):
        if audit_record.get(field) != state.get(field):
            return False
    if audit_record.get("filed_framework_digest") != state.get(
        "filed_framework_digest"
    ):
        return False
    if audit_record.get("filed_framework_trace") != state.get(
        "filed_framework_trace"
    ):
        return False
    if audit_record.get("filed_framework_results") != state.get(
        "filed_framework_results"
    ):
        return False
    if audit_record.get("gala_attestation") != state.get("gala_attestation"):
        return False
    lifecycle_trace = state.get("filed_lifecycle_trace", [])
    if type(lifecycle_trace) is not list:
        return False
    expected_lifecycle_digest = (
        canonical_integrity_hash(lifecycle_trace)
        if lifecycle_trace
        else None
    )
    expected_lifecycle_record = (
        lifecycle_trace[-1]
        if lifecycle_trace
        else state.get("filed_lifecycle_record")
    )
    if audit_record.get("filed_lifecycle_trace") != lifecycle_trace:
        return False
    if audit_record.get("filed_lifecycle_results") != state.get(
        "filed_lifecycle_results"
    ):
        return False
    if (
        audit_record.get("filed_lifecycle_record")
        != expected_lifecycle_record
        or state.get("filed_lifecycle_record")
        != expected_lifecycle_record
    ):
        return False
    if audit_record.get("filed_lifecycle_result") != state.get(
        "filed_lifecycle_result"
    ):
        return False
    if audit_record.get("filed_lifecycle_reason") != state.get(
        "filed_lifecycle_reason"
    ):
        return False
    if (
        audit_record.get("filed_lifecycle_digest")
        != expected_lifecycle_digest
        or state.get("filed_lifecycle_digest")
        != expected_lifecycle_digest
    ):
        return False
    if lifecycle_trace:
        lifecycle_result = state.get("filed_lifecycle_result")
        if lifecycle_result not in {"PASS", "DENY", "ESCALATE"}:
            return False
        if lifecycle_result == "PASS":
            if (
                not isinstance(
                    filed_lifecycle_attestation_trust_context,
                    HybridVerificationContext,
                )
                or type(filed_lifecycle_owner_pinned_context_digest) is not str
                or not verify_filed_lifecycle(
                    state,
                    evaluator=filed_lifecycle_evaluator,
                    attestation_provider=filed_lifecycle_attestation_provider,
                    attestation_trust_context=(
                        filed_lifecycle_attestation_trust_context
                    ),
                    owner_pinned_context_digest=(
                        filed_lifecycle_owner_pinned_context_digest
                    ),
                    require_hash_binding=True,
                )
            ):
                return False
    governance_integrity_trace = state.get(
        "filed_governance_integrity_trace", []
    )
    if type(governance_integrity_trace) is not list:
        return False
    expected_governance_integrity_digest = (
        canonical_integrity_hash(governance_integrity_trace)
        if governance_integrity_trace
        else None
    )
    expected_governance_integrity_record = (
        governance_integrity_trace[-1]
        if governance_integrity_trace
        else state.get("filed_governance_integrity_record")
    )
    for field in (
        "filed_governance_integrity_revocation_binding",
        "filed_governance_integrity_trace",
        "filed_governance_integrity_results",
        "filed_governance_integrity_result",
        "filed_governance_integrity_reason",
        "filed_governance_integrity_authority_granted",
        "filed_governance_integrity_licence_granted",
        "filed_governance_integrity_execution_authority_granted",
        "filed_governance_integrity_effect_granted",
        "filed_governance_integrity_bypass_permitted",
    ):
        if audit_record.get(field) != state.get(field):
            return False
    governance_integrity_revocation = state.get(
        "filed_governance_integrity_revocation_binding"
    )
    if (
        type(governance_integrity_revocation) is not dict
        or audit_record.get(
            "filed_governance_integrity_revocation_status"
        )
        != governance_integrity_revocation.get("status")
        or audit_record.get(
            "filed_governance_integrity_revocation_sequence"
        )
        != governance_integrity_revocation.get("sequence")
        or audit_record.get(
            "filed_governance_integrity_revocation_digest"
        )
        != governance_integrity_revocation.get("digest")
    ):
        return False
    if (
        audit_record.get("filed_governance_integrity_record")
        != expected_governance_integrity_record
        or state.get("filed_governance_integrity_record")
        != expected_governance_integrity_record
        or audit_record.get("filed_governance_integrity_digest")
        != expected_governance_integrity_digest
        or state.get("filed_governance_integrity_digest")
        != expected_governance_integrity_digest
        or audit_record.get(
            "governance_integrity_implementation_order_authority"
        )
        != FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        or any(
            state.get(field) is not False
            for field in (
                "filed_governance_integrity_authority_granted",
                "filed_governance_integrity_licence_granted",
                "filed_governance_integrity_execution_authority_granted",
                "filed_governance_integrity_effect_granted",
                "filed_governance_integrity_bypass_permitted",
            )
        )
    ):
        return False
    if governance_integrity_trace:
        governance_integrity_result = state.get(
            "filed_governance_integrity_result"
        )
        if governance_integrity_result not in {"PASS", "DENY", "ESCALATE"}:
            return False
        if governance_integrity_result == "PASS":
            if (
                not isinstance(
                    filed_governance_integrity_attestation_trust_context,
                    HybridVerificationContext,
                )
                or type(filed_governance_integrity_owner_pinned_context_digest)
                is not str
                or not verify_filed_governance_integrity(
                    state,
                    evaluator=filed_governance_integrity_evaluator,
                    attestation_provider=(
                        filed_governance_integrity_attestation_provider
                    ),
                    attestation_trust_context=(
                        filed_governance_integrity_attestation_trust_context
                    ),
                    owner_pinned_context_digest=(
                        filed_governance_integrity_owner_pinned_context_digest
                    ),
                    require_hash_binding=True,
                )
            ):
                return False
    filed_licence_trace = state.get("filed_licence_trace", [])
    expected_filed_licence_digest = (
        canonical_integrity_hash(filed_licence_trace)
        if filed_licence_trace
        else None
    )
    if audit_record.get(
        "filed_licence_digest"
    ) != expected_filed_licence_digest:
        return False
    if audit_record.get("filed_licence_trace") != filed_licence_trace:
        return False
    if audit_record.get("filed_licence_record") != state.get(
        "filed_licence_record"
    ):
        return False
    if audit_record.get("filed_licence_result") != state.get(
        "filed_licence_result"
    ):
        return False
    if audit_record.get("filed_licence_reason") != state.get(
        "filed_licence_reason"
    ):
        return False
    if audit_record.get("licence_id") != state.get("licence_id"):
        return False
    if audit_record.get("license_tier") != state.get("license_tier"):
        return False
    if audit_record.get("licence_bindings") != (
        state.get("filed_licence_record", {})
        .get("evaluation_snapshot", {})
        .get("bindings")
    ):
        return False
    if audit_record.get("licence_invalidation_status") != state.get(
        "licence_invalidation_status"
    ):
        return False
    if audit_record.get("licence_execution_disabled") != state.get(
        "licence_execution_disabled"
    ):
        return False
    invalidation_trace = state.get("licence_invalidation_trace", [])
    expected_invalidation_digest = (
        canonical_integrity_hash(invalidation_trace)
        if invalidation_trace
        else None
    )
    if audit_record.get(
        "licence_invalidation_digest"
    ) != expected_invalidation_digest:
        return False
    if audit_record.get("licence_invalidation_trace") != invalidation_trace:
        return False
    if audit_record.get("licence_revocation_status") != state.get(
        "licence_revocation_status"
    ):
        return False
    if audit_record.get("licence_revocation_sequence") != state.get(
        "licence_revocation_sequence"
    ):
        return False
    if audit_record.get("legacy_admission_digest") != canonical_integrity_hash(
        state.get("legacy_admission_trace", [])
    ):
        return False
    if audit_record.get(
        "legacy_admission_reconciliation_digest"
    ) != canonical_integrity_hash(
        state.get("legacy_admission_reconciliation_trace", [])
    ):
        return False
    if audit_record.get("effect_adapter_id") != state.get("effect_adapter_id"):
        return False
    if audit_record.get("effect_id") != state.get("effect_id"):
        return False
    if audit_record.get("effect_result") != state.get("effect_result"):
        return False
    if audit_record.get("effect_permit") != state.get("effect_permit"):
        return False
    if audit_record.get("effect_receipt") != state.get("effect_receipt"):
        return False
    if audit_record.get("effect_trace") != state.get("effect_trace"):
        return False
    for field in (
        "rust_authority_route_status",
        "rust_authority_terminal_validated",
        "rust_authority_terminal_evidence",
        "rust_authority_terminal_transcript",
        "controlled_local_adapter_classification",
    ):
        if audit_record.get(field) != state.get(field):
            return False
    terminal_evidence = state.get("rust_authority_terminal_evidence")
    terminal_transcript = state.get("rust_authority_terminal_transcript")
    if state.get("rust_authority_terminal_validated"):
        if (
            type(terminal_evidence) is not dict
            or type(terminal_transcript) is not list
            or not terminal_transcript
            or terminal_evidence.get(
                "complete_signed_terminal_transcript_validated"
            )
            is not True
            or terminal_evidence.get("frame_count") != len(terminal_transcript)
            or terminal_evidence.get("terminal_transcript_digest")
            != terminal_transcript[-1].get("transcript_digest")
            or terminal_evidence.get("route_admission_state")
            != RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED
            or terminal_evidence.get("programme_success_eligible") is not False
            or terminal_evidence.get("effect_authority_granted") is not False
            or state.get("rust_authority_route_status")
            != RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED
            or state.get("execution_result") != "HALT"
            or state.get("decision") != "DENY"
            or state.get("effect_result") != "BLOCKED"
            or state.get("execution_reason") != RUST_AUTHORITY_ROUTE_NOT_ADMITTED
        ):
            return False
        try:
            encoded = b"".join(
                wire_v2.encode_frame(message)
                for message in terminal_transcript
            )
        except (TypeError, ValueError, wire_v2.WireError):
            return False
        if terminal_evidence.get("transcript_sha512") != hashlib.sha512(
            encoded
        ).hexdigest():
            return False
    elif terminal_evidence is not None or terminal_transcript is not None:
        return False
    return True


def verify_audit_ledger(state: Dict[str, Any]) -> bool:
    ledger = state.get("audit_ledger")
    if type(ledger) is not list or not ledger:
        return False
    previous_hash = GENESIS_HASH
    for entry in ledger:
        if type(entry) is not dict or set(entry) != {
            "previous_ledger_hash",
            "audit_hash",
            "ledger_hash",
        }:
            return False
        if entry.get("previous_ledger_hash") != previous_hash:
            return False
        if not is_sha512(entry.get("audit_hash")):
            return False
        unsigned = {
            "previous_ledger_hash": entry["previous_ledger_hash"],
            "audit_hash": entry["audit_hash"],
        }
        if entry.get("ledger_hash") != _compute_digest(unsigned):
            return False
        previous_hash = entry["ledger_hash"]
    return ledger[-1]["audit_hash"] == state.get("audit_hash")
