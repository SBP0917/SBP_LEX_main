from __future__ import annotations

from typing import Dict, Any

from sbp_lex.security.integrity import canonical_integrity_hash


# ─────────────────────────────────────────────
# SBP-LEX V2 AUDIT ENGINE (LOCKED)
# ─────────────────────────────────────────────

class AuditEngine:
    """
    Generates deterministic audit trace from state.
    """

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        state.setdefault("audit_trace", [])

        record = self._build_audit_trace(state)

        state["audit_trace"].append(record)

        return state

    # ─────────────────────────────────────────

    def _build_audit_trace(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build immutable audit snapshot of decision pathway.
        """

        record = {
            "request_fingerprint": state.get("request_fingerprint"),
            "decision": state.get("decision"),

            # Core results
            "authority_first_result": state.get("authority_first_result"),
            "procedural_truth_result": state.get("procedural_truth_result"),
            "classification_result": state.get("classification_result"),
            "licensing_result": state.get("licensing_result"),
            "governance_result": state.get("governance_result"),
            "domain_result": state.get("domain_result"),
            "aurion15_result": state.get("aurion15_result"),
            "execution_result": state.get("execution_result"),
            "effect_adapter_id": state.get("effect_adapter_id"),
            "effect_id": state.get("effect_id"),
            "effect_result": state.get("effect_result"),
            "effect_permit_digest": state.get("effect_permit", {}).get(
                "digest"
            ),
            "effect_receipt_digest": state.get("effect_receipt", {}).get(
                "digest"
            ),
            "rust_authority_route_status": state.get(
                "rust_authority_route_status"
            ),
            "rust_authority_terminal_validated": state.get(
                "rust_authority_terminal_validated"
            ),
            "rust_authority_terminal_evidence": state.get(
                "rust_authority_terminal_evidence"
            ),
            "controlled_local_adapter_classification": state.get(
                "controlled_local_adapter_classification"
            ),

            # Foundational public-traversal evidence
            "application_integrity_result": state.get(
                "application_integrity_result"
            ),
            "application_integrity_result_digest": state.get(
                "application_integrity_result_digest"
            ),
            "application_integrity_receipt_digest": state.get(
                "application_integrity_receipt_digest"
            ),
            "application_integrity_manifest_digest": state.get(
                "application_integrity_manifest_digest"
            ),
            "application_integrity_runtime_measurement_digest": state.get(
                "application_integrity_runtime_measurement_digest"
            ),
            "application_integrity_trust_context_digest": state.get(
                "application_integrity_trust_context_digest"
            ),
            "digital_provenance_digest": state.get(
                "digital_provenance_digest"
            ),
            "sovereign_identity_digest": state.get(
                "sovereign_identity_digest"
            ),
            "authority_boundary_digest": state.get(
                "authority_boundary_digest"
            ),
            "authority_boundary_trace_digest": state.get(
                "authority_boundary_trace_digest"
            ),
            "impersonation_protection_digest": state.get(
                "impersonation_protection_digest"
            ),
            "australian_minor_access_record_digest": state.get(
                "foundational_baseline_record", {}
            ).get("australian_minor_access_record_digest"),
            "foundational_baseline_digest": state.get(
                "foundational_baseline_digest"
            ),

            # P0 authenticated authority provenance (non-authorising)
            "authority_provenance_result": state.get(
                "authority_provenance_result"
            ),
            "authority_provenance_digest": state.get(
                "authority_provenance_digest"
            ),
            "authority_provenance_trace_digest": state.get(
                "authority_provenance_trace_digest"
            ),
            "authority_provenance_trust_context_digest": state.get(
                "authority_provenance_trust_context_digest"
            ),
            "authority_provenance_clock_receipt_digest": state.get(
                "authority_provenance_clock_receipt_digest"
            ),
            "authority_provenance_registry_head_digest": state.get(
                "authority_provenance_registry_head_digest"
            ),

            # Constitutional layer
            "three_p_core_result": state.get("three_p_core_result"),
            "three_p_core_digest": state.get("three_p_core_digest"),
            "three_p_trace_hash": state.get("three_p_trace_hash"),

            # Authenticated constitutional authority substrate
            "skg_authority_result": state.get("skg_authority_result"),
            "skg_authority_digest": state.get("skg_authority_digest"),
            "skg_authority_trace_digest": state.get(
                "skg_authority_trace_digest"
            ),

            # Filed lifecycle traversal
            "filed_lifecycle_result": state.get(
                "filed_lifecycle_result"
            ),
            "filed_lifecycle_digest": state.get(
                "filed_lifecycle_digest"
            ),

            # Filed governance-integrity mandatory-veto evidence
            "filed_governance_integrity_result": state.get(
                "filed_governance_integrity_result"
            ),
            "filed_governance_integrity_digest": state.get(
                "filed_governance_integrity_digest"
            ),
            "filed_governance_integrity_revocation_status": state.get(
                "filed_governance_integrity_revocation_binding", {}
            ).get("status"),
            "filed_governance_integrity_revocation_sequence": state.get(
                "filed_governance_integrity_revocation_binding", {}
            ).get("sequence"),
            "filed_governance_integrity_revocation_digest": state.get(
                "filed_governance_integrity_revocation_binding", {}
            ).get("digest"),
            "filed_governance_integrity_authority_granted": state.get(
                "filed_governance_integrity_authority_granted"
            ),
            "filed_governance_integrity_licence_granted": state.get(
                "filed_governance_integrity_licence_granted"
            ),
            "filed_governance_integrity_execution_authority_granted": (
                state.get(
                    "filed_governance_integrity_execution_authority_granted"
                )
            ),
            "filed_governance_integrity_effect_granted": state.get(
                "filed_governance_integrity_effect_granted"
            ),
            "filed_governance_integrity_bypass_permitted": state.get(
                "filed_governance_integrity_bypass_permitted"
            ),

            # Filed four-tier licensing and five bindings
            "filed_licence_result": state.get("filed_licence_result"),
            "filed_licence_digest": state.get("filed_licence_digest"),
            "licence_id": state.get("licence_id"),
            "license_tier": state.get("license_tier"),
            "licence_bindings_digest": canonical_integrity_hash(
                state.get("filed_licence_record", {})
                .get("evaluation_snapshot", {})
                .get("bindings")
            ),
            "licence_invalidation_status": state.get(
                "licence_invalidation_status"
            ),
            "licence_execution_disabled": state.get(
                "licence_execution_disabled"
            ),
            "licence_invalidation_digest": state.get(
                "licence_invalidation_digest"
            ),
            "licence_revocation_status": state.get(
                "licence_revocation_status"
            ),
            "licence_revocation_sequence": state.get(
                "licence_revocation_sequence"
            ),

            # Thresholds
            "tier": state.get("safety_profile", {}).get("computed_tier"),
            "corroboration_required": state.get("corroboration_required"),
            "corroboration_met": state.get("corroboration_met"),

            # Tokens
            "token_names": list(state.get("tokens", {}).keys()),
            "token_stack_valid": state.get("token_stack_valid"),

            # Collective
            "collective_signal_status": state.get("collective_signal_status"),

            # Integrity
            "state_hash": state.get("state_hash"),
            "legacy_admission_digest": canonical_integrity_hash(
                state.get("legacy_admission_trace", [])
            ),
        }

        record["audit_digest"] = self._compute_digest(record)

        return record

    # ─────────────────────────────────────────

    def _compute_digest(self, payload: Dict[str, Any]) -> str:
        return canonical_integrity_hash(payload)
