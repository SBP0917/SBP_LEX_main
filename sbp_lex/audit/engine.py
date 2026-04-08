from __future__ import annotations

from typing import Dict, Any
from hashlib import sha256
import json


# ─────────────────────────────────────────────
# SBP-LEX V6 AUDIT ENGINE (LOCKED)
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
        }

        record["audit_digest"] = self._compute_digest(record)

        return record

    # ─────────────────────────────────────────

    def _compute_digest(self, payload: Dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return sha256(encoded).hexdigest()
