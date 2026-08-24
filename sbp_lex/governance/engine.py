from __future__ import annotations

from typing import Any, Dict

from sbp_lex.governance.filed_frameworks import (
    AJ_SAAF,
    FRAMEWORK_PASS,
    PTODF,
)
from sbp_lex.governance.authority_provenance import (
    verify_authority_provenance,
)


class GovernanceEngine:
    """Derive governance from upstream results and an explicit policy."""

    name = "governance_engine"

    @staticmethod
    def _finish(
        state: Dict[str, Any],
        *,
        result: str,
        reason: str,
        checks: dict[str, bool],
    ) -> Dict[str, Any]:
        state["governance_result"] = result
        state["governance_reason"] = reason
        state.setdefault("governance_trace", []).append(
            {
                "layer": "governance_composition",
                "result": result,
                "reason": reason,
                "checks": dict(sorted(checks.items())),
            }
        )
        return state

    def execute(
        self,
        state: Dict[str, Any],
        *,
        authority_provenance_dependencies: Any | None = None,
    ) -> Dict[str, Any]:
        provenance_valid = verify_authority_provenance(
            state,
            dependencies=authority_provenance_dependencies,
            require_hash_binding=True,
        )
        policy = state.get("governance_policy_record")
        policy = policy if isinstance(policy, dict) else {}
        permitted_actions = policy.get("permitted_actions")
        restricted_actions = policy.get("restricted_actions", [])
        action = state.get("action")
        conflicts = state.get("collective_signals", {}).get(
            "policy_conflict_signal", {}
        )
        filed_framework_results = state.get("filed_framework_results", {})
        checks = {
            "aj_saaf_pass": filed_framework_results.get(AJ_SAAF)
            == FRAMEWORK_PASS,
            "authority_first_allow": state.get("authority_first_result") == "ALLOW",
            "classification_allow": state.get("classification_result") == "ALLOW",
            "jurisdiction_present": bool(state.get("jurisdiction")),
            "licensing_allow": state.get("licensing_result") == "ALLOW",
            "authority_provenance_current": provenance_valid,
            "policy_active": policy.get("status") == "ACTIVE",
            "policy_digest_current": state.get("governance_policy_digest")
            == policy.get("policy_digest"),
            "policy_id_present": bool(policy.get("policy_id")),
            "policy_version_present": bool(policy.get("policy_version")),
            "procedural_truth_pass": state.get("procedural_truth_result") == "PASS",
            "ptodf_pass": filed_framework_results.get(PTODF)
            == FRAMEWORK_PASS,
            "resolved_authority_present": bool(state.get("resolved_authority")),
        }
        if conflicts.get("conflicts_detected") is True and conflicts.get(
            "severity"
        ) == "HIGH":
            return self._finish(
                state,
                result="ESCALATE",
                reason="high_policy_conflict_detected",
                checks=checks,
            )
        if not all(checks.values()):
            return self._finish(
                state,
                result="DENY",
                reason="governance_prerequisite_or_policy_invalid",
                checks=checks,
            )
        if (
            not isinstance(permitted_actions, list)
            or not all(isinstance(item, str) for item in permitted_actions)
            or action not in permitted_actions
        ):
            return self._finish(
                state,
                result="DENY",
                reason="action_not_explicitly_permitted_by_policy",
                checks=checks,
            )
        if (
            not isinstance(restricted_actions, list)
            or not all(isinstance(item, str) for item in restricted_actions)
            or action in restricted_actions
        ):
            return self._finish(
                state,
                result="DENY",
                reason="action_restricted_or_policy_restrictions_invalid",
                checks=checks,
            )
        return self._finish(
            state,
            result="ALLOW",
            reason="explicit_policy_and_upstream_governance_checks_passed",
            checks=checks,
        )
