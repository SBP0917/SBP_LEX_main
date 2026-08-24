"""The locked non-authority and runtime-detachment boundary."""

from __future__ import annotations

from .constants import DEPLOYMENT_LIMITS, DETACHED_BOUNDARY, NO_AUTHORITY


def boundary_statement() -> dict[str, object]:
    return {
        "no_authority": dict(NO_AUTHORITY),
        "detached_boundary": dict(DETACHED_BOUNDARY),
        "deployment_limits": dict(DEPLOYMENT_LIMITS),
        "permitted_operations": [
            "collect_local_evidence",
            "hash_local_evidence",
            "sign_local_evidence",
            "verify_local_evidence",
            "write_new_local_receipt",
            "write_new_local_report",
        ],
        "prohibited_operations": [
            "grant_decision",
            "mint_token",
            "mutate_audit",
            "mutate_hash_chain",
            "grant_governance",
            "grant_licence",
            "grant_execution",
            "perform_effect",
            "publish",
            "network",
            "cloud",
            "blockchain",
            "ledger",
        ],
    }


__all__ = ["boundary_statement"]
