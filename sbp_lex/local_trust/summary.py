"""Privacy-minimal local-trust summary."""

from __future__ import annotations

from typing import Any

from .constants import DEPLOYMENT_LIMITS, DETACHED_BOUNDARY, NO_AUTHORITY


def build_local_trust_summary(package: Any) -> dict[str, Any]:
    if type(package) is not dict:
        return {
            "package_status": "FAIL",
            "stage_count": 0,
            "head_digest": None,
            "no_authority": dict(NO_AUTHORITY),
            "detached_boundary": dict(DETACHED_BOUNDARY),
        }
    artifacts = package.get("artifacts")
    if type(artifacts) is not list:
        artifacts = []
    return {
        "package_schema": package.get("package_schema"),
        "package_status": package.get("package_status"),
        "stage_count": len(artifacts),
        "stage_order": [item.get("stage") for item in artifacts if type(item) is dict],
        "head_digest": artifacts[-1].get("artifact_digest") if artifacts else None,
        "package_digest": package.get("package_digest"),
        "artifact_context_digest": package.get("artifact_context_digest"),
        "clock_context_digest": package.get("clock_context_digest"),
        "history_context_digest": package.get("history_context_digest"),
        "accepted_history_digest": package.get("accepted_history_digest"),
        "accepted_history_sequence": package.get("accepted_history_sequence"),
        "no_authority": dict(NO_AUTHORITY),
        "detached_boundary": dict(DETACHED_BOUNDARY),
        "deployment_limits": dict(DEPLOYMENT_LIMITS),
    }


__all__ = ["build_local_trust_summary"]
