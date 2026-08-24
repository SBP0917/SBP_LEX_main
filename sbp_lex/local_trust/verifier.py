"""Offline verifier entrypoints using an independently owner-pinned context."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .package_io import load_local_trust_package
from .pipeline import validate_local_trust_package
from .deployment import DeploymentTrust


def verify_local_trust_package(
    package: Any,
    repository_root: str | Path,
    *,
    deployment: DeploymentTrust,
    accepted_history: dict[str, Any],
) -> dict[str, Any]:
    try:
        return validate_local_trust_package(
            package,
            repository_root,
            deployment=deployment,
            accepted_history=accepted_history,
        )
    except Exception as exc:
        return {
            "status": "FAIL",
            "validation_failures": [f"local_trust_verification_error:{type(exc).__name__}"],
        }


def verify_local_trust_package_file(
    package_path: str | Path,
    repository_root: str | Path,
    *,
    deployment: DeploymentTrust,
    accepted_history: dict[str, Any],
) -> dict[str, Any]:
    try:
        package = load_local_trust_package(package_path)
    except Exception as exc:
        return {
            "status": "FAIL",
            "validation_failures": [f"local_trust_package_load_error:{type(exc).__name__}"],
        }
    return verify_local_trust_package(
        package,
        repository_root,
        deployment=deployment,
        accepted_history=accepted_history,
    )


__all__ = ["verify_local_trust_package", "verify_local_trust_package_file"]
