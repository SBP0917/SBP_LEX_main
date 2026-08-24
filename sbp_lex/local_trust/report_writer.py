"""Deterministic reviewer-readable report output."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import DEPLOYMENT_LIMITS
from .paths import write_bytes_exclusive
from .summary import build_local_trust_summary


def render_local_trust_report(package: Any, validation: Any | None = None) -> str:
    summary = build_local_trust_summary(package)
    validation_status = validation.get("status") if type(validation) is dict else "NOT_RUN"
    failures = validation.get("validation_failures", []) if type(validation) is dict else []
    lines = [
        "# SBP-LEX V2 Detached Local-Trust Report",
        "",
        f"Package status: {summary.get('package_status')}",
        f"Verification status: {validation_status}",
        f"Artifact trust-context digest: {summary.get('artifact_context_digest')}",
        f"Clock trust-context digest: {summary.get('clock_context_digest')}",
        f"History trust-context digest: {summary.get('history_context_digest')}",
        f"Artifact-chain head: {summary.get('head_digest')}",
        "",
        "## Locked boundary",
        "",
        "Local/private, offline-verifiable, runtime-detached, publication/network/cloud/blockchain/ledger inactive, and non-authorizing.",
        "",
        "## Stage chain",
        "",
    ]
    lines.extend(f"{index}. {stage}" for index, stage in enumerate(summary.get("stage_order", []), start=1))
    lines.extend(["", "## Validation failures", ""])
    lines.extend(f"- {failure}" for failure in failures)
    if not failures:
        lines.append("- None recorded.")
    lines.extend(["", "## Explicitly unproven deployment requirements", ""])
    lines.extend(f"- {key}: {value}" for key, value in sorted(DEPLOYMENT_LIMITS.items()))
    return "\n".join(lines) + "\n"


def write_local_trust_report(
    package: Any,
    output_path: str | Path,
    *,
    validation: Any | None = None,
) -> Path:
    return write_bytes_exclusive(
        render_local_trust_report(package, validation).encode("utf-8"),
        Path(output_path),
    )


__all__ = ["render_local_trust_report", "write_local_trust_report"]
