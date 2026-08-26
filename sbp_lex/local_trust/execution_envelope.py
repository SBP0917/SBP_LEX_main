"""Execution-environment and command-evidence envelope (stage 2)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifact import build_signed_artifact, validate_signed_artifact
from .command_evidence import (
    capture_commands,
    environment_record,
    resolved_command_policy,
    validate_full_byte_transcript,
)
from .constants import FAIL, PASS
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_EXECUTION_ENVELOPE_PAYLOAD_V1"
_PAYLOAD_FIELDS = frozenset({
    "schema_id", "status", "bound_manifest_digest", "environment",
    "command_policy", "command_results", "required_command_failures",
    "secrets_retained", "runtime_attachment",
})


def build_execution_envelope(
    repository_root: str | Path,
    *,
    manifest: Mapping[str, Any],
    signer: HybridSigningContext,
    time_evidence: Mapping[str, Any],
    timeout_seconds: int = 900,
) -> dict[str, Any]:
    policy = resolved_command_policy()
    results = capture_commands(repository_root, timeout_seconds=timeout_seconds)
    by_id = {item.get("command_id"): item for item in results}
    failures = [
        spec["command_id"]
        for spec in policy
        if spec["required"] and by_id.get(spec["command_id"], {}).get("status") != "COMMAND_PASS"
    ]
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if not failures else FAIL,
        "bound_manifest_digest": manifest.get("artifact_digest"),
        "environment": environment_record(repository_root),
        "command_policy": policy,
        "command_results": results,
        "required_command_failures": failures,
        "secrets_retained": False,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="execution_envelope",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(manifest.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_execution_envelope(
    envelope: Any,
    repository_root: str | Path,
    *,
    expected_manifest_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
    expected_time_digest: str | None = None,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        envelope,
        expected_stage="execution_envelope",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_manifest_digest,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
        expected_time_digest=expected_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = envelope["payload"]
        if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
            failures.append("execution_envelope_payload_shape_invalid")
        elif (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_manifest_digest") != expected_manifest_digest
            or payload.get("command_policy") != resolved_command_policy()
            or payload.get("required_command_failures") != []
            or payload.get("secrets_retained") is not False
            or payload.get("runtime_attachment") != "NONE"
            or payload.get("environment") != environment_record(repository_root)
        ):
            failures.append("execution_envelope_not_current_or_admissible")
        else:
            results = payload.get("command_results")
            policy = payload["command_policy"]
            if type(results) is not list or len(results) != len(policy):
                failures.append("command_results_incomplete")
            elif [item.get("command_id") for item in results] != [item["command_id"] for item in policy]:
                failures.append("command_results_order_invalid")
            elif any(
                result.get("status") != "COMMAND_PASS"
                or not validate_full_byte_transcript(result)
                or result.get("stdout_full_bytes") is not True
                or result.get("stderr_full_bytes") is not True
                or result.get("output_truncated") is not False
                or result.get("shell_used") is not False
                or set(result) != {
                    "command_id", "arguments", "required", "working_directory",
                    "status", "exit_code",
                    "duration_ms", "timed_out", "stdout_bytes", "stdout_sha512",
                    "stdout_b64", "stdout_full_bytes", "stderr_bytes",
                    "stderr_sha512", "stderr_b64", "stderr_full_bytes",
                    "output_truncated", "shell_used",
                }
                for result in results
            ):
                failures.append("command_result_invalid")
    except (KeyError, TypeError, ValueError):
        failures.append("execution_envelope_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


__all__ = ["PAYLOAD_SCHEMA", "build_execution_envelope", "validate_execution_envelope"]
