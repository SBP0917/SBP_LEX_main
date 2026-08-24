from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from .envelope import canonical_json_bytes
from .envelope import assurance_envelope_digest


ASSURANCE_VERDICT_VERSION = "sbp.v2.assurance-verdict/1"
MAX_VERIFIER_INPUT_BYTES = 1_048_576
MAX_VERIFIER_OUTPUT_BYTES = 65_536
DEFAULT_VERIFIER_TIMEOUT_SECONDS = 2.0

_VERIFIER_REASON_CODES = frozenset(
    {
        "VERIFIED",
        "INPUT_TOO_LARGE",
        "MALFORMED_ENVELOPE",
        "UNSUPPORTED_VERSION",
        "INVALID_REQUEST_FINGERPRINT",
        "INVALID_CHECKPOINT",
        "INVALID_PREVIOUS_DIGEST",
        "INVALID_BASE64",
        "NON_CANONICAL_BASE64",
        "STATE_DIGEST_MISMATCH",
        "INVALID_CANONICAL_STATE",
        "FLOAT_FORBIDDEN",
        "NON_CANONICAL_STATE",
        "INTERNAL_VERIFIER_ERROR",
    }
)

_REQUIRED_VERDICT_FIELDS = frozenset(
    {
        "schema_version",
        "verifier_version",
        "accepted",
        "reason_code",
    }
)
_OPTIONAL_VERDICT_FIELDS = frozenset(
    {
        "request_fingerprint",
        "checkpoint",
        "observed_state_sha512",
        "envelope_sha512",
    }
)


class AssuranceMode(str, Enum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    REQUIRED = "required"


@dataclass(frozen=True)
class VerifierInvocation:
    status: str
    accepted: bool
    reason_code: str
    exit_code: int | None
    verdict: Mapping[str, Any] | None = None


def _invalid(reason_code: str, *, exit_code: int | None = None) -> VerifierInvocation:
    return VerifierInvocation(
        status="INVALID",
        accepted=False,
        reason_code=reason_code,
        exit_code=exit_code,
    )


def _is_sha512_or_none(value: Any) -> bool:
    return value is None or (
        isinstance(value, str)
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_verdict(value: Any, *, exit_code: int) -> VerifierInvocation:
    if not isinstance(value, dict):
        return _invalid("VERDICT_NOT_OBJECT", exit_code=exit_code)
    fields = frozenset(value)
    if not _REQUIRED_VERDICT_FIELDS.issubset(fields):
        return _invalid("VERDICT_REQUIRED_FIELD_MISSING", exit_code=exit_code)
    if fields - (_REQUIRED_VERDICT_FIELDS | _OPTIONAL_VERDICT_FIELDS):
        return _invalid("VERDICT_UNKNOWN_FIELD", exit_code=exit_code)
    if value.get("schema_version") != ASSURANCE_VERDICT_VERSION:
        return _invalid("VERDICT_VERSION_MISMATCH", exit_code=exit_code)
    if (
        not isinstance(value.get("verifier_version"), str)
        or not value["verifier_version"]
        or len(value["verifier_version"]) > 64
    ):
        return _invalid("VERDICT_VERIFIER_VERSION_INVALID", exit_code=exit_code)
    if not isinstance(value.get("accepted"), bool):
        return _invalid("VERDICT_ACCEPTED_INVALID", exit_code=exit_code)
    if value.get("reason_code") not in _VERIFIER_REASON_CODES:
        return _invalid("VERDICT_REASON_INVALID", exit_code=exit_code)
    if value.get("request_fingerprint") is not None and not _is_sha512_or_none(
        value.get("request_fingerprint")
    ):
        return _invalid("VERDICT_REQUEST_FINGERPRINT_INVALID", exit_code=exit_code)
    if value.get("checkpoint") is not None and not isinstance(value.get("checkpoint"), str):
        return _invalid("VERDICT_CHECKPOINT_INVALID", exit_code=exit_code)
    if not _is_sha512_or_none(value.get("observed_state_sha512")):
        return _invalid("VERDICT_STATE_DIGEST_INVALID", exit_code=exit_code)
    if not _is_sha512_or_none(value.get("envelope_sha512")):
        return _invalid("VERDICT_ENVELOPE_DIGEST_INVALID", exit_code=exit_code)

    accepted = value["accepted"]
    if accepted and exit_code != 0:
        return _invalid("VERDICT_EXIT_STATUS_CONTRADICTION", exit_code=exit_code)
    if not accepted and exit_code == 0:
        return _invalid("VERDICT_EXIT_STATUS_CONTRADICTION", exit_code=exit_code)
    if exit_code not in {0, 2}:
        return _invalid("VERIFIER_UNEXPECTED_EXIT", exit_code=exit_code)

    return VerifierInvocation(
        status="VERIFIED" if accepted else "REJECTED",
        accepted=accepted,
        reason_code=value["reason_code"],
        exit_code=exit_code,
        verdict=value,
    )


def invoke_veto_verifier(
    envelope: Mapping[str, Any],
    *,
    command: Sequence[str | Path],
    timeout_seconds: float = DEFAULT_VERIFIER_TIMEOUT_SECONDS,
) -> VerifierInvocation:
    """Invoke a bounded veto verifier without a shell.

    The command is build configuration, not request data. Production callers
    must bind its executable and arguments into measured startup evidence.
    """

    if not command:
        return _invalid("VERIFIER_COMMAND_MISSING")
    if timeout_seconds <= 0:
        return _invalid("VERIFIER_TIMEOUT_INVALID")

    executable = Path(command[0])
    if not executable.is_absolute() or not executable.is_file():
        return _invalid("VERIFIER_EXECUTABLE_INVALID")

    encoded_envelope = canonical_json_bytes(envelope)
    if len(encoded_envelope) > MAX_VERIFIER_INPUT_BYTES:
        return _invalid("VERIFIER_INPUT_TOO_LARGE")
    try:
        completed = subprocess.run(
            [str(part) for part in command],
            input=encoded_envelope,
            capture_output=True,
            check=False,
            shell=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return _invalid("VERIFIER_TIMEOUT")
    except OSError:
        return _invalid("VERIFIER_LAUNCH_FAILED")

    if len(completed.stdout) > MAX_VERIFIER_OUTPUT_BYTES:
        return _invalid("VERIFIER_OUTPUT_TOO_LARGE", exit_code=completed.returncode)
    if len(completed.stderr) > MAX_VERIFIER_OUTPUT_BYTES:
        return _invalid("VERIFIER_ERROR_OUTPUT_TOO_LARGE", exit_code=completed.returncode)
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = child
        return value

    try:
        decoded = completed.stdout.decode("utf-8", errors="strict")
        verdict = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _invalid("VERIFIER_OUTPUT_MALFORMED", exit_code=completed.returncode)
    invocation = _validate_verdict(verdict, exit_code=completed.returncode)
    if not invocation.accepted or invocation.verdict is None:
        return invocation
    expected = {
        "request_fingerprint": envelope.get("request_fingerprint"),
        "checkpoint": envelope.get("checkpoint"),
        "observed_state_sha512": envelope.get("canonical_state_sha512"),
        "envelope_sha512": assurance_envelope_digest(envelope),
    }
    if any(invocation.verdict.get(field) != value for field, value in expected.items()):
        return _invalid(
            "VERDICT_BINDING_MISMATCH",
            exit_code=completed.returncode,
        )
    return invocation


def mode_requires_denial(mode: AssuranceMode, invocation: VerifierInvocation | None) -> bool:
    """Return whether verifier state must deny progress under the configured mode."""

    if mode is not AssuranceMode.REQUIRED:
        return False
    return invocation is None or invocation.status != "VERIFIED" or not invocation.accepted
