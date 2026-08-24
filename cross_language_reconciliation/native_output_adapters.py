"""Strict adapters for raw native cross-language output.

Parsing raw frames proves that normalized observations were derived from native
output bytes rather than copied normalized JSON. It does not attest the claimed
binary identity or close an external implementation lane by itself.

GNATprove and TLC currently have no repository-defined machine-readable mapping
from their native text to the normalized lifecycle observation schema.  Their
adapter therefore validates only a bounded, canonical raw-output bundle and
returns an explicit unavailable semantic contract.  It never interprets a
process exit code or a text fragment as lifecycle refinement evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Final

from wire_protocol.v2.python import sbp_lex_wire_v2 as wire


SCHEMA: Final = "SBP-LEX-NATIVE-WIRE-V2-FRAMED-TRANSCRIPTS/1"
RAW_TOOL_BUNDLE_SCHEMA: Final = "SBP-LEX-C10-RAW-NATIVE-TOOL-OUTPUT-BUNDLE/1"
RAW_TOOL_OPEN_STATUS: Final = (
    "OPEN_NATIVE_OUTPUT_ADAPTER_SEMANTIC_MAPPING_UNAVAILABLE"
)
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_IMPLEMENTATION = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_CASE_ID = re.compile(r"[a-z0-9_]{1,96}\Z")
_MAX_CASES = 64
_MAX_FRAMES_PER_CASE = 21
_MAX_RAW_BYTES = 16 * 1024 * 1024
_MAX_IDENTITY_BYTES = 64 * 1024
_RAW_TOOL_BY_LANE: Final = {
    "spark_safety_monitor": "gnatprove",
    "formal_model": "tlc2.TLC",
}


class NativeOutputAdapterError(ValueError):
    pass


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise NativeOutputAdapterError(f"duplicate raw bundle key: {key}")
        result[key] = value
    return result


def _reject_number(value: str) -> None:
    raise NativeOutputAdapterError(f"non-integer raw bundle number: {value}")


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise NativeOutputAdapterError(f"{label} is not an object")
    return value


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise NativeOutputAdapterError(f"{label} key set mismatch")


def _parse_bound_blob(
    value: object,
    *,
    label: str,
    maximum: int,
    require_nonempty: bool,
) -> tuple[bytes, dict[str, object]]:
    blob = _mapping(value, label)
    _exact_keys(blob, {"bytes_hex", "sha512", "size"}, label)
    size = blob["size"]
    encoded = blob["bytes_hex"]
    digest = blob["sha512"]
    if (
        type(size) is not int
        or size < 0
        or size > maximum
        or (require_nonempty and size == 0)
    ):
        raise NativeOutputAdapterError(f"{label} size invalid")
    if (
        not isinstance(encoded, str)
        or len(encoded) != 2 * size
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise NativeOutputAdapterError(f"{label} hex/size binding invalid")
    if not isinstance(digest, str) or not _HEX128.fullmatch(digest):
        raise NativeOutputAdapterError(f"{label} digest invalid")
    raw = bytes.fromhex(encoded)
    if hashlib.sha512(raw).hexdigest() != digest:
        raise NativeOutputAdapterError(f"{label} digest mismatch")
    return raw, {"sha512": digest, "size": size}


def parse_raw_native_tool_output_bundle(
    data: bytes,
    *,
    expected_lane: str,
    expected_candidate_commit: str,
    expected_candidate_tree: str,
    expected_source_aggregate_sha512: str,
) -> dict[str, object]:
    """Validate a bounded SPARK/TLC raw-output bundle and remain explicitly OPEN.

    The exact native GNATprove/TLC semantic-output formats are not defined in
    this repository, so this function deliberately performs no lifecycle
    normalization.  ``identity_attestation`` must say ``UNAVAILABLE``: any
    assertion that this local parser authenticated a binary is rejected.
    """

    expected_tool = _RAW_TOOL_BY_LANE.get(expected_lane)
    if expected_tool is None:
        raise NativeOutputAdapterError("raw native tool lane unsupported")
    maximum_transport = 2 * (2 * _MAX_RAW_BYTES + _MAX_IDENTITY_BYTES) + 32_768
    if not isinstance(data, bytes) or not data or len(data) > maximum_transport:
        raise NativeOutputAdapterError("raw native tool bundle transport bounds")
    try:
        value = json.loads(
            data.decode("ascii"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, NativeOutputAdapterError):
            raise
        raise NativeOutputAdapterError("raw native tool bundle is invalid JSON") from error
    if _canonical_bytes(value) != data:
        raise NativeOutputAdapterError("raw native tool bundle is noncanonical")
    bundle = _mapping(value, "raw native tool bundle")
    _exact_keys(
        bundle,
        {"candidate", "execution", "lane", "producer", "schema", "termination"},
        "raw native tool bundle",
    )
    if (
        bundle["schema"] != RAW_TOOL_BUNDLE_SCHEMA
        or bundle["lane"] != expected_lane
        or bundle["termination"] != "COMPLETE_UNTRUNCATED"
    ):
        raise NativeOutputAdapterError("raw native tool bundle contract mismatch")

    candidate = _mapping(bundle["candidate"], "raw native candidate")
    _exact_keys(
        candidate,
        {"commit", "source_aggregate_sha512", "tree"},
        "raw native candidate",
    )
    for field in ("commit", "tree"):
        if not isinstance(candidate[field], str) or not _OBJECT_ID.fullmatch(
            candidate[field]
        ):
            raise NativeOutputAdapterError(f"raw native candidate {field} invalid")
    if (
        candidate["commit"] != expected_candidate_commit
        or candidate["tree"] != expected_candidate_tree
        or candidate["source_aggregate_sha512"]
        != expected_source_aggregate_sha512
        or not isinstance(candidate["source_aggregate_sha512"], str)
        or not _HEX128.fullmatch(candidate["source_aggregate_sha512"])
    ):
        raise NativeOutputAdapterError("raw native candidate/source binding mismatch")

    producer = _mapping(bundle["producer"], "raw native producer")
    _exact_keys(
        producer,
        {
            "claimed_binary_sha512",
            "identity_attestation",
            "tool",
            "tool_identity_output",
        },
        "raw native producer",
    )
    if producer["tool"] != expected_tool:
        raise NativeOutputAdapterError("raw native tool identity mismatch")
    binary_sha512 = producer["claimed_binary_sha512"]
    if (
        not isinstance(binary_sha512, str)
        or not _HEX128.fullmatch(binary_sha512)
        or binary_sha512 == "0" * 128
    ):
        raise NativeOutputAdapterError("raw native binary identity missing/invalid")
    if producer["identity_attestation"] != "UNAVAILABLE":
        raise NativeOutputAdapterError(
            "raw native binary identity attestation claim is not verifiable"
        )
    _identity_raw, identity_summary = _parse_bound_blob(
        producer["tool_identity_output"],
        label="raw native tool identity output",
        maximum=_MAX_IDENTITY_BYTES,
        require_nonempty=True,
    )

    execution = _mapping(bundle["execution"], "raw native execution")
    _exact_keys(execution, {"exit_status", "stderr", "stdout"}, "raw native execution")
    exit_status = execution["exit_status"]
    if type(exit_status) is not int or not 0 <= exit_status <= 255:
        raise NativeOutputAdapterError("raw native exit status invalid")
    stdout, stdout_summary = _parse_bound_blob(
        execution["stdout"],
        label="raw native stdout",
        maximum=_MAX_RAW_BYTES,
        require_nonempty=False,
    )
    stderr, stderr_summary = _parse_bound_blob(
        execution["stderr"],
        label="raw native stderr",
        maximum=_MAX_RAW_BYTES,
        require_nonempty=False,
    )
    if not stdout and not stderr:
        raise NativeOutputAdapterError("raw native output is entirely absent")

    return {
        "binary_identity_attested": False,
        "binary_identity_attestation": "UNAVAILABLE",
        "candidate_commit": candidate["commit"],
        "candidate_tree": candidate["tree"],
        "claimed_binary_sha512": binary_sha512,
        "exit_status": exit_status,
        "lane": expected_lane,
        "schema": RAW_TOOL_BUNDLE_SCHEMA,
        "semantic_observation_contract": "UNAVAILABLE",
        "source_aggregate_sha512": candidate["source_aggregate_sha512"],
        "stderr": stderr_summary,
        "stdout": stdout_summary,
        "tool": expected_tool,
        "tool_identity_output": identity_summary,
    }


def parse_native_wire_v2_transcripts(
    data: bytes,
    *,
    expected_case_ids: list[str],
) -> tuple[dict[str, object], list[tuple[str, list[dict[str, object]]]]]:
    if (
        not data.endswith(b"\n")
        or b"\r" in data
        or b"\n\n" in data
        or len(expected_case_ids) > _MAX_CASES
    ):
        raise NativeOutputAdapterError("noncanonical native output transport")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise NativeOutputAdapterError("native output is not ASCII") from error
    if len(lines) < 4 or lines[0] != SCHEMA or lines[-1] != "END":
        raise NativeOutputAdapterError("native output header or terminal marker")
    if not lines[1].startswith("IMPLEMENTATION "):
        raise NativeOutputAdapterError("native implementation identity absent")
    implementation = lines[1].removeprefix("IMPLEMENTATION ")
    if not _IMPLEMENTATION.fullmatch(implementation):
        raise NativeOutputAdapterError("native implementation identity invalid")
    if not lines[2].startswith("BINARY_SHA512 "):
        raise NativeOutputAdapterError("native binary identity absent")
    binary_sha512 = lines[2].removeprefix("BINARY_SHA512 ")
    if not _HEX128.fullmatch(binary_sha512):
        raise NativeOutputAdapterError("native binary identity invalid")

    cursor = 3
    cases: list[tuple[str, list[dict[str, object]]]] = []
    while cursor < len(lines) - 1:
        parts = lines[cursor].split(" ")
        if len(parts) != 3 or parts[0] != "CASE" or not _CASE_ID.fullmatch(parts[1]):
            raise NativeOutputAdapterError("native case header")
        try:
            frame_count = int(parts[2])
        except ValueError as error:
            raise NativeOutputAdapterError("native frame count") from error
        if not 1 <= frame_count <= _MAX_FRAMES_PER_CASE:
            raise NativeOutputAdapterError("native frame count bounds")
        cursor += 1
        messages: list[dict[str, object]] = []
        for _ in range(frame_count):
            if cursor >= len(lines) - 1 or not lines[cursor].startswith("FRAME "):
                raise NativeOutputAdapterError("native frame absent")
            encoded = lines[cursor].removeprefix("FRAME ")
            if (
                not encoded
                or len(encoded) % 2
                or any(character not in "0123456789abcdef" for character in encoded)
            ):
                raise NativeOutputAdapterError("native frame hex")
            try:
                frame = bytes.fromhex(encoded)
                messages.append(wire.decode_frame(frame))
            except (ValueError, wire.WireError) as error:
                raise NativeOutputAdapterError("native frame rejected") from error
            cursor += 1
        cases.append((parts[1], messages))

    actual_ids = [case_id for case_id, _ in cases]
    if actual_ids != expected_case_ids:
        raise NativeOutputAdapterError(
            "native cases omitted, reordered, duplicated, or added"
        )
    return (
        {
            "schema": SCHEMA,
            "implementation": implementation,
            "claimed_binary_sha512": binary_sha512,
            "binary_identity_attested": False,
        },
        cases,
    )
