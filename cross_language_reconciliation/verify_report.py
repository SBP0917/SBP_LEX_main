#!/usr/bin/env python3
"""Detached stdlib verifier for a Candidate 10 reconciliation report."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Mapping


ROOT = Path(__file__).resolve().parents[1]
CATALOG = Path(__file__).with_name("case_catalog.json")
OBSERVATION_SCHEMA = Path(__file__).with_name("observation_schema.json")
REPORT_NAME = "reconciliation_report.json"
SIDECAR_NAME = REPORT_NAME + ".sha512"
REPORT_SCHEMA = "SBP-LEX-C10-SEMANTIC-RECONCILIATION-REPORT/1"
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
SIDECAR = re.compile(rf"([0-9a-f]{{128}})  {re.escape(REPORT_NAME)}\n\Z")
TDOM = b"SBP-LEX-AUTH-WIRE/2\0TRANSCRIPT\0"
SDOM = b"SBP-LEX-AUTH-WIRE/2\0SIGNATURE\0"
TESTDOM = b"SBP-LEX-TEST-SIGNATURE/1\0"
NATIVE_WIRE_SCHEMA = "SBP-LEX-NATIVE-WIRE-V2-FRAMED-TRANSCRIPTS/1"
RAW_TOOL_BUNDLE_SCHEMA = "SBP-LEX-C10-RAW-NATIVE-TOOL-OUTPUT-BUNDLE/1"
RAW_TOOL_OPEN_STATUS = "OPEN_NATIVE_OUTPUT_ADAPTER_SEMANTIC_MAPPING_UNAVAILABLE"
IMPLEMENTATION = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
CASE_ID = re.compile(r"[a-z0-9_]{1,96}\Z")
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
RAW_TOOL_BY_LANE = {
    "spark_safety_monitor": "gnatprove",
    "formal_model": "tlc2.TLC",
}
MAX_RAW_BYTES = 16 * 1024 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
EXPECTED_REPORT_KEYS = {
    "authority_effect", "capture_inventory", "case_catalog", "case_results",
    "component_aggregate_sha512", "evidence_execution_ready", "lane_results",
    "limitations", "normalized_observation_schema", "oracle_sha512", "overall_status", "report_class", "schema",
    "source_inventory", "subject",
}
EXCLUDED_PARTS = frozenset({"target", "obj", "bin", "__pycache__", ".pytest_cache"})


class VerificationError(RuntimeError):
    pass


def sha512_bytes(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")


def reject_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_number(value: str) -> None:
    raise VerificationError(f"forbidden JSON number: {value}")


def parse_json(data: bytes) -> object:
    try:
        text = data.decode("ascii")
        value = json.loads(
            text,
            object_pairs_hook=reject_pairs,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError(f"invalid JSON: {error}") from error
    if canonical_bytes(value) != data:
        raise VerificationError("noncanonical JSON")
    return value


def mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise VerificationError(f"{label} is not an object")
    return value


def exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise VerificationError(f"{label} key set mismatch")


def safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise VerificationError("invalid relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts) or path.as_posix() != value:
        raise VerificationError(f"unsafe/noncanonical relative path: {value!r}")
    return value


def repo_file(value: object) -> Path:
    relative = safe_relative(value)
    path = ROOT.joinpath(*PurePosixPath(relative).parts)
    current = ROOT
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            raise VerificationError(f"symlink refused: {relative}")
    if not path.is_file():
        raise VerificationError(f"bound file missing: {relative}")
    return path


def raw_json_object(fields: Mapping[str, object]) -> bytes:
    chunks: list[bytes] = []
    for key in sorted(fields):
        value = fields[key]
        if type(value) is int:
            encoded = str(value).encode("ascii")
        elif isinstance(value, str) and value and all(0x20 <= ord(char) <= 0x7e for char in value) and '"' not in value and "\\" not in value:
            encoded = b'"' + value.encode("ascii") + b'"'
        else:
            raise VerificationError(f"noncanonical wire value: {key}")
        chunks.append(b'"' + key.encode("ascii") + b'":' + encoded)
    return b"{" + b",".join(chunks) + b"}"


def load_vector_bytes(data: bytes) -> list[dict[str, object]]:
    """Parse one exact wire-v2 vector without depending on a filesystem path."""
    if not data.endswith(b"\n") or b"\r" in data or b"\n\n" in data:
        raise VerificationError("noncanonical JSONL")
    messages: list[dict[str, object]] = []
    previous = "0" * 128
    nonces: set[str] = set()
    for sequence, line in enumerate(data.splitlines()):
        message = mapping(parse_json(line + b"\n"), f"vector line {sequence + 1}")
        if message.get("sequence") != sequence or message.get("prior_transcript_digest") != previous:
            raise VerificationError("wire sequence/hash-chain mismatch")
        unsigned = dict(message)
        signature = unsigned.pop("signature_hex", None)
        supplied_digest = unsigned.pop("transcript_digest", None)
        kind = unsigned.get("kind")
        if not isinstance(kind, str) or not isinstance(supplied_digest, str) or not HEX128.fullmatch(supplied_digest):
            raise VerificationError("wire kind/transcript digest invalid")
        actual_digest = hashlib.sha512(TDOM + kind.encode("ascii") + b"\0" + raw_json_object(unsigned)).hexdigest()
        if actual_digest != supplied_digest:
            raise VerificationError("wire transcript digest mismatch")
        public_key = message.get("signing_public_key_hex")
        key_id = message.get("signer_key_id")
        if not isinstance(public_key, str) or not HEX128.fullmatch(public_key) or hashlib.sha512(bytes.fromhex(public_key)).hexdigest() != key_id:
            raise VerificationError("wire signer key identity mismatch")
        preimage = SDOM + kind.encode("ascii") + b"\0" + bytes.fromhex(supplied_digest)
        actual_signature = hashlib.sha512(TESTDOM + bytes.fromhex(public_key) + preimage).hexdigest()
        if message.get("signature_algorithm") != "TEST-SHA512" or signature != actual_signature:
            raise VerificationError("wire fixture signature mismatch")
        nonce = message.get("nonce")
        if not isinstance(nonce, str) or not HEX128.fullmatch(nonce) or nonce in nonces:
            raise VerificationError("wire nonce invalid/replayed")
        nonces.add(nonce)
        previous = supplied_digest
        messages.append(message)
    return messages


def load_vector(path: Path) -> list[dict[str, object]]:
    return load_vector_bytes(path.read_bytes())


def parse_native_wire_capture(
    data: bytes,
    expected_case_ids: list[str],
) -> tuple[dict[str, object], list[tuple[str, list[dict[str, object]]]]]:
    if not data.endswith(b"\n") or b"\r" in data or b"\n\n" in data:
        raise VerificationError("noncanonical native output transport")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("native output is not ASCII") from error
    if len(lines) < 4 or lines[0] != NATIVE_WIRE_SCHEMA or lines[-1] != "END":
        raise VerificationError("native output header or terminal marker")
    if not lines[1].startswith("IMPLEMENTATION "):
        raise VerificationError("native implementation identity absent")
    implementation = lines[1].removeprefix("IMPLEMENTATION ")
    if not IMPLEMENTATION.fullmatch(implementation):
        raise VerificationError("native implementation identity invalid")
    if not lines[2].startswith("BINARY_SHA512 "):
        raise VerificationError("native binary identity absent")
    binary_sha512 = lines[2].removeprefix("BINARY_SHA512 ")
    if not HEX128.fullmatch(binary_sha512):
        raise VerificationError("native binary identity invalid")
    cursor = 3
    cases: list[tuple[str, list[dict[str, object]]]] = []
    while cursor < len(lines) - 1:
        header = lines[cursor].split(" ")
        if len(header) != 3 or header[0] != "CASE" or not CASE_ID.fullmatch(header[1]):
            raise VerificationError("native case header")
        try:
            count = int(header[2])
        except ValueError as error:
            raise VerificationError("native frame count") from error
        if not 1 <= count <= 21:
            raise VerificationError("native frame count bounds")
        cursor += 1
        payloads: list[bytes] = []
        for _ in range(count):
            if cursor >= len(lines) - 1 or not lines[cursor].startswith("FRAME "):
                raise VerificationError("native frame absent")
            value = lines[cursor].removeprefix("FRAME ")
            if not value or len(value) % 2 or any(char not in "0123456789abcdef" for char in value):
                raise VerificationError("native frame hex")
            frame = bytes.fromhex(value)
            if len(frame) < 4:
                raise VerificationError("native frame truncated")
            size = int.from_bytes(frame[:4], "big")
            if size == 0 or size > 32_768 or len(frame) != size + 4:
                raise VerificationError("native frame length")
            payloads.append(frame[4:])
            cursor += 1
        cases.append((header[1], load_vector_bytes(b"\n".join(payloads) + b"\n")))
    if [case_id for case_id, _messages in cases] != expected_case_ids:
        raise VerificationError("native case set/order mismatch")
    return (
        {
            "schema": NATIVE_WIRE_SCHEMA,
            "implementation": implementation,
            "claimed_binary_sha512": binary_sha512,
            "binary_identity_attested": False,
        },
        cases,
    )


def _parse_bound_blob(
    value: object,
    *,
    label: str,
    maximum: int,
    require_nonempty: bool,
) -> tuple[bytes, dict[str, object]]:
    blob = mapping(value, label)
    exact_keys(blob, {"bytes_hex", "sha512", "size"}, label)
    size = blob["size"]
    encoded = blob["bytes_hex"]
    digest = blob["sha512"]
    if (
        type(size) is not int
        or size < 0
        or size > maximum
        or (require_nonempty and size == 0)
    ):
        raise VerificationError(f"{label} size invalid")
    if (
        not isinstance(encoded, str)
        or len(encoded) != 2 * size
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        raise VerificationError(f"{label} hex/size binding invalid")
    if not isinstance(digest, str) or not HEX128.fullmatch(digest):
        raise VerificationError(f"{label} digest invalid")
    raw = bytes.fromhex(encoded)
    if sha512_bytes(raw) != digest:
        raise VerificationError(f"{label} digest mismatch")
    return raw, {"sha512": digest, "size": size}


def parse_raw_native_tool_output_bundle(
    data: bytes,
    *,
    expected_lane: str,
    expected_candidate_commit: str,
    expected_candidate_tree: str,
    expected_source_aggregate_sha512: str,
) -> dict[str, object]:
    expected_tool = RAW_TOOL_BY_LANE.get(expected_lane)
    if expected_tool is None:
        raise VerificationError("raw native tool lane unsupported")
    maximum_transport = 2 * (2 * MAX_RAW_BYTES + MAX_IDENTITY_BYTES) + 32_768
    if not isinstance(data, bytes) or not data or len(data) > maximum_transport:
        raise VerificationError("raw native tool bundle transport bounds")
    bundle = mapping(parse_json(data), "raw native tool bundle")
    exact_keys(
        bundle,
        {"candidate", "execution", "lane", "producer", "schema", "termination"},
        "raw native tool bundle",
    )
    if (
        bundle["schema"] != RAW_TOOL_BUNDLE_SCHEMA
        or bundle["lane"] != expected_lane
        or bundle["termination"] != "COMPLETE_UNTRUNCATED"
    ):
        raise VerificationError("raw native tool bundle contract mismatch")
    candidate = mapping(bundle["candidate"], "raw native candidate")
    exact_keys(
        candidate,
        {"commit", "source_aggregate_sha512", "tree"},
        "raw native candidate",
    )
    for field in ("commit", "tree"):
        if not isinstance(candidate[field], str) or not OBJECT_ID.fullmatch(
            candidate[field]
        ):
            raise VerificationError(f"raw native candidate {field} invalid")
    if (
        candidate["commit"] != expected_candidate_commit
        or candidate["tree"] != expected_candidate_tree
        or candidate["source_aggregate_sha512"]
        != expected_source_aggregate_sha512
        or not isinstance(candidate["source_aggregate_sha512"], str)
        or not HEX128.fullmatch(candidate["source_aggregate_sha512"])
    ):
        raise VerificationError("raw native candidate/source binding mismatch")
    producer = mapping(bundle["producer"], "raw native producer")
    exact_keys(
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
        raise VerificationError("raw native tool identity mismatch")
    binary_sha512 = producer["claimed_binary_sha512"]
    if (
        not isinstance(binary_sha512, str)
        or not HEX128.fullmatch(binary_sha512)
        or binary_sha512 == "0" * 128
    ):
        raise VerificationError("raw native binary identity missing/invalid")
    if producer["identity_attestation"] != "UNAVAILABLE":
        raise VerificationError(
            "raw native binary identity attestation claim is not verifiable"
        )
    _identity_raw, identity_summary = _parse_bound_blob(
        producer["tool_identity_output"],
        label="raw native tool identity output",
        maximum=MAX_IDENTITY_BYTES,
        require_nonempty=True,
    )
    execution = mapping(bundle["execution"], "raw native execution")
    exact_keys(execution, {"exit_status", "stderr", "stdout"}, "raw native execution")
    exit_status = execution["exit_status"]
    if type(exit_status) is not int or not 0 <= exit_status <= 255:
        raise VerificationError("raw native exit status invalid")
    stdout, stdout_summary = _parse_bound_blob(
        execution["stdout"],
        label="raw native stdout",
        maximum=MAX_RAW_BYTES,
        require_nonempty=False,
    )
    stderr, stderr_summary = _parse_bound_blob(
        execution["stderr"],
        label="raw native stderr",
        maximum=MAX_RAW_BYTES,
        require_nonempty=False,
    )
    if not stdout and not stderr:
        raise VerificationError("raw native output is entirely absent")
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


def one(messages: list[dict[str, object]], kind: str, required: bool = True) -> dict[str, object] | None:
    found = [message for message in messages if message.get("kind") == kind]
    if len(found) > 1 or (required and len(found) != 1):
        raise VerificationError(f"wrong number of {kind} records")
    return found[0] if found else None


def digest_set(value: object) -> set[str]:
    if not isinstance(value, str) or not value:
        raise VerificationError("invalid digest set")
    parts = value.split(",")
    if parts != sorted(set(parts)) or not all(HEX128.fullmatch(part) for part in parts):
        raise VerificationError("noncanonical digest set")
    return set(parts)


def derive_observation(messages: list[dict[str, object]]) -> dict[str, object]:
    mode = messages[0].get("mode")
    convergence_request = one(messages, "convergence_request")
    convergence_result = one(messages, "convergence_result")
    prepare_result = one(messages, "prepare_result")
    prepare_request = one(messages, "prepare_request")
    commit_request = one(messages, "commit_request")
    commit_result = one(messages, "commit_result")
    lease = one(messages, "lease_redeem_result")
    arm = one(messages, "watchdog_arm_result")
    permit_request = one(messages, "effect_permit_request")
    permit = one(messages, "effect_permit_result")
    terminal = one(messages, "watchdog_terminal")
    final = one(messages, "watchdog_result")
    required = [convergence_request, convergence_result, prepare_request, prepare_result, commit_request, commit_result, lease, arm, permit_request, permit, terminal, final]
    if any(item is None for item in required):
        raise VerificationError("normalized lifecycle record missing")
    assert all(item is not None for item in required)
    assert convergence_request is not None and convergence_result is not None
    assert prepare_request is not None and prepare_result is not None
    assert commit_request is not None and commit_result is not None
    assert lease is not None and arm is not None and permit_request is not None and permit is not None
    assert terminal is not None and final is not None

    convergence_fields = ("convergence_digest", "evidence_a_digest", "evidence_b_digest", "mode_evidence_digest", "projection_digest")
    if convergence_result.get("decision") != "ALLOW" or any(convergence_request.get(field) != convergence_result.get(field) for field in convergence_fields):
        raise VerificationError("non-exact convergence")
    if prepare_result.get("decision") != "ALLOW" or "capability_digest" in prepare_result or not HEX128.fullmatch(str(prepare_result.get("prepare_proof_digest"))) or str(prepare_result.get("prepare_proof_digest")) == "0" * 128:
        raise VerificationError("PREPARE semantic mismatch")
    if not HEX32.fullmatch(str(prepare_result.get("prepare_id"))) or str(prepare_result.get("prepare_id")) == "0" * 32:
        raise VerificationError("PREPARE id mismatch")
    if not (int(prepare_result["sequence"]) < int(commit_request["sequence"]) < int(commit_result["sequence"])):
        raise VerificationError("PREPARE/COMMIT order mismatch")
    if commit_result.get("decision") != "ALLOW" or not HEX128.fullmatch(str(commit_result.get("capability_digest"))) or str(commit_result.get("capability_digest")) == "0" * 128:
        raise VerificationError("COMMIT semantic mismatch")

    epochs = {message.get("authority_epoch") for message in messages}
    durable = {message.get("durable_consumption_digest") for message in messages}
    if len(epochs) != 1 or len(durable) != 1:
        raise VerificationError("replay identity mismatch")
    authority_epoch = next(iter(epochs))
    durable_digest = next(iter(durable))
    if type(authority_epoch) is not int or authority_epoch <= 0 or not HEX128.fullmatch(str(durable_digest)):
        raise VerificationError("replay identity invalid")
    if any(item.get("decision") != "ALLOW" for item in (lease, arm, permit)):
        raise VerificationError("lease/arm/permit denial")
    if not HEX128.fullmatch(str(permit_request.get("point_of_use_digest"))) or str(permit_request.get("point_of_use_digest")) == "0" * 128:
        raise VerificationError("point-of-use digest invalid")

    deadlines = {
        "LEASE": int(lease["lease_deadline_ms"]),
        "PERMIT": int(permit["permit_deadline_ms"]),
        "WATCHDOG": int(arm["watchdog_deadline_ms"]),
    }
    bound = min(deadlines.values())
    bound_sources = "+".join(name for name in ("LEASE", "PERMIT", "WATCHDOG") if deadlines[name] == bound)
    for message in messages[int(permit["sequence"]) + 1 :]:
        if "permit_id" in message and message["permit_id"] != permit["permit_id"]:
            raise VerificationError("permit id tail transplant")
        if "permit_digest" in message and message["permit_digest"] != permit["permit_digest"]:
            raise VerificationError("permit digest tail transplant")

    receipt = one(messages, "effect_receipt", False)
    ack = one(messages, "receipt_ack", False)
    if receipt is None:
        if ack is not None or terminal.get("watchdog_status") != "TIMEOUT" or int(terminal["message_time_ms"]) != bound:
            raise VerificationError("timeout tail mismatch")
        if not int(terminal["message_time_ms"]) <= int(final["message_time_ms"]) <= int(terminal["message_time_ms"]) + 1000:
            raise VerificationError("timeout record bound mismatch")
        completion = "TIMEOUT_TERMINAL_EQUALS_BOUND"
        effect_outcome = "NO_RECEIPT"
        receipt_presence = "ABSENT"
        ack_decision = "NONE"
        scenario = "TIMEOUT"
        disposition = "FAIL_CLOSED_TIMEOUT"
    else:
        if ack is None or not all(int(value) < bound for value in (
            receipt["message_time_ms"], receipt["adapter_consumed_at_ms"], ack["message_time_ms"], terminal["message_time_ms"], final["message_time_ms"],
        )):
            raise VerificationError("receipt half-open bound mismatch")
        completion = "ALL_PRESENT_TAIL_STRICTLY_BEFORE_BOUND"
        effect_outcome = str(receipt.get("effect_outcome"))
        receipt_presence = "PRESENT"
        ack_decision = str(ack.get("decision"))
        outcomes = {
            "SUCCEEDED": ("SUCCESS", "EFFECT_RECORDED"),
            "FAILED": ("FAILURE", "FAIL_CLOSED_FAILED"),
            "UNKNOWN": ("UNKNOWN", "FAIL_CLOSED_UNKNOWN"),
        }
        if effect_outcome not in outcomes:
            raise VerificationError("unknown receipt outcome")
        scenario, disposition = outcomes[effect_outcome]

    if mode == "MODE_1":
        release_request = one(messages, "mode1_release_request")
        release = one(messages, "mode1_release_result")
        a = one(messages, "branch_a_statement")
        b = one(messages, "branch_b_statement")
        one(messages, "mode1_overlap_witness")
        assert release_request is not None and release is not None and a is not None and b is not None
        released = int(release["rendezvous_released_at_ms"])
        if released < int(release_request["message_time_ms"]) or released > min(int(a["substantive_start_ms"]), int(b["substantive_start_ms"])):
            raise VerificationError("Mode 1 release causality mismatch")
        if max(int(a["substantive_start_ms"]), int(b["substantive_start_ms"])) >= min(int(a["substantive_end_ms"]), int(b["substantive_end_ms"])):
            raise VerificationError("Mode 1 overlap mismatch")
        mode_shape = "DUAL_BRANCH_CAUSAL_OVERLAP"
        mode_relation = "RELEASE_EQUALS_REQUEST_TIME" if released == int(release_request["message_time_ms"]) else "RELEASE_AFTER_REQUEST_TIME"
    elif mode == "MODE_2":
        one(messages, "branch_a_statement")
        cert = one(messages, "mode2_validator_certificate")
        assert cert is not None
        ci, co = digest_set(cert["candidate_input_set"]), digest_set(cert["candidate_output_set"])
        pi, po = digest_set(cert["pathway_input_set"]), digest_set(cert["pathway_output_set"])
        if not co <= ci or not po <= pi:
            raise VerificationError("Mode 2 widening")
        mode_relation = "EQUAL_CANDIDATE_AND_PATHWAY_NONWIDENING" if co == ci and po == pi else ("STRICT_CANDIDATE_AND_PATHWAY_REDUCTION" if co < ci and po < pi else "MIXED_NONWIDENING_REDUCTION")
        mode_shape = "PRIMARY_PLUS_INDEPENDENT_VALIDATOR"
    elif mode == "MODE_3":
        proof = one(messages, "mode3_single_state_proof")
        assert proof is not None
        if not all(HEX128.fullmatch(str(proof.get(field))) and str(proof.get(field)) != "0" * 128 for field in ("state_seal_digest", "single_state_proof_digest", "single_state_callable_digest", "single_state_provenance_digest")):
            raise VerificationError("Mode 3 proof incomplete")
        mode_shape = "SINGLE_STATE_SEALED_PROOF"
        mode_relation = "DERIVED_STATE_SEAL_AND_PROOF"
    else:
        raise VerificationError("unknown mode")

    return {
        "adapter_atomic_consumption_context": "REVALIDATED_IMMEDIATELY_BEFORE_CONSUMPTION",
        "authority_epoch": authority_epoch,
        "commit_authority_stage": "SOLE_COMMIT",
        "commit_decision": commit_result["decision"],
        "commit_result_count": 1,
        "completion_bound_ms": bound,
        "completion_bound_source": bound_sources,
        "completion_relation": completion,
        "convergence_decision": convergence_result["decision"],
        "convergence_exact": True,
        "durable_consumption_digest": durable_digest,
        "effect_disposition": disposition,
        "effect_outcome": effect_outcome,
        "final_decision": final["decision"],
        "lease_decision": lease["decision"],
        "mode": mode,
        "mode_evidence_shape": mode_shape,
        "mode_specific_relation": mode_relation,
        "permit_decision": permit["decision"],
        "permit_digest": permit["permit_digest"],
        "permit_id": permit["permit_id"],
        "point_of_use_digest": permit_request["point_of_use_digest"],
        "prepare_authority_granted": False,
        "prepare_decision": prepare_result["decision"],
        "prepare_result_count": 1,
        "receipt_ack_decision": ack_decision,
        "receipt_presence": receipt_presence,
        "replay_key": f"{authority_epoch}:{durable_digest}",
        "scenario": scenario,
        "single_commit": True,
        "watchdog_arm_decision": arm["decision"],
        "watchdog_status": terminal["watchdog_status"],
    }


def expected_inventory(catalog: Mapping[str, object]) -> list[dict[str, object]]:
    roots = mapping(catalog["component_roots"], "component roots")
    assignments: dict[str, str] = {}
    for component in sorted(roots):
        paths = roots[component]
        if not isinstance(paths, list):
            raise VerificationError("component roots list invalid")
        for raw in paths:
            relative = safe_relative(raw)
            path = ROOT.joinpath(*PurePosixPath(relative).parts)
            if not path.exists() or path.is_symlink():
                raise VerificationError(f"component root absent/symlink: {relative}")
            candidates = [path] if path.is_file() else sorted(path.rglob("*"))
            for candidate in candidates:
                rel_path = candidate.relative_to(ROOT)
                if any(part in EXCLUDED_PARTS for part in rel_path.parts) or not candidate.is_file() or candidate.suffix in {".pyc", ".pyo"}:
                    continue
                if candidate.is_symlink():
                    raise VerificationError(f"component symlink: {rel_path.as_posix()}")
                relative_file = rel_path.as_posix()
                if relative_file in assignments and assignments[relative_file] != component:
                    raise VerificationError(f"component overlap: {relative_file}")
                assignments[relative_file] = component
    cases = catalog["cases"]
    if not isinstance(cases, list):
        raise VerificationError("catalog cases invalid")
    for raw_case in cases:
        case = mapping(raw_case, "catalog case")
        relative = safe_relative(case["source"] if case["kind"] == "vector" else case["base"])
        assignments.setdefault(relative, "wire_v2_vectors")
    assignments.setdefault("wire_protocol/v2/vectors/adversarial_cases.txt", "wire_v2_vectors")
    result = []
    for relative, component in sorted(assignments.items()):
        path = repo_file(relative)
        result.append({"component": component, "path": relative, "sha512": sha512_file(path), "size": path.stat().st_size})
    return result


def aggregate_inventory(entries: list[dict[str, object]]) -> dict[str, str]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        grouped.setdefault(str(entry["component"]), []).append(entry)
    result: dict[str, str] = {}
    for component, items in sorted(grouped.items()):
        digest = hashlib.sha512(b"SBP-LEX-C10-COMPONENT-INVENTORY/1\0")
        for entry in items:
            digest.update(str(entry["path"]).encode("ascii") + b"\0")
            digest.update(str(entry["sha512"]).encode("ascii") + b"\0")
            digest.update(str(entry["size"]).encode("ascii") + b"\0")
        result[component] = digest.hexdigest()
    return result


def parse_independent_trace(data: bytes) -> dict[str, object]:
    if not data.endswith(b"\n") or b"\r" in data or b"\n\n" in data:
        raise VerificationError("independent verifier trace transport mismatch")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise VerificationError("independent verifier trace is not ASCII") from error
    if len(lines) < 7 or lines[0] != "SBP-LEX-INDEPENDENT-EVIDENCE-V1":
        raise VerificationError("independent verifier trace header/length mismatch")
    tags = [line.split(" ", 1)[0] for line in lines[1:]]
    if tags[-1] != "END":
        raise VerificationError("independent verifier trace has no END")
    parsed: list[dict[str, str]] = []
    for line in lines[1:-1]:
        parts = line.split(" ")
        fields: dict[str, str] = {"tag": parts[0]}
        for part in parts[1:]:
            if "=" not in part:
                raise VerificationError("independent verifier field mismatch")
            key, value = part.split("=", 1)
            if not key or not value or key in fields:
                raise VerificationError("independent verifier duplicate/empty field")
            fields[key] = value
        parsed.append(fields)
    envelope = next((item for item in parsed if item["tag"] == "ENVELOPE"), None)
    if envelope is None or envelope.get("decision") not in {"ALLOW", "BLOCK"}:
        raise VerificationError("independent verifier decision mismatch")
    decision = envelope["decision"]
    expected_tags = (
        ["REQUEST", "STATE", "CONVERGENCE", "ENVELOPE", "PROOF", "PREPARE", "LEASE", "REDEEM", "COMMIT", "RECEIPT", "WATCHDOG", "END"]
        if decision == "ALLOW"
        else ["REQUEST", "STATE", "CONVERGENCE", "ENVELOPE", "RECEIPT", "WATCHDOG", "END"]
    )
    if tags != expected_tags:
        raise VerificationError("independent verifier record order mismatch")
    return {
        "decision": decision,
        "event_count": len(parsed),
        "profile": "SBP-LEX-INDEPENDENT-EVIDENCE-V1",
        "record_kinds": tags,
        "verification_scope": "STRUCTURAL_TEXT_ONLY_SIGNATURES_NOT_REVERIFIED",
    }


def safe_git_environment() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update(GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    return environment


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "--no-optional-locks", "-c", f"safe.directory={ROOT}", "-C", str(ROOT), *arguments],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=safe_git_environment(), check=False,
    )
    if result.returncode:
        raise VerificationError("Git subject verification failed")
    return result.stdout.decode("ascii").strip()


def verify(report_path: Path) -> dict[str, object]:
    report_path = report_path.resolve(strict=True)
    directory = report_path.parent
    if report_path.name != REPORT_NAME or {path.name for path in directory.iterdir()} != {REPORT_NAME, SIDECAR_NAME}:
        raise VerificationError("report directory path set is not exact")
    report_data = report_path.read_bytes()
    sidecar_data = (directory / SIDECAR_NAME).read_bytes()
    try:
        sidecar_text = sidecar_data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("sidecar is not ASCII") from error
    matched = SIDECAR.fullmatch(sidecar_text)
    if not matched or matched.group(1) != sha512_bytes(report_data):
        raise VerificationError("report SHA-512 sidecar mismatch")
    report = mapping(parse_json(report_data), "report")
    exact_keys(report, EXPECTED_REPORT_KEYS, "report")
    if report["schema"] != REPORT_SCHEMA or report["authority_effect"] != "NONE":
        raise VerificationError("report schema/authority effect mismatch")

    observation_schema_data = OBSERVATION_SCHEMA.read_bytes()
    observation_schema = mapping(parse_json(observation_schema_data), "observation schema")
    schema_binding = mapping(report["normalized_observation_schema"], "observation schema binding")
    exact_keys(schema_binding, {"path", "sha512"}, "observation schema binding")
    if schema_binding != {
        "path": "cross_language_reconciliation/observation_schema.json",
        "sha512": sha512_bytes(observation_schema_data),
    }:
        raise VerificationError("observation schema binding mismatch")
    required_observation_fields = observation_schema.get("required_fields")
    if not isinstance(required_observation_fields, list) or len(required_observation_fields) != len(set(required_observation_fields)):
        raise VerificationError("observation schema fields invalid")

    catalog_data = CATALOG.read_bytes()
    catalog = mapping(parse_json(catalog_data), "catalog")
    case_catalog = mapping(report["case_catalog"], "report case catalog")
    exact_keys(case_catalog, {"case_count", "matrix_case_ids", "path", "sha512"}, "report case catalog")
    if case_catalog["path"] != "cross_language_reconciliation/case_catalog.json" or case_catalog["sha512"] != sha512_bytes(catalog_data):
        raise VerificationError("case catalog hash/path mismatch")
    cases = catalog.get("cases")
    if not isinstance(cases, list) or case_catalog["case_count"] != len(cases) or case_catalog["matrix_case_ids"] != catalog.get("matrix_case_ids"):
        raise VerificationError("case catalog membership mismatch")

    inventory = expected_inventory(catalog)
    component_aggregates = aggregate_inventory(inventory)
    if report["source_inventory"] != inventory or report["component_aggregate_sha512"] != component_aggregates:
        raise VerificationError("source inventory is missing, extra, reordered, or altered")

    results = report["case_results"]
    if not isinstance(results, list) or len(results) != len(cases):
        raise VerificationError("case result count mismatch")
    expected_ids = [mapping(case, "case")["id"] for case in cases]
    if [mapping(result, "result").get("case_id") for result in results] != expected_ids:
        raise VerificationError("case result path set/order mismatch")
    matrix_ids = case_catalog["matrix_case_ids"]
    if not isinstance(matrix_ids, list) or not all(isinstance(item, str) for item in matrix_ids):
        raise VerificationError("matrix case id contract mismatch")
    matrix_observations: dict[str, dict[str, object]] = {}
    for raw_case, raw_result in zip(cases, results, strict=True):
        case = mapping(raw_case, "case")
        result = mapping(raw_result, "result")
        if case["kind"] == "vector":
            exact_keys(result, {"adapter", "case_id", "kind", "observation", "source_path", "source_sha512", "verdict"}, f"result {case['id']}")
            path = repo_file(case["source"])
            if result["adapter"] != "WIRE_V2_PYTHON_EXECUTED" or result["kind"] != "VECTOR" or result["verdict"] != "ACCEPT" or result["source_path"] != case["source"] or result["source_sha512"] != sha512_file(path):
                raise VerificationError(f"vector result binding mismatch: {case['id']}")
            observation = derive_observation(load_vector(path))
            if sorted(observation) != sorted(required_observation_fields):
                raise VerificationError(f"observation schema mismatch: {case['id']}")
            if result["observation"] != observation:
                raise VerificationError(f"normalized lifecycle mismatch: {case['id']}")
            expected = mapping(case["expected"], f"expected {case['id']}")
            if any(observation.get(key) != value for key, value in expected.items()):
                raise VerificationError(f"catalog expectation mismatch: {case['id']}")
            if case["id"] in matrix_ids:
                matrix_observations[str(case["id"])] = observation
        else:
            exact_keys(result, {"adapter", "base_path", "base_sha512", "case_id", "kind", "mutation", "registry_case", "rejection", "verdict"}, f"result {case['id']}")
            path = repo_file(case["base"])
            expected = {
                "adapter": "WIRE_V2_PYTHON_IN_MEMORY_SIGNED_NEGATIVE",
                "base_path": case["base"],
                "base_sha512": sha512_file(path),
                "case_id": case["id"],
                "kind": "SYNTHETIC_NEGATIVE",
                "mutation": case["mutation"],
                "registry_case": case["required_registry_case"],
                "rejection": "WIRE_V2_REJECTED",
                "verdict": "REJECT",
            }
            if result != expected:
                raise VerificationError(f"negative result binding mismatch: {case['id']}")

    if list(matrix_observations) != matrix_ids:
        raise VerificationError("matrix observations are missing, extra, or reordered")

    external_lanes = [
        "wire_v2_rust", "rust_trusted_core", "rust_authority_service",
        "independent_verifier", "spark_safety_monitor", "formal_model",
    ]
    captures = report["capture_inventory"]
    if not isinstance(captures, list):
        raise VerificationError("capture inventory invalid")
    capture_lanes: set[str] = set()
    capture_paths: set[str] = set()
    capture_by_lane: dict[str, dict[str, object]] = {}
    for raw in captures:
        capture = mapping(raw, "capture")
        exact_keys(capture, {"format", "lane", "path", "sha512", "size"}, "capture")
        path = repo_file(capture["path"])
        lane_name = str(capture["lane"])
        if lane_name not in external_lanes:
            raise VerificationError("unknown capture lane")
        if lane_name in capture_lanes or capture["path"] in capture_paths:
            raise VerificationError("duplicate capture lane/path")
        capture_lanes.add(lane_name)
        capture_paths.add(str(capture["path"]))
        if capture["sha512"] != sha512_file(path) or capture["size"] != path.stat().st_size:
            raise VerificationError("capture bytes mismatch")
        capture_by_lane[lane_name] = capture
    if [str(mapping(item, "capture")["lane"]) for item in captures] != [
        lane for lane in external_lanes if lane in capture_by_lane
    ]:
        raise VerificationError("capture lane order mismatch")

    lanes = report["lane_results"]
    if not isinstance(lanes, list):
        raise VerificationError("lane results invalid")
    expected_lanes: list[dict[str, object]] = [{
        "case_count": len(cases),
        "lane": "wire_v2_python",
        "matrix_case_count": len(matrix_ids),
        "status": "CLOSED_LOCAL_FIXTURE_SEMANTICS",
    }]
    for lane_name in external_lanes:
        capture = capture_by_lane.get(lane_name)
        if capture is None:
            expected_lanes.append({"lane": lane_name, "status": "OPEN_MISSING_EXACT_CAPTURE"})
            continue
        capture_path = repo_file(capture["path"])
        capture_format = capture["format"]
        declared_result: object = None
        # The declared result is in the lane result; only its exact allowed
        # token is trusted after the capture bytes and format are checked.
        actual_lane = next(
            (mapping(item, "lane result") for item in lanes if mapping(item, "lane result").get("lane") == lane_name),
            None,
        )
        if actual_lane is None:
            raise VerificationError(f"missing lane result: {lane_name}")
        declared_result = actual_lane.get("declared_result")
        if declared_result not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
            raise VerificationError(f"invalid declared result: {lane_name}")
        if capture_format == "canonical_observation_set":
            observed = mapping(parse_json(capture_path.read_bytes()), f"observation set {lane_name}")
            exact_keys(observed, {"case_catalog_sha512", "implementation", "observations", "schema"}, f"observation set {lane_name}")
            if observed["schema"] != "SBP-LEX-C10-NORMALIZED-OBSERVATION-SET/1" or observed["case_catalog_sha512"] != case_catalog["sha512"] or not isinstance(observed["implementation"], str) or not observed["implementation"]:
                raise VerificationError(f"observation set contract mismatch: {lane_name}")
            items = observed["observations"]
            if not isinstance(items, list):
                raise VerificationError(f"observation set missing array: {lane_name}")
            observed_by_id: dict[str, dict[str, object]] = {}
            for raw_item in items:
                item = mapping(raw_item, f"observation item {lane_name}")
                exact_keys(item, {"case_id", "observation"}, f"observation item {lane_name}")
                case_id = str(item["case_id"])
                if case_id in observed_by_id:
                    raise VerificationError(f"duplicate captured observation: {case_id}")
                captured_observation = mapping(item["observation"], f"captured observation {case_id}")
                if sorted(captured_observation) != sorted(required_observation_fields):
                    raise VerificationError(f"captured observation schema mismatch: {case_id}")
                observed_by_id[case_id] = captured_observation
            if list(observed_by_id) != matrix_ids:
                raise VerificationError(f"captured case set/order mismatch: {lane_name}")
            mismatch = [
                case_id for case_id in matrix_ids
                if observed_by_id[case_id] != matrix_observations[case_id]
            ]
            expected_lanes.append({
                "declared_result": declared_result,
                "lane": lane_name,
                "semantic_mismatches": mismatch,
                "status": (
                    "OPEN_MATCH_NOT_DERIVED_BY_NATIVE_OUTPUT_ADAPTER"
                    if not mismatch else "FAIL_SEMANTIC_MISMATCH"
                ),
            })
        elif capture_format == "native_wire_v2_framed_transcripts" and lane_name in {
            "wire_v2_rust",
            "rust_authority_service",
        }:
            producer, native_cases = parse_native_wire_capture(
                capture_path.read_bytes(), matrix_ids
            )
            native_observations = {
                case_id: derive_observation(messages)
                for case_id, messages in native_cases
            }
            mismatch = [
                case_id
                for case_id in matrix_ids
                if native_observations[case_id] != matrix_observations[case_id]
            ]
            expected_lanes.append({
                "declared_result": declared_result,
                "lane": lane_name,
                "native_producer": producer,
                "semantic_mismatches": mismatch,
                "status": (
                    "OPEN_NATIVE_OUTPUT_ADAPTER_BINARY_IDENTITY_UNATTESTED"
                    if not mismatch
                    else "FAIL_SEMANTIC_MISMATCH"
                ),
            })
        elif capture_format == "independent_verifier_v1_trace" and lane_name == "independent_verifier":
            expected_lanes.append({
                "declared_result": declared_result,
                "lane": lane_name,
                "status": "OPEN_PROFILE_DOES_NOT_COVER_3X4_WIRE_V2_MATRIX",
                "trace_summary": parse_independent_trace(capture_path.read_bytes()),
            })
        elif capture_format == "native_tool_raw_output_bundle" and lane_name in {
            "spark_safety_monitor",
            "formal_model",
        }:
            candidate_subject = mapping(report["subject"], "subject")
            native_output = parse_raw_native_tool_output_bundle(
                capture_path.read_bytes(),
                expected_lane=lane_name,
                expected_candidate_commit=str(candidate_subject["commit"]),
                expected_candidate_tree=str(candidate_subject["tree"]),
                expected_source_aggregate_sha512=component_aggregates[lane_name],
            )
            expected_lanes.append({
                "declared_result": declared_result,
                "lane": lane_name,
                "native_output": native_output,
                "status": RAW_TOOL_OPEN_STATUS,
            })
        elif capture_format == "opaque_result":
            expected_lanes.append({
                "declared_result": declared_result,
                "lane": lane_name,
                "status": "OPEN_OPAQUE_RESULT_HAS_NO_CASE_SEMANTICS",
            })
        else:
            raise VerificationError(f"unsupported capture format: {lane_name}")
    if lanes != expected_lanes:
        raise VerificationError("lane result semantics do not match captured bytes")

    subject = mapping(report["subject"], "subject")
    exact_keys(subject, {"clean", "commit", "fixed_subject_verified", "tree"}, "subject")
    expected_limitations = [
        "No production, live, deployment, safety, owner-admission or external-IV&V claim.",
        "TEST-SHA512 and fixture keys are non-production test material.",
        "Opaque PASS output and equal test counts never establish semantic equivalence.",
        "SPARK/formal raw-output bundles remain OPEN because no native lifecycle-observation mapping exists.",
        "Independent verifier V1 text alone does not cover the wire-v2 3x4 matrix.",
    ]
    if report["limitations"] != expected_limitations or report["oracle_sha512"] != catalog.get("oracle_sha512"):
        raise VerificationError("limitations/oracle binding mismatch")
    evidence = report["report_class"] == "EVIDENTIARY_RECONCILIATION_CANDIDATE"
    all_closed = all(mapping(item, "lane").get("status") == "CLOSED_SEMANTIC_MATCH" for item in lanes[1:])
    ready = bool(evidence and subject["fixed_subject_verified"] and all_closed)
    if report["evidence_execution_ready"] is not ready:
        raise VerificationError("evidence readiness derivation mismatch")
    expected_overall = "CLOSED_ALL_DECLARED_IMPLEMENTATIONS_SEMANTICALLY_MATCH" if all_closed else "OPEN_CROSS_LANGUAGE_REFINEMENT_INCOMPLETE"
    if report["overall_status"] != expected_overall:
        raise VerificationError("overall status derivation mismatch")
    current_commit = git("rev-parse", "--verify", "HEAD^{commit}")
    current_tree = git("rev-parse", "--verify", "HEAD^{tree}")
    current_clean = not bool(git("status", "--porcelain=v1", "--untracked-files=all"))
    if subject["commit"] != current_commit or subject["tree"] != current_tree or subject["clean"] is not current_clean:
        raise VerificationError("report subject no longer matches verifier worktree")
    if evidence:
        if not current_clean:
            raise VerificationError("dirty worktree refused for evidentiary verification")
        if subject["clean"] is not True or subject["fixed_subject_verified"] is not True:
            raise VerificationError("evidentiary subject mismatch")
    elif report["report_class"] != "NON_EVIDENTIARY_SYNTHETIC_LOCAL_ASSURANCE" or subject["fixed_subject_verified"] is not False or report["evidence_execution_ready"] is not False:
        raise VerificationError("synthetic report mislabeled as evidence")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = verify(arguments.report)
    except (OSError, VerificationError, subprocess.SubprocessError) as error:
        print(f"RECONCILIATION REPORT VERIFY FAIL: {error}", file=sys.stderr)
        return 1
    print("RECONCILIATION REPORT VERIFY PASS")
    print(f"class={report['report_class']}")
    print(f"overall={report['overall_status']}")
    print(f"evidence_execution_ready={str(report['evidence_execution_ready']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
