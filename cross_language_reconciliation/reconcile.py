#!/usr/bin/env python3
"""Fail-closed Candidate 10 lifecycle-semantic reconciliation.

This tool is local assurance infrastructure.  It never grants execution
authority and never treats process success or equal test counts as semantic
equivalence.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = Path(__file__).with_name("case_catalog.json")
OBSERVATION_SCHEMA_PATH = Path(__file__).with_name("observation_schema.json")
REPORT_NAME = "reconciliation_report.json"
REPORT_SIDECAR = REPORT_NAME + ".sha512"
REPORT_SCHEMA = "SBP-LEX-C10-SEMANTIC-RECONCILIATION-REPORT/1"
OBSERVATION_SET_SCHEMA = "SBP-LEX-C10-NORMALIZED-OBSERVATION-SET/1"
CAPTURE_SCHEMA = "SBP-LEX-C10-RECONCILIATION-CAPTURES/1"
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
ZERO128 = "0" * 128
ZERO32 = "0" * 32
EXCLUDED_PARTS = frozenset({"target", "obj", "bin", "__pycache__", ".pytest_cache"})
REQUIRED_EXTERNAL_LANES = (
    "wire_v2_rust",
    "rust_trusted_core",
    "rust_authority_service",
    "independent_verifier",
    "spark_safety_monitor",
    "formal_model",
)


class ReconciliationError(RuntimeError):
    """A fail-closed reconciliation or input-contract violation."""


def sha512_bytes(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def sha512_file(path: Path) -> str:
    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("ascii")


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReconciliationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_float(value: str) -> None:
    raise ReconciliationError(f"non-integer JSON number: {value}")


def strict_json_bytes(data: bytes, *, canonical: bool = True) -> object:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ReconciliationError("JSON is not ASCII") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except (json.JSONDecodeError, ValueError) as error:
        if isinstance(error, ReconciliationError):
            raise
        raise ReconciliationError(f"invalid JSON: {error}") from error
    if canonical and canonical_bytes(value) != data:
        raise ReconciliationError("JSON is not the canonical sorted compact encoding")
    return value


def strict_json_file(path: Path, *, canonical: bool = True) -> object:
    return strict_json_bytes(path.read_bytes(), canonical=canonical)


def _validate_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ReconciliationError("path must be a nonempty canonical POSIX path")
    pure = PurePosixPath(value)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ReconciliationError(f"unsafe relative path: {value!r}")
    if pure.as_posix() != value:
        raise ReconciliationError(f"noncanonical relative path: {value!r}")
    return value


def repo_path(relative: object) -> Path:
    value = _validate_relative_path(relative)
    candidate = ROOT.joinpath(*PurePosixPath(value).parts)
    try:
        candidate.resolve(strict=False).relative_to(ROOT.resolve(strict=True))
    except ValueError as error:
        raise ReconciliationError(f"path escapes repository: {value}") from error
    current = ROOT
    for part in PurePosixPath(value).parts:
        current = current / part
        if current.is_symlink():
            raise ReconciliationError(f"symlink input refused: {value}")
    return candidate


def _require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReconciliationError(f"{label} must be a JSON object")
    return value


def _require_exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise ReconciliationError(
            f"{label} keys differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def load_catalog() -> dict[str, object]:
    catalog = _require_mapping(strict_json_file(CATALOG_PATH), "case catalog")
    _require_exact_keys(
        catalog,
        {
            "cases",
            "component_roots",
            "matrix_case_ids",
            "oracle_sha512",
            "schema",
        },
        "case catalog",
    )
    if catalog["schema"] != "SBP-LEX-C10-RECONCILIATION-CASE-CATALOG/1":
        raise ReconciliationError("unknown case catalog schema")
    if not HEX128.fullmatch(str(catalog["oracle_sha512"])):
        raise ReconciliationError("invalid oracle digest")
    cases = catalog["cases"]
    matrix_ids = catalog["matrix_case_ids"]
    roots = catalog["component_roots"]
    if not isinstance(cases, list) or not isinstance(matrix_ids, list):
        raise ReconciliationError("cases and matrix_case_ids must be arrays")
    if not isinstance(roots, dict):
        raise ReconciliationError("component_roots must be an object")
    ids: list[str] = []
    matrix_pairs: list[tuple[str, str]] = []
    for raw in cases:
        case = _require_mapping(raw, "catalog case")
        case_id = case.get("id")
        kind = case.get("kind")
        if not isinstance(case_id, str) or not case_id:
            raise ReconciliationError("case id must be nonempty")
        if kind == "vector":
            _require_exact_keys(
                case,
                {"expected", "id", "kind", "mode", "scenario", "source"},
                f"vector case {case_id}",
            )
            if case["mode"] not in {"MODE_1", "MODE_2", "MODE_3"}:
                raise ReconciliationError(f"invalid mode for {case_id}")
            if case["scenario"] not in {"SUCCESS", "FAILURE", "UNKNOWN", "TIMEOUT"}:
                raise ReconciliationError(f"invalid scenario for {case_id}")
            _validate_relative_path(case["source"])
            _require_mapping(case["expected"], f"expected {case_id}")
            if case_id in matrix_ids:
                matrix_pairs.append((str(case["mode"]), str(case["scenario"])))
        elif kind == "synthetic_negative":
            _require_exact_keys(
                case,
                {"base", "id", "kind", "mutation", "required_registry_case"},
                f"negative case {case_id}",
            )
            _validate_relative_path(case["base"])
        else:
            raise ReconciliationError(f"unknown case kind for {case_id}")
        ids.append(case_id)
    if len(ids) != len(set(ids)):
        raise ReconciliationError("duplicate catalog case id")
    if not all(isinstance(item, str) for item in matrix_ids):
        raise ReconciliationError("matrix case ids must be strings")
    if len(matrix_ids) != 12 or len(set(matrix_ids)) != 12 or not set(matrix_ids) <= set(ids):
        raise ReconciliationError("matrix must name exactly twelve distinct existing cases")
    required_pairs = {
        (mode, scenario)
        for mode in ("MODE_1", "MODE_2", "MODE_3")
        for scenario in ("SUCCESS", "FAILURE", "UNKNOWN", "TIMEOUT")
    }
    if set(matrix_pairs) != required_pairs or len(matrix_pairs) != 12:
        raise ReconciliationError("matrix is not exact 3 modes x 4 outcomes")
    for component, paths in roots.items():
        if not isinstance(component, str) or not isinstance(paths, list) or not paths:
            raise ReconciliationError("invalid component root declaration")
        for path in paths:
            _validate_relative_path(path)
    return catalog


def load_vector(relative: object) -> list[dict[str, object]]:
    path = repo_path(relative)
    data = path.read_bytes()
    if not data or not data.endswith(b"\n") or b"\r" in data or b"\n\n" in data:
        raise ReconciliationError(f"noncanonical JSONL transport: {relative}")
    messages: list[dict[str, object]] = []
    for line_number, line in enumerate(data.splitlines(), 1):
        value = strict_json_bytes(line + b"\n")
        message = _require_mapping(value, f"{relative}:{line_number}")
        if message.get("sequence") != line_number - 1:
            raise ReconciliationError(f"sequence mismatch at {relative}:{line_number}")
        messages.append(message)
    digests = [message.get("transcript_digest") for message in messages]
    if len(digests) != len(set(digests)):
        raise ReconciliationError(f"duplicate transcript digest in {relative}")
    return messages


def _one(messages: Iterable[Mapping[str, object]], kind: str, *, required: bool = True) -> Mapping[str, object] | None:
    matches = [message for message in messages if message.get("kind") == kind]
    if len(matches) > 1 or (required and len(matches) != 1):
        raise ReconciliationError(f"expected exactly one {kind}, found {len(matches)}")
    return matches[0] if matches else None


def _nonzero_hex(value: object, length: int) -> bool:
    return isinstance(value, str) and len(value) == length and set(value) <= set("0123456789abcdef") and set(value) != {"0"}


def _parse_digest_set(value: object) -> set[str]:
    if not isinstance(value, str) or not value:
        raise ReconciliationError("invalid digest set")
    parts = value.split(",")
    if parts != sorted(set(parts)) or not all(HEX128.fullmatch(part) for part in parts):
        raise ReconciliationError("noncanonical digest set")
    return set(parts)


def normalize(messages: list[dict[str, object]]) -> dict[str, object]:
    if not messages:
        raise ReconciliationError("empty transcript")
    mode = messages[0].get("mode")
    if mode not in {"MODE_1", "MODE_2", "MODE_3"}:
        raise ReconciliationError("unknown normalized mode")

    convergence_request = _one(messages, "convergence_request")
    convergence_result = _one(messages, "convergence_result")
    assert convergence_request is not None and convergence_result is not None
    convergence_fields = (
        "convergence_digest",
        "evidence_a_digest",
        "evidence_b_digest",
        "mode_evidence_digest",
        "projection_digest",
    )
    convergence_exact = all(
        convergence_request.get(field) == convergence_result.get(field)
        for field in convergence_fields
    ) and convergence_result.get("decision") == "ALLOW"
    if not convergence_exact:
        raise ReconciliationError("convergence is not exact ALLOW")

    prepare_request = _one(messages, "prepare_request")
    prepare_result = _one(messages, "prepare_result")
    commit_request = _one(messages, "commit_request")
    commit_result = _one(messages, "commit_result")
    assert prepare_request is not None and prepare_result is not None
    assert commit_request is not None and commit_result is not None
    prepare_is_nonauthorizing = (
        prepare_result.get("decision") == "ALLOW"
        and _nonzero_hex(prepare_result.get("prepare_proof_digest"), 128)
        and _nonzero_hex(prepare_result.get("prepare_id"), 32)
        and "capability_digest" not in prepare_result
        and int(prepare_result["sequence"]) < int(commit_request["sequence"])
    )
    if not prepare_is_nonauthorizing:
        raise ReconciliationError("PREPARE is missing or authorizing")
    single_commit = (
        commit_result.get("decision") == "ALLOW"
        and _nonzero_hex(commit_result.get("capability_digest"), 128)
        and _nonzero_hex(commit_result.get("capability_id"), 32)
        and int(commit_request["sequence"]) < int(commit_result["sequence"])
    )
    if not single_commit:
        raise ReconciliationError("COMMIT is not one sole-authority ALLOW")

    epochs = {message.get("authority_epoch") for message in messages}
    durable = {message.get("durable_consumption_digest") for message in messages}
    if len(epochs) != 1 or len(durable) != 1:
        raise ReconciliationError("unstable durable replay identity")
    authority_epoch = next(iter(epochs))
    durable_digest = next(iter(durable))
    if type(authority_epoch) is not int or authority_epoch <= 0 or not HEX128.fullmatch(str(durable_digest)):
        raise ReconciliationError("invalid durable replay identity")

    lease_request = _one(messages, "lease_redeem_request")
    lease_result = _one(messages, "lease_redeem_result")
    watchdog_request = _one(messages, "watchdog_arm_request")
    watchdog_arm = _one(messages, "watchdog_arm_result")
    permit_request = _one(messages, "effect_permit_request")
    permit_result = _one(messages, "effect_permit_result")
    assert lease_request is not None and lease_result is not None
    assert watchdog_request is not None and watchdog_arm is not None
    assert permit_request is not None and permit_result is not None
    if not all(item.get("decision") == "ALLOW" for item in (lease_result, watchdog_arm, permit_result)):
        raise ReconciliationError("lease/watchdog/permit handoff is not ALLOW")
    if not _nonzero_hex(permit_request.get("point_of_use_digest"), 128):
        raise ReconciliationError("point-of-use digest is absent")

    deadlines = {
        "LEASE": int(lease_result["lease_deadline_ms"]),
        "PERMIT": int(permit_result["permit_deadline_ms"]),
        "WATCHDOG": int(watchdog_arm["watchdog_deadline_ms"]),
    }
    completion_bound = min(deadlines.values())
    completion_sources = "+".join(
        name for name in ("LEASE", "PERMIT", "WATCHDOG")
        if deadlines[name] == completion_bound
    )

    permit_sequence = int(permit_result["sequence"])
    for message in messages:
        if int(message["sequence"]) <= permit_sequence:
            continue
        if "permit_id" in message and message["permit_id"] != permit_result["permit_id"]:
            raise ReconciliationError("tail permit id transplant")
        if "permit_digest" in message and message["permit_digest"] != permit_result["permit_digest"]:
            raise ReconciliationError("tail permit digest transplant")

    receipt = _one(messages, "effect_receipt", required=False)
    receipt_ack = _one(messages, "receipt_ack", required=False)
    terminal = _one(messages, "watchdog_terminal")
    final = _one(messages, "watchdog_result")
    assert terminal is not None and final is not None
    if receipt is None:
        if receipt_ack is not None or terminal.get("watchdog_status") != "TIMEOUT":
            raise ReconciliationError("invalid no-receipt fail-close tail")
        if int(terminal["message_time_ms"]) != completion_bound:
            raise ReconciliationError("timeout terminal is not exactly at effective deadline")
        if not (
            int(terminal["message_time_ms"])
            <= int(final["message_time_ms"])
            <= int(terminal["message_time_ms"]) + 1000
        ):
            raise ReconciliationError("timeout result is outside bounded record window")
        completion_relation = "TIMEOUT_TERMINAL_EQUALS_BOUND"
        effect_outcome = "NO_RECEIPT"
        receipt_presence = "ABSENT"
        receipt_ack_decision = "NONE"
        scenario = "TIMEOUT"
        effect_disposition = "FAIL_CLOSED_TIMEOUT"
    else:
        if receipt_ack is None:
            raise ReconciliationError("present receipt lacks acknowledgement")
        tail_times = [
            int(receipt["message_time_ms"]),
            int(receipt["adapter_consumed_at_ms"]),
            int(receipt_ack["message_time_ms"]),
            int(terminal["message_time_ms"]),
            int(final["message_time_ms"]),
        ]
        if not all(value < completion_bound for value in tail_times):
            raise ReconciliationError("present tail violates a half-open deadline")
        completion_relation = "ALL_PRESENT_TAIL_STRICTLY_BEFORE_BOUND"
        effect_outcome = str(receipt.get("effect_outcome"))
        receipt_presence = "PRESENT"
        receipt_ack_decision = str(receipt_ack.get("decision"))
        if effect_outcome == "SUCCEEDED":
            scenario = "SUCCESS"
            effect_disposition = "EFFECT_RECORDED"
        elif effect_outcome == "FAILED":
            scenario = "FAILURE"
            effect_disposition = "FAIL_CLOSED_FAILED"
        elif effect_outcome == "UNKNOWN":
            scenario = "UNKNOWN"
            effect_disposition = "FAIL_CLOSED_UNKNOWN"
        else:
            raise ReconciliationError("unknown receipt outcome")

    if mode == "MODE_1":
        release_request = _one(messages, "mode1_release_request")
        release_result = _one(messages, "mode1_release_result")
        branch_a = _one(messages, "branch_a_statement")
        branch_b = _one(messages, "branch_b_statement")
        witness = _one(messages, "mode1_overlap_witness")
        assert all(item is not None for item in (release_request, release_result, branch_a, branch_b, witness))
        assert release_request is not None and release_result is not None
        assert branch_a is not None and branch_b is not None
        released = int(release_result["rendezvous_released_at_ms"])
        if released < int(release_request["message_time_ms"]):
            raise ReconciliationError("retrocausal Mode 1 release")
        if max(int(branch_a["substantive_start_ms"]), int(branch_b["substantive_start_ms"])) >= min(
            int(branch_a["substantive_end_ms"]), int(branch_b["substantive_end_ms"])
        ):
            raise ReconciliationError("Mode 1 intervals do not overlap")
        if released > min(int(branch_a["substantive_start_ms"]), int(branch_b["substantive_start_ms"])):
            raise ReconciliationError("Mode 1 release postdates substantive start")
        mode_shape = "DUAL_BRANCH_CAUSAL_OVERLAP"
        mode_relation = (
            "RELEASE_EQUALS_REQUEST_TIME"
            if released == int(release_request["message_time_ms"])
            else "RELEASE_AFTER_REQUEST_TIME"
        )
    elif mode == "MODE_2":
        _one(messages, "branch_a_statement")
        certificate = _one(messages, "mode2_validator_certificate")
        assert certificate is not None
        candidate_in = _parse_digest_set(certificate["candidate_input_set"])
        candidate_out = _parse_digest_set(certificate["candidate_output_set"])
        pathway_in = _parse_digest_set(certificate["pathway_input_set"])
        pathway_out = _parse_digest_set(certificate["pathway_output_set"])
        if not candidate_out <= candidate_in or not pathway_out <= pathway_in:
            raise ReconciliationError("Mode 2 widening")
        if candidate_out == candidate_in and pathway_out == pathway_in:
            mode_relation = "EQUAL_CANDIDATE_AND_PATHWAY_NONWIDENING"
        elif candidate_out < candidate_in and pathway_out < pathway_in:
            mode_relation = "STRICT_CANDIDATE_AND_PATHWAY_REDUCTION"
        else:
            mode_relation = "MIXED_NONWIDENING_REDUCTION"
        mode_shape = "PRIMARY_PLUS_INDEPENDENT_VALIDATOR"
    else:
        proof = _one(messages, "mode3_single_state_proof")
        assert proof is not None
        if not all(_nonzero_hex(proof.get(field), 128) for field in (
            "state_seal_digest", "single_state_proof_digest",
            "single_state_callable_digest", "single_state_provenance_digest",
        )):
            raise ReconciliationError("Mode 3 derived proof is incomplete")
        mode_shape = "SINGLE_STATE_SEALED_PROOF"
        mode_relation = "DERIVED_STATE_SEAL_AND_PROOF"

    return {
        "adapter_atomic_consumption_context": "REVALIDATED_IMMEDIATELY_BEFORE_CONSUMPTION",
        "authority_epoch": authority_epoch,
        "commit_authority_stage": "SOLE_COMMIT",
        "commit_decision": commit_result["decision"],
        "commit_result_count": 1,
        "completion_bound_ms": completion_bound,
        "completion_bound_source": completion_sources,
        "completion_relation": completion_relation,
        "convergence_decision": convergence_result["decision"],
        "convergence_exact": True,
        "durable_consumption_digest": durable_digest,
        "effect_disposition": effect_disposition,
        "effect_outcome": effect_outcome,
        "final_decision": final["decision"],
        "lease_decision": lease_result["decision"],
        "mode": mode,
        "mode_evidence_shape": mode_shape,
        "mode_specific_relation": mode_relation,
        "permit_decision": permit_result["decision"],
        "permit_digest": permit_result["permit_digest"],
        "permit_id": permit_result["permit_id"],
        "point_of_use_digest": permit_request["point_of_use_digest"],
        "prepare_authority_granted": False,
        "prepare_decision": prepare_result["decision"],
        "prepare_result_count": 1,
        "receipt_ack_decision": receipt_ack_decision,
        "receipt_presence": receipt_presence,
        "replay_key": f"{authority_epoch}:{durable_digest}",
        "scenario": scenario,
        "single_commit": True,
        "watchdog_arm_decision": watchdog_arm["decision"],
        "watchdog_status": terminal["watchdog_status"],
    }


def _expected_subset(actual: Mapping[str, object], expected: Mapping[str, object], label: str) -> None:
    for key, value in expected.items():
        if key not in actual:
            raise ReconciliationError(f"{label} missing expected field {key}")
        if actual[key] != value:
            raise ReconciliationError(
                f"{label}.{key} mismatch: expected {value!r}, got {actual[key]!r}"
            )


def _wire_modules() -> tuple[Any, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from wire_protocol.v2.python import golden  # type: ignore
    from wire_protocol.v2.python import sbp_lex_wire_v2 as wire  # type: ignore

    return golden, wire


def validate_python_vector(messages: list[dict[str, object]]) -> None:
    golden, wire = _wire_modules()
    registry = golden.fixture_registry()
    mode = str(messages[0]["mode"])
    for message in messages:
        encoded = wire.encode_message(message)
        if wire.parse_message(encoded) != message:
            raise ReconciliationError("wire-v2 Python encode/parse mismatch")
    wire.validate_transcript(
        messages,
        registry=registry,
        admission=golden.fixture_admission(registry, mode),
        verifier=wire.fixture_verify,
        trusted_now_ms=golden.BASE_MS + 5_000,
    )
    permit_index = next(
        index for index, message in enumerate(messages)
        if message["kind"] == "effect_permit_result"
    )
    permit_time = int(messages[permit_index]["message_time_ms"])
    wire.validate_effect_permit_for_atomic_consumption(
        messages[: permit_index + 1],
        registry=registry,
        admission=golden.fixture_admission(registry, mode),
        verifier=wire.fixture_verify,
        trusted_now_ms=permit_time,
    )


def _rechain(messages: list[dict[str, object]]) -> list[dict[str, object]]:
    golden, wire = _wire_modules()
    registry = golden.fixture_registry()
    result: list[dict[str, object]] = []
    for sequence, source in enumerate(messages):
        item = dict(source)
        item["sequence"] = sequence
        item["prior_transcript_digest"] = result[-1]["transcript_digest"] if result else ZERO128
        result.append(wire.seal_fixture_message(item, registry.entries[str(item["signer_role"])]))
    return result


def _mutated_messages(base: list[dict[str, object]], mutation: str) -> list[dict[str, object]]:
    messages = copy.deepcopy(base)
    _, wire = _wire_modules()
    if mutation == "REPLAY_NONCE":
        messages[1]["nonce"] = messages[0]["nonce"]
    elif mutation == "REPLAY_IDENTITY_TRANSPLANT":
        for message in messages:
            message["durable_consumption_digest"] = "f" * 128
    elif mutation == "PERMIT_TAIL_TRANSPLANT":
        permit_index = next(i for i, item in enumerate(messages) if item["kind"] == "effect_permit_result")
        receipt_index = next(i for i, item in enumerate(messages) if item["kind"] == "effect_receipt")
        for message in messages[permit_index + 1 :]:
            if "permit_id" in message:
                message["permit_id"] = "f" * 32
            if "permit_digest" in message:
                message["permit_digest"] = "f" * 128
        messages[receipt_index]["receipt_digest"] = wire.effect_receipt_digest(messages[receipt_index])
        for message in messages[receipt_index + 1 :]:
            if "receipt_digest" in message:
                message["receipt_digest"] = messages[receipt_index]["receipt_digest"]
    elif mutation == "RECEIPT_AT_DEADLINE":
        permit = next(item for item in messages if item["kind"] == "effect_permit_result")
        lease = next(item for item in messages if item["kind"] == "lease_redeem_result")
        arm = next(item for item in messages if item["kind"] == "watchdog_arm_result")
        bound = min(
            int(permit["permit_deadline_ms"]),
            int(lease["lease_deadline_ms"]),
            int(arm["watchdog_deadline_ms"]),
        )
        receipt_index = next(i for i, item in enumerate(messages) if item["kind"] == "effect_receipt")
        receipt = messages[receipt_index]
        receipt["message_time_ms"] = bound
        receipt["adapter_consumed_at_ms"] = bound
        receipt["adapter_consumption_digest"] = wire.adapter_consumption_digest(
            str(receipt["durable_consumption_digest"]),
            str(receipt["permit_digest"]),
            str(receipt["effect_digest"]),
            str(receipt["adapter_digest"]),
            bound,
            str(receipt["effect_outcome"]),
        )
        receipt["receipt_digest"] = wire.effect_receipt_digest(receipt)
        for offset, message in enumerate(messages[receipt_index + 1 :], 1):
            message["message_time_ms"] = bound + offset
            if "receipt_digest" in message:
                message["receipt_digest"] = receipt["receipt_digest"]
    elif mutation == "FAILED_EFFECT_AS_SUCCESS":
        ack = next(item for item in messages if item["kind"] == "receipt_ack")
        terminal = next(item for item in messages if item["kind"] == "watchdog_terminal")
        final = next(item for item in messages if item["kind"] == "watchdog_result")
        ack.update(decision="ACK", receipt_status="SUCCESS_RECORDED", error_code="NONE")
        terminal["watchdog_status"] = "HEALTHY"
        final.update(decision="ACK", error_code="NONE")
    else:
        raise ReconciliationError(f"unknown synthetic mutation: {mutation}")
    return _rechain(messages)


def run_negative(base: list[dict[str, object]], mutation: str) -> str:
    mutated = _mutated_messages(base, mutation)
    _, wire = _wire_modules()
    try:
        validate_python_vector(mutated)
    except wire.WireError:
        return "WIRE_V2_REJECTED"
    except Exception as error:
        raise ReconciliationError(
            f"synthetic negative harness failed instead of a wire rejection: {mutation}: {error}"
        ) from error
    raise ReconciliationError(f"synthetic negative unexpectedly accepted: {mutation}")


def _read_adversarial_registry() -> set[str]:
    path = repo_path("wire_protocol/v2/vectors/adversarial_cases.txt")
    data = path.read_bytes()
    if not data.endswith(b"\n") or b"\r" in data:
        raise ReconciliationError("adversarial registry is not LF canonical")
    try:
        names = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReconciliationError("adversarial registry is not ASCII") from error
    if not names or any(not re.fullmatch(r"[a-z0-9_]+", name) for name in names):
        raise ReconciliationError("invalid adversarial registry entry")
    if len(names) != len(set(names)):
        raise ReconciliationError("duplicate adversarial registry entry")
    return set(names)


def run_python_cases(catalog: Mapping[str, object]) -> tuple[list[dict[str, object]], dict[str, dict[str, object]]]:
    registry_names = _read_adversarial_registry()
    results: list[dict[str, object]] = []
    observations: dict[str, dict[str, object]] = {}
    for raw in catalog["cases"]:  # type: ignore[index]
        case = _require_mapping(raw, "case")
        case_id = str(case["id"])
        if case["kind"] == "vector":
            messages = load_vector(case["source"])
            validate_python_vector(messages)
            observation = normalize(messages)
            if observation["mode"] != case["mode"] or observation["scenario"] != case["scenario"]:
                raise ReconciliationError(f"derived mode/scenario mismatch for {case_id}")
            _expected_subset(observation, _require_mapping(case["expected"], case_id), case_id)
            observations[case_id] = observation
            results.append({
                "adapter": "WIRE_V2_PYTHON_EXECUTED",
                "case_id": case_id,
                "kind": "VECTOR",
                "observation": observation,
                "source_path": case["source"],
                "source_sha512": sha512_file(repo_path(case["source"])),
                "verdict": "ACCEPT",
            })
        else:
            required = str(case["required_registry_case"])
            if required not in registry_names:
                raise ReconciliationError(f"required adversarial case absent: {required}")
            base = load_vector(case["base"])
            rejection = run_negative(base, str(case["mutation"]))
            results.append({
                "adapter": "WIRE_V2_PYTHON_IN_MEMORY_SIGNED_NEGATIVE",
                "base_path": case["base"],
                "base_sha512": sha512_file(repo_path(case["base"])),
                "case_id": case_id,
                "kind": "SYNTHETIC_NEGATIVE",
                "mutation": case["mutation"],
                "registry_case": required,
                "rejection": rejection,
                "verdict": "REJECT",
            })
    expected_ids = [str(case["id"]) for case in catalog["cases"]]  # type: ignore[index]
    if [str(result["case_id"]) for result in results] != expected_ids:
        raise ReconciliationError("case execution order or path set mismatch")
    return results, observations


def _component_inventory(catalog: Mapping[str, object]) -> tuple[list[dict[str, object]], dict[str, str]]:
    roots = _require_mapping(catalog["component_roots"], "component roots")
    assignments: dict[str, str] = {}
    for component in sorted(roots):
        raw_paths = roots[component]
        if not isinstance(raw_paths, list):
            raise ReconciliationError("component path list invalid")
        for raw in raw_paths:
            path = repo_path(raw)
            if not path.exists():
                raise ReconciliationError(f"missing component input: {raw}")
            candidates = [path] if path.is_file() else sorted(path.rglob("*"))
            for candidate in candidates:
                relative_to_root = candidate.relative_to(ROOT)
                if any(part in EXCLUDED_PARTS for part in relative_to_root.parts):
                    continue
                if candidate.is_symlink():
                    raise ReconciliationError(f"symlink component input: {relative_to_root.as_posix()}")
                if not candidate.is_file() or candidate.suffix in {".pyc", ".pyo"}:
                    continue
                relative = relative_to_root.as_posix()
                previous = assignments.setdefault(relative, component)
                if previous != component:
                    raise ReconciliationError(f"component input overlap: {relative}")

    for raw_case in catalog["cases"]:  # type: ignore[index]
        case = _require_mapping(raw_case, "case")
        relative = str(case["source"] if case["kind"] == "vector" else case["base"])
        assignments.setdefault(relative, "wire_v2_vectors")
    assignments.setdefault("wire_protocol/v2/vectors/adversarial_cases.txt", "wire_v2_vectors")

    inventory: list[dict[str, object]] = []
    component_entries: dict[str, list[dict[str, object]]] = {}
    for relative, component in sorted(assignments.items()):
        path = repo_path(relative)
        if not path.is_file():
            raise ReconciliationError(f"missing source inventory path: {relative}")
        entry = {
            "component": component,
            "path": relative,
            "sha512": sha512_file(path),
            "size": path.stat().st_size,
        }
        inventory.append(entry)
        component_entries.setdefault(component, []).append(entry)
    aggregates: dict[str, str] = {}
    for component, entries in sorted(component_entries.items()):
        digest = hashlib.sha512(b"SBP-LEX-C10-COMPONENT-INVENTORY/1\0")
        for entry in entries:
            digest.update(str(entry["path"]).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(entry["sha512"]).encode("ascii"))
            digest.update(b"\0")
            digest.update(str(entry["size"]).encode("ascii"))
            digest.update(b"\0")
        aggregates[component] = digest.hexdigest()
    return inventory, aggregates


def _safe_git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return environment


def _git(*arguments: str) -> str:
    command = [
        "git", "--no-optional-locks", "-c", f"safe.directory={ROOT}",
        "-C", str(ROOT), *arguments,
    ]
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_safe_git_environment(),
    )
    if result.returncode != 0:
        raise ReconciliationError(
            "Git subject query failed: " + result.stderr.decode("utf-8", errors="replace").strip()
        )
    return result.stdout.decode("ascii").strip()


def subject_record(
    *, evidentiary: bool, expected_commit: str | None, expected_tree: str | None,
) -> dict[str, object]:
    commit = _git("rev-parse", "--verify", "HEAD^{commit}")
    tree = _git("rev-parse", "--verify", "HEAD^{tree}")
    dirty_text = _git("status", "--porcelain=v1", "--untracked-files=all")
    clean = dirty_text == ""
    if evidentiary:
        if not clean:
            raise ReconciliationError("dirty worktree refused for evidentiary reconciliation")
        if not expected_commit or not expected_tree:
            raise ReconciliationError("evidentiary mode requires --subject-commit and --subject-tree")
        if expected_commit != commit or expected_tree != tree:
            raise ReconciliationError("evidentiary fixed Git subject mismatch")
    return {
        "clean": clean,
        "commit": commit,
        "fixed_subject_verified": bool(evidentiary and clean),
        "tree": tree,
    }


def _parse_independent_trace(data: bytes) -> dict[str, object]:
    if not data.endswith(b"\n") or b"\r" in data or b"\n\n" in data:
        raise ReconciliationError("independent verifier trace transport is noncanonical")
    try:
        lines = data.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ReconciliationError("independent verifier trace is not ASCII") from error
    if len(lines) < 7 or lines[0] != "SBP-LEX-INDEPENDENT-EVIDENCE-V1":
        raise ReconciliationError("independent verifier trace header/length invalid")
    tags = [line.split(" ", 1)[0] for line in lines[1:]]
    if tags[-1] != "END":
        raise ReconciliationError("independent verifier trace lacks END")
    parsed: list[dict[str, str]] = []
    for line in lines[1:-1]:
        parts = line.split(" ")
        fields: dict[str, str] = {"tag": parts[0]}
        for part in parts[1:]:
            if "=" not in part:
                raise ReconciliationError("independent verifier field lacks equals")
            key, value = part.split("=", 1)
            if not key or not value or key in fields:
                raise ReconciliationError("independent verifier duplicate/empty field")
            fields[key] = value
        parsed.append(fields)
    envelope = next((item for item in parsed if item["tag"] == "ENVELOPE"), None)
    if envelope is None or envelope.get("decision") not in {"ALLOW", "BLOCK"}:
        raise ReconciliationError("independent verifier envelope decision absent")
    decision = envelope["decision"]
    expected_tags = (
        ["REQUEST", "STATE", "CONVERGENCE", "ENVELOPE", "PROOF", "PREPARE", "LEASE", "REDEEM", "COMMIT", "RECEIPT", "WATCHDOG", "END"]
        if decision == "ALLOW"
        else ["REQUEST", "STATE", "CONVERGENCE", "ENVELOPE", "RECEIPT", "WATCHDOG", "END"]
    )
    if tags != expected_tags:
        raise ReconciliationError("independent verifier record order mismatch")
    return {
        "decision": decision,
        "event_count": len(parsed),
        "profile": "SBP-LEX-INDEPENDENT-EVIDENCE-V1",
        "record_kinds": tags,
        "verification_scope": "STRUCTURAL_TEXT_ONLY_SIGNATURES_NOT_REVERIFIED",
    }


def _load_capture_manifest(path: Path | None) -> dict[str, object]:
    if path is None:
        return {"lanes": {}, "schema": CAPTURE_SCHEMA}
    manifest = _require_mapping(strict_json_file(path), "capture manifest")
    _require_exact_keys(manifest, {"lanes", "schema"}, "capture manifest")
    if manifest["schema"] != CAPTURE_SCHEMA:
        raise ReconciliationError("capture manifest schema mismatch")
    lanes = _require_mapping(manifest["lanes"], "capture lanes")
    unknown = set(lanes) - set(REQUIRED_EXTERNAL_LANES)
    if unknown:
        raise ReconciliationError(f"unknown capture lanes: {sorted(unknown)}")
    return manifest


def process_captures(
    capture_manifest: Mapping[str, object],
    matrix_observations: Mapping[str, dict[str, object]],
    matrix_ids: list[str],
    catalog_sha: str,
    subject: Mapping[str, object],
    component_aggregates: Mapping[str, str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    declared = _require_mapping(capture_manifest["lanes"], "capture lanes")
    lane_results: list[dict[str, object]] = []
    capture_inventory: list[dict[str, object]] = []
    for lane in REQUIRED_EXTERNAL_LANES:
        raw = declared.get(lane)
        if raw is None:
            lane_results.append({
                "lane": lane,
                "status": "OPEN_MISSING_EXACT_CAPTURE",
            })
            continue
        capture = _require_mapping(raw, f"capture {lane}")
        _require_exact_keys(
            capture,
            {"declared_result", "format", "path", "sha512"},
            f"capture {lane}",
        )
        relative = _validate_relative_path(capture["path"])
        expected_sha = str(capture["sha512"])
        if capture["declared_result"] not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
            raise ReconciliationError(f"capture {lane} has invalid declared result")
        if not HEX128.fullmatch(expected_sha):
            raise ReconciliationError(f"capture {lane} has invalid SHA-512")
        path = repo_path(relative)
        if not path.is_file():
            raise ReconciliationError(f"capture {lane} path absent: {relative}")
        actual_sha = sha512_file(path)
        if actual_sha != expected_sha:
            raise ReconciliationError(f"capture {lane} SHA-512 mismatch")
        capture_inventory.append({
            "format": capture["format"],
            "lane": lane,
            "path": relative,
            "sha512": actual_sha,
            "size": path.stat().st_size,
        })
        capture_format = capture["format"]
        if capture_format == "canonical_observation_set":
            observed = _require_mapping(strict_json_file(path), f"observation set {lane}")
            _require_exact_keys(
                observed,
                {"case_catalog_sha512", "implementation", "observations", "schema"},
                f"observation set {lane}",
            )
            if observed["schema"] != OBSERVATION_SET_SCHEMA or observed["case_catalog_sha512"] != catalog_sha:
                raise ReconciliationError(f"observation set contract mismatch for {lane}")
            items = observed["observations"]
            if not isinstance(items, list):
                raise ReconciliationError(f"observation set array missing for {lane}")
            by_id: dict[str, dict[str, object]] = {}
            for raw_item in items:
                item = _require_mapping(raw_item, f"observation {lane}")
                _require_exact_keys(item, {"case_id", "observation"}, f"observation {lane}")
                case_id = str(item["case_id"])
                if case_id in by_id:
                    raise ReconciliationError(f"duplicate observation case for {lane}: {case_id}")
                by_id[case_id] = _require_mapping(item["observation"], f"observation {case_id}")
            if list(by_id) != matrix_ids or set(by_id) != set(matrix_ids):
                raise ReconciliationError(f"{lane} omitted, reordered, or added matrix cases")
            mismatch = [case_id for case_id in matrix_ids if by_id[case_id] != matrix_observations[case_id]]
            lane_results.append({
                "declared_result": capture["declared_result"],
                "lane": lane,
                "semantic_mismatches": mismatch,
                "status": (
                    "OPEN_MATCH_NOT_DERIVED_BY_NATIVE_OUTPUT_ADAPTER"
                    if not mismatch else "FAIL_SEMANTIC_MISMATCH"
                ),
            })
        elif capture_format == "native_wire_v2_framed_transcripts" and lane in {
            "wire_v2_rust",
            "rust_authority_service",
        }:
            from native_output_adapters import (
                NativeOutputAdapterError,
                parse_native_wire_v2_transcripts,
            )

            try:
                producer, native_cases = parse_native_wire_v2_transcripts(
                    path.read_bytes(),
                    expected_case_ids=matrix_ids,
                )
                native_observations: dict[str, dict[str, object]] = {}
                for case_id, messages in native_cases:
                    validate_python_vector(messages)
                    native_observations[case_id] = normalize(messages)
            except NativeOutputAdapterError as error:
                raise ReconciliationError(
                    f"native output adapter rejected {lane}: {error}"
                ) from error
            mismatch = [
                case_id
                for case_id in matrix_ids
                if native_observations[case_id] != matrix_observations[case_id]
            ]
            lane_results.append({
                "declared_result": capture["declared_result"],
                "lane": lane,
                "native_producer": producer,
                "semantic_mismatches": mismatch,
                "status": (
                    "OPEN_NATIVE_OUTPUT_ADAPTER_BINARY_IDENTITY_UNATTESTED"
                    if not mismatch
                    else "FAIL_SEMANTIC_MISMATCH"
                ),
            })
        elif capture_format == "independent_verifier_v1_trace" and lane == "independent_verifier":
            summary = _parse_independent_trace(path.read_bytes())
            lane_results.append({
                "declared_result": capture["declared_result"],
                "lane": lane,
                "status": "OPEN_PROFILE_DOES_NOT_COVER_3X4_WIRE_V2_MATRIX",
                "trace_summary": summary,
            })
        elif capture_format == "native_tool_raw_output_bundle" and lane in {
            "spark_safety_monitor",
            "formal_model",
        }:
            from native_output_adapters import (
                NativeOutputAdapterError,
                RAW_TOOL_OPEN_STATUS,
                parse_raw_native_tool_output_bundle,
            )

            try:
                native_output = parse_raw_native_tool_output_bundle(
                    path.read_bytes(),
                    expected_lane=lane,
                    expected_candidate_commit=str(subject["commit"]),
                    expected_candidate_tree=str(subject["tree"]),
                    expected_source_aggregate_sha512=component_aggregates[lane],
                )
            except NativeOutputAdapterError as error:
                raise ReconciliationError(
                    f"native raw tool adapter rejected {lane}: {error}"
                ) from error
            lane_results.append({
                "declared_result": capture["declared_result"],
                "lane": lane,
                "native_output": native_output,
                "status": RAW_TOOL_OPEN_STATUS,
            })
        elif capture_format == "opaque_result":
            lane_results.append({
                "declared_result": capture["declared_result"],
                "lane": lane,
                "status": "OPEN_OPAQUE_RESULT_HAS_NO_CASE_SEMANTICS",
            })
        else:
            raise ReconciliationError(f"unsupported capture format for {lane}: {capture_format}")
    return lane_results, capture_inventory


def build_report(
    *, evidentiary: bool, expected_commit: str | None, expected_tree: str | None,
    capture_manifest_path: Path | None,
) -> dict[str, object]:
    catalog = load_catalog()
    subject = subject_record(
        evidentiary=evidentiary,
        expected_commit=expected_commit,
        expected_tree=expected_tree,
    )
    inventory, aggregates = _component_inventory(catalog)
    case_results, observations = run_python_cases(catalog)
    observation_schema = _require_mapping(
        strict_json_file(OBSERVATION_SCHEMA_PATH), "observation schema",
    )
    _require_exact_keys(
        observation_schema,
        {"deadline_semantics", "field_types", "required_fields", "schema", "semantic_invariants"},
        "observation schema",
    )
    if observation_schema["schema"] != "SBP-LEX-C10-NORMALIZED-LIFECYCLE-OBSERVATION/1":
        raise ReconciliationError("unknown normalized observation schema")
    required_observation_fields = observation_schema["required_fields"]
    if not isinstance(required_observation_fields, list) or len(required_observation_fields) != len(set(required_observation_fields)):
        raise ReconciliationError("observation schema field list is invalid")
    for case_id, observation in observations.items():
        if sorted(observation) != sorted(required_observation_fields):
            raise ReconciliationError(f"normalized observation schema mismatch for {case_id}")
    matrix_ids = [str(item) for item in catalog["matrix_case_ids"]]  # type: ignore[index]
    matrix_observations = {case_id: observations[case_id] for case_id in matrix_ids}
    catalog_sha = sha512_file(CATALOG_PATH)
    capture_manifest = _load_capture_manifest(capture_manifest_path)
    lane_results, capture_inventory = process_captures(
        capture_manifest,
        matrix_observations,
        matrix_ids,
        catalog_sha,
        subject,
        aggregates,
    )
    closed = [result["lane"] for result in lane_results if result["status"] == "CLOSED_SEMANTIC_MATCH"]
    all_closed = len(closed) == len(REQUIRED_EXTERNAL_LANES)
    if evidentiary and not all_closed:
        raise ReconciliationError(
            "evidentiary reconciliation requires every external lane to be "
            "closed by a native-output semantic adapter"
        )
    report_class = (
        "EVIDENTIARY_RECONCILIATION_CANDIDATE"
        if evidentiary
        else "NON_EVIDENTIARY_SYNTHETIC_LOCAL_ASSURANCE"
    )
    return {
        "authority_effect": "NONE",
        "capture_inventory": capture_inventory,
        "case_catalog": {
            "case_count": len(catalog["cases"]),  # type: ignore[arg-type]
            "matrix_case_ids": matrix_ids,
            "path": "cross_language_reconciliation/case_catalog.json",
            "sha512": catalog_sha,
        },
        "case_results": case_results,
        "component_aggregate_sha512": aggregates,
        "evidence_execution_ready": bool(
            evidentiary
            and subject["fixed_subject_verified"]
            and all_closed
        ),
        "lane_results": [
            {
                "case_count": len(case_results),
                "lane": "wire_v2_python",
                "matrix_case_count": len(matrix_ids),
                "status": "CLOSED_LOCAL_FIXTURE_SEMANTICS",
            },
            *lane_results,
        ],
        "limitations": [
            "No production, live, deployment, safety, owner-admission or external-IV&V claim.",
            "TEST-SHA512 and fixture keys are non-production test material.",
            "Opaque PASS output and equal test counts never establish semantic equivalence.",
            "SPARK/formal raw-output bundles remain OPEN because no native lifecycle-observation mapping exists.",
            "Independent verifier V1 text alone does not cover the wire-v2 3x4 matrix.",
        ],
        "normalized_observation_schema": {
            "path": "cross_language_reconciliation/observation_schema.json",
            "sha512": sha512_file(OBSERVATION_SCHEMA_PATH),
        },
        "oracle_sha512": catalog["oracle_sha512"],
        "overall_status": (
            "CLOSED_ALL_DECLARED_IMPLEMENTATIONS_SEMANTICALLY_MATCH"
            if all_closed
            else "OPEN_CROSS_LANGUAGE_REFINEMENT_INCOMPLETE"
        ),
        "report_class": report_class,
        "schema": REPORT_SCHEMA,
        "source_inventory": inventory,
        "subject": subject,
    }


def write_report(output: Path, report: Mapping[str, object]) -> tuple[Path, str]:
    if output.exists():
        if not output.is_dir() or any(output.iterdir()):
            raise ReconciliationError("output directory must be absent or empty")
    else:
        output.mkdir(parents=True, exist_ok=False)
    data = canonical_bytes(report)
    report_path = output / REPORT_NAME
    sidecar_path = output / REPORT_SIDECAR
    report_path.write_bytes(data)
    digest = sha512_bytes(data)
    sidecar_path.write_text(f"{digest}  {REPORT_NAME}\n", encoding="ascii", newline="\n")
    if {path.name for path in output.iterdir()} != {REPORT_NAME, REPORT_SIDECAR}:
        raise ReconciliationError("output directory path set is not closed")
    return report_path, digest


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--synthetic-non-evidentiary", action="store_true")
    mode.add_argument("--evidentiary", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--captures", type=Path)
    parser.add_argument("--subject-commit")
    parser.add_argument("--subject-tree")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        report = build_report(
            evidentiary=arguments.evidentiary,
            expected_commit=arguments.subject_commit,
            expected_tree=arguments.subject_tree,
            capture_manifest_path=arguments.captures,
        )
        path, digest = write_report(arguments.output.resolve(), report)
    except (OSError, ReconciliationError, subprocess.SubprocessError) as error:
        print(f"RECONCILIATION FAIL: {error}", file=sys.stderr)
        return 1
    print(f"RECONCILIATION {report['overall_status']}")
    print(f"report={path}")
    print(f"sha512={digest}")
    print(f"evidence_execution_ready={str(report['evidence_execution_ready']).lower()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
