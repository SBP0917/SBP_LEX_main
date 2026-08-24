"""Independent Python implementation of SBP-LEX-WIRE/1.

This module deliberately accepts only a small, non-executable JSON subset.  It
does not import application classes and does not perform authority decisions.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from typing import Final


PROTOCOL: Final = "SBP-LEX-WIRE/1"
ORACLE_SHA256: Final = (
    "94578afd81a13aab31904f1fb3c8733addd8718658602f638ad4086d2e9d4df0"
)
MAX_FRAME_BYTES: Final = 16_384
MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
ZERO_DIGEST: Final = "0" * 64
_DOMAIN: Final = b"SBP-LEX-WIRE/1\x00TRANSCRIPT\x00"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40_OR_64 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_ERROR_CODE = re.compile(r"(?:NONE|[A-Z][A-Z0-9_]{0,63})\Z")

_COMMON = frozenset(
    {
        "adapter_digest",
        "adapter_boundary_digest",
        "adapter_key_class",
        "adapter_key_id",
        "audit_anchor_digest",
        "authority_build_id",
        "authority_class",
        "authority_key_class",
        "authority_key_id",
        "authority_profile",
        "challenge",
        "crypto_evidence_digest",
        "crypto_key_class",
        "crypto_result",
        "durable_consumption_digest",
        "effect_digest",
        "effect_intent_digest",
        "error_code",
        "expires_at_ms",
        "inhibit_binding_digest",
        "interlock_digest",
        "issued_at_ms",
        "kind",
        "message_time_ms",
        "mode",
        "not_before_ms",
        "nonce",
        "operation_id",
        "oracle_sha256",
        "prior_transcript_digest",
        "protocol",
        "request_digest",
        "replay_namespace",
        "runtime_subject",
        "runtime_tree",
        "sequence",
        "signature_algorithm",
        "signature_hex",
        "signer_key_id",
        "signer_role",
        "signing_public_key_hex",
        "state_digest",
        "transcript_digest",
        "traversal_id",
        "watchdog_key_class",
        "watchdog_key_id",
    }
)

_KIND_FIELDS: Final[dict[str, frozenset[str]]] = {
    "convergence_request": frozenset(
        {
            "branch_a_provenance_digest",
            "branch_b_provenance_digest",
            "candidate_input_set",
            "candidate_output_set",
            "mode_evidence_digest",
            "mode_evidence_type",
            "no_widening_proof_digest",
            "pathway_input_set",
            "pathway_output_set",
            "policy_projection_digest",
            "projection_a_digest",
            "projection_b_digest",
            "snapshot_a_digest",
            "snapshot_b_digest",
            "validator_certificate_digest",
        }
    ),
    "convergence_result": frozenset({"convergence_digest", "decision"}),
    "prepare_request": frozenset({"convergence_digest"}),
    "prepare_result": frozenset({"decision", "prepare_proof_digest"}),
    "commit_request": frozenset({"prepare_proof_digest"}),
    "commit_result": frozenset({"capability_digest", "decision"}),
    "lease_redeem_request": frozenset(
        {"capability_digest", "lease_deadline_ms", "lease_digest"}
    ),
    "lease_redeem_result": frozenset(
        {"decision", "lease_deadline_ms", "lease_digest"}
    ),
    "watchdog_arm_request": frozenset({"lease_digest", "watchdog_deadline_ms"}),
    "watchdog_arm_result": frozenset(
        {"decision", "watchdog_deadline_ms", "watchdog_digest"}
    ),
    "effect_permit_request": frozenset(
        {
            "lease_deadline_ms",
            "lease_digest",
            "point_of_use_digest",
            "watchdog_deadline_ms",
            "watchdog_digest",
        }
    ),
    "effect_permit_result": frozenset(
        {"decision", "permit_deadline_ms", "permit_digest", "watchdog_digest"}
    ),
    "effect_receipt": frozenset(
        {
            "adapter_consumption_digest",
            "adapter_consumed_at_ms",
            "effect_outcome",
            "permit_digest",
            "receipt_digest",
            "watchdog_digest",
        }
    ),
    "receipt_ack": frozenset(
        {"decision", "receipt_digest", "receipt_status", "watchdog_digest"}
    ),
    "watchdog_terminal": frozenset(
        {"permit_digest", "receipt_digest", "watchdog_digest", "watchdog_status"}
    ),
    "watchdog_result": frozenset({"decision", "watchdog_digest"}),
}

_ORDER: Final[tuple[str, ...]] = tuple(_KIND_FIELDS)
_REQUEST_KINDS = frozenset(
    {
        "convergence_request",
        "prepare_request",
        "commit_request",
        "lease_redeem_request",
        "watchdog_arm_request",
        "effect_permit_request",
        "effect_receipt",
        "watchdog_terminal",
    }
)
_DECISIONS = frozenset({"ALLOW", "ACK", "DENY", "BLOCK"})
_DIGEST_FIELDS = frozenset(
    {
        "adapter_digest",
        "adapter_boundary_digest",
        "adapter_consumption_digest",
        "adapter_key_id",
        "audit_anchor_digest",
        "authority_build_id",
        "authority_key_id",
        "branch_a_provenance_digest",
        "branch_b_provenance_digest",
        "capability_digest",
        "challenge",
        "convergence_digest",
        "crypto_evidence_digest",
        "durable_consumption_digest",
        "effect_digest",
        "effect_intent_digest",
        "inhibit_binding_digest",
        "interlock_digest",
        "lease_digest",
        "nonce",
        "permit_digest",
        "point_of_use_digest",
        "policy_projection_digest",
        "prepare_proof_digest",
        "prior_transcript_digest",
        "projection_a_digest",
        "projection_b_digest",
        "receipt_digest",
        "request_digest",
        "replay_namespace",
        "snapshot_a_digest",
        "snapshot_b_digest",
        "state_digest",
        "transcript_digest",
        "watchdog_digest",
        "mode_evidence_digest",
        "no_widening_proof_digest",
        "signer_key_id",
        "validator_certificate_digest",
        "watchdog_key_id",
    }
)

_TIME_FIELDS = frozenset(
    {
        "expires_at_ms",
        "issued_at_ms",
        "message_time_ms",
        "adapter_consumed_at_ms",
        "lease_deadline_ms",
        "not_before_ms",
        "permit_deadline_ms",
        "watchdog_deadline_ms",
    }
)


class WireError(ValueError):
    """A fail-closed wire parsing, binding or lifecycle error."""


def _reject_float(_: str) -> None:
    raise WireError("floating-point JSON values are forbidden")


def _reject_constant(_: str) -> None:
    raise WireError("non-finite JSON values are forbidden")


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise WireError("duplicate or non-string key")
        result[key] = value
    return result


def _quote(value: str) -> bytes:
    if not value or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
        raise WireError("strings must be nonempty printable ASCII")
    if '"' in value or "\\" in value:
        raise WireError("wire strings may not require JSON escaping")
    return b'"' + value.encode("ascii") + b'"'


def _encode_unchecked(fields: Mapping[str, object]) -> bytes:
    chunks: list[bytes] = []
    for key in sorted(fields):
        value = fields[key]
        encoded = str(value).encode("ascii") if type(value) is int else _quote(value)  # type: ignore[arg-type]
        chunks.append(_quote(key) + b":" + encoded)
    return b"{" + b",".join(chunks) + b"}"


def _validate(fields: Mapping[str, object], *, check_digest: bool) -> None:
    kind = fields.get("kind")
    if type(kind) is not str or kind not in _KIND_FIELDS:
        raise WireError("unknown message kind")
    expected = _COMMON | _KIND_FIELDS[kind]
    if set(fields) != expected:
        missing = sorted(expected - set(fields))
        extra = sorted(set(fields) - expected)
        raise WireError(f"field set mismatch: missing={missing}, extra={extra}")

    for name, value in fields.items():
        if name == "sequence" or name in _TIME_FIELDS:
            if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
                raise WireError(f"{name} is not a canonical safe unsigned integer")
        elif type(value) is not str:
            raise WireError(f"{name} must be an exact string")
        elif not value or any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in value):
            raise WireError(f"{name} must be nonempty printable ASCII")
        elif '"' in value or "\\" in value:
            raise WireError(f"{name} requires a forbidden JSON escape")

    for name in _DIGEST_FIELDS & set(fields):
        if not _HEX64.fullmatch(fields[name]):  # type: ignore[arg-type]
            raise WireError(f"{name} must be lowercase SHA-256 hex")
    if not _HEX40_OR_64.fullmatch(fields["runtime_subject"]):  # type: ignore[arg-type]
        raise WireError("runtime_subject must be 40 or 64 lowercase hex")
    if not _HEX40_OR_64.fullmatch(fields["runtime_tree"]):  # type: ignore[arg-type]
        raise WireError("runtime_tree must be 40 or 64 lowercase hex")
    if not _HEX32.fullmatch(fields["traversal_id"]):  # type: ignore[arg-type]
        raise WireError("traversal_id must be 32 lowercase hex")
    if not _HEX32.fullmatch(fields["operation_id"]):  # type: ignore[arg-type]
        raise WireError("operation_id must be 32 lowercase hex")
    if fields["protocol"] != PROTOCOL or fields["oracle_sha256"] != ORACLE_SHA256:
        raise WireError("protocol or controlling oracle mismatch")
    if fields["mode"] not in {"MODE_1", "MODE_2", "MODE_3"}:
        raise WireError("invalid mode")
    if fields["authority_class"] not in {"TEST_ONLY", "SOFTWARE", "HSM", "TPM"}:
        raise WireError("invalid authority_class")
    if not _ERROR_CODE.fullmatch(fields["authority_profile"]):  # type: ignore[arg-type]
        raise WireError("invalid authority_profile")
    not_before = fields["not_before_ms"]
    issued = fields["issued_at_ms"]
    expires = fields["expires_at_ms"]
    if not (not_before <= issued < expires):  # type: ignore[operator]
        raise WireError("invalid common validity interval")
    for deadline_name in _TIME_FIELDS & set(fields) - {
        "not_before_ms",
        "issued_at_ms",
        "expires_at_ms",
    }:
        deadline = fields[deadline_name]
        if not (issued <= deadline <= expires):  # type: ignore[operator]
            raise WireError(f"{deadline_name} outside common validity interval")
    if not _ERROR_CODE.fullmatch(fields["error_code"]):  # type: ignore[arg-type]
        raise WireError("invalid error_code")
    for class_field in (
        "adapter_key_class",
        "authority_key_class",
        "watchdog_key_class",
    ):
        if fields[class_field] not in {
            "TEST_FIXTURE",
            "PRODUCTION_HSM",
            "PRODUCTION_TPM",
        }:
            raise WireError(f"invalid {class_field}")
    if fields["authority_class"] == "TEST_ONLY" and fields["authority_key_class"] != "TEST_FIXTURE":
        raise WireError("test authority requires a test key class")
    if fields["authority_class"] == "HSM" and fields["authority_key_class"] != "PRODUCTION_HSM":
        raise WireError("HSM authority requires an HSM key class")
    if fields["authority_class"] == "TPM" and fields["authority_key_class"] != "PRODUCTION_TPM":
        raise WireError("TPM authority requires a TPM key class")
    if fields["authority_class"] == "SOFTWARE" and fields["authority_key_class"] != "TEST_FIXTURE":
        raise WireError("software authority is restricted to non-production fixtures")

    key_class = fields["crypto_key_class"]
    crypto_result = fields["crypto_result"]
    evidence = fields["crypto_evidence_digest"]
    algorithm = fields["signature_algorithm"]
    public_key = fields["signing_public_key_hex"]
    signature = fields["signature_hex"]
    signer_role = fields["signer_role"]
    signer_key_id = fields["signer_key_id"]
    if key_class not in {"NONE", "TEST_FIXTURE", "PRODUCTION_HSM", "PRODUCTION_TPM"}:
        raise WireError("invalid crypto_key_class")
    if crypto_result not in {"NOT_CHECKED", "SIGNATURE_PRESENT"}:
        raise WireError("invalid crypto_result")
    if (
        key_class,
        crypto_result,
        evidence,
        algorithm,
        public_key,
        signature,
        signer_role,
        signer_key_id,
    ) == (
        "NONE",
        "NOT_CHECKED",
        ZERO_DIGEST,
        "NONE",
        "NONE",
        "NONE",
        "NONE",
        ZERO_DIGEST,
    ):
        pass
    elif (
        key_class in {"TEST_FIXTURE", "PRODUCTION_HSM", "PRODUCTION_TPM"}
        and crypto_result == "SIGNATURE_PRESENT"
        and evidence != ZERO_DIGEST
        and algorithm in {"ML-DSA-65", "ML-DSA-87"}
        and _is_even_lower_hex(public_key)
        and _is_even_lower_hex(signature)
        and signer_role in {"AUTHORITY", "ADAPTER", "WATCHDOG"}
        and _HEX64.fullmatch(signer_key_id) is not None  # type: ignore[arg-type]
        and signer_key_id == hashlib.sha256(bytes.fromhex(public_key)).hexdigest()  # type: ignore[arg-type]
        and key_class == fields[f"{signer_role.lower()}_key_class"]
        and signer_key_id == fields[f"{signer_role.lower()}_key_id"]
    ):
        pass
    else:
        raise WireError("incoherent cryptographic result")
    expected_signer = {
        "convergence_request": "NONE",
        "convergence_result": "AUTHORITY",
        "prepare_request": "NONE",
        "prepare_result": "AUTHORITY",
        "commit_request": "NONE",
        "commit_result": "AUTHORITY",
        "lease_redeem_request": "NONE",
        "lease_redeem_result": "AUTHORITY",
        "watchdog_arm_request": "NONE",
        "watchdog_arm_result": "AUTHORITY",
        "effect_permit_request": "NONE",
        "effect_permit_result": "AUTHORITY",
        "effect_receipt": "ADAPTER",
        "receipt_ack": "AUTHORITY",
        "watchdog_terminal": "WATCHDOG",
        "watchdog_result": "AUTHORITY",
    }[kind]
    if signer_role != expected_signer:
        raise WireError("message kind has the wrong signer role")

    if kind in _REQUEST_KINDS and fields["error_code"] != "NONE":
        raise WireError("request/event kinds cannot carry an error")
    if "decision" in fields:
        decision = fields["decision"]
        if decision not in _DECISIONS:
            raise WireError("invalid decision")
        if decision in {"ALLOW", "ACK"} and fields["error_code"] != "NONE":
            raise WireError("successful decision carries an error")
        if decision in {"DENY", "BLOCK"} and fields["error_code"] == "NONE":
            raise WireError("fail-closed decision requires an error code")
        allowed_by_kind = {
            "convergence_result": {"ALLOW", "DENY"},
            "prepare_result": {"ALLOW", "DENY"},
            "commit_result": {"ALLOW", "DENY"},
            "lease_redeem_result": {"ALLOW", "DENY"},
            "watchdog_arm_result": {"ALLOW", "DENY"},
            "effect_permit_result": {"ALLOW", "DENY"},
            "receipt_ack": {"ACK"},
            "watchdog_result": {"ACK", "BLOCK"},
        }
        if decision not in allowed_by_kind[kind]:
            raise WireError("decision is invalid for message kind")
    if "effect_outcome" in fields and fields["effect_outcome"] not in {
        "SUCCEEDED",
        "FAILED",
        "UNKNOWN",
    }:
        raise WireError("invalid effect outcome")
    if "watchdog_status" in fields and fields["watchdog_status"] not in {
        "HEALTHY",
        "STOP",
        "TIMEOUT",
    }:
        raise WireError("invalid watchdog status")
    if kind == "receipt_ack" and fields["receipt_status"] not in {
        "SUCCESS_RECORDED",
        "FAILURE_RECORDED",
        "UNKNOWN_BLOCKED",
    }:
        raise WireError("invalid receipt status")
    if kind == "watchdog_terminal":
        if fields["watchdog_status"] == "HEALTHY" and fields["receipt_digest"] == ZERO_DIGEST:
            raise WireError("healthy watchdog requires a receipt")
        if fields["watchdog_status"] in {"STOP", "TIMEOUT"} and fields["receipt_digest"] != ZERO_DIGEST:
            # A STOP following a recorded failed receipt uses the receipt-tail form;
            # transcript validation establishes that relation.
            pass

    if kind == "convergence_request":
        projection_a = fields["projection_a_digest"]
        projection_b = fields["projection_b_digest"]
        policy_projection = fields["policy_projection_digest"]
        if not (projection_a == projection_b == policy_projection):
            raise WireError("execution projections do not exactly converge")
        mode = fields["mode"]
        evidence_type = fields["mode_evidence_type"]
        set_fields = (
            fields["candidate_input_set"],
            fields["candidate_output_set"],
            fields["pathway_input_set"],
            fields["pathway_output_set"],
        )
        if mode == "MODE_1":
            if evidence_type != "DUAL_EXECUTION_PROOF" or set_fields != ("NONE",) * 4:
                raise WireError("Mode 1 carries inappropriate evidence")
            if (
                fields["branch_a_provenance_digest"]
                == fields["branch_b_provenance_digest"]
            ):
                raise WireError("Mode 1 requires distinct branch provenance")
            if fields["validator_certificate_digest"] != ZERO_DIGEST or fields["no_widening_proof_digest"] != ZERO_DIGEST:
                raise WireError("Mode 1 cannot carry Mode 2 certificate evidence")
        elif mode == "MODE_2":
            if evidence_type != "VALIDATOR_REDUCTION_PROOF":
                raise WireError("Mode 2 validator evidence type missing")
            candidate_input = _parse_digest_set(set_fields[0])
            candidate_output = _parse_digest_set(set_fields[1])
            pathway_input = _parse_digest_set(set_fields[2])
            pathway_output = _parse_digest_set(set_fields[3])
            if not candidate_output < candidate_input or not pathway_output < pathway_input:
                raise WireError("Mode 2 must prove strict reduction and no widening")
            if not candidate_output or not pathway_output:
                raise WireError("Mode 2 cannot reduce to an empty admitted space")
            if fields["validator_certificate_digest"] == ZERO_DIGEST or fields["no_widening_proof_digest"] == ZERO_DIGEST:
                raise WireError("Mode 2 certificate digests missing")
            if fields["branch_a_provenance_digest"] == fields["branch_b_provenance_digest"]:
                raise WireError("Mode 2 validator provenance must be independent")
        else:
            if evidence_type != "SINGLE_STATE_PROOF" or set_fields != ("NONE",) * 4:
                raise WireError("Mode 3 carries inappropriate evidence")
            if fields["branch_b_provenance_digest"] != ZERO_DIGEST:
                raise WireError("Mode 3 cannot claim a second branch")
            if fields["validator_certificate_digest"] != ZERO_DIGEST or fields["no_widening_proof_digest"] != ZERO_DIGEST:
                raise WireError("Mode 3 cannot carry Mode 2 certificate evidence")

    if check_digest and fields["transcript_digest"] != transcript_digest(fields):
        raise WireError("transcript digest mismatch")


def _is_even_lower_hex(value: object) -> bool:
    return (
        type(value) is str
        and len(value) >= 2
        and len(value) % 2 == 0
        and all(ch in "0123456789abcdef" for ch in value)
    )


def _parse_digest_set(value: object) -> set[str]:
    if type(value) is not str or value == "NONE":
        raise WireError("Mode 2 digest set missing")
    items = value.split(",")
    if items != sorted(set(items)) or any(_HEX64.fullmatch(item) is None for item in items):
        raise WireError("digest set is not sorted, unique lowercase SHA-256")
    return set(items)


def transcript_digest(fields: Mapping[str, object]) -> str:
    unsigned = dict(fields)
    unsigned.pop("transcript_digest", None)
    unsigned.pop("signature_hex", None)
    kind = unsigned.get("kind")
    if type(kind) is not str or kind not in _KIND_FIELDS:
        raise WireError("cannot digest unknown kind")
    material = _DOMAIN + kind.encode("ascii") + b"\x00" + _encode_unchecked(unsigned)
    return hashlib.sha256(material).hexdigest()


def signature_preimage(fields: Mapping[str, object]) -> bytes:
    """Return the exact ML-DSA input; this function does not verify a signature."""
    kind = fields.get("kind")
    digest = fields.get("transcript_digest")
    if type(kind) is not str or kind not in _KIND_FIELDS:
        raise WireError("cannot create signature preimage for unknown kind")
    if type(digest) is not str or _HEX64.fullmatch(digest) is None:
        raise WireError("invalid transcript digest for signature")
    return b"SBP-LEX-WIRE/1\x00SIGNATURE\x00" + kind.encode("ascii") + b"\x00" + bytes.fromhex(digest)


def seal_message(fields: Mapping[str, object]) -> dict[str, object]:
    sealed = dict(fields)
    sealed["transcript_digest"] = ZERO_DIGEST
    _validate(sealed, check_digest=False)
    sealed["transcript_digest"] = transcript_digest(sealed)
    _validate(sealed, check_digest=True)
    return sealed


def encode_message(fields: Mapping[str, object]) -> bytes:
    _validate(fields, check_digest=True)
    encoded = _encode_unchecked(fields)
    if not 1 <= len(encoded) <= MAX_FRAME_BYTES:
        raise WireError("payload length outside protocol bounds")
    return encoded


def parse_message(payload: bytes) -> dict[str, object]:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_FRAME_BYTES:
        raise WireError("payload length outside protocol bounds")
    if payload.startswith(b"\xef\xbb\xbf") or any(byte > 0x7F for byte in payload):
        raise WireError("payload must be BOM-free ASCII-compatible UTF-8")
    try:
        text = payload.decode("utf-8", errors="strict")
        loaded = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except WireError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WireError("malformed JSON payload") from exc
    if type(loaded) is not dict:
        raise WireError("payload must be one flat object")
    _validate(loaded, check_digest=True)
    if _encode_unchecked(loaded) != payload:
        raise WireError("payload is not canonical byte-for-byte JSON")
    return loaded


def encode_frame(fields: Mapping[str, object]) -> bytes:
    payload = encode_message(fields)
    return len(payload).to_bytes(4, "big") + payload


def decode_frame(frame: bytes) -> dict[str, object]:
    if type(frame) is not bytes or len(frame) < 4:
        raise WireError("truncated frame prefix")
    size = int.from_bytes(frame[:4], "big")
    if not 1 <= size <= MAX_FRAME_BYTES:
        raise WireError("frame length outside protocol bounds")
    if len(frame) != size + 4:
        raise WireError("truncated frame or trailing bytes")
    return parse_message(frame[4:])


def validate_transcript(
    messages: Iterable[Mapping[str, object]], *, trusted_now_ms: int | None = None
) -> None:
    transcript = list(messages)
    if not 1 <= len(transcript) <= 16:
        raise WireError("v1 transcript has invalid lifecycle length")
    parsed: list[dict[str, object]] = []
    for message in transcript:
        encoded = encode_message(message)
        parsed.append(parse_message(encoded))

    binding_names = (
        "adapter_digest",
        "adapter_boundary_digest",
        "adapter_key_class",
        "adapter_key_id",
        "audit_anchor_digest",
        "authority_build_id",
        "authority_class",
        "authority_key_class",
        "authority_key_id",
        "authority_profile",
        "challenge",
        "durable_consumption_digest",
        "effect_digest",
        "effect_intent_digest",
        "expires_at_ms",
        "inhibit_binding_digest",
        "interlock_digest",
        "issued_at_ms",
        "mode",
        "not_before_ms",
        "oracle_sha256",
        "operation_id",
        "protocol",
        "replay_namespace",
        "request_digest",
        "runtime_subject",
        "runtime_tree",
        "state_digest",
        "traversal_id",
        "watchdog_key_class",
        "watchdog_key_id",
    )
    first_binding = tuple(parsed[0][name] for name in binding_names)
    if trusted_now_ms is not None:
        if type(trusted_now_ms) is not int or not 0 <= trusted_now_ms <= MAX_SAFE_INTEGER:
            raise WireError("trusted_now_ms is invalid")
        if not (
            parsed[0]["not_before_ms"]
            <= trusted_now_ms
            < parsed[0]["expires_at_ms"]
        ):
            raise WireError("transcript is not fresh at trusted time")
    nonces: set[object] = set()
    prior = ZERO_DIGEST
    common_order = _ORDER[:12]
    if len(parsed) <= 12:
        expected_order = common_order[: len(parsed)]
    elif parsed[12]["kind"] == "effect_receipt":
        expected_order = common_order + _ORDER[12:16][: len(parsed) - 12]
    elif parsed[12]["kind"] == "watchdog_terminal":
        expected_order = common_order + ("watchdog_terminal", "watchdog_result")[: len(parsed) - 12]
    else:
        raise WireError("invalid receipt-or-timeout lifecycle tail")
    prior_time: int | None = None
    terminal_denial = False
    for sequence, (expected_kind, message) in enumerate(
        zip(expected_order, parsed, strict=True)
    ):
        if message["sequence"] != sequence or message["kind"] != expected_kind:
            raise WireError("kind or sequence order mismatch")
        if message["prior_transcript_digest"] != prior:
            raise WireError("transcript chain mismatch")
        if tuple(message[name] for name in binding_names) != first_binding:
            raise WireError("immutable execution binding changed")
        if message["nonce"] in nonces:
            raise WireError("nonce replay")
        nonces.add(message["nonce"])
        message_time = message["message_time_ms"]
        if not (message["not_before_ms"] <= message_time < message["expires_at_ms"]):
            raise WireError("message time outside validity interval")
        if prior_time is not None and message_time < prior_time:
            raise WireError("message time regressed")
        prior_time = message_time  # type: ignore[assignment]
        prior = message["transcript_digest"]  # type: ignore[assignment]
        if message.get("decision") in {"DENY", "BLOCK"}:
            if sequence != len(parsed) - 1:
                raise WireError("denied lifecycle cannot continue")
            terminal_denial = True

    common_links = (
        (1, "convergence_digest", 2, "convergence_digest"),
        (3, "prepare_proof_digest", 4, "prepare_proof_digest"),
        (5, "capability_digest", 6, "capability_digest"),
        (6, "lease_digest", 7, "lease_digest"),
        (6, "lease_deadline_ms", 7, "lease_deadline_ms"),
        (7, "lease_digest", 8, "lease_digest"),
        (8, "watchdog_deadline_ms", 9, "watchdog_deadline_ms"),
        (9, "watchdog_digest", 10, "watchdog_digest"),
        (9, "watchdog_deadline_ms", 10, "watchdog_deadline_ms"),
        (7, "lease_digest", 10, "lease_digest"),
        (7, "lease_deadline_ms", 10, "lease_deadline_ms"),
        (10, "watchdog_digest", 11, "watchdog_digest"),
    )
    for left_i, left_name, right_i, right_name in common_links:
        if right_i >= len(parsed):
            continue
        if parsed[left_i][left_name] != parsed[right_i][right_name]:
            raise WireError(f"handoff mismatch: {left_name}->{right_name}")
    if len(parsed) > 6 and parsed[6]["message_time_ms"] > parsed[6]["lease_deadline_ms"]:
        raise WireError("lease redemption was late")
    if len(parsed) > 8 and parsed[8]["message_time_ms"] > parsed[8]["watchdog_deadline_ms"]:
        raise WireError("watchdog arm was late")
    if len(parsed) > 10 and parsed[10]["message_time_ms"] > min(
        parsed[10]["lease_deadline_ms"], parsed[10]["watchdog_deadline_ms"]
    ):
        raise WireError("point-of-use request was late")
    if len(parsed) > 11:
        if not (
            parsed[11]["permit_deadline_ms"] <= parsed[10]["lease_deadline_ms"]
            and parsed[11]["permit_deadline_ms"] <= parsed[10]["watchdog_deadline_ms"]
            and parsed[11]["message_time_ms"] <= parsed[11]["permit_deadline_ms"]
        ):
            raise WireError("permit deadline order or issuance time invalid")

    if terminal_denial and len(parsed) <= 12:
        return
    if len(parsed) <= 12:
        raise WireError("successful lifecycle is incomplete")

    if parsed[12]["kind"] == "watchdog_terminal":
        if len(parsed) != 14 or not terminal_denial:
            raise WireError("timeout/stop tail must terminate with BLOCK")
        terminal = parsed[12]
        result = parsed[13]
        if terminal["watchdog_status"] not in {"STOP", "TIMEOUT"}:
            raise WireError("no-receipt tail must stop or time out")
        if terminal["receipt_digest"] != ZERO_DIGEST:
            raise WireError("no-receipt tail cannot invent a receipt")
        if terminal["permit_digest"] != parsed[11]["permit_digest"] or terminal["watchdog_digest"] != parsed[11]["watchdog_digest"]:
            raise WireError("timeout/stop tail binding mismatch")
        if result["watchdog_digest"] != terminal["watchdog_digest"] or result["decision"] != "BLOCK":
            raise WireError("timeout/stop must end in BLOCK")
        if terminal["watchdog_status"] == "TIMEOUT" and terminal["message_time_ms"] < parsed[10]["watchdog_deadline_ms"]:
            raise WireError("watchdog timed out before its deadline")
        return

    if len(parsed) != 16:
        raise WireError("receipt lifecycle is incomplete")
    receipt, ack, terminal, result = parsed[12:16]
    receipt_links = (
        (parsed[11], "permit_digest", receipt, "permit_digest"),
        (parsed[11], "watchdog_digest", receipt, "watchdog_digest"),
        (receipt, "receipt_digest", ack, "receipt_digest"),
        (receipt, "watchdog_digest", ack, "watchdog_digest"),
        (parsed[11], "permit_digest", terminal, "permit_digest"),
        (receipt, "receipt_digest", terminal, "receipt_digest"),
        (receipt, "watchdog_digest", terminal, "watchdog_digest"),
        (terminal, "watchdog_digest", result, "watchdog_digest"),
    )
    for left, left_name, right, right_name in receipt_links:
        if left[left_name] != right[right_name]:
            raise WireError(f"receipt handoff mismatch: {left_name}->{right_name}")
    consumed = receipt["adapter_consumed_at_ms"]
    if not (
        parsed[11]["message_time_ms"] <= consumed <= parsed[11]["permit_deadline_ms"]
        and consumed <= receipt["message_time_ms"]
        and receipt["message_time_ms"] <= parsed[10]["watchdog_deadline_ms"]
    ):
        raise WireError("adapter did not atomically consume a fresh permit")
    outcome = receipt["effect_outcome"]
    if outcome == "SUCCEEDED":
        if ack["receipt_status"] != "SUCCESS_RECORDED" or terminal["watchdog_status"] != "HEALTHY" or result["decision"] != "ACK":
            raise WireError("successful effect tail is incoherent")
        if terminal_denial:
            raise WireError("successful effect was terminally blocked")
    elif outcome == "FAILED":
        if ack["receipt_status"] != "FAILURE_RECORDED" or terminal["watchdog_status"] != "STOP" or result["decision"] != "BLOCK":
            raise WireError("failed effect tail is incoherent")
        if not terminal_denial:
            raise WireError("failed effect did not fail closed")
    else:
        if ack["receipt_status"] != "UNKNOWN_BLOCKED" or terminal["watchdog_status"] != "STOP" or result["decision"] != "BLOCK":
            raise WireError("unknown effect tail is incoherent")
        if not terminal_denial:
            raise WireError("unknown effect did not fail closed")
