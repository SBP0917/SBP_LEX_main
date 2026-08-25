"""Independent Python implementation of SBP-LEX-AUTH-WIRE/2."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from typing import Final, TypeGuard, cast

WireValue = str | int

PROTOCOL: Final = "SBP-LEX-AUTH-WIRE/2"
# SHA-512 migration pin over the former v2 SHA-256 oracle bytes.  It is a
# fixed protocol value, not a runtime fallback accepting legacy SHA-256.
ORACLE_SHA512: Final = "4953fa1136348279509933ddb91102591015af3e7d45f1d6b1ca39ccb9e44190b5880c9f1a0ec054add824dd31d74feefc2922aa652833b16252cac159921f82"
MAX_FRAME_BYTES: Final = 32_768
MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
FAIL_CLOSE_RESULT_MAX_DELAY_MS: Final = 1_000
ZERO: Final = "0" * 128
ZERO_ID: Final = "0" * 32
_TDOM = b"SBP-LEX-AUTH-WIRE/2\0TRANSCRIPT\0"
_SDOM = b"SBP-LEX-AUTH-WIRE/2\0SIGNATURE\0"
_PDOM = b"SBP-LEX-EXEC-PROJECTION/2\0"
_RDOM = b"SBP-LEX-AUTH-WIRE/2\0REGISTRY\0"
_SETDOM = b"SBP-LEX-AUTH-WIRE/2\0SET\0"
_CDOM = b"SBP-LEX-AUTH-WIRE/2\0CONVERGENCE\0"
_TESTDOM = b"SBP-LEX-TEST-SIGNATURE/1\0"
_STABLEREQUESTDOM = b"SBP-LEX-AUTH-WIRE/2\0STABLE-REQUEST\0"
_STABLEDOM = b"SBP-LEX-AUTH-WIRE/2\0STABLE-EFFECT-INTENT\0"
_DURABLEDOM = b"SBP-LEX-AUTH-WIRE/2\0DURABLE-CONSUMPTION\0"
_POUDOM = b"SBP-LEX-AUTH-WIRE/2\0POINT-OF-USE\0"
_ARTIFACT_IDDOM = b"SBP-LEX-AUTH-WIRE/2\0ARTIFACT-ID\0"
_ARTIFACT_DOMAINS: Final[dict[str, bytes]] = {
    "prepare_request": b"SBP-LEX-AUTH-WIRE/2\0PREPARE-PROOF\0",
    "commit_request": b"SBP-LEX-AUTH-WIRE/2\0EXECUTION-CAPABILITY\0",
    "lease_redeem_request": b"SBP-LEX-AUTH-WIRE/2\0EXECUTION-LEASE\0",
    "watchdog_arm_request": b"SBP-LEX-AUTH-WIRE/2\0WATCHDOG-ARM\0",
    "effect_permit_request": b"SBP-LEX-AUTH-WIRE/2\0EFFECT-PERMIT\0",
}
_CHECKPOINTDOM = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-CHECKPOINT\0"
_RELEASEDOM = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-RELEASE\0"
_ACKDOM = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-ACK\0"
_STATESEALDOM = b"SBP-LEX-AUTH-WIRE/2\0MODE3-STATE-SEAL\0"
_SINGLEPROOFDOM = b"SBP-LEX-AUTH-WIRE/2\0MODE3-PROOF\0"
_CONSUMEDOM = b"SBP-LEX-AUTH-WIRE/2\0ATOMIC-CONSUMPTION\0"
_RECEIPTDOM = b"SBP-LEX-AUTH-WIRE/2\0EFFECT-RECEIPT\0"
_ADMISSIONDOM = b"SBP-LEX-AUTH-WIRE/2\0ADMISSION-POLICY\0"
_AUTHCONVDOM = b"SBP-LEX-AUTH-WIRE/2\0AUTHENTICATED-CONVERGENCE\0"
_STAGECTXDOM = b"SBP-LEX-AUTH-WIRE/2\0VERIFIED-STAGE-CONTEXT\0"

_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX40_OR_128 = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{128})\Z")
_TOKEN = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_ROLES = frozenset({"BRANCH_A", "BRANCH_B", "VALIDATOR", "SINGLE_STATE", "WITNESS", "COORDINATOR", "AUTHORITY", "ADAPTER", "WATCHDOG"})

_COMMON = frozenset(
    {
        "adapter_boundary_digest", "adapter_digest", "audit_anchor_digest",
        "authority_build_id", "authority_class", "authority_epoch", "authority_profile",
        "challenge", "domain_digest", "durable_consumption_digest", "effect_digest", "effect_intent_digest",
        "extension_admission_binding_digest", "extension_admission_mode",
        "extension_configuration_digest", "extension_schema",
        "error_code", "expires_at_ms", "inhibit_binding_digest", "interlock_digest",
        "issued_at_ms", "kind", "message_time_ms", "mode", "nonce", "not_before_ms",
        "operation_id", "oracle_sha512", "prior_transcript_digest", "protocol",
        "replay_namespace", "request_digest", "runtime_subject", "runtime_tree",
        "sequence", "signature_algorithm", "signature_hex", "signer_key_class",
        "signer_key_id", "signer_role", "signing_public_key_hex", "state_digest",
        "stable_effect_intent_digest", "stable_request_digest", "subject_digest", "transcript_digest",
        "traversal_id", "trust_registry_digest", "trust_root_digest",
    }
)

_PROJECTION = frozenset(
    {
        "projection_adapter_digest", "projection_audit_context_digest",
        "projection_aurion_digest", "projection_candidate_digest",
        "projection_constraints_digest", "projection_digest", "projection_domain_digest",
        "projection_effect_digest", "projection_mode_freeze_digest",
        "projection_outcome_digest", "projection_pathway_digest", "projection_policy_digest",
        "projection_provider_linkage_digest", "projection_request_digest", "projection_schema",
        "projection_state_digest", "projection_token_stack_digest",
        "extension_admission_binding_digest", "extension_admission_mode",
        "extension_configuration_digest", "extension_schema",
    }
)

_KINDS: Final[dict[str, frozenset[str]]] = {
    "branch_a_statement": _PROJECTION | frozenset(
        {"callable_digest", "code_provenance_digest", "process_digest", "release_checkpoint_digest", "snapshot_digest", "substantive_end_ms", "substantive_start_ms", "worker_id"}
    ),
    "branch_b_statement": _PROJECTION | frozenset(
        {"callable_digest", "code_provenance_digest", "process_digest", "release_checkpoint_digest", "snapshot_digest", "substantive_end_ms", "substantive_start_ms", "worker_id"}
    ),
    "mode1_release_request": frozenset(
        {"a_checkpoint_digest", "a_process_digest", "b_checkpoint_digest", "b_process_digest", "rendezvous_opened_at_ms", "worker_a_id", "worker_b_id"}
    ),
    "mode1_release_result": frozenset(
        {"a_checkpoint_digest", "b_checkpoint_digest", "decision", "release_request_digest", "rendezvous_opened_at_ms", "rendezvous_release_digest", "rendezvous_released_at_ms"}
    ),
    "mode1_overlap_witness": frozenset(
        {"a_ack_digest", "a_checkpoint_digest", "a_end_ms", "a_process_digest", "a_start_ms", "b_ack_digest", "b_checkpoint_digest", "b_end_ms", "b_process_digest", "b_start_ms", "projection_digest", "rendezvous_opened_at_ms", "rendezvous_release_digest", "rendezvous_released_at_ms", "release_result_digest", "statement_a_digest", "statement_b_digest", "worker_a_id", "worker_b_id"}
    ),
    "mode2_validator_certificate": _PROJECTION | frozenset(
        {"candidate_input_set", "candidate_output_set", "candidate_rejections", "pathway_input_set", "pathway_output_set", "pathway_rejections", "primary_statement_digest", "validator_code_digest", "validator_provenance_digest"}
    ),
    "mode3_single_state_proof": _PROJECTION | frozenset(
        {"single_state_callable_digest", "single_state_proof_digest", "single_state_provenance_digest", "state_seal_digest"}
    ),
    "convergence_request": frozenset(
        {"convergence_digest", "evidence_a_digest", "evidence_b_digest", "mode_evidence_digest", "projection_digest"}
    ),
    "convergence_result": frozenset(
        {"convergence_digest", "decision", "evidence_a_digest", "evidence_b_digest", "mode_evidence_digest", "projection_digest"}
    ),
    "prepare_request": frozenset({"convergence_digest"}),
    "prepare_result": frozenset({"decision", "prepare_id", "prepare_proof_digest"}),
    "commit_request": frozenset({"prepare_id", "prepare_proof_digest"}),
    "commit_result": frozenset({"capability_digest", "capability_id", "decision"}),
    "lease_redeem_request": frozenset({"capability_digest", "capability_id", "lease_deadline_ms"}),
    "lease_redeem_result": frozenset({"decision", "lease_deadline_ms", "lease_digest", "lease_id"}),
    "watchdog_arm_request": frozenset({"lease_digest", "lease_id", "watchdog_deadline_ms"}),
    "watchdog_arm_result": frozenset({"decision", "watchdog_deadline_ms", "watchdog_digest"}),
    "effect_permit_request": frozenset({"lease_deadline_ms", "lease_digest", "lease_id", "point_of_use_digest", "watchdog_deadline_ms", "watchdog_digest"}),
    "effect_permit_result": frozenset({"decision", "permit_deadline_ms", "permit_digest", "permit_id", "watchdog_digest"}),
    "effect_receipt": frozenset({"adapter_consumed_at_ms", "adapter_consumption_digest", "effect_outcome", "permit_digest", "permit_id", "receipt_digest", "watchdog_digest"}),
    "receipt_ack": frozenset({"decision", "permit_digest", "permit_id", "receipt_digest", "receipt_status", "watchdog_digest"}),
    "watchdog_terminal": frozenset({"permit_digest", "permit_id", "receipt_digest", "watchdog_digest", "watchdog_status"}),
    "watchdog_result": frozenset({"decision", "permit_digest", "permit_id", "receipt_digest", "watchdog_digest"}),
}

_ROLE_BY_KIND = {
    "branch_a_statement": "BRANCH_A", "branch_b_statement": "BRANCH_B",
    "mode1_release_request": "COORDINATOR", "mode1_release_result": "AUTHORITY",
    "mode1_overlap_witness": "WITNESS", "mode2_validator_certificate": "VALIDATOR",
    "mode3_single_state_proof": "SINGLE_STATE", "convergence_request": "COORDINATOR",
    "convergence_result": "AUTHORITY", "prepare_request": "COORDINATOR",
    "prepare_result": "AUTHORITY", "commit_request": "COORDINATOR",
    "commit_result": "AUTHORITY", "lease_redeem_request": "ADAPTER",
    "lease_redeem_result": "AUTHORITY", "watchdog_arm_request": "COORDINATOR",
    "watchdog_arm_result": "WATCHDOG", "effect_permit_request": "ADAPTER",
    "effect_permit_result": "AUTHORITY", "effect_receipt": "ADAPTER",
    "receipt_ack": "AUTHORITY", "watchdog_terminal": "WATCHDOG",
    "watchdog_result": "AUTHORITY",
}

_DIGEST_EXCEPTIONS = {"projection_schema"}
_TIME_FIELDS = {"message_time_ms", "issued_at_ms", "not_before_ms", "expires_at_ms", "substantive_start_ms", "substantive_end_ms", "a_start_ms", "a_end_ms", "b_start_ms", "b_end_ms", "rendezvous_opened_at_ms", "rendezvous_released_at_ms", "lease_deadline_ms", "watchdog_deadline_ms", "permit_deadline_ms", "adapter_consumed_at_ms"}


class WireError(ValueError):
    pass


@dataclass(frozen=True)
class KeyRecord:
    role: str
    key_class: str
    public_key_hex: str

    @property
    def key_id(self) -> str:
        return hashlib.sha512(bytes.fromhex(self.public_key_hex)).hexdigest()


@dataclass(frozen=True)
class TrustRegistry:
    root_digest: str
    entries: Mapping[str, KeyRecord]

    def digest(self) -> str:
        lines = []
        for role in sorted(self.entries):
            item = self.entries[role]
            if item.role != role or not _is_hex(item.public_key_hex):
                raise WireError("invalid registry entry")
            lines.append(f"{role}|{item.key_class}|{item.key_id}|{item.public_key_hex}\n")
        return hashlib.sha512(_RDOM + "".join(lines).encode("ascii")).hexdigest()


@dataclass(frozen=True)
class AdmissionPolicy:
    trust_root_digest: str
    registry_digest: str
    runtime_subject: str
    runtime_tree: str
    authority_class: str
    authority_epoch: int
    authority_profile: str
    authority_build_id: str
    mode: str
    traversal_id: str
    operation_id: str
    challenge: str
    replay_namespace: str
    stable_request_digest: str
    request_digest: str
    state_digest: str
    effect_digest: str
    effect_intent_digest: str
    adapter_digest: str
    adapter_boundary_digest: str
    inhibit_binding_digest: str
    interlock_digest: str
    audit_anchor_digest: str
    domain_digest: str
    subject_digest: str
    extension_admission_mode: str
    extension_schema: str
    extension_configuration_digest: str
    extension_admission_binding_digest: str
    branch_a_callable_digest: str
    branch_a_code_provenance_digest: str
    branch_b_callable_digest: str
    branch_b_code_provenance_digest: str
    validator_code_digest: str
    validator_provenance_digest: str
    single_state_callable_digest: str
    single_state_provenance_digest: str


Verifier = Callable[[str, bytes, bytes, bytes], bool]


_MODE_PREFIXES: Final[dict[str, tuple[str, ...]]] = {
    "MODE_1": (
        "mode1_release_request", "mode1_release_result", "branch_a_statement",
        "branch_b_statement", "mode1_overlap_witness", "convergence_request",
        "convergence_result",
    ),
    "MODE_2": (
        "branch_a_statement", "mode2_validator_certificate", "convergence_request",
        "convergence_result",
    ),
    "MODE_3": (
        "mode3_single_state_proof", "convergence_request", "convergence_result",
    ),
}

_POST_KINDS: Final[tuple[str, ...]] = (
    "prepare_request", "prepare_result", "commit_request", "commit_result",
    "lease_redeem_request", "lease_redeem_result", "watchdog_arm_request",
    "watchdog_arm_result", "effect_permit_request", "effect_permit_result",
)

_RESULT_FOR_REQUEST: Final[dict[str, str]] = {
    "mode1_release_request": "mode1_release_result",
    "convergence_request": "convergence_result",
    "prepare_request": "prepare_result",
    "commit_request": "commit_result",
    "lease_redeem_request": "lease_redeem_result",
    "watchdog_arm_request": "watchdog_arm_result",
    "effect_permit_request": "effect_permit_result",
    "effect_receipt": "receipt_ack",
    "watchdog_terminal": "watchdog_result",
}

_IMMUTABLE_FIELDS: Final[tuple[str, ...]] = (
    "adapter_boundary_digest", "adapter_digest", "audit_anchor_digest",
    "authority_build_id", "authority_class", "authority_epoch", "authority_profile", "challenge",
    "domain_digest",
    "durable_consumption_digest", "effect_digest", "effect_intent_digest",
    "extension_admission_binding_digest", "extension_admission_mode",
    "extension_configuration_digest", "extension_schema",
    "expires_at_ms", "inhibit_binding_digest", "interlock_digest", "issued_at_ms",
    "mode", "not_before_ms", "operation_id", "oracle_sha512", "protocol",
    "replay_namespace", "request_digest", "runtime_subject", "runtime_tree",
    "stable_effect_intent_digest", "stable_request_digest", "state_digest", "subject_digest",
    "traversal_id", "trust_registry_digest", "trust_root_digest",
)

_STAGE_SEAL = object()


class AuthenticatedStageContext:
    """Opaque result of validating one authority input prefix.

    It is evidence for a service-private stage-specific decision method, not a serializable
    capability.  The constructor is intentionally unavailable to callers.
    """

    __slots__ = (
        "_admission_policy_digest",
        "_authenticated_convergence_binding_digest",
        "_chain_tip_digest",
        "_context_digest",
        "_expected_result_kind",
        "_request_transcript_digest",
        "_stage_kind",
        "_values",
    )

    def __init__(
        self, *, stage_kind: str, expected_result_kind: str,
        request_transcript_digest: str, chain_tip_digest: str,
        admission_policy_digest_value: str,
        authenticated_convergence_binding_digest_value: str,
        context_digest: str, values: tuple[tuple[str, str | int], ...], _seal: object,
    ) -> None:
        if _seal is not _STAGE_SEAL:
            raise WireError("stage context is validator-only")
        self._stage_kind = stage_kind
        self._expected_result_kind = expected_result_kind
        self._request_transcript_digest = request_transcript_digest
        self._chain_tip_digest = chain_tip_digest
        self._admission_policy_digest = admission_policy_digest_value
        self._authenticated_convergence_binding_digest = authenticated_convergence_binding_digest_value
        self._context_digest = context_digest
        self._values = values

    @property
    def stage_kind(self) -> str:
        return self._stage_kind

    @property
    def expected_result_kind(self) -> str:
        return self._expected_result_kind

    @property
    def request_transcript_digest(self) -> str:
        return self._request_transcript_digest

    @property
    def chain_tip_digest(self) -> str:
        return self._chain_tip_digest

    @property
    def admission_policy_digest(self) -> str:
        return self._admission_policy_digest

    @property
    def authenticated_convergence_binding_digest(self) -> str:
        return self._authenticated_convergence_binding_digest

    @property
    def context_digest(self) -> str:
        return self._context_digest

    def derived(self, name: str) -> str | int:
        for key, value in self._values:
            if key == name:
                return value
        raise WireError("unknown derived stage value")

    def derived_items(self) -> tuple[tuple[str, str | int], ...]:
        return self._values


class VerifiedEffectPermitContext:
    """Opaque final point-of-use permit context; never a transport capability."""

    __slots__ = ("_stage", "_values")

    def __init__(self, stage: AuthenticatedStageContext, values: tuple[tuple[str, str | int], ...], *, _seal: object) -> None:
        if _seal is not _STAGE_SEAL:
            raise WireError("permit context is validator-only")
        self._stage = stage
        self._values = values

    @property
    def authenticated_convergence_binding_digest(self) -> str:
        return self._stage.authenticated_convergence_binding_digest

    @property
    def admission_policy_digest(self) -> str:
        return self._stage.admission_policy_digest

    @property
    def stage_context_digest(self) -> str:
        return self._stage.context_digest

    def derived(self, name: str) -> str | int:
        for key, value in self._values:
            if key == name:
                return value
        raise WireError("unknown permit value")


def fixture_verify(algorithm: str, public_key: bytes, preimage: bytes, signature: bytes) -> bool:
    return algorithm == "TEST-SHA512" and signature == hashlib.sha512(_TESTDOM + public_key + preimage).digest()


def fixture_signature(public_key_hex: str, preimage: bytes) -> str:
    return hashlib.sha512(_TESTDOM + bytes.fromhex(public_key_hex) + preimage).hexdigest()


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WireError("duplicate field")
        result[key] = value
    return result


def _is_wire_mapping(fields: Mapping[str, object]) -> TypeGuard[Mapping[str, WireValue]]:
    return all(type(value) in {str, int} for value in fields.values())


def _wire_str(fields: Mapping[str, WireValue], key: str) -> str:
    value = fields[key]
    if type(value) is not str:
        raise WireError(f"non-text wire field {key}")
    return value


def _wire_int(fields: Mapping[str, WireValue], key: str) -> int:
    value = fields[key]
    if type(value) is not int:
        raise WireError(f"non-integer wire field {key}")
    return value


def _reject_number(_: str) -> None:
    raise WireError("forbidden JSON number")


def _quote(value: str) -> bytes:
    if not value or any(ord(c) < 0x20 or ord(c) > 0x7E for c in value) or '"' in value or "\\" in value:
        raise WireError("noncanonical string")
    return b'"' + value.encode("ascii") + b'"'


def _raw(fields: Mapping[str, object]) -> bytes:
    chunks = []
    for key in sorted(fields):
        value = fields[key]
        encoded = str(value).encode("ascii") if type(value) is int else _quote(value)  # type: ignore[arg-type]
        chunks.append(_quote(key) + b":" + encoded)
    return b"{" + b",".join(chunks) + b"}"


def parse_message(payload: bytes) -> dict[str, WireValue]:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_FRAME_BYTES or any(b > 0x7F for b in payload):
        raise WireError("payload bounds or encoding")
    try:
        result = json.loads(payload.decode("ascii"), object_pairs_hook=_pairs, parse_float=_reject_number, parse_constant=_reject_number)
    except WireError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WireError("malformed JSON") from exc
    if type(result) is not dict:
        raise WireError("payload is not an object")
    _validate_structure(result, check_digest=True)
    if _raw(result) != payload:
        raise WireError("noncanonical bytes")
    return cast(dict[str, WireValue], result)


def encode_message(fields: Mapping[str, object]) -> bytes:
    _validate_structure(fields, check_digest=True)
    result = _raw(fields)
    if not 1 <= len(result) <= MAX_FRAME_BYTES:
        raise WireError("payload bounds")
    return result


def encode_frame(fields: Mapping[str, object]) -> bytes:
    payload = encode_message(fields)
    return len(payload).to_bytes(4, "big") + payload


def decode_frame(frame: bytes) -> dict[str, WireValue]:
    if type(frame) is not bytes or len(frame) < 4:
        raise WireError("truncated frame")
    size = int.from_bytes(frame[:4], "big")
    if not 1 <= size <= MAX_FRAME_BYTES or len(frame) != size + 4:
        raise WireError("frame length")
    return parse_message(frame[4:])


def transcript_digest(fields: Mapping[str, object]) -> str:
    unsigned = dict(fields)
    unsigned.pop("transcript_digest", None)
    unsigned.pop("signature_hex", None)
    kind = unsigned.get("kind")
    if type(kind) is not str or kind not in _KINDS:
        raise WireError("unknown kind")
    return hashlib.sha512(_TDOM + kind.encode("ascii") + b"\0" + _raw(unsigned)).hexdigest()


def signature_preimage(fields: Mapping[str, object]) -> bytes:
    kind = fields.get("kind")
    digest = fields.get("transcript_digest")
    if type(kind) is not str or kind not in _KINDS or type(digest) is not str or not _HEX128.fullmatch(digest):
        raise WireError("signature preimage fields")
    return _SDOM + kind.encode("ascii") + b"\0" + bytes.fromhex(digest)


def projection_digest(fields: Mapping[str, object]) -> str:
    projection = {key: fields[key] for key in sorted(_PROJECTION - {"projection_digest"})}
    return hashlib.sha512(_PDOM + _raw(projection)).hexdigest()


def set_digest(value: str) -> str:
    _parse_set(value)
    return hashlib.sha512(_SETDOM + value.encode("ascii")).hexdigest()


def convergence_digest(evidence_a: str, evidence_b: str, mode_evidence: str, projection: str) -> str:
    for value in (evidence_a, evidence_b, mode_evidence, projection):
        if not _HEX128.fullmatch(value):
            raise WireError("convergence reference")
    return hashlib.sha512(_CDOM + bytes.fromhex(evidence_a + evidence_b + mode_evidence + projection)).hexdigest()


def stable_request_digest(request_digest: str) -> str:
    """Derive the only permitted stable request identity from canonical request semantics."""
    if not _HEX128.fullmatch(request_digest):
        raise WireError("stable request binding")
    return hashlib.sha512(_STABLEREQUESTDOM + bytes.fromhex(request_digest)).hexdigest()


def stable_effect_intent_digest(
    stable_request: str, effect_intent: str, effect: str, adapter: str, adapter_boundary: str,
) -> str:
    values = (stable_request, effect_intent, effect, adapter, adapter_boundary)
    if any(not _HEX128.fullmatch(value) for value in values):
        raise WireError("stable effect binding")
    return hashlib.sha512(_STABLEDOM + bytes.fromhex("".join(values))).hexdigest()


def durable_consumption_digest(replay_namespace: str, stable_effect_intent: str) -> str:
    if not _HEX128.fullmatch(replay_namespace) or not _HEX128.fullmatch(stable_effect_intent):
        raise WireError("durable consumption binding")
    return hashlib.sha512(_DURABLEDOM + bytes.fromhex(replay_namespace + stable_effect_intent)).hexdigest()


_POINT_OF_USE_TEXT_FIELDS: Final[tuple[str, ...]] = (
    "authority_build_id", "authority_class", "authority_profile",
    "adapter_boundary_digest", "adapter_digest", "audit_anchor_digest",
    "domain_digest", "durable_consumption_digest", "effect_digest",
    "effect_intent_digest", "inhibit_binding_digest", "interlock_digest",
    "lease_digest", "lease_id", "operation_id", "replay_namespace", "request_digest",
    "stable_effect_intent_digest", "stable_request_digest", "state_digest",
    "subject_digest", "traversal_id", "watchdog_digest",
)


def point_of_use_digest(fields: Mapping[str, object]) -> str:
    """Derive the final adapter-use binding; caller-supplied opaque values are invalid."""
    try:
        values: dict[str, object] = {key: fields[key] for key in _POINT_OF_USE_TEXT_FIELDS}
        values.update({
            "authority_epoch": fields["authority_epoch"],
            "lease_deadline_ms": fields["lease_deadline_ms"],
            "watchdog_deadline_ms": fields["watchdog_deadline_ms"],
        })
    except KeyError as exc:
        raise WireError("point-of-use binding fields") from exc
    if any(type(values[key]) is not str or not values[key] for key in _POINT_OF_USE_TEXT_FIELDS):
        raise WireError("point-of-use binding text")
    for key in ("authority_epoch", "lease_deadline_ms", "watchdog_deadline_ms"):
        if type(values[key]) is not int or not 0 <= values[key] <= MAX_SAFE_INTEGER:  # type: ignore[operator]
            raise WireError("point-of-use binding integer")
    if values["authority_epoch"] == 0:
        raise WireError("point-of-use epoch")
    return hashlib.sha512(_POUDOM + _raw(values)).hexdigest()


_ARTIFACT_RESULT_FIELD: Final[dict[str, str]] = {
    "prepare_request": "prepare_proof_digest",
    "commit_request": "capability_digest",
    "lease_redeem_request": "lease_digest",
    "watchdog_arm_request": "watchdog_digest",
    "effect_permit_request": "permit_digest",
}
_ARTIFACT_ID_FIELD: Final[dict[str, str]] = {
    "prepare_request": "prepare_id",
    "commit_request": "capability_id",
    "lease_redeem_request": "lease_id",
    "effect_permit_request": "permit_id",
}
_ARTIFACT_REQUEST_FIELDS: Final[dict[str, tuple[str, ...]]] = {
    "prepare_request": ("convergence_digest",),
    "commit_request": ("prepare_id", "prepare_proof_digest"),
    "lease_redeem_request": ("capability_digest", "capability_id", "lease_deadline_ms"),
    "watchdog_arm_request": ("lease_digest", "lease_id", "watchdog_deadline_ms"),
    "effect_permit_request": (
        "lease_deadline_ms", "lease_digest", "lease_id", "point_of_use_digest",
        "watchdog_deadline_ms", "watchdog_digest",
    ),
}


def authority_artifact_digest(
    stage: str, context: AuthenticatedStageContext,
    request: Mapping[str, object], result: Mapping[str, object],
) -> str:
    """Derive an authority artifact from the verified stage and signed result metadata."""
    if stage not in _ARTIFACT_DOMAINS or context.stage_kind != stage:
        raise WireError("authority artifact stage")
    values: dict[str, object] = {
        "admission_policy_digest": context.admission_policy_digest,
        "authenticated_convergence_binding_digest": context.authenticated_convergence_binding_digest,
        "authority_build_id": result["authority_build_id"],
        "authority_class": result["authority_class"],
        "authority_epoch": result["authority_epoch"],
        "authority_profile": result["authority_profile"],
        "context_digest": context.context_digest,
        "message_time_ms": result["message_time_ms"],
        "nonce": result["nonce"],
        "request_transcript_digest": request["transcript_digest"],
        "signer_key_id": result["signer_key_id"],
        "stage": stage,
    }
    for key in _ARTIFACT_REQUEST_FIELDS[stage]:
        values[f"request_{key}"] = request[key]
    if stage == "effect_permit_request":
        values["result_permit_deadline_ms"] = result["permit_deadline_ms"]
    return hashlib.sha512(_ARTIFACT_DOMAINS[stage] + _raw(values)).hexdigest()


def authority_artifact_id(stage: str, artifact_digest: str) -> str:
    """Derive a 16-byte core identifier without truncating an unrelated digest."""
    if stage not in _ARTIFACT_DOMAINS or not _HEX128.fullmatch(artifact_digest):
        raise WireError("authority artifact ID")
    return hashlib.sha512(
        _ARTIFACT_IDDOM + stage.encode("ascii") + b"\0" + bytes.fromhex(artifact_digest)
    ).digest()[:16].hex()


def rendezvous_checkpoint_digest(
    branch: str, traversal_id: str, challenge: str, worker_id: str, process_digest: str,
) -> str:
    if branch not in {"A", "B"} or not _HEX32.fullmatch(traversal_id) or not _HEX128.fullmatch(challenge) or not _HEX128.fullmatch(process_digest) or not _TOKEN.fullmatch(worker_id):
        raise WireError("rendezvous checkpoint binding")
    return hashlib.sha512(_CHECKPOINTDOM + branch.encode("ascii") + b"\0" + bytes.fromhex(traversal_id + challenge + process_digest) + b"\0" + worker_id.encode("ascii")).hexdigest()


def rendezvous_release_digest(
    checkpoint_a: str, checkpoint_b: str, opened_at_ms: int, released_at_ms: int,
) -> str:
    if not _HEX128.fullmatch(checkpoint_a) or not _HEX128.fullmatch(checkpoint_b) or type(opened_at_ms) is not int or type(released_at_ms) is not int or not 0 <= opened_at_ms <= released_at_ms <= MAX_SAFE_INTEGER:
        raise WireError("rendezvous release binding")
    return hashlib.sha512(_RELEASEDOM + bytes.fromhex(checkpoint_a + checkpoint_b) + opened_at_ms.to_bytes(8, "big") + released_at_ms.to_bytes(8, "big")).hexdigest()


def rendezvous_ack_digest(branch: str, release: str, statement_digest: str) -> str:
    if branch not in {"A", "B"} or not _HEX128.fullmatch(release) or not _HEX128.fullmatch(statement_digest):
        raise WireError("rendezvous ACK binding")
    return hashlib.sha512(_ACKDOM + branch.encode("ascii") + b"\0" + bytes.fromhex(release + statement_digest)).hexdigest()


def mode3_state_seal_digest(state: str, mode_freeze: str, projection: str, traversal_id: str, challenge: str) -> str:
    if any(not _HEX128.fullmatch(value) for value in (state, mode_freeze, projection, challenge)) or not _HEX32.fullmatch(traversal_id):
        raise WireError("Mode 3 seal binding")
    return hashlib.sha512(_STATESEALDOM + bytes.fromhex(state + mode_freeze + projection + traversal_id + challenge)).hexdigest()


def mode3_single_state_proof_digest(seal: str, callable_digest: str, provenance: str) -> str:
    if any(not _HEX128.fullmatch(value) for value in (seal, callable_digest, provenance)):
        raise WireError("Mode 3 proof binding")
    return hashlib.sha512(_SINGLEPROOFDOM + bytes.fromhex(seal + callable_digest + provenance)).hexdigest()


def adapter_consumption_digest(
    durable: str, permit: str, effect: str, adapter: str, consumed_at_ms: int, outcome: str,
) -> str:
    if any(not _HEX128.fullmatch(value) for value in (durable, permit, effect, adapter)) or type(consumed_at_ms) is not int or not 0 <= consumed_at_ms <= MAX_SAFE_INTEGER or outcome not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
        raise WireError("atomic consumption binding")
    return hashlib.sha512(_CONSUMEDOM + bytes.fromhex(durable + permit + effect + adapter) + consumed_at_ms.to_bytes(8, "big") + b"\0" + outcome.encode("ascii")).hexdigest()


_RECEIPT_TEXT_FIELDS: Final[tuple[str, ...]] = (
    "adapter_boundary_digest", "adapter_consumption_digest", "adapter_digest",
    "audit_anchor_digest", "domain_digest", "durable_consumption_digest",
    "effect_digest", "effect_intent_digest", "effect_outcome",
    "inhibit_binding_digest", "interlock_digest", "operation_id",
    "permit_digest", "permit_id", "request_digest", "stable_effect_intent_digest",
    "stable_request_digest", "state_digest", "subject_digest", "watchdog_digest",
)


def effect_receipt_digest(fields: Mapping[str, object]) -> str:
    """Derive a present receipt identity; ZERO is reserved for no-receipt timeout."""
    try:
        values: dict[str, object] = {key: fields[key] for key in _RECEIPT_TEXT_FIELDS}
        values.update({
            "adapter_consumed_at_ms": fields["adapter_consumed_at_ms"],
            "authority_epoch": fields["authority_epoch"],
        })
    except KeyError as exc:
        raise WireError("effect receipt binding fields") from exc
    if any(type(values[key]) is not str or not values[key] for key in _RECEIPT_TEXT_FIELDS):
        raise WireError("effect receipt binding text")
    if values["effect_outcome"] not in {"SUCCEEDED", "FAILED", "UNKNOWN"}:
        raise WireError("effect receipt outcome")
    if not _HEX32.fullmatch(str(values["operation_id"])) or not _HEX32.fullmatch(str(values["permit_id"])):
        raise WireError("effect receipt identifier")
    for key in _RECEIPT_TEXT_FIELDS:
        if key in {"effect_outcome", "operation_id", "permit_id"}:
            continue
        if not _HEX128.fullmatch(str(values[key])):
            raise WireError("effect receipt digest field")
    for key in ("adapter_consumed_at_ms", "authority_epoch"):
        if type(values[key]) is not int or not 0 <= values[key] <= MAX_SAFE_INTEGER:  # type: ignore[operator]
            raise WireError("effect receipt binding integer")
    if values["authority_epoch"] == 0:
        raise WireError("effect receipt epoch")
    derived = hashlib.sha512(_RECEIPTDOM + _raw(values)).hexdigest()
    if derived == ZERO:
        raise WireError("zero effect receipt derivation")
    return derived


def admission_policy_digest(admission: AdmissionPolicy) -> str:
    """Canonical digest of the externally pinned admission oracle."""
    values = {item.name: getattr(admission, item.name) for item in dataclass_fields(admission)}
    if type(values.get("authority_epoch")) is not int or not 1 <= values["authority_epoch"] <= MAX_SAFE_INTEGER:  # type: ignore[operator]
        raise WireError("invalid admission policy epoch")
    if any(type(value) is not str or not value for key, value in values.items() if key != "authority_epoch"):
        raise WireError("invalid admission policy")
    if any(
        not _HEX128.fullmatch(value) or value == ZERO
        for value in (
            admission.extension_configuration_digest,
            admission.extension_admission_binding_digest,
        )
    ):
        raise WireError("zero extension admission digest")
    if admission.stable_request_digest != stable_request_digest(admission.request_digest):
        raise WireError("admission stable request derivation")
    return hashlib.sha512(_ADMISSIONDOM + _raw(values)).hexdigest()


def authenticated_convergence_binding_digest(
    admission: AdmissionPolicy, registry: TrustRegistry,
    prefix_messages: Iterable[Mapping[str, object]], *, convergence: str,
    projection: str,
) -> str:
    """Bind the full admitted oracle and every verified convergence-prefix item."""
    messages = tuple(prefix_messages)
    if not messages or any(not _HEX128.fullmatch(str(item.get("transcript_digest", ""))) for item in messages):
        raise WireError("invalid authenticated convergence prefix")
    if not _HEX128.fullmatch(convergence) or not _HEX128.fullmatch(projection):
        raise WireError("invalid authenticated convergence derivation")
    body = (
        bytes.fromhex(admission_policy_digest(admission))
        + bytes.fromhex(registry.root_digest)
        + bytes.fromhex(registry.digest())
        + len(messages).to_bytes(4, "big")
        + b"".join(bytes.fromhex(str(item["transcript_digest"])) for item in messages)
        + bytes.fromhex(convergence + projection)
    )
    frozen = PROTOCOL.encode("ascii") + b"\0" + ORACLE_SHA512.encode("ascii") + b"\0SBP-LEX-EXEC-PROJECTION/2\0"
    return hashlib.sha512(_AUTHCONVDOM + frozen + body).hexdigest()


def seal_fixture_message(fields: Mapping[str, object], key: KeyRecord) -> dict[str, object]:
    sealed = dict(fields)
    sealed.update(
        {
            "signer_key_class": key.key_class,
            "signer_key_id": key.key_id,
            "signer_role": key.role,
            "signature_algorithm": "TEST-SHA512",
            "signing_public_key_hex": key.public_key_hex,
            "signature_hex": "00",
            "transcript_digest": ZERO,
        }
    )
    _validate_structure(sealed, check_digest=False)
    sealed["transcript_digest"] = transcript_digest(sealed)
    sealed["signature_hex"] = fixture_signature(key.public_key_hex, signature_preimage(sealed))
    _validate_structure(sealed, check_digest=True)
    return sealed


def validate_transcript(
    messages: Iterable[Mapping[str, object]], *, registry: TrustRegistry,
    admission: AdmissionPolicy, verifier: Verifier, trusted_now_ms: int,
) -> None:
    supplied = tuple(messages)
    if not supplied:
        raise WireError("empty transcript")
    mode = supplied[0].get("mode")
    if type(mode) is not str or mode not in _MODE_PREFIXES:
        raise WireError("unknown mode")
    prefix = _MODE_PREFIXES[mode]
    base = prefix + _POST_KINDS
    supplied_kinds = tuple(item.get("kind") for item in supplied)
    if len(supplied) <= len(base):
        expected = base[: len(supplied)]
    elif supplied_kinds[len(base)] == "effect_receipt":
        expected = base + ("effect_receipt", "receipt_ack", "watchdog_terminal", "watchdog_result")[: len(supplied) - len(base)]
    elif supplied_kinds[len(base)] == "watchdog_terminal":
        expected = base + ("watchdog_terminal", "watchdog_result")[: len(supplied) - len(base)]
    else:
        raise WireError("invalid lifecycle tail")
    if len(supplied) > len(base) + 4:
        raise WireError("lifecycle length")
    parsed, terminal_denial = _authenticate_messages(
        supplied, expected, registry=registry, admission=admission,
        verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    # A terminal authority refusal is valid audit evidence only when the entire
    # request prefix that led to it independently validates first.
    if terminal_denial:
        result_kind = str(parsed[-1]["kind"])
        request_kind = next((request for request, result in _RESULT_FOR_REQUEST.items() if result == result_kind), None)
        if request_kind is None or len(parsed) < 2:
            raise WireError("denial without staged request")
        context = validate_request_prefix(
            parsed[:-1], expected_request_kind=request_kind, registry=registry,
            admission=admission, verifier=verifier, trusted_now_ms=trusted_now_ms,
        )
        _validate_stage_result(parsed[-1], context, parsed[:-1])
        return
    cidx = len(prefix) - 1
    if len(parsed) <= cidx:
        raise WireError("incomplete convergence prefix")
    _validate_mode_prefix(parsed, mode, cidx, admission)
    _validate_completed_lifecycle(
        parsed, len(prefix), registry=registry, admission=admission,
    )
    if len(parsed) <= len(base):
        raise WireError("successful lifecycle incomplete")
    _validate_post_lifecycle(parsed, len(prefix), len(base), False)


def _authenticate_messages(
    messages: Iterable[Mapping[str, object]], expected: tuple[str, ...], *,
    registry: TrustRegistry, admission: AdmissionPolicy, verifier: Verifier,
    trusted_now_ms: int,
) -> tuple[list[dict[str, WireValue]], bool]:
    parsed = [parse_message(encode_message(message)) for message in messages]
    if not parsed or len(parsed) != len(expected) or type(trusted_now_ms) is not int:
        raise WireError("empty/mismatched authenticated prefix")
    binding = tuple(parsed[0][key] for key in _IMMUTABLE_FIELDS)
    if admission.trust_root_digest != registry.root_digest or parsed[0]["trust_root_digest"] != admission.trust_root_digest:
        raise WireError("trust root mismatch")
    if admission.registry_digest != registry.digest() or parsed[0]["trust_registry_digest"] != admission.registry_digest:
        raise WireError("registry mismatch")
    if (
        parsed[0]["runtime_subject"] != admission.runtime_subject
        or parsed[0]["runtime_tree"] != admission.runtime_tree
        or parsed[0]["authority_class"] != admission.authority_class
        or parsed[0]["authority_epoch"] != admission.authority_epoch
        or parsed[0]["authority_profile"] != admission.authority_profile
        or parsed[0]["authority_build_id"] != admission.authority_build_id
    ):
        raise WireError("admission policy mismatch")
    if set(registry.entries) != _ROLES:
        raise WireError("registry role set mismatch")
    if len({item.key_id for item in registry.entries.values()}) != len(registry.entries):
        raise WireError("role keys are not distinct")
    expected_registry_class = {
        "TEST_ONLY": "TEST_FIXTURE",
        "PRODUCTION_HSM": "PRODUCTION_HSM",
        "PRODUCTION_TPM": "PRODUCTION_TPM",
    }[admission.authority_class]
    if any(item.key_class != expected_registry_class for item in registry.entries.values()):
        raise WireError("registry authority class mismatch")
    expected_context = {
        "mode": admission.mode,
        "traversal_id": admission.traversal_id,
        "operation_id": admission.operation_id,
        "challenge": admission.challenge,
        "replay_namespace": admission.replay_namespace,
        "domain_digest": admission.domain_digest,
        "subject_digest": admission.subject_digest,
        "stable_request_digest": admission.stable_request_digest,
        "request_digest": admission.request_digest,
        "state_digest": admission.state_digest,
        "effect_digest": admission.effect_digest,
        "effect_intent_digest": admission.effect_intent_digest,
        "adapter_digest": admission.adapter_digest,
        "adapter_boundary_digest": admission.adapter_boundary_digest,
        "inhibit_binding_digest": admission.inhibit_binding_digest,
        "interlock_digest": admission.interlock_digest,
        "audit_anchor_digest": admission.audit_anchor_digest,
        "extension_admission_mode": admission.extension_admission_mode,
        "extension_schema": admission.extension_schema,
        "extension_configuration_digest": admission.extension_configuration_digest,
        "extension_admission_binding_digest": admission.extension_admission_binding_digest,
    }
    if any(parsed[0][key] != value for key, value in expected_context.items()):
        raise WireError("expected execution context mismatch")
    if parsed[0]["stable_request_digest"] != stable_request_digest(str(parsed[0]["request_digest"])):
        raise WireError("stable request derivation")
    stable = stable_effect_intent_digest(
        str(parsed[0]["stable_request_digest"]), str(parsed[0]["effect_intent_digest"]),
        str(parsed[0]["effect_digest"]), str(parsed[0]["adapter_digest"]),
        str(parsed[0]["adapter_boundary_digest"]),
    )
    if parsed[0]["stable_effect_intent_digest"] != stable or parsed[0]["durable_consumption_digest"] != durable_consumption_digest(str(parsed[0]["replay_namespace"]), stable):
        raise WireError("stable/durable effect binding")
    prior, prior_time, nonces = ZERO, None, set()
    terminal_denial = False
    for index, (message, kind) in enumerate(zip(parsed, expected, strict=True)):
        if message["kind"] != kind or message["sequence"] != index:
            raise WireError("order mismatch")
        if tuple(message[key] for key in _IMMUTABLE_FIELDS) != binding:
            raise WireError("execution binding mutation")
        nonce = _wire_str(message, "nonce")
        if message["prior_transcript_digest"] != prior or nonce in nonces:
            raise WireError("chain or nonce replay")
        nonces.add(nonce)
        time = _wire_int(message, "message_time_ms")
        not_before = _wire_int(message, "not_before_ms")
        expires = _wire_int(message, "expires_at_ms")
        if not not_before <= time < expires or (prior_time is not None and time < prior_time):
            raise WireError("message freshness/order")
        if not not_before <= time <= trusted_now_ms < expires:
            raise WireError("trusted-time freshness")
        prior_time, prior = time, _wire_str(message, "transcript_digest")
        role = _ROLE_BY_KIND[kind]
        if message["signer_role"] != role or role not in registry.entries:
            raise WireError("unadmitted signer role")
        admitted = registry.entries[role]
        if (
            message["signer_key_class"] != admitted.key_class
            or message["signer_key_id"] != admitted.key_id
            or message["signing_public_key_hex"] != admitted.public_key_hex
        ):
            raise WireError("signer registry mismatch")
        algorithm = _wire_str(message, "signature_algorithm")
        matrix = {
            "TEST_ONLY": ("TEST_FIXTURE", {"TEST-SHA512"}),
            "PRODUCTION_HSM": ("PRODUCTION_HSM", {"ML-DSA-65", "ML-DSA-87"}),
            "PRODUCTION_TPM": ("PRODUCTION_TPM", {"ML-DSA-65", "ML-DSA-87"}),
        }
        expected_key_class, expected_algorithms = matrix[
            _wire_str(message, "authority_class")
        ]
        if admitted.key_class != expected_key_class or algorithm not in expected_algorithms:
            raise WireError("authority/key/algorithm matrix")
        if not verifier(algorithm, bytes.fromhex(admitted.public_key_hex), signature_preimage(message), bytes.fromhex(_wire_str(message, "signature_hex"))):
            raise WireError("signature verification failed")
        if kind == "effect_permit_request" and message["point_of_use_digest"] != point_of_use_digest(message):
            raise WireError("point-of-use derivation")
        if message.get("decision") in {"DENY", "BLOCK"}:
            if index != len(parsed) - 1:
                raise WireError("continued after denial")
            terminal_denial = True
    return parsed, terminal_denial


def _expected_stage_prefix(mode: str, stage: str, actual_kinds: tuple[object, ...]) -> tuple[str, ...]:
    if mode not in _MODE_PREFIXES or stage not in _RESULT_FOR_REQUEST:
        raise WireError("unknown staged request")
    prefix = _MODE_PREFIXES[mode]
    if stage == "mode1_release_request":
        if mode != "MODE_1":
            raise WireError("release stage outside Mode 1")
        return (stage,)
    if stage == "convergence_request":
        return prefix[:-1]
    offsets = {
        "prepare_request": 1, "commit_request": 3, "lease_redeem_request": 5,
        "watchdog_arm_request": 7, "effect_permit_request": 9,
    }
    base = prefix + _POST_KINDS
    if stage in offsets:
        return prefix + _POST_KINDS[: offsets[stage]]
    if stage == "effect_receipt":
        return base + ("effect_receipt",)
    if stage == "watchdog_terminal":
        receipt_path = base + ("effect_receipt", "receipt_ack", "watchdog_terminal")
        timeout_path = base + ("watchdog_terminal",)
        if actual_kinds == receipt_path:
            return receipt_path
        return timeout_path
    raise WireError("unsupported staged request")


def _validate_release_request(request: Mapping[str, WireValue]) -> dict[str, WireValue]:
    checkpoint_a = rendezvous_checkpoint_digest(
        "A", _wire_str(request, "traversal_id"), _wire_str(request, "challenge"),
        _wire_str(request, "worker_a_id"), _wire_str(request, "a_process_digest"),
    )
    checkpoint_b = rendezvous_checkpoint_digest(
        "B", _wire_str(request, "traversal_id"), _wire_str(request, "challenge"),
        _wire_str(request, "worker_b_id"), _wire_str(request, "b_process_digest"),
    )
    if (
        request["a_checkpoint_digest"] != checkpoint_a
        or request["b_checkpoint_digest"] != checkpoint_b
        or request["worker_a_id"] == request["worker_b_id"]
        or request["a_process_digest"] == request["b_process_digest"]
        or not _wire_int(request, "not_before_ms")
        <= _wire_int(request, "rendezvous_opened_at_ms")
        <= _wire_int(request, "message_time_ms")
    ):
        raise WireError("Mode 1 release request evidence")
    return {
        "a_checkpoint_digest": checkpoint_a,
        "b_checkpoint_digest": checkpoint_b,
        "rendezvous_opened_at_ms": request["rendezvous_opened_at_ms"],
        "release_request_digest": request["transcript_digest"],
    }


def _validate_release_pair(request: Mapping[str, WireValue], result: Mapping[str, WireValue]) -> str:
    derived = _validate_release_request(request)
    common_mismatch = (
        result["a_checkpoint_digest"] != derived["a_checkpoint_digest"]
        or result["b_checkpoint_digest"] != derived["b_checkpoint_digest"]
        or result["release_request_digest"] != derived["release_request_digest"]
        or result["rendezvous_opened_at_ms"] != derived["rendezvous_opened_at_ms"]
    )
    if result["decision"] == "DENY":
        if (
            common_mismatch
            or result["rendezvous_release_digest"] != ZERO
            or result["rendezvous_released_at_ms"] != 0
        ):
            raise WireError("Mode 1 denied release evidence")
        return ZERO
    release = rendezvous_release_digest(
        str(derived["a_checkpoint_digest"]), str(derived["b_checkpoint_digest"]),
        int(derived["rendezvous_opened_at_ms"]), int(result["rendezvous_released_at_ms"]),
    )
    if (
        common_mismatch
        or result["rendezvous_release_digest"] != release
        or not request["message_time_ms"] <= result["rendezvous_released_at_ms"] <= result["message_time_ms"]  # type: ignore[operator]
    ):
        raise WireError("Mode 1 release result evidence")
    return release


def _receipt_request_values(
    messages: list[dict[str, WireValue]], start: int, base: int,
) -> dict[str, str | int]:
    if len(messages) != base + 1 or messages[base]["kind"] != "effect_receipt":
        raise WireError("receipt request prefix")
    permit_result = messages[start + 9]
    lease_result = messages[start + 5]
    arm_result = messages[start + 7]
    receipt = messages[base]
    if permit_result["decision"] != "ALLOW" or arm_result["decision"] != "ALLOW":
        raise WireError("receipt without active permit/watchdog")
    if receipt["permit_digest"] != permit_result["permit_digest"] or receipt["permit_id"] != permit_result["permit_id"] or receipt["watchdog_digest"] != permit_result["watchdog_digest"]:
        raise WireError("receipt permit/watchdog binding")
    deadline = min(
        _wire_int(lease_result, "lease_deadline_ms"),
        _wire_int(permit_result, "permit_deadline_ms"),
        _wire_int(arm_result, "watchdog_deadline_ms"),
    )
    permit_time = _wire_int(permit_result, "message_time_ms")
    consumed_at = _wire_int(receipt, "adapter_consumed_at_ms")
    receipt_time = _wire_int(receipt, "message_time_ms")
    if (
        not permit_time <= consumed_at < deadline
        or consumed_at > receipt_time
        or receipt_time >= deadline
    ):
        raise WireError("adapter atomic consumption freshness")
    expected_consumption = adapter_consumption_digest(
        _wire_str(receipt, "durable_consumption_digest"),
        _wire_str(receipt, "permit_digest"),
        _wire_str(receipt, "effect_digest"),
        _wire_str(receipt, "adapter_digest"),
        consumed_at,
        _wire_str(receipt, "effect_outcome"),
    )
    if receipt["adapter_consumption_digest"] != expected_consumption:
        raise WireError("adapter consumption derivation")
    expected_receipt = effect_receipt_digest(receipt)
    if receipt["receipt_digest"] != expected_receipt or receipt["receipt_digest"] == ZERO:
        raise WireError("effect receipt derivation")
    outcomes = {
        "SUCCEEDED": ("SUCCESS_RECORDED", "ACK", "HEALTHY", "ACK"),
        "FAILED": ("FAILURE_RECORDED", "FAILURE_ACK", "STOP", "BLOCK"),
        "UNKNOWN": ("UNKNOWN_BLOCKED", "FAILURE_ACK", "STOP", "BLOCK"),
    }
    if receipt["effect_outcome"] not in outcomes:
        raise WireError("effect outcome")
    status, ack_decision, watchdog_status, watchdog_decision = outcomes[
        _wire_str(receipt, "effect_outcome")
    ]
    return {
        "adapter_consumption_digest": expected_consumption,
        "completion_deadline_ms": deadline,
        "permit_digest": receipt["permit_digest"],
        "permit_id": receipt["permit_id"],
        "receipt_digest": expected_receipt,
        "receipt_status": status,
        "required_ack_decision": ack_decision,
        "required_watchdog_decision": watchdog_decision,
        "required_watchdog_status": watchdog_status,
        "watchdog_digest": receipt["watchdog_digest"],
    }


def _watchdog_terminal_values(
    messages: list[dict[str, WireValue]], start: int, base: int,
) -> dict[str, str | int]:
    lease_result = messages[start + 5]
    permit_result, arm_result = messages[start + 9], messages[start + 7]
    tail = messages[base:]
    if len(tail) == 1:
        terminal = tail[0]
        fail_close_deadline = min(
            _wire_int(lease_result, "lease_deadline_ms"),
            _wire_int(permit_result, "permit_deadline_ms"),
            _wire_int(arm_result, "watchdog_deadline_ms"),
        )
        terminal_time = _wire_int(terminal, "message_time_ms")
        result_deadline_exclusive = min(
            terminal_time + FAIL_CLOSE_RESULT_MAX_DELAY_MS + 1,  # type: ignore[operator]
            MAX_SAFE_INTEGER + 1,
        )
        valid_trip_time = (
            terminal_time == fail_close_deadline
            if terminal["watchdog_status"] == "TIMEOUT"
            else _wire_int(permit_result, "message_time_ms")
            <= terminal_time
            <= fail_close_deadline
        )
        if (
            terminal["watchdog_status"] not in {"STOP", "TIMEOUT"}
            or terminal["receipt_digest"] != ZERO
            or terminal["permit_digest"] != permit_result["permit_digest"]
            or terminal["permit_id"] != permit_result["permit_id"]
            or terminal["watchdog_digest"] != permit_result["watchdog_digest"]
            or not valid_trip_time
        ):
            raise WireError("invalid no-receipt watchdog request")
        return {
            "completion_deadline_ms": result_deadline_exclusive,
            "fail_close_deadline_ms": fail_close_deadline,
            "permit_digest": terminal["permit_digest"],
            "permit_id": terminal["permit_id"],
            "receipt_digest": ZERO,
            "required_watchdog_decision": "BLOCK",
            "watchdog_digest": terminal["watchdog_digest"],
        }
    if len(tail) != 3 or tail[0]["kind"] != "effect_receipt" or tail[1]["kind"] != "receipt_ack":
        raise WireError("watchdog request prefix")
    receipt_values = _receipt_request_values(messages[: base + 1], start, base)
    _receipt, ack, terminal = tail
    if (
        ack["permit_digest"] != receipt_values["permit_digest"]
        or ack["permit_id"] != receipt_values["permit_id"]
        or ack["receipt_digest"] != receipt_values["receipt_digest"]
        or ack["watchdog_digest"] != receipt_values["watchdog_digest"]
        or ack["receipt_status"] != receipt_values["receipt_status"]
        or ack["decision"] != receipt_values["required_ack_decision"]
        or terminal["receipt_digest"] != receipt_values["receipt_digest"]
        or terminal["permit_digest"] != receipt_values["permit_digest"]
        or terminal["permit_id"] != receipt_values["permit_id"]
        or terminal["watchdog_digest"] != receipt_values["watchdog_digest"]
        or terminal["watchdog_status"] != receipt_values["required_watchdog_status"]
        or ack["message_time_ms"] >= receipt_values["completion_deadline_ms"]  # type: ignore[operator]
        or terminal["message_time_ms"] >= receipt_values["completion_deadline_ms"]  # type: ignore[operator]
    ):
        raise WireError("receipt/watchdog staged semantics")
    return {
        "completion_deadline_ms": receipt_values["completion_deadline_ms"],
        "permit_digest": receipt_values["permit_digest"],
        "permit_id": receipt_values["permit_id"],
        "receipt_digest": receipt_values["receipt_digest"],
        "required_watchdog_decision": receipt_values["required_watchdog_decision"],
        "watchdog_digest": receipt_values["watchdog_digest"],
    }


def validate_request_prefix(
    messages: Iterable[Mapping[str, object]], *, expected_request_kind: str,
    registry: TrustRegistry, admission: AdmissionPolicy, verifier: Verifier,
    trusted_now_ms: int,
) -> AuthenticatedStageContext:
    """Authenticate one request prefix before any result is constructed/signed."""
    supplied = tuple(messages)
    if not supplied:
        raise WireError("empty staged request")
    mode = supplied[0].get("mode")
    if type(mode) is not str:
        raise WireError("missing staged mode")
    actual_kinds = tuple(item.get("kind") for item in supplied)
    expected = _expected_stage_prefix(mode, expected_request_kind, actual_kinds)
    if actual_kinds != expected or actual_kinds[-1] != expected_request_kind:
        raise WireError("staged request shape/order")
    parsed, terminal = _authenticate_messages(
        supplied, expected, registry=registry, admission=admission,
        verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    if terminal:
        raise WireError("terminal denial is not a new request")
    prefix = _MODE_PREFIXES[mode]
    if expected_request_kind not in {"mode1_release_request", "convergence_request"}:
        _validate_completed_lifecycle(
            parsed, len(prefix), registry=registry, admission=admission,
        )
    return _stage_context_from_authenticated(
        parsed, expected_request_kind=expected_request_kind,
        registry=registry, admission=admission,
    )


def _stage_context_from_authenticated(
    parsed: list[dict[str, WireValue]], *, expected_request_kind: str,
    registry: TrustRegistry, admission: AdmissionPolicy,
) -> AuthenticatedStageContext:
    """Derive one context from an already authenticated, prior-validated prefix."""
    mode = str(parsed[0]["mode"])
    prefix = _MODE_PREFIXES[mode]
    convergence_binding = ZERO
    derived: dict[str, str | int]
    if expected_request_kind == "mode1_release_request":
        derived = _validate_release_request(parsed[0])
    elif expected_request_kind == "convergence_request":
        refs, convergence = _derive_mode_request(parsed, mode, len(parsed) - 1, admission)
        derived = {
            "convergence_digest": convergence,
            "evidence_a_digest": refs[0], "evidence_b_digest": refs[1],
            "mode_evidence_digest": refs[2], "projection_digest": refs[3],
        }
        convergence_binding = authenticated_convergence_binding_digest(
            admission, registry, parsed, convergence=convergence, projection=refs[3],
        )
    else:
        convergence_result_index = len(prefix) - 1
        _validate_mode_prefix(parsed, mode, convergence_result_index, admission)
        if parsed[convergence_result_index]["decision"] != "ALLOW":
            raise WireError("request after refused convergence")
        refs, convergence = _derive_mode_request(parsed, mode, convergence_result_index - 1, admission)
        convergence_binding = authenticated_convergence_binding_digest(
            admission, registry, parsed[:convergence_result_index],
            convergence=convergence, projection=refs[3],
        )
        start, base = len(prefix), len(prefix) + len(_POST_KINDS)
        request = parsed[-1]
        if expected_request_kind == "prepare_request":
            derived = {"convergence_digest": request["convergence_digest"]}
        elif expected_request_kind == "commit_request":
            derived = {key: request[key] for key in ("prepare_id", "prepare_proof_digest")}
        elif expected_request_kind == "lease_redeem_request":
            derived = {key: request[key] for key in ("capability_digest", "capability_id", "lease_deadline_ms")}
        elif expected_request_kind == "watchdog_arm_request":
            derived = {key: request[key] for key in ("lease_digest", "lease_id", "watchdog_deadline_ms")}
        elif expected_request_kind == "effect_permit_request":
            derived = {key: request[key] for key in ("lease_deadline_ms", "lease_digest", "lease_id", "point_of_use_digest", "watchdog_deadline_ms", "watchdog_digest")}
        elif expected_request_kind == "effect_receipt":
            derived = _receipt_request_values(parsed, start, base)
        elif expected_request_kind == "watchdog_terminal":
            derived = _watchdog_terminal_values(parsed, start, base)
        else:
            raise WireError("unsupported staged request semantics")
    result_kind = _RESULT_FOR_REQUEST[expected_request_kind]
    policy_digest = admission_policy_digest(admission)
    derived_tuple = tuple(sorted(derived.items()))
    context_body = (
        bytes.fromhex(policy_digest + registry.digest() + convergence_binding)
        + len(parsed).to_bytes(4, "big")
        + b"".join(bytes.fromhex(str(item["transcript_digest"])) for item in parsed)
        + expected_request_kind.encode("ascii") + b"\0" + result_kind.encode("ascii") + b"\0"
        + _raw(dict(derived_tuple))
    )
    context_digest = hashlib.sha512(_STAGECTXDOM + context_body).hexdigest()
    return AuthenticatedStageContext(
        stage_kind=expected_request_kind, expected_result_kind=result_kind,
        request_transcript_digest=str(parsed[-1]["transcript_digest"]),
        chain_tip_digest=str(parsed[-1]["transcript_digest"]),
        admission_policy_digest_value=policy_digest,
        authenticated_convergence_binding_digest_value=convergence_binding,
        context_digest=context_digest, values=derived_tuple, _seal=_STAGE_SEAL,
    )


def validate_and_append_result(
    request_prefix: Iterable[Mapping[str, object]], result: Mapping[str, object], *,
    context: AuthenticatedStageContext, registry: TrustRegistry,
    admission: AdmissionPolicy, verifier: Verifier, trusted_now_ms: int,
) -> tuple[dict[str, WireValue], ...]:
    """Validate an already signed result and return the authenticated new chain.

    A result cannot be returned by this API unless its prefix, kind, sequence,
    chain, signature, trusted time and stage-derived fields all validate.
    """
    supplied = tuple(request_prefix)
    fresh = validate_request_prefix(
        supplied, expected_request_kind=context.stage_kind, registry=registry,
        admission=admission, verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    if fresh.context_digest != context.context_digest:
        raise WireError("stale or foreign stage context")
    expected = _expected_stage_prefix(
        admission.mode, context.stage_kind, tuple(item.get("kind") for item in supplied),
    ) + (context.expected_result_kind,)
    parsed, _terminal = _authenticate_messages(
        supplied + (result,), expected, registry=registry, admission=admission,
        verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    _validate_stage_result(parsed[-1], fresh, parsed[:-1])
    return tuple(parsed)


def validate_effect_permit_for_atomic_consumption(
    messages_through_permit: Iterable[Mapping[str, object]], *,
    registry: TrustRegistry, admission: AdmissionPolicy, verifier: Verifier,
    trusted_now_ms: int,
) -> VerifiedEffectPermitContext:
    """Revalidate an internal signed permit immediately before adapter consume."""
    supplied = tuple(messages_through_permit)
    if len(supplied) < 2 or supplied[-1].get("kind") != "effect_permit_result":
        raise WireError("atomic permit prefix")
    request_prefix = supplied[:-1]
    stage = validate_request_prefix(
        request_prefix, expected_request_kind="effect_permit_request", registry=registry,
        admission=admission, verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    appended = validate_and_append_result(
        request_prefix, supplied[-1], context=stage, registry=registry,
        admission=admission, verifier=verifier, trusted_now_ms=trusted_now_ms,
    )
    permit = appended[-1]
    if permit["decision"] != "ALLOW":
        raise WireError("non-authorizing permit result")
    lease_deadline = stage.derived("lease_deadline_ms")
    watchdog_deadline = stage.derived("watchdog_deadline_ms")
    point_of_use = stage.derived("point_of_use_digest")
    if (
        type(lease_deadline) is not int or type(watchdog_deadline) is not int
        or trusted_now_ms
        >= min(
            lease_deadline,
            watchdog_deadline,
            _wire_int(permit, "permit_deadline_ms"),
        )
    ):
        raise WireError("permit expired at point of use")
    values: tuple[tuple[str, str | int], ...] = tuple(sorted({
        "adapter_boundary_digest": permit["adapter_boundary_digest"],
        "adapter_digest": permit["adapter_digest"],
        "authority_epoch": permit["authority_epoch"],
        "domain_digest": permit["domain_digest"],
        "durable_consumption_digest": permit["durable_consumption_digest"],
        "effect_digest": permit["effect_digest"],
        "operation_id": permit["operation_id"],
        "permit_deadline_ms": permit["permit_deadline_ms"],
        "permit_digest": permit["permit_digest"],
        "permit_id": permit["permit_id"],
        "lease_id": stage.derived("lease_id"),
        "point_of_use_digest": point_of_use,
        "stable_effect_intent_digest": permit["stable_effect_intent_digest"],
        "subject_digest": permit["subject_digest"],
        "traversal_id": permit["traversal_id"],
        "watchdog_deadline_ms": watchdog_deadline,
        "watchdog_digest": permit["watchdog_digest"],
    }.items()))
    return VerifiedEffectPermitContext(stage, values, _seal=_STAGE_SEAL)


def _validate_stage_result(
    result: Mapping[str, WireValue], context: AuthenticatedStageContext,
    request_prefix: list[dict[str, WireValue]] | tuple[dict[str, WireValue], ...],
) -> None:
    if result["kind"] != context.expected_result_kind:
        raise WireError("staged result kind")
    if result["sequence"] != len(request_prefix) or result["prior_transcript_digest"] != context.chain_tip_digest:
        raise WireError("staged result chain")
    if _wire_int(result, "message_time_ms") < _wire_int(
        request_prefix[-1], "message_time_ms"
    ):
        raise WireError("staged result chronology")
    stage = context.stage_kind
    _validate_completed_result_semantics(stage, request_prefix[-1], result, context=context)
    if stage == "mode1_release_request":
        _validate_release_pair(request_prefix[-1], result)
    elif stage == "convergence_request":
        for key in ("convergence_digest", "evidence_a_digest", "evidence_b_digest", "mode_evidence_digest", "projection_digest"):
            if result[key] != context.derived(key):
                raise WireError("convergence result derivation")
    elif stage == "lease_redeem_request":
        if result["lease_deadline_ms"] != context.derived("lease_deadline_ms"):
            raise WireError("authority lifecycle handoff: lease result")
        if result["decision"] == "ALLOW" and _wire_int(
            result, "message_time_ms"
        ) >= _wire_int(result, "lease_deadline_ms"):
            raise WireError("lease result deadline")
    elif stage == "watchdog_arm_request":
        if result["watchdog_deadline_ms"] != context.derived("watchdog_deadline_ms"):
            raise WireError("watchdog result derivation")
        if result["decision"] == "ALLOW" and _wire_int(
            result, "message_time_ms"
        ) >= _wire_int(result, "watchdog_deadline_ms"):
            raise WireError("watchdog arm result deadline")
    elif stage == "effect_permit_request":
        if result["watchdog_digest"] != context.derived("watchdog_digest"):
            raise WireError("permit result derivation")
        if result["decision"] == "ALLOW" and (
            _wire_int(result, "permit_deadline_ms")
            > min(
                cast(int, context.derived("lease_deadline_ms")),
                cast(int, context.derived("watchdog_deadline_ms")),
            )
            or _wire_int(result, "message_time_ms")
            >= _wire_int(result, "permit_deadline_ms")
        ):
            raise WireError("permit result deadline")
    elif stage == "effect_receipt":
        for key in ("permit_digest", "permit_id", "receipt_digest", "receipt_status", "watchdog_digest"):
            if result[key] != context.derived(key):
                raise WireError("receipt ACK derivation")
        if result["decision"] != context.derived("required_ack_decision"):
            raise WireError("receipt ACK decision")
        if _wire_int(result, "message_time_ms") >= cast(
            int, context.derived("completion_deadline_ms")
        ):
            raise WireError("receipt ACK deadline")
    elif stage == "watchdog_terminal":
        if (
            result["permit_digest"] != context.derived("permit_digest")
            or result["permit_id"] != context.derived("permit_id")
            or result["receipt_digest"] != context.derived("receipt_digest")
            or result["watchdog_digest"] != context.derived("watchdog_digest")
            or result["decision"] != context.derived("required_watchdog_decision")
        ):
            raise WireError("watchdog final result derivation")
        deadline = context.derived("completion_deadline_ms")
        if deadline != 0 and _wire_int(result, "message_time_ms") >= cast(int, deadline):
            raise WireError("watchdog final result deadline")
    if result["decision"] in {"ALLOW", "ACK"}:
        artifact = {
            "prepare_request": "prepare_proof_digest", "commit_request": "capability_digest",
            "lease_redeem_request": "lease_digest", "watchdog_arm_request": "watchdog_digest",
            "effect_permit_request": "permit_digest",
        }.get(stage)
        if artifact is not None and result[artifact] == ZERO:
            raise WireError("zero authority artifact")


def _validate_completed_lifecycle(
    messages: list[dict[str, WireValue]], start: int, *,
    registry: TrustRegistry, admission: AdmissionPolicy,
) -> None:
    """Validate every already-present authority transition, even before a later DENY."""
    checks = (
        (0, -1, "convergence_digest", "convergence_digest"),
        (2, 1, "prepare_proof_digest", "prepare_proof_digest"),
        (2, 1, "prepare_id", "prepare_id"),
        (4, 3, "capability_digest", "capability_digest"),
        (4, 3, "capability_id", "capability_id"),
        (5, 4, "lease_deadline_ms", "lease_deadline_ms"),
        (6, 5, "lease_digest", "lease_digest"),
        (6, 5, "lease_id", "lease_id"),
        (7, 6, "watchdog_deadline_ms", "watchdog_deadline_ms"),
        (8, 5, "lease_digest", "lease_digest"),
        (8, 5, "lease_id", "lease_id"),
        (8, 5, "lease_deadline_ms", "lease_deadline_ms"),
        (8, 7, "watchdog_digest", "watchdog_digest"),
        (8, 7, "watchdog_deadline_ms", "watchdog_deadline_ms"),
        (9, 8, "watchdog_digest", "watchdog_digest"),
    )
    present = len(messages) - start
    for right_offset, left_offset, left_key, right_key in checks:
        if right_offset >= present:
            continue
        left = messages[start + left_offset] if left_offset >= 0 else messages[start - 1]
        right = messages[start + right_offset]
        if left[left_key] != right[right_key]:
            raise WireError("authority lifecycle handoff")
    deadline_fields = {
        4: ("lease_deadline_ms",), 5: ("lease_deadline_ms",),
        6: ("watchdog_deadline_ms",), 7: ("watchdog_deadline_ms",),
        8: ("lease_deadline_ms", "watchdog_deadline_ms"), 9: ("permit_deadline_ms",),
    }
    for offset, fields in deadline_fields.items():
        if offset >= present:
            continue
        item = messages[start + offset]
        if item.get("decision") == "DENY":
            continue
        for field in fields:
            if _wire_int(item, "message_time_ms") >= _wire_int(item, field):
                raise WireError("expired authority lifecycle deadline")
    if present > 9:
        permit_request, permit_result = messages[start + 8], messages[start + 9]
        if permit_result["decision"] == "ALLOW" and _wire_int(
            permit_result, "permit_deadline_ms"
        ) > min(
            _wire_int(permit_request, "lease_deadline_ms"),
            _wire_int(permit_request, "watchdog_deadline_ms"),
        ):
            raise WireError("permit deadline widening")
    # Replay the pure transition semantics of every completed result. A caller
    # may supply an arbitrary signed historical prefix, so prior successful
    # results cannot be trusted merely because their fields link together.
    pairs = (
        ("prepare_request", 0, 1), ("commit_request", 2, 3),
        ("lease_redeem_request", 4, 5), ("watchdog_arm_request", 6, 7),
        ("effect_permit_request", 8, 9),
    )
    for stage, request_offset, result_offset in pairs:
        if result_offset >= present:
            continue
        context = _stage_context_from_authenticated(
            messages[: start + request_offset + 1],
            expected_request_kind=stage, registry=registry, admission=admission,
        )
        _validate_completed_result_semantics(
            stage, messages[start + request_offset], messages[start + result_offset],
            context=context,
        )


def _validate_completed_result_semantics(
    stage: str, request: Mapping[str, WireValue], result: Mapping[str, WireValue], *,
    context: AuthenticatedStageContext,
) -> None:
    artifact = _ARTIFACT_RESULT_FIELD.get(stage)
    identity = _ARTIFACT_ID_FIELD.get(stage)
    if result["decision"] != "ALLOW":
        if artifact is not None and result[artifact] != ZERO:
            raise WireError("denied authority artifact must be zero")
        if identity is not None and result[identity] != ZERO_ID:
            raise WireError("denied authority artifact ID must be zero")
        return
    if artifact is not None and result[artifact] != authority_artifact_digest(stage, context, request, result):
        raise WireError("authority artifact derivation")
    if artifact is not None and identity is not None and result[identity] != authority_artifact_id(stage, str(result[artifact])):
        raise WireError("authority artifact ID derivation")
    if stage == "prepare_request" and result["prepare_proof_digest"] == ZERO:
        raise WireError("zero authority artifact: prepare proof")
    if stage == "commit_request" and result["capability_digest"] == ZERO:
        raise WireError("zero authority artifact: capability")
    if stage == "lease_redeem_request":
        if result["lease_digest"] == ZERO:
            raise WireError("zero authority artifact: lease")
        if result["lease_deadline_ms"] != request["lease_deadline_ms"]:
            raise WireError("authority lifecycle handoff: lease result")
    if stage == "watchdog_arm_request":
        if result["watchdog_digest"] == ZERO:
            raise WireError("zero authority artifact: watchdog")
        if result["watchdog_deadline_ms"] != request["watchdog_deadline_ms"]:
            raise WireError("watchdog result derivation")
    if stage == "effect_permit_request":
        if result["permit_digest"] == ZERO:
            raise WireError("zero authority artifact: permit")
        if result["watchdog_digest"] != request["watchdog_digest"]:
            raise WireError("permit result derivation")
        if _wire_int(result, "permit_deadline_ms") > min(
            _wire_int(request, "lease_deadline_ms"),
            _wire_int(request, "watchdog_deadline_ms"),
        ):
            raise WireError("permit deadline widening")


def _derive_mode_request(
    messages: list[dict[str, WireValue]], mode: str, request_index: int,
    admission: AdmissionPolicy,
) -> tuple[tuple[str, str, str, str], str]:
    request = messages[request_index]
    if mode == "MODE_1":
        release_request, release_result, a, b, witness = messages[:5]
        checkpoint_a = rendezvous_checkpoint_digest(
            "A", _wire_str(release_request, "traversal_id"),
            _wire_str(release_request, "challenge"),
            _wire_str(release_request, "worker_a_id"),
            _wire_str(release_request, "a_process_digest"),
        )
        checkpoint_b = rendezvous_checkpoint_digest(
            "B", _wire_str(release_request, "traversal_id"),
            _wire_str(release_request, "challenge"),
            _wire_str(release_request, "worker_b_id"),
            _wire_str(release_request, "b_process_digest"),
        )
        release = rendezvous_release_digest(
            checkpoint_a, checkpoint_b,
            _wire_int(release_request, "rendezvous_opened_at_ms"),
            _wire_int(release_result, "rendezvous_released_at_ms"),
        )
        if (
            release_request["a_checkpoint_digest"] != checkpoint_a
            or release_request["b_checkpoint_digest"] != checkpoint_b
            or release_result["release_request_digest"] != release_request["transcript_digest"]
            or release_result["a_checkpoint_digest"] != checkpoint_a
            or release_result["b_checkpoint_digest"] != checkpoint_b
            or release_result["rendezvous_opened_at_ms"] != release_request["rendezvous_opened_at_ms"]
            or release_result["rendezvous_release_digest"] != release
            or release_result["decision"] != "ALLOW"
            or not _wire_int(release_request, "not_before_ms")
            <= _wire_int(release_request, "rendezvous_opened_at_ms")
            <= _wire_int(release_request, "message_time_ms")
            <= _wire_int(release_result, "rendezvous_released_at_ms")
            <= _wire_int(release_result, "message_time_ms")
        ):
            raise WireError("Mode 1 admitted causal release evidence")
        if a["projection_digest"] != b["projection_digest"]:
            raise WireError("Mode 1 projection divergence")
        if (
            a["callable_digest"] != admission.branch_a_callable_digest
            or a["code_provenance_digest"] != admission.branch_a_code_provenance_digest
            or b["callable_digest"] != admission.branch_b_callable_digest
            or b["code_provenance_digest"] != admission.branch_b_code_provenance_digest
        ):
            raise WireError("Mode 1 semantic provenance not admitted")
        if a["callable_digest"] == b["callable_digest"] or a["code_provenance_digest"] == b["code_provenance_digest"]:
            raise WireError("Mode 1 substantive implementations not distinct")
        if a["signer_key_id"] == b["signer_key_id"] or a["worker_id"] == b["worker_id"]:
            raise WireError("Mode 1 independence failure")
        if (
            a["worker_id"] != release_request["worker_a_id"]
            or b["worker_id"] != release_request["worker_b_id"]
            or a["process_digest"] != release_request["a_process_digest"]
            or b["process_digest"] != release_request["b_process_digest"]
            or a["release_checkpoint_digest"] != checkpoint_a
            or b["release_checkpoint_digest"] != checkpoint_b
            or witness["worker_a_id"] != release_request["worker_a_id"]
            or witness["worker_b_id"] != release_request["worker_b_id"]
            or witness["a_process_digest"] != release_request["a_process_digest"]
            or witness["b_process_digest"] != release_request["b_process_digest"]
        ):
            raise WireError("Mode 1 release identity transplant")
        for side, statement in (("a", a), ("b", b)):
            if witness[f"statement_{side}_digest"] != statement["transcript_digest"] or witness[f"worker_{side}_id"] != statement["worker_id"] or witness[f"{side}_start_ms"] != statement["substantive_start_ms"] or witness[f"{side}_end_ms"] != statement["substantive_end_ms"]:
                raise WireError("Mode 1 witness mismatch")
            if not _wire_int(statement, "not_before_ms") <= _wire_int(
                statement, "substantive_start_ms"
            ) < _wire_int(statement, "substantive_end_ms") <= _wire_int(
                statement, "message_time_ms"
            ):
                raise WireError("Mode 1 branch time evidence")
        if _wire_int(witness, "message_time_ms") < max(
            _wire_int(witness, "a_end_ms"), _wire_int(witness, "b_end_ms")
        ):
            raise WireError("Mode 1 witness predates branch completion")
        if not _wire_int(witness, "not_before_ms") <= _wire_int(
            witness, "rendezvous_opened_at_ms"
        ) <= _wire_int(witness, "rendezvous_released_at_ms") <= _wire_int(
            witness, "message_time_ms"
        ):
            raise WireError("Mode 1 rendezvous time bounds")
        if witness["a_process_digest"] == witness["b_process_digest"]:
            raise WireError("Mode 1 process identity not distinct")
        if (
            witness["a_checkpoint_digest"] != checkpoint_a
            or witness["b_checkpoint_digest"] != checkpoint_b
            or witness["rendezvous_release_digest"] != release
            or witness["release_result_digest"] != release_result["transcript_digest"]
            or witness["rendezvous_opened_at_ms"] != release_request["rendezvous_opened_at_ms"]
            or witness["rendezvous_released_at_ms"] != release_result["rendezvous_released_at_ms"]
            or witness["a_ack_digest"] != rendezvous_ack_digest("A", release, _wire_str(a, "transcript_digest"))
            or witness["b_ack_digest"] != rendezvous_ack_digest("B", release, _wire_str(b, "transcript_digest"))
            or _wire_int(witness, "rendezvous_released_at_ms")
            > min(_wire_int(witness, "a_start_ms"), _wire_int(witness, "b_start_ms"))
            or _wire_int(release_result, "rendezvous_released_at_ms")
            > min(_wire_int(a, "substantive_start_ms"), _wire_int(b, "substantive_start_ms"))
        ):
            raise WireError("Mode 1 causal rendezvous evidence")
        if max(_wire_int(witness, "a_start_ms"), _wire_int(witness, "b_start_ms")) >= min(
            _wire_int(witness, "a_end_ms"), _wire_int(witness, "b_end_ms")
        ):
            raise WireError("Mode 1 substantive work did not overlap")
        refs = (
            _wire_str(a, "transcript_digest"),
            _wire_str(b, "transcript_digest"),
            _wire_str(witness, "transcript_digest"),
            _wire_str(a, "projection_digest"),
        )
    elif mode == "MODE_2":
        primary, cert = messages[:2]
        if primary["callable_digest"] != admission.branch_a_callable_digest or primary["code_provenance_digest"] != admission.branch_a_code_provenance_digest or cert["validator_code_digest"] != admission.validator_code_digest or cert["validator_provenance_digest"] != admission.validator_provenance_digest:
            raise WireError("Mode 2 semantic provenance not admitted")
        if cert["primary_statement_digest"] != primary["transcript_digest"]:
            raise WireError("Mode 2 primary reference")
        ci, co = _parse_set(_wire_str(cert, "candidate_input_set")), _parse_set(_wire_str(cert, "candidate_output_set"))
        pi, po = _parse_set(_wire_str(cert, "pathway_input_set")), _parse_set(_wire_str(cert, "pathway_output_set"))
        if not co or not po or not co <= ci or not po <= pi:
            raise WireError("Mode 2 no-widening/reduction")
        _check_rejections(ci - co, _wire_str(cert, "candidate_rejections"))
        _check_rejections(pi - po, _wire_str(cert, "pathway_rejections"))
        if primary["projection_candidate_digest"] != set_digest(_wire_str(cert, "candidate_input_set")) or primary["projection_pathway_digest"] != set_digest(_wire_str(cert, "pathway_input_set")) or cert["projection_candidate_digest"] != set_digest(_wire_str(cert, "candidate_output_set")) or cert["projection_pathway_digest"] != set_digest(_wire_str(cert, "pathway_output_set")):
            raise WireError("Mode 2 set/projection mismatch")
        unchanged = _PROJECTION - {"projection_digest", "projection_candidate_digest", "projection_pathway_digest"}
        if any(primary[key] != cert[key] for key in unchanged):
            raise WireError("Mode 2 non-set projection widening")
        refs = (
            _wire_str(primary, "transcript_digest"),
            _wire_str(cert, "transcript_digest"),
            _wire_str(cert, "transcript_digest"),
            _wire_str(cert, "projection_digest"),
        )
    else:
        proof = messages[0]
        if proof["single_state_callable_digest"] != admission.single_state_callable_digest or proof["single_state_provenance_digest"] != admission.single_state_provenance_digest:
            raise WireError("Mode 3 semantic provenance not admitted")
        seal = mode3_state_seal_digest(
            _wire_str(proof, "state_digest"),
            _wire_str(proof, "projection_mode_freeze_digest"),
            _wire_str(proof, "projection_digest"),
            _wire_str(proof, "traversal_id"),
            _wire_str(proof, "challenge"),
        )
        derived_proof = mode3_single_state_proof_digest(
            seal,
            _wire_str(proof, "single_state_callable_digest"),
            _wire_str(proof, "single_state_provenance_digest"),
        )
        if proof["state_seal_digest"] != seal or proof["single_state_proof_digest"] != derived_proof:
            raise WireError("Mode 3 proof derivation")
        refs = (
            _wire_str(proof, "transcript_digest"), ZERO,
            _wire_str(proof, "transcript_digest"),
            _wire_str(proof, "projection_digest"),
        )
    expected_convergence = convergence_digest(*refs)
    actual = (request["evidence_a_digest"], request["evidence_b_digest"], request["mode_evidence_digest"], request["projection_digest"])
    if actual != refs or request["convergence_digest"] != expected_convergence:
        raise WireError("invented or mismatched convergence evidence")
    return refs, expected_convergence


def _validate_mode_prefix(messages: list[dict[str, WireValue]], mode: str, result_index: int, admission: AdmissionPolicy) -> None:
    result = messages[result_index]
    refs, expected_convergence = _derive_mode_request(messages, mode, result_index - 1, admission)
    actual = (result["evidence_a_digest"], result["evidence_b_digest"], result["mode_evidence_digest"], result["projection_digest"])
    if actual != refs or result["convergence_digest"] != expected_convergence:
        raise WireError("invented or mismatched convergence result")


def _validate_post_lifecycle(messages: list[dict[str, WireValue]], start: int, base: int, denied: bool) -> None:
    prepare_req, prepare_res, commit_req, commit_res, lease_req, lease_res, arm_req, arm_res, permit_req, permit_res = messages[start:base]
    links = (
        (messages[start - 1], "convergence_digest", prepare_req, "convergence_digest"),
        (prepare_res, "prepare_proof_digest", commit_req, "prepare_proof_digest"),
        (prepare_res, "prepare_id", commit_req, "prepare_id"),
        (commit_res, "capability_digest", lease_req, "capability_digest"),
        (commit_res, "capability_id", lease_req, "capability_id"),
        (lease_req, "lease_deadline_ms", lease_res, "lease_deadline_ms"),
        (lease_res, "lease_digest", arm_req, "lease_digest"),
        (lease_res, "lease_id", arm_req, "lease_id"),
        (arm_req, "watchdog_deadline_ms", arm_res, "watchdog_deadline_ms"),
        (lease_res, "lease_digest", permit_req, "lease_digest"),
        (lease_res, "lease_id", permit_req, "lease_id"),
        (lease_res, "lease_deadline_ms", permit_req, "lease_deadline_ms"),
        (arm_res, "watchdog_digest", permit_req, "watchdog_digest"),
        (arm_res, "watchdog_deadline_ms", permit_req, "watchdog_deadline_ms"),
        (permit_req, "watchdog_digest", permit_res, "watchdog_digest"),
    )
    for left, lk, right, rk in links:
        if left[lk] != right[rk]:
            raise WireError("authority lifecycle handoff")
    if not (
        _wire_int(lease_req, "message_time_ms") < _wire_int(lease_req, "lease_deadline_ms")
        and _wire_int(lease_res, "message_time_ms") < _wire_int(lease_res, "lease_deadline_ms")
        and _wire_int(arm_req, "message_time_ms") < _wire_int(arm_req, "watchdog_deadline_ms")
        and _wire_int(arm_res, "message_time_ms") < _wire_int(arm_res, "watchdog_deadline_ms")
        and _wire_int(permit_req, "message_time_ms") < _wire_int(permit_req, "lease_deadline_ms")
        and _wire_int(permit_req, "message_time_ms") < _wire_int(permit_req, "watchdog_deadline_ms")
        and _wire_int(permit_res, "message_time_ms") < _wire_int(permit_res, "permit_deadline_ms")
    ):
        raise WireError("expired authority lifecycle deadline")
    if _wire_int(permit_res, "permit_deadline_ms") > min(
        _wire_int(permit_req, "lease_deadline_ms"),
        _wire_int(permit_req, "watchdog_deadline_ms"),
    ):
        raise WireError("permit deadline widening")
    tail = messages[base:]
    if tail[0]["kind"] == "watchdog_terminal":
        fail_close_deadline = min(
            _wire_int(lease_res, "lease_deadline_ms"),
            _wire_int(permit_res, "permit_deadline_ms"),
            _wire_int(arm_res, "watchdog_deadline_ms"),
        )
        if (
            len(tail) != 2
            or tail[0]["watchdog_status"] not in {"STOP", "TIMEOUT"}
            or tail[0]["receipt_digest"] != ZERO
            or tail[0]["permit_digest"] != permit_res["permit_digest"]
            or tail[0]["permit_id"] != permit_res["permit_id"]
            or tail[0]["watchdog_digest"] != permit_res["watchdog_digest"]
            or tail[1]["permit_digest"] != permit_res["permit_digest"]
            or tail[1]["permit_id"] != permit_res["permit_id"]
            or tail[1]["receipt_digest"] != ZERO
            or tail[1]["watchdog_digest"] != tail[0]["watchdog_digest"]
            or tail[1]["decision"] != "BLOCK"
            or not denied
            or (
                tail[0]["message_time_ms"] != fail_close_deadline
                if tail[0]["watchdog_status"] == "TIMEOUT"
                else not _wire_int(permit_res, "message_time_ms")
                <= _wire_int(tail[0], "message_time_ms")
                <= fail_close_deadline
            )
            or not _wire_int(tail[0], "message_time_ms")
            <= _wire_int(tail[1], "message_time_ms")
            <= _wire_int(tail[0], "message_time_ms")
            + FAIL_CLOSE_RESULT_MAX_DELAY_MS
        ):
            raise WireError("invalid no-receipt fail-closed tail")
        return
    if len(tail) != 4:
        raise WireError("receipt tail incomplete")
    receipt, ack, terminal, result = tail
    if (
        receipt["permit_digest"] != permit_res["permit_digest"]
        or receipt["permit_id"] != permit_res["permit_id"]
        or receipt["watchdog_digest"] != permit_res["watchdog_digest"]
        or ack["permit_digest"] != permit_res["permit_digest"]
        or ack["permit_id"] != permit_res["permit_id"]
        or ack["receipt_digest"] != receipt["receipt_digest"]
        or ack["watchdog_digest"] != receipt["watchdog_digest"]
        or terminal["receipt_digest"] != receipt["receipt_digest"]
        or terminal["permit_digest"] != permit_res["permit_digest"]
        or terminal["permit_id"] != permit_res["permit_id"]
        or terminal["watchdog_digest"] != receipt["watchdog_digest"]
        or result["permit_digest"] != permit_res["permit_digest"]
        or result["permit_id"] != permit_res["permit_id"]
        or result["receipt_digest"] != receipt["receipt_digest"]
        or result["watchdog_digest"] != terminal["watchdog_digest"]
    ):
        raise WireError("receipt tail binding")
    if (
        not _wire_int(permit_res, "message_time_ms")
        <= _wire_int(receipt, "adapter_consumed_at_ms")
        < min(
            _wire_int(lease_res, "lease_deadline_ms"),
            _wire_int(permit_res, "permit_deadline_ms"),
            _wire_int(arm_res, "watchdog_deadline_ms"),
        )
        or _wire_int(receipt, "adapter_consumed_at_ms")
        > _wire_int(receipt, "message_time_ms")
        or _wire_int(receipt, "message_time_ms")
        >= min(
            _wire_int(lease_res, "lease_deadline_ms"),
            _wire_int(permit_res, "permit_deadline_ms"),
            _wire_int(arm_res, "watchdog_deadline_ms"),
        )
    ):
        raise WireError("adapter atomic consumption freshness")
    completion_deadline = min(
        _wire_int(lease_res, "lease_deadline_ms"),
        _wire_int(permit_res, "permit_deadline_ms"),
        _wire_int(arm_res, "watchdog_deadline_ms"),
    )
    if any(_wire_int(item, "message_time_ms") >= completion_deadline for item in (ack, terminal, result)):
        raise WireError("success/failure tail completion deadline")
    expected_consumption = adapter_consumption_digest(
        _wire_str(receipt, "durable_consumption_digest"),
        _wire_str(receipt, "permit_digest"),
        _wire_str(receipt, "effect_digest"),
        _wire_str(receipt, "adapter_digest"),
        _wire_int(receipt, "adapter_consumed_at_ms"),
        _wire_str(receipt, "effect_outcome"),
    )
    if receipt["adapter_consumption_digest"] != expected_consumption:
        raise WireError("adapter consumption derivation")
    expected_receipt = effect_receipt_digest(receipt)
    if receipt["receipt_digest"] != expected_receipt or receipt["receipt_digest"] == ZERO:
        raise WireError("effect receipt derivation")
    outcomes = {
        "SUCCEEDED": ("SUCCESS_RECORDED", "ACK", "HEALTHY", "ACK", False),
        "FAILED": ("FAILURE_RECORDED", "FAILURE_ACK", "STOP", "BLOCK", True),
        "UNKNOWN": ("UNKNOWN_BLOCKED", "FAILURE_ACK", "STOP", "BLOCK", True),
    }
    expected = outcomes[_wire_str(receipt, "effect_outcome")]
    if (ack["receipt_status"], ack["decision"], terminal["watchdog_status"], result["decision"], denied) != expected:
        raise WireError("effect/watchdog fail-closed semantics")


def _validate_structure(fields: Mapping[str, object], *, check_digest: bool) -> None:
    kind = fields.get("kind")
    if type(kind) is not str or kind not in _KINDS or set(fields) != _COMMON | _KINDS[kind]:
        raise WireError("kind or exact field set")
    for key, value in fields.items():
        if key in {"sequence", "authority_epoch"} or key in _TIME_FIELDS:
            if type(value) is not int or not 0 <= value <= MAX_SAFE_INTEGER:
                raise WireError("integer field")
        elif type(value) is not str or not value or any(ord(c) < 0x20 or ord(c) > 0x7E for c in value) or '"' in value or "\\" in value:
            raise WireError("string field")
    if not _is_wire_mapping(fields):
        raise WireError("wire field type")
    for key, value in fields.items():
        if (
            (key.endswith("_digest") and key not in _DIGEST_EXCEPTIONS)
            or key
            in {
                "challenge",
                "nonce",
                "signer_key_id",
                "trust_root_digest",
                "trust_registry_digest",
            }
        ) and (type(value) is not str or not _HEX128.fullmatch(value)):
            raise WireError(f"digest field {key}")
    for key in ("runtime_subject", "runtime_tree"):
        if not _HEX40_OR_128.fullmatch(_wire_str(fields, key)):
            raise WireError("runtime identity")
    if not _HEX32.fullmatch(_wire_str(fields, "traversal_id")) or not _HEX32.fullmatch(
        _wire_str(fields, "operation_id")
    ):
        raise WireError("operation identity")
    for key in ("prepare_id", "capability_id", "lease_id", "permit_id"):
        if key in fields and not _HEX32.fullmatch(_wire_str(fields, key)):
            raise WireError("artifact identity")
    if fields["protocol"] != PROTOCOL or fields["oracle_sha512"] != ORACLE_SHA512 or fields["mode"] not in {"MODE_1", "MODE_2", "MODE_3"}:
        raise WireError("protocol/oracle/mode")
    if fields["authority_class"] not in {"TEST_ONLY", "PRODUCTION_HSM", "PRODUCTION_TPM"}:
        raise WireError("authority class")
    if fields["authority_epoch"] == 0:
        raise WireError("authority epoch")
    if not _wire_int(fields, "not_before_ms") <= _wire_int(
        fields, "issued_at_ms"
    ) <= _wire_int(fields, "message_time_ms") < _wire_int(fields, "expires_at_ms"):
        raise WireError("message validity")
    if fields["signer_role"] != _ROLE_BY_KIND[kind]:
        raise WireError("kind/signer role")
    if fields["signer_key_class"] not in {"TEST_FIXTURE", "PRODUCTION_HSM", "PRODUCTION_TPM"} or fields["signature_algorithm"] not in {"TEST-SHA512", "ML-DSA-65", "ML-DSA-87"} or not _is_hex(_wire_str(fields, "signing_public_key_hex")) or not _is_hex(_wire_str(fields, "signature_hex")):
        raise WireError("signature structure")
    if hashlib.sha512(bytes.fromhex(_wire_str(fields, "signing_public_key_hex"))).hexdigest() != fields["signer_key_id"]:
        raise WireError("key ID derivation")
    if kind in {"branch_a_statement", "branch_b_statement"} and not _wire_int(
        fields, "not_before_ms"
    ) <= _wire_int(fields, "substantive_start_ms") < _wire_int(
        fields, "substantive_end_ms"
    ) <= _wire_int(fields, "message_time_ms"):
        raise WireError("branch substantive time")
    if kind in {"branch_a_statement", "branch_b_statement", "mode2_validator_certificate", "mode3_single_state_proof"}:
        if fields["projection_schema"] != "SBP-LEX-EXEC-PROJECTION/2" or fields["projection_digest"] != projection_digest(fields):
            raise WireError("projection derivation")
        if (fields["projection_request_digest"], fields["projection_state_digest"], fields["projection_effect_digest"], fields["projection_adapter_digest"]) != (fields["request_digest"], fields["state_digest"], fields["effect_digest"], fields["adapter_digest"]):
            raise WireError("projection execution binding")
    if (
        fields["extension_admission_mode"] != "EXTENSIONS_DISABLED"
        or fields["extension_schema"] != "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED"
        or fields["extension_configuration_digest"] == ZERO
        or fields["extension_admission_binding_digest"] == ZERO
    ):
        raise WireError("unsupported extension admission mode/schema")
    if "decision" in fields:
        allowed = {"receipt_ack": {"ACK", "FAILURE_ACK"}, "watchdog_result": {"ACK", "BLOCK"}}.get(kind, {"ALLOW", "DENY"})
        if fields["decision"] not in allowed or (fields["decision"] in {"ALLOW", "ACK"}) != (fields["error_code"] == "NONE"):
            raise WireError("decision/error semantics")
    elif fields["error_code"] != "NONE":
        raise WireError("non-result error")
    if check_digest and fields["transcript_digest"] != transcript_digest(fields):
        raise WireError("transcript digest")


def _parse_set(value: object) -> set[str]:
    if type(value) is not str or not value or value == "NONE":
        raise WireError("digest set")
    parts = value.split(",")
    if parts != sorted(set(parts)) or any(not _HEX128.fullmatch(item) for item in parts):
        raise WireError("noncanonical digest set")
    return set(parts)


def _check_rejections(removed: set[str], value: object) -> None:
    if type(value) is not str:
        raise WireError("rejection map")
    entries = value.split(",") if value != "NONE" else []
    parsed = {}
    for entry in entries:
        if "=" not in entry:
            raise WireError("rejection syntax")
        digest, reason = entry.split("=", 1)
        if not _HEX128.fullmatch(digest) or not _TOKEN.fullmatch(reason) or digest in parsed:
            raise WireError("rejection entry")
        parsed[digest] = reason
    if set(parsed) != removed or entries != sorted(entries):
        raise WireError("rejection coverage")


def _is_hex(value: object) -> bool:
    return type(value) is str and len(value) >= 2 and len(value) % 2 == 0 and all(c in "0123456789abcdef" for c in value)
