"""Preparation-only history inputs that cannot grant trust or admission.

The functions in this module create unsigned, canonical documents for later
owner and independently operated production actions.  They never create a
live accepted-package history, sign a document, or treat a digest carried by
an artifact as an independent pin.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from sbp_ptde.canonical import (
    canonical_json_document_bytes,
    canonical_sha512,
    exact_fields,
    identifier,
    require_sha512,
)
from sbp_ptde.constants import NO_AUTHORITY as PTDE_NO_AUTHORITY
from sbp_ptde.errors import reject
from sbp_ptde.preparation import (
    read_canonical_document_file,
    write_canonical_document_exclusive,
)
from sbp_ptde.trust import (
    GENESIS_SHA512,
    AcceptedAttemptHistory,
    accepted_attempt_history_from_document,
)

from .constants import (
    ACCEPTED_HISTORY_SCHEMA,
    GENESIS,
    HISTORY_SIGNING_PURPOSE,
    PRODUCTION,
)
from .constants import (
    NO_AUTHORITY as LOCAL_NO_AUTHORITY,
)
from .digests import digest_equal, is_sha512
from .signing import (
    PRODUCTION_DUAL_CUSTODY_CLASS,
    HybridVerificationContext,
    LocalTrustSignatureError,
    verification_context_from_record,
)

PTDE_HISTORY_PREPARATION_SCHEMA = (
    "sbp.lex.v2.history-input-preparation.ptde-genesis/1"
)
PRODUCTION_CUSTODY_METADATA_SCHEMA = (
    "sbp.lex.v2.local-trust.production-history-custody-metadata/1"
)
LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA = (
    "sbp.lex.v2.local-trust.accepted-package-history-genesis-signing-request/1"
)

OWNER_ACTION_REQUIRED = "OWNER_ACTION_REQUIRED"
NOT_INDEPENDENTLY_PINNED = "NOT_INDEPENDENTLY_PINNED"
NOT_ADMITTED = "NOT_ADMITTED"
UNSIGNED = "UNSIGNED"
EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED = "EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED"
NOT_A_VALID_HISTORY = "NOT_A_VALID_HISTORY"

_MAX_OWNER_IDENTIFIER_BYTES = 255
_PTDE_PREPARATION_FIELDS = {
    "schema_id",
    "preparation_state",
    "pin_state",
    "signature_state",
    "admission_state",
    "accepted_attempt_history",
    "accepted_attempt_history_sha512",
    "no_authority",
}
_CUSTODY_METADATA_FIELDS = {
    "schema_id",
    "verification_context_sha512",
    "custody_class",
    "dual_custody_admission_sha512",
    "mldsa87_custody",
    "ed448_custody",
    "no_authority",
}
_UNSIGNED_HISTORY_FIELDS = {
    "schema_id",
    "repository_identity_digest",
    "history_id",
    "sequence",
    "prior_history_digest",
    "live_head_digest",
    "records",
    "status",
    "no_authority",
}
_SIGNING_REQUEST_FIELDS = {
    "schema_id",
    "request_state",
    "signature_state",
    "history_validation_state",
    "admission_state",
    "repository_identity_digest",
    "history_id",
    "signing_purpose",
    "owner_pinned_verification_context_sha512",
    "verification_context",
    "owner_pinned_production_custody_metadata_sha512",
    "production_custody_metadata",
    "unsigned_history",
    "unsigned_history_sha512",
    "owner_action_required",
    "no_authority",
    "request_sha512",
}
_LANE_CUSTODY_FIELDS = {
    "algorithm",
    "provider_id",
    "key_id",
    "key_version",
    "key_epoch",
    "rotation_epoch",
    "custody_class",
    "custody_reference",
    "signer_class",
    "lifecycle_status",
    "revoked_at_epoch",
    "external_custody_admitted",
    "custody_admission_sha512",
    "non_exportable",
}
_FORBIDDEN_SOFTWARE_MARKERS = (
    "TEST_ONLY",
    "SOFTWARE",
    "PROCESS_MEMORY",
    "PROCESS-MEMORY",
    "IN_MEMORY",
    "IN-MEMORY",
)


def _owner_identifier(value: Any, *, code: str) -> str:
    checked = identifier(value, code=code)
    if (
        len(checked.encode("utf-8", errors="strict"))
        > _MAX_OWNER_IDENTIFIER_BYTES
        or _contains_forbidden_software_marker(checked)
    ):
        raise reject(code)
    return checked


def _contains_forbidden_software_marker(value: object) -> bool:
    if type(value) is not str:
        return False
    upper = value.upper()
    return any(marker in upper for marker in _FORBIDDEN_SOFTWARE_MARKERS)


def _validate_lane_custody(
    value: Any,
    *,
    algorithm: str,
    custody_class: str,
    code: str,
) -> dict[str, Any]:
    lane = exact_fields(value, _LANE_CUSTODY_FIELDS, code=code)
    if (
        lane["algorithm"] != algorithm
        or lane["custody_class"] != custody_class
        or lane["signer_class"] != PRODUCTION
        or lane["lifecycle_status"] != "ACTIVE"
        or lane["revoked_at_epoch"] is not None
        or lane["external_custody_admitted"] is not True
        or lane["non_exportable"] is not True
        or not is_sha512(lane["key_id"])
        or not is_sha512(lane["custody_admission_sha512"])
        or any(
            _contains_forbidden_software_marker(lane[field])
            for field in (
                "provider_id",
                "key_version",
                "custody_class",
                "custody_reference",
                "signer_class",
            )
        )
    ):
        raise reject(f"{code}_INVALID")
    return lane


def prepare_ptde_genesis_history(history_id: str) -> dict[str, Any]:
    """Build an unsigned sequence-zero snapshot with no independent pin claim."""

    checked_history_id = _owner_identifier(
        history_id, code="HISTORY_PREPARATION_PTDE_HISTORY_ID_INVALID"
    )
    history = AcceptedAttemptHistory(
        history_id=checked_history_id,
        sequence=0,
        prior_history_sha512=GENESIS_SHA512,
        records=(),
    )
    document = {
        "schema_id": PTDE_HISTORY_PREPARATION_SCHEMA,
        "preparation_state": OWNER_ACTION_REQUIRED,
        "pin_state": NOT_INDEPENDENTLY_PINNED,
        "signature_state": UNSIGNED,
        "admission_state": NOT_ADMITTED,
        "accepted_attempt_history": history.as_dict(),
        "accepted_attempt_history_sha512": history.sha512(),
        "no_authority": dict(PTDE_NO_AUTHORITY),
    }
    return validate_ptde_genesis_preparation(document)


def validate_ptde_genesis_preparation(value: Any) -> dict[str, Any]:
    """Validate the exact non-authorizing PTDE preparation envelope."""

    packet = exact_fields(
        value, _PTDE_PREPARATION_FIELDS, code="HISTORY_PREPARATION_PTDE"
    )
    if (
        packet["schema_id"] != PTDE_HISTORY_PREPARATION_SCHEMA
        or packet["preparation_state"] != OWNER_ACTION_REQUIRED
        or packet["pin_state"] != NOT_INDEPENDENTLY_PINNED
        or packet["signature_state"] != UNSIGNED
        or packet["admission_state"] != NOT_ADMITTED
        or packet["no_authority"] != PTDE_NO_AUTHORITY
    ):
        raise reject("HISTORY_PREPARATION_PTDE_CONTRACT_INVALID")
    snapshot = packet["accepted_attempt_history"]
    if type(snapshot) is not dict:
        raise reject("HISTORY_PREPARATION_PTDE_SNAPSHOT_INVALID")
    history = accepted_attempt_history_from_document(
        canonical_json_document_bytes(snapshot)
    )
    _owner_identifier(
        history.history_id, code="HISTORY_PREPARATION_PTDE_HISTORY_ID_INVALID"
    )
    if (
        history.sequence != 0
        or history.prior_history_sha512 != GENESIS_SHA512
        or history.records != ()
        or not digest_equal(
            history.sha512(),
            require_sha512(
                packet["accepted_attempt_history_sha512"],
                "HISTORY_PREPARATION_PTDE_DIGEST_INVALID",
            ),
        )
    ):
        raise reject("HISTORY_PREPARATION_PTDE_GENESIS_INVALID")
    return deepcopy(packet)


def _validate_production_context(
    record: Any,
    *,
    owner_pinned_context_sha512: str,
) -> tuple[HybridVerificationContext, dict[str, Any]]:
    owner_pin = require_sha512(
        owner_pinned_context_sha512,
        "HISTORY_PREPARATION_CONTEXT_OWNER_PIN_INVALID",
    )
    try:
        context = verification_context_from_record(
            record,
            owner_pinned_context_digest=owner_pin,
            allow_test_only=False,
        )
    except LocalTrustSignatureError as exc:
        raise reject("HISTORY_PREPARATION_CONTEXT_INVALID") from exc
    public_record = context.public_record()
    if (
        context.signer_class != PRODUCTION
        or context.purpose != HISTORY_SIGNING_PURPOSE
        or context.custody_class != PRODUCTION_DUAL_CUSTODY_CLASS
        or context.allow_test_only
        or public_record["software_custody_limitation"] is not False
        or public_record["external_custody_required"] is not True
        or any(
            _contains_forbidden_software_marker(public_record[field])
            for field in (
                "context_id",
                "provider_id",
                "key_id",
                "custody_class",
                "signer_class",
            )
        )
    ):
        raise reject("HISTORY_PREPARATION_PRODUCTION_CONTEXT_REQUIRED")
    ml = _validate_lane_custody(
        public_record["mldsa87_custody"],
        algorithm="ML-DSA-87",
        custody_class="EXTERNAL_NON_EXPORTABLE_ML_DSA_87",
        code="HISTORY_PREPARATION_MLDSA87_CUSTODY",
    )
    ed = _validate_lane_custody(
        public_record["ed448_custody"],
        algorithm="Ed448",
        custody_class="EXTERNAL_NON_EXPORTABLE_ED448",
        code="HISTORY_PREPARATION_ED448_CUSTODY",
    )
    if (
        ml["provider_id"] == ed["provider_id"]
        or ml["key_id"] == ed["key_id"]
        or ml["custody_reference"] == ed["custody_reference"]
        or ml["custody_admission_sha512"] == ed["custody_admission_sha512"]
        or context.mldsa87_fingerprint == context.ed448_fingerprint
    ):
        raise reject("HISTORY_PREPARATION_COPIED_LANE_TRUST_MATERIAL")
    return context, public_record


def validate_production_custody_metadata(
    value: Any,
    *,
    verification_context_record: Mapping[str, Any],
    owner_pinned_verification_context_sha512: str,
    owner_pinned_production_custody_metadata_sha512: str,
) -> dict[str, Any]:
    """Validate separately owner-pinned custody metadata against the context."""

    if type(verification_context_record) is not dict:
        raise reject("HISTORY_PREPARATION_CONTEXT_INVALID")
    metadata = exact_fields(
        value,
        _CUSTODY_METADATA_FIELDS,
        code="HISTORY_PREPARATION_CUSTODY_METADATA",
    )
    context, public_record = _validate_production_context(
        dict(verification_context_record),
        owner_pinned_context_sha512=owner_pinned_verification_context_sha512,
    )
    custody_pin = require_sha512(
        owner_pinned_production_custody_metadata_sha512,
        "HISTORY_PREPARATION_CUSTODY_OWNER_PIN_INVALID",
    )
    calculated_custody_digest = canonical_sha512(metadata)
    if (
        not digest_equal(calculated_custody_digest, custody_pin)
        or metadata["schema_id"] != PRODUCTION_CUSTODY_METADATA_SCHEMA
        or metadata["verification_context_sha512"] != context.context_digest
        or metadata["custody_class"] != context.custody_class
        or metadata["dual_custody_admission_sha512"]
        != context.dual_custody_admission_sha512
        or metadata["mldsa87_custody"] != public_record["mldsa87_custody"]
        or metadata["ed448_custody"] != public_record["ed448_custody"]
        or metadata["no_authority"] != LOCAL_NO_AUTHORITY
    ):
        raise reject("HISTORY_PREPARATION_CUSTODY_METADATA_MISMATCH")
    ml = _validate_lane_custody(
        metadata["mldsa87_custody"],
        algorithm="ML-DSA-87",
        custody_class="EXTERNAL_NON_EXPORTABLE_ML_DSA_87",
        code="HISTORY_PREPARATION_MLDSA87_CUSTODY",
    )
    ed = _validate_lane_custody(
        metadata["ed448_custody"],
        algorithm="Ed448",
        custody_class="EXTERNAL_NON_EXPORTABLE_ED448",
        code="HISTORY_PREPARATION_ED448_CUSTODY",
    )
    independent_values = {
        owner_pinned_verification_context_sha512,
        custody_pin,
        context.dual_custody_admission_sha512,
        ml["custody_admission_sha512"],
        ed["custody_admission_sha512"],
        ml["key_id"],
        ed["key_id"],
    }
    if len(independent_values) != 7:
        raise reject("HISTORY_PREPARATION_TRUST_PINS_NOT_INDEPENDENT")
    return deepcopy(metadata)


def _unsigned_history(
    *, repository_identity_digest: str, history_id: str
) -> dict[str, Any]:
    return {
        "schema_id": ACCEPTED_HISTORY_SCHEMA,
        "repository_identity_digest": repository_identity_digest,
        "history_id": history_id,
        "sequence": 0,
        "prior_history_digest": GENESIS,
        "live_head_digest": GENESIS,
        "records": [],
        "status": "CURRENT_LIVE_HEAD",
        "no_authority": dict(LOCAL_NO_AUTHORITY),
    }


def _request_digest(packet: Mapping[str, Any]) -> str:
    unsigned_packet = dict(packet)
    unsigned_packet.pop("request_sha512", None)
    return canonical_sha512(unsigned_packet)


def prepare_local_trust_genesis_signing_request(
    *,
    repository_identity_digest: str,
    history_id: str,
    verification_context_record: Mapping[str, Any],
    owner_pinned_verification_context_sha512: str,
    production_custody_metadata: Mapping[str, Any],
    owner_pinned_production_custody_metadata_sha512: str,
) -> dict[str, Any]:
    """Build an unsigned external-production signing request, never a history."""

    repository_digest = require_sha512(
        repository_identity_digest,
        "HISTORY_PREPARATION_REPOSITORY_IDENTITY_INVALID",
    )
    checked_history_id = _owner_identifier(
        history_id, code="HISTORY_PREPARATION_LOCAL_HISTORY_ID_INVALID"
    )
    if (
        type(verification_context_record) is not dict
        or type(production_custody_metadata) is not dict
    ):
        raise reject("HISTORY_PREPARATION_LOCAL_TRUST_INPUT_INVALID")
    context_record = dict(verification_context_record)
    context, public_record = _validate_production_context(
        context_record,
        owner_pinned_context_sha512=owner_pinned_verification_context_sha512,
    )
    custody_record = validate_production_custody_metadata(
        dict(production_custody_metadata),
        verification_context_record=context_record,
        owner_pinned_verification_context_sha512=(
            owner_pinned_verification_context_sha512
        ),
        owner_pinned_production_custody_metadata_sha512=(
            owner_pinned_production_custody_metadata_sha512
        ),
    )
    ml_custody = public_record["mldsa87_custody"]
    ed_custody = public_record["ed448_custody"]
    if repository_digest in {
        owner_pinned_verification_context_sha512,
        owner_pinned_production_custody_metadata_sha512,
        context.dual_custody_admission_sha512,
        ml_custody["custody_admission_sha512"],
        ed_custody["custody_admission_sha512"],
        ml_custody["key_id"],
        ed_custody["key_id"],
    }:
        raise reject("HISTORY_PREPARATION_REPOSITORY_IDENTITY_NOT_INDEPENDENT")
    unsigned_history = _unsigned_history(
        repository_identity_digest=repository_digest,
        history_id=checked_history_id,
    )
    packet: dict[str, Any] = {
        "schema_id": LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA,
        "request_state": EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED,
        "signature_state": UNSIGNED,
        "history_validation_state": NOT_A_VALID_HISTORY,
        "admission_state": NOT_ADMITTED,
        "repository_identity_digest": repository_digest,
        "history_id": checked_history_id,
        "signing_purpose": HISTORY_SIGNING_PURPOSE,
        "owner_pinned_verification_context_sha512": (
            owner_pinned_verification_context_sha512
        ),
        "verification_context": context_record,
        "owner_pinned_production_custody_metadata_sha512": (
            owner_pinned_production_custody_metadata_sha512
        ),
        "production_custody_metadata": custody_record,
        "unsigned_history": unsigned_history,
        "unsigned_history_sha512": canonical_sha512(unsigned_history),
        "owner_action_required": (
            "SUBMIT_UNSIGNED_HISTORY_TO_INDEPENDENT_EXTERNAL_PRODUCTION_SIGNER_"
            "THEN_INDEPENDENTLY_VALIDATE_AND_PIN_RESULT"
        ),
        "no_authority": dict(LOCAL_NO_AUTHORITY),
    }
    packet["request_sha512"] = _request_digest(packet)
    return validate_local_trust_genesis_signing_request(packet)


def prepare_local_trust_genesis_signing_request_from_files(
    *,
    repository_identity_digest: str,
    history_id: str,
    verification_context_path: str | Path,
    owner_pinned_verification_context_sha512: str,
    production_custody_metadata_path: str | Path,
    owner_pinned_production_custody_metadata_sha512: str,
) -> dict[str, Any]:
    """Stable-read exact public inputs and build the unsigned request packet."""

    context_record = read_canonical_document_file(
        verification_context_path,
        code="HISTORY_PREPARATION_VERIFICATION_CONTEXT",
    )
    custody_record = read_canonical_document_file(
        production_custody_metadata_path,
        code="HISTORY_PREPARATION_PRODUCTION_CUSTODY",
    )
    return prepare_local_trust_genesis_signing_request(
        repository_identity_digest=repository_identity_digest,
        history_id=history_id,
        verification_context_record=context_record,
        owner_pinned_verification_context_sha512=(
            owner_pinned_verification_context_sha512
        ),
        production_custody_metadata=custody_record,
        owner_pinned_production_custody_metadata_sha512=(
            owner_pinned_production_custody_metadata_sha512
        ),
    )


def validate_local_trust_genesis_signing_request(value: Any) -> dict[str, Any]:
    """Validate exact shape, pins and fixed no-authority preparation states."""

    packet = exact_fields(
        value,
        _SIGNING_REQUEST_FIELDS,
        code="HISTORY_PREPARATION_LOCAL_SIGNING_REQUEST",
    )
    if (
        packet["schema_id"] != LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA
        or packet["request_state"] != EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED
        or packet["signature_state"] != UNSIGNED
        or packet["history_validation_state"] != NOT_A_VALID_HISTORY
        or packet["admission_state"] != NOT_ADMITTED
        or packet["signing_purpose"] != HISTORY_SIGNING_PURPOSE
        or packet["owner_action_required"]
        != (
            "SUBMIT_UNSIGNED_HISTORY_TO_INDEPENDENT_EXTERNAL_PRODUCTION_SIGNER_"
            "THEN_INDEPENDENTLY_VALIDATE_AND_PIN_RESULT"
        )
        or packet["no_authority"] != LOCAL_NO_AUTHORITY
    ):
        raise reject("HISTORY_PREPARATION_LOCAL_REQUEST_CONTRACT_INVALID")
    repository_digest = require_sha512(
        packet["repository_identity_digest"],
        "HISTORY_PREPARATION_REPOSITORY_IDENTITY_INVALID",
    )
    checked_history_id = _owner_identifier(
        packet["history_id"],
        code="HISTORY_PREPARATION_LOCAL_HISTORY_ID_INVALID",
    )
    context_record = packet["verification_context"]
    custody_record = packet["production_custody_metadata"]
    if type(context_record) is not dict or type(custody_record) is not dict:
        raise reject("HISTORY_PREPARATION_LOCAL_TRUST_INPUT_INVALID")
    context, public_record = _validate_production_context(
        context_record,
        owner_pinned_context_sha512=packet[
            "owner_pinned_verification_context_sha512"
        ],
    )
    validate_production_custody_metadata(
        custody_record,
        verification_context_record=context_record,
        owner_pinned_verification_context_sha512=packet[
            "owner_pinned_verification_context_sha512"
        ],
        owner_pinned_production_custody_metadata_sha512=packet[
            "owner_pinned_production_custody_metadata_sha512"
        ],
    )
    ml_custody = public_record["mldsa87_custody"]
    ed_custody = public_record["ed448_custody"]
    if repository_digest in {
        packet["owner_pinned_verification_context_sha512"],
        packet["owner_pinned_production_custody_metadata_sha512"],
        context.dual_custody_admission_sha512,
        ml_custody["custody_admission_sha512"],
        ed_custody["custody_admission_sha512"],
        ml_custody["key_id"],
        ed_custody["key_id"],
    }:
        raise reject("HISTORY_PREPARATION_REPOSITORY_IDENTITY_NOT_INDEPENDENT")
    unsigned_history = exact_fields(
        packet["unsigned_history"],
        _UNSIGNED_HISTORY_FIELDS,
        code="HISTORY_PREPARATION_UNSIGNED_HISTORY",
    )
    expected_unsigned = _unsigned_history(
        repository_identity_digest=repository_digest,
        history_id=checked_history_id,
    )
    if (
        unsigned_history != expected_unsigned
        or not digest_equal(
            canonical_sha512(unsigned_history),
            require_sha512(
                packet["unsigned_history_sha512"],
                "HISTORY_PREPARATION_UNSIGNED_HISTORY_DIGEST_INVALID",
            ),
        )
        or not digest_equal(
            _request_digest(packet),
            require_sha512(
                packet["request_sha512"],
                "HISTORY_PREPARATION_REQUEST_DIGEST_INVALID",
            ),
        )
    ):
        raise reject("HISTORY_PREPARATION_LOCAL_REQUEST_BINDING_INVALID")
    return deepcopy(packet)


def write_history_preparation_document_exclusive(
    document: Mapping[str, Any], output_path: str | Path
) -> str:
    """Validate and exclusively persist one preparation-only document."""

    candidate = dict(document)
    schema = candidate.get("schema_id")
    if schema == PTDE_HISTORY_PREPARATION_SCHEMA:
        validated = validate_ptde_genesis_preparation(candidate)
    elif schema == LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA:
        validated = validate_local_trust_genesis_signing_request(candidate)
    else:
        raise reject("HISTORY_PREPARATION_OUTPUT_SCHEMA_INVALID")
    return write_canonical_document_exclusive(validated, output_path)


__all__ = [
    "EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED",
    "LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA",
    "NOT_ADMITTED",
    "NOT_A_VALID_HISTORY",
    "NOT_INDEPENDENTLY_PINNED",
    "OWNER_ACTION_REQUIRED",
    "PRODUCTION_CUSTODY_METADATA_SCHEMA",
    "PTDE_HISTORY_PREPARATION_SCHEMA",
    "UNSIGNED",
    "prepare_local_trust_genesis_signing_request",
    "prepare_local_trust_genesis_signing_request_from_files",
    "prepare_ptde_genesis_history",
    "validate_local_trust_genesis_signing_request",
    "validate_production_custody_metadata",
    "validate_ptde_genesis_preparation",
    "write_history_preparation_document_exclusive",
]
