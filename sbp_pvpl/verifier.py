"""Strict offline verification and claim derivation for V2 PVPL."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Sequence

from .canonical import canonical_sha512, exact_fields, nonnegative_int, require_sha512
from .constants import (
    ADMISSION_STATE,
    CLAIM_RESULT,
    CLAIM_SCHEMA_ID,
    CLAIM_SCOPE,
    CLAIM_TEXT,
    CONTRACT_VERSION,
    EXTERNAL_PINS_SCHEMA_ID,
    HISTORY_SCHEMA_ID,
    LIMITATIONS,
    MAX_HISTORY_ITEMS,
    NO_AUTHORITY,
    PUBLICATION_STATE,
    RECEIPT_SCHEMA_ID,
    SOURCE_KINDS,
    SOURCE_OUTCOMES,
    SOURCE_RESULT_SCHEMA_ID,
    SOURCE_RESULT_SCHEMAS,
    VALIDATION_SCHEMA_ID,
)
from .errors import PVPLValidationError, reject


_SOURCE_FIELDS = {
    "schema_id",
    "contract_version",
    "source_kind",
    "source_result_schema_id",
    "source_result_sha512",
    "source_evidence_head_sha512",
    "source_history_sha512",
    "source_history_sequence",
    "source_current_head_sha512",
    "verification_outcome",
    "claim_scope",
    "admission_state",
    "runtime_attachment",
    "no_authority",
    "source_artifact_sha512",
}
_RECEIPT_FIELDS = {
    "schema_id",
    "contract_version",
    "receipt_kind",
    "source_kind",
    "verification_status",
    "verification_scope",
    "source_artifact_sha512",
    "source_result_sha512",
    "source_evidence_head_sha512",
    "source_history_sha512",
    "source_history_sequence",
    "source_current_head_sha512",
    "verifier_trust_root_sha512",
    "bindings_sha512",
    "receipt_sha512",
}
_RECEIPT_BINDING_FIELDS = {
    "source_kind",
    "source_artifact_sha512",
    "source_result_sha512",
    "source_evidence_head_sha512",
    "source_history_sha512",
    "source_history_sequence",
    "source_current_head_sha512",
    "verifier_trust_root_sha512",
}
_PIN_FIELDS = {
    "source_kind",
    "expected_source_artifact_sha512",
    "expected_receipt_sha512",
    "expected_verifier_trust_root_sha512",
    "expected_source_result_sha512",
    "expected_source_evidence_head_sha512",
    "expected_source_history_sha512",
    "minimum_source_history_sequence",
    "expected_source_current_head_sha512",
}
_PUBLICATION_HISTORY_PIN_FIELDS = {
    "expected_history_sha512",
    "expected_sequence",
    "expected_current_head_sha512",
}
_PINS_FIELDS = {
    "schema_id",
    "contract_version",
    "source_pins",
    "publication_history_pin",
    "pins_sha512",
}
_HISTORY_FIELDS = {
    "schema_id",
    "contract_version",
    "sequence",
    "current_head_sha512",
    "accepted_claim_sha512",
    "accepted_source_artifact_sha512",
    "accepted_receipt_sha512",
    "history_sha512",
}
_SOURCE_BINDING_FIELDS = {
    "source_kind",
    "source_artifact_sha512",
    "receipt_sha512",
    "source_result_sha512",
    "source_evidence_head_sha512",
    "source_history_sha512",
    "source_history_sequence",
    "source_current_head_sha512",
    "verifier_trust_root_sha512",
}
_CLAIM_FIELDS = {
    "schema_id",
    "contract_version",
    "result",
    "claim_text",
    "claim_scope",
    "admission_state",
    "publication_state",
    "source_bindings",
    "prior_publication_history_sha512",
    "prior_publication_sequence",
    "prior_publication_current_head_sha512",
    "no_authority",
    "limitations",
    "claim_sha512",
}

_FORBIDDEN_FIELD_FRAGMENTS = (
    "secret",
    "password",
    "passwd",
    "credential",
    "private_key",
    "public_key",
    "filesystem_path",
    "absolute_path",
    "repository_path",
    "username",
    "email",
    "ip_address",
    "hostname",
    "device_id",
    "user_identity",
    "subject_identity",
    "runtime_fingerprint",
    "os_fingerprint",
    "toolchain_fingerprint",
    "process_id",
    "environment_variable",
)
_WINDOWS_PATH = re.compile(r"(?i)^[a-z]:[\\/]")
_UNC_PATH = re.compile(r"^(?:\\\\|//)")
_EMAIL = re.compile(r"^[^\s/@]+@[^\s/@]+\.[^\s/@]+$")


def _reject_leakage(value: Any) -> None:
    """Reject any field outside the privacy-minimal digest/enumeration model."""

    if type(value) is dict:
        for key, item in value.items():
            lowered = key.casefold()
            if any(fragment in lowered for fragment in _FORBIDDEN_FIELD_FRAGMENTS):
                raise reject("REDACTION_PRIVACY_FIELD_REJECTED")
            _reject_leakage(item)
        return
    if type(value) is list:
        for item in value:
            _reject_leakage(item)
        return
    if type(value) is str and (
        _WINDOWS_PATH.search(value)
        or _UNC_PATH.search(value)
        or value.startswith("/")
        or _EMAIL.fullmatch(value)
        or "-----BEGIN " in value
    ):
        raise reject("REDACTION_PRIVACY_VALUE_REJECTED")


def _unsigned_digest(value: dict[str, Any], digest_field: str, code: str) -> None:
    observed = require_sha512(value[digest_field], f"{code}_DIGEST_INVALID")
    unsigned = {key: item for key, item in value.items() if key != digest_field}
    if observed != canonical_sha512(unsigned):
        raise reject(f"{code}_DIGEST_MISMATCH")


def _sha512_list(value: Any, *, code: str, expected_count: int | None = None) -> list[str]:
    if (
        type(value) is not list
        or len(value) > MAX_HISTORY_ITEMS
        or (expected_count is not None and len(value) != expected_count)
    ):
        raise reject(f"{code}_INVALID")
    result = [require_sha512(item, f"{code}_ITEM_INVALID") for item in value]
    if len(result) != len(set(result)):
        raise reject(f"{code}_DUPLICATE")
    return result


def validate_redacted_source_result(value: Any) -> dict[str, Any]:
    source = exact_fields(value, _SOURCE_FIELDS, "SOURCE_RESULT")
    _reject_leakage(source)
    kind = source["source_kind"]
    if (
        source["schema_id"] != SOURCE_RESULT_SCHEMA_ID
        or source["contract_version"] != CONTRACT_VERSION
        or kind not in SOURCE_KINDS
        or source["source_result_schema_id"] != SOURCE_RESULT_SCHEMAS.get(kind)
        or source["verification_outcome"] != SOURCE_OUTCOMES.get(kind)
        or source["claim_scope"] != CLAIM_SCOPE
        or source["admission_state"] != ADMISSION_STATE
        or source["runtime_attachment"] != "NONE"
        or source["no_authority"] != NO_AUTHORITY
    ):
        raise reject("SOURCE_RESULT_CONTRACT_INVALID")
    for field in (
        "source_result_sha512",
        "source_evidence_head_sha512",
        "source_history_sha512",
        "source_current_head_sha512",
    ):
        require_sha512(source[field], f"SOURCE_RESULT_{field.upper()}_INVALID")
    nonnegative_int(source["source_history_sequence"], "SOURCE_HISTORY_SEQUENCE_INVALID")
    _unsigned_digest(source, "source_artifact_sha512", "SOURCE_ARTIFACT")
    return source


def _receipt_bindings(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in sorted(_RECEIPT_BINDING_FIELDS)}


def validate_detached_receipt(value: Any) -> dict[str, Any]:
    receipt = exact_fields(value, _RECEIPT_FIELDS, "DETACHED_RECEIPT")
    _reject_leakage(receipt)
    if (
        receipt["schema_id"] != RECEIPT_SCHEMA_ID
        or receipt["contract_version"] != CONTRACT_VERSION
        or receipt["receipt_kind"] != "DETACHED_INDEPENDENT_VERIFICATION"
        or receipt["source_kind"] not in SOURCE_KINDS
        or receipt["verification_status"] != "VERIFIED"
        or receipt["verification_scope"]
        != "CANONICAL_SOURCE_RESULT_AND_REQUIRED_BINDINGS"
    ):
        raise reject("DETACHED_RECEIPT_CONTRACT_INVALID")
    for field in _RECEIPT_BINDING_FIELDS - {"source_kind", "source_history_sequence"}:
        require_sha512(receipt[field], f"DETACHED_RECEIPT_{field.upper()}_INVALID")
    nonnegative_int(receipt["source_history_sequence"], "RECEIPT_HISTORY_SEQUENCE_INVALID")
    require_sha512(receipt["bindings_sha512"], "RECEIPT_BINDINGS_DIGEST_INVALID")
    if receipt["bindings_sha512"] != canonical_sha512(_receipt_bindings(receipt)):
        raise reject("RECEIPT_BINDINGS_DIGEST_MISMATCH")
    _unsigned_digest(receipt, "receipt_sha512", "DETACHED_RECEIPT")
    return receipt


def validate_external_pins(value: Any) -> dict[str, Any]:
    pins = exact_fields(value, _PINS_FIELDS, "EXTERNAL_PINS")
    _reject_leakage(pins)
    if (
        pins["schema_id"] != EXTERNAL_PINS_SCHEMA_ID
        or pins["contract_version"] != CONTRACT_VERSION
        or type(pins["source_pins"]) is not list
        or len(pins["source_pins"]) != len(SOURCE_KINDS)
    ):
        raise reject("EXTERNAL_PINS_CONTRACT_INVALID")
    kinds: list[str] = []
    for item in pins["source_pins"]:
        pin = exact_fields(item, _PIN_FIELDS, "SOURCE_PIN")
        kind = pin["source_kind"]
        if kind not in SOURCE_KINDS:
            raise reject("SOURCE_PIN_KIND_INVALID")
        kinds.append(kind)
        for field in _PIN_FIELDS - {"source_kind", "minimum_source_history_sequence"}:
            require_sha512(pin[field], f"SOURCE_PIN_{field.upper()}_INVALID")
        nonnegative_int(
            pin["minimum_source_history_sequence"],
            "SOURCE_PIN_MINIMUM_SEQUENCE_INVALID",
        )
    if tuple(kinds) != SOURCE_KINDS:
        raise reject("SOURCE_PINS_ORDER_INVALID")
    publication_pin = exact_fields(
        pins["publication_history_pin"],
        _PUBLICATION_HISTORY_PIN_FIELDS,
        "PUBLICATION_HISTORY_PIN",
    )
    require_sha512(
        publication_pin["expected_history_sha512"],
        "PUBLICATION_HISTORY_PIN_DIGEST_INVALID",
    )
    require_sha512(
        publication_pin["expected_current_head_sha512"],
        "PUBLICATION_HISTORY_PIN_HEAD_INVALID",
    )
    nonnegative_int(
        publication_pin["expected_sequence"],
        "PUBLICATION_HISTORY_PIN_SEQUENCE_INVALID",
    )
    _unsigned_digest(pins, "pins_sha512", "EXTERNAL_PINS")
    return pins


def validate_accepted_history(value: Any) -> dict[str, Any]:
    history = exact_fields(value, _HISTORY_FIELDS, "ACCEPTED_HISTORY")
    _reject_leakage(history)
    if (
        history["schema_id"] != HISTORY_SCHEMA_ID
        or history["contract_version"] != CONTRACT_VERSION
    ):
        raise reject("ACCEPTED_HISTORY_CONTRACT_INVALID")
    sequence = nonnegative_int(history["sequence"], "ACCEPTED_HISTORY_SEQUENCE_INVALID")
    require_sha512(history["current_head_sha512"], "ACCEPTED_HISTORY_HEAD_INVALID")
    claims = _sha512_list(
        history["accepted_claim_sha512"],
        code="ACCEPTED_HISTORY_CLAIMS",
        expected_count=sequence,
    )
    source_artifacts = _sha512_list(
        history["accepted_source_artifact_sha512"],
        code="ACCEPTED_HISTORY_SOURCE_ARTIFACTS",
        expected_count=sequence * len(SOURCE_KINDS),
    )
    receipts = _sha512_list(
        history["accepted_receipt_sha512"],
        code="ACCEPTED_HISTORY_RECEIPTS",
        expected_count=sequence * len(SOURCE_KINDS),
    )
    if sequence == 0:
        if history["current_head_sha512"] != "0" * 128:
            raise reject("ACCEPTED_HISTORY_GENESIS_HEAD_INVALID")
    elif history["current_head_sha512"] != claims[-1]:
        raise reject("ACCEPTED_HISTORY_CURRENT_HEAD_INVALID")
    if len(source_artifacts) != len(receipts):
        raise reject("ACCEPTED_HISTORY_BINDING_COUNT_INVALID")
    _unsigned_digest(history, "history_sha512", "ACCEPTED_HISTORY")
    return history


def _validate_source_receipt_binding(
    source: dict[str, Any], receipt: dict[str, Any]
) -> None:
    for field in (
        "source_kind",
        "source_artifact_sha512",
        "source_result_sha512",
        "source_evidence_head_sha512",
        "source_history_sha512",
        "source_history_sequence",
        "source_current_head_sha512",
    ):
        if source[field] != receipt[field]:
            raise reject("SOURCE_RECEIPT_BINDING_MISMATCH")


def _validate_external_source_pin(
    source: dict[str, Any], receipt: dict[str, Any], pin: dict[str, Any]
) -> None:
    expected = {
        "expected_source_artifact_sha512": source["source_artifact_sha512"],
        "expected_receipt_sha512": receipt["receipt_sha512"],
        "expected_verifier_trust_root_sha512": receipt["verifier_trust_root_sha512"],
        "expected_source_result_sha512": source["source_result_sha512"],
        "expected_source_evidence_head_sha512": source["source_evidence_head_sha512"],
        "expected_source_history_sha512": source["source_history_sha512"],
        "expected_source_current_head_sha512": source["source_current_head_sha512"],
    }
    if pin["source_kind"] != source["source_kind"]:
        raise reject("SOURCE_PIN_KIND_MISMATCH")
    if any(pin[field] != observed for field, observed in expected.items()):
        raise reject("SOURCE_EXTERNAL_PIN_MISMATCH")
    if source["source_history_sequence"] < pin["minimum_source_history_sequence"]:
        raise reject("SOURCE_RESULT_STALE")


def _claim_binding(
    source: dict[str, Any], receipt: dict[str, Any]
) -> dict[str, Any]:
    return {
        "source_kind": source["source_kind"],
        "source_artifact_sha512": source["source_artifact_sha512"],
        "receipt_sha512": receipt["receipt_sha512"],
        "source_result_sha512": source["source_result_sha512"],
        "source_evidence_head_sha512": source["source_evidence_head_sha512"],
        "source_history_sha512": source["source_history_sha512"],
        "source_history_sequence": source["source_history_sequence"],
        "source_current_head_sha512": source["source_current_head_sha512"],
        "verifier_trust_root_sha512": receipt["verifier_trust_root_sha512"],
    }


def build_publication_claim(
    source_results: Sequence[Any],
    receipts: Sequence[Any],
    external_pins: Any,
    accepted_history: Any,
) -> dict[str, Any]:
    """Derive one non-activating, privacy-minimal claim from externally pinned inputs."""

    try:
        if type(source_results) not in {list, tuple} or len(source_results) != len(SOURCE_KINDS):
            raise reject("SOURCE_RESULT_SET_INVALID")
        if type(receipts) not in {list, tuple} or len(receipts) != len(SOURCE_KINDS):
            raise reject("RECEIPT_SET_INVALID")
        sources = [validate_redacted_source_result(item) for item in source_results]
        checked_receipts = [validate_detached_receipt(item) for item in receipts]
        pins = validate_external_pins(external_pins)
        history = validate_accepted_history(accepted_history)
        if tuple(item["source_kind"] for item in sources) != SOURCE_KINDS:
            raise reject("SOURCE_RESULTS_ORDER_INVALID")
        if tuple(item["source_kind"] for item in checked_receipts) != SOURCE_KINDS:
            raise reject("RECEIPTS_ORDER_INVALID")

        publication_pin = pins["publication_history_pin"]
        if (
            history["history_sha512"] != publication_pin["expected_history_sha512"]
            or history["sequence"] != publication_pin["expected_sequence"]
            or history["current_head_sha512"]
            != publication_pin["expected_current_head_sha512"]
        ):
            raise reject("PUBLICATION_HISTORY_ROLLBACK_OR_PIN_MISMATCH")

        bindings: list[dict[str, Any]] = []
        accepted_sources = set(history["accepted_source_artifact_sha512"])
        accepted_receipts = set(history["accepted_receipt_sha512"])
        for source, receipt, pin in zip(sources, checked_receipts, pins["source_pins"]):
            _validate_source_receipt_binding(source, receipt)
            _validate_external_source_pin(source, receipt, pin)
            if source["source_artifact_sha512"] in accepted_sources:
                raise reject("SOURCE_RESULT_REPLAYED")
            if receipt["receipt_sha512"] in accepted_receipts:
                raise reject("DETACHED_RECEIPT_REPLAYED")
            bindings.append(_claim_binding(source, receipt))

        unsigned = {
            "schema_id": CLAIM_SCHEMA_ID,
            "contract_version": CONTRACT_VERSION,
            "result": CLAIM_RESULT,
            "claim_text": CLAIM_TEXT,
            "claim_scope": CLAIM_SCOPE,
            "admission_state": ADMISSION_STATE,
            "publication_state": PUBLICATION_STATE,
            "source_bindings": bindings,
            "prior_publication_history_sha512": history["history_sha512"],
            "prior_publication_sequence": history["sequence"],
            "prior_publication_current_head_sha512": history["current_head_sha512"],
            "no_authority": deepcopy(NO_AUTHORITY),
            "limitations": list(LIMITATIONS),
        }
        claim = {**unsigned, "claim_sha512": canonical_sha512(unsigned)}
        if claim["claim_sha512"] in set(history["accepted_claim_sha512"]):
            raise reject("PUBLICATION_CLAIM_REPLAYED")
        return validate_publication_claim(claim)
    except PVPLValidationError:
        raise
    except (Exception, MemoryError) as exc:
        raise reject(f"PVPL_FAIL_CLOSED:{type(exc).__name__}") from exc


def validate_publication_claim(value: Any) -> dict[str, Any]:
    claim = exact_fields(value, _CLAIM_FIELDS, "PUBLICATION_CLAIM")
    _reject_leakage(claim)
    if (
        claim["schema_id"] != CLAIM_SCHEMA_ID
        or claim["contract_version"] != CONTRACT_VERSION
        or claim["result"] != CLAIM_RESULT
        or claim["claim_text"] != CLAIM_TEXT
        or claim["claim_scope"] != CLAIM_SCOPE
        or claim["admission_state"] != ADMISSION_STATE
        or claim["publication_state"] != PUBLICATION_STATE
        or claim["no_authority"] != NO_AUTHORITY
        or claim["limitations"] != list(LIMITATIONS)
        or type(claim["source_bindings"]) is not list
        or len(claim["source_bindings"]) != len(SOURCE_KINDS)
    ):
        raise reject("PUBLICATION_CLAIM_CONTRACT_INVALID")
    kinds: list[str] = []
    for item in claim["source_bindings"]:
        binding = exact_fields(item, _SOURCE_BINDING_FIELDS, "PUBLICATION_SOURCE_BINDING")
        kinds.append(binding["source_kind"])
        for field in _SOURCE_BINDING_FIELDS - {"source_kind", "source_history_sequence"}:
            require_sha512(binding[field], f"PUBLICATION_BINDING_{field.upper()}_INVALID")
        nonnegative_int(
            binding["source_history_sequence"],
            "PUBLICATION_BINDING_SEQUENCE_INVALID",
        )
    if tuple(kinds) != SOURCE_KINDS:
        raise reject("PUBLICATION_SOURCE_BINDINGS_ORDER_INVALID")
    require_sha512(
        claim["prior_publication_history_sha512"],
        "PUBLICATION_PRIOR_HISTORY_DIGEST_INVALID",
    )
    require_sha512(
        claim["prior_publication_current_head_sha512"],
        "PUBLICATION_PRIOR_HEAD_INVALID",
    )
    nonnegative_int(claim["prior_publication_sequence"], "PUBLICATION_PRIOR_SEQUENCE_INVALID")
    _unsigned_digest(claim, "claim_sha512", "PUBLICATION_CLAIM")
    return claim


def validation_report(claim: Any) -> dict[str, Any]:
    checked = validate_publication_claim(claim)
    unsigned = {
        "schema_id": VALIDATION_SCHEMA_ID,
        "contract_version": CONTRACT_VERSION,
        "status": "PASS",
        "claim_sha512": checked["claim_sha512"],
        "admission_state": ADMISSION_STATE,
        "publication_state": PUBLICATION_STATE,
        "no_authority": deepcopy(NO_AUTHORITY),
    }
    return {**unsigned, "report_sha512": canonical_sha512(unsigned)}


__all__ = [
    "build_publication_claim",
    "validate_accepted_history",
    "validate_detached_receipt",
    "validate_external_pins",
    "validate_publication_claim",
    "validate_redacted_source_result",
    "validation_report",
]
