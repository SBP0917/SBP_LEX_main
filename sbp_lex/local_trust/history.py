"""Independently signed accepted-package history and live-head contract."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from typing import Any

from .constants import (
    ACCEPTED_HISTORY_SCHEMA,
    GENESIS,
    HISTORY_SIGNING_PURPOSE,
    NO_AUTHORITY,
)
from .digests import digest, digest_equal, is_sha512
from .signing import (
    HybridSigningContext,
    HybridVerificationContext,
    sign_hybrid,
    verify_hybrid,
)


class AcceptedHistoryError(ValueError):
    pass


_RECORD_FIELDS = {
    "acceptance_sequence",
    "package_digest",
    "chain_head_digest",
    "time_head_digest",
    "prior_package_digest",
    "prior_record_digest",
    "replay_id",
    "record_digest",
    "no_authority",
}
_UNSIGNED_FIELDS = {
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
_HISTORY_FIELDS = _UNSIGNED_FIELDS | {"signatures", "history_digest"}


def _record(
    *,
    sequence: int,
    package_digest: object,
    chain_head_digest: object,
    time_head_digest: object,
    prior_package_digest: object,
    prior_record_digest: object,
) -> dict[str, Any]:
    for digest_value in (package_digest, chain_head_digest, time_head_digest):
        if not is_sha512(digest_value):
            raise AcceptedHistoryError("accepted_record_digest_invalid")
    if prior_package_digest != GENESIS and not is_sha512(prior_package_digest):
        raise AcceptedHistoryError("accepted_record_predecessor_invalid")
    if prior_record_digest != GENESIS and not is_sha512(prior_record_digest):
        raise AcceptedHistoryError("accepted_record_chain_invalid")
    replay_id = digest(
        {
            "acceptance_sequence": sequence,
            "package_digest": package_digest,
            "prior_package_digest": prior_package_digest,
            "prior_record_digest": prior_record_digest,
        }
    )
    value = {
        "acceptance_sequence": sequence,
        "package_digest": package_digest,
        "chain_head_digest": chain_head_digest,
        "time_head_digest": time_head_digest,
        "prior_package_digest": prior_package_digest,
        "prior_record_digest": prior_record_digest,
        "replay_id": replay_id,
        "no_authority": dict(NO_AUTHORITY),
    }
    value["record_digest"] = digest(value)
    return value


def build_accepted_history_genesis(
    *,
    repository_identity_digest: str,
    history_id: str,
    signer: HybridSigningContext,
) -> dict[str, Any]:
    return _build_history(
        repository_identity_digest=repository_identity_digest,
        history_id=history_id,
        sequence=0,
        prior_history_digest=GENESIS,
        records=[],
        signer=signer,
    )


def advance_accepted_package_history(
    prior_history: Mapping[str, Any],
    *,
    package_digest: str,
    chain_head_digest: str,
    time_head_digest: str,
    signer: HybridSigningContext,
    prior_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    expected_prior_history_digest: str,
) -> dict[str, Any]:
    if type(prior_history) is not dict:
        raise AcceptedHistoryError("prior_history_invalid")
    sequence = prior_history.get("sequence")
    records = prior_history.get("records")
    if type(sequence) is not int or sequence < 0 or type(records) is not list:
        raise AcceptedHistoryError("prior_history_invalid")
    prior_validation = validate_accepted_package_history(
        prior_history,
        repository_identity_digest=str(prior_history.get("repository_identity_digest")),
        trust_context=prior_trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_history_digest=expected_prior_history_digest,
        minimum_sequence=sequence,
    )
    if prior_validation["status"] != "PASS":
        raise AcceptedHistoryError("prior_history_not_current_or_valid")
    prior_package = records[-1]["package_digest"] if records else GENESIS
    prior_record = records[-1]["record_digest"] if records else GENESIS
    next_record = _record(
        sequence=sequence + 1,
        package_digest=package_digest,
        chain_head_digest=chain_head_digest,
        time_head_digest=time_head_digest,
        prior_package_digest=prior_package,
        prior_record_digest=prior_record,
    )
    return _build_history(
        repository_identity_digest=str(prior_history.get("repository_identity_digest")),
        history_id=str(prior_history.get("history_id")),
        sequence=sequence + 1,
        prior_history_digest=str(prior_history.get("history_digest")),
        records=[*deepcopy(records), next_record],
        signer=signer,
    )


def _build_history(
    *,
    repository_identity_digest: str,
    history_id: str,
    sequence: int,
    prior_history_digest: str,
    records: list[dict[str, Any]],
    signer: HybridSigningContext,
) -> dict[str, Any]:
    if signer.purpose != HISTORY_SIGNING_PURPOSE:
        raise AcceptedHistoryError("history_signer_purpose_invalid")
    if not is_sha512(repository_identity_digest):
        raise AcceptedHistoryError("history_repository_identity_invalid")
    if type(history_id) is not str or not history_id:
        raise AcceptedHistoryError("history_id_invalid")
    live_head = records[-1]["record_digest"] if records else GENESIS
    unsigned = {
        "schema_id": ACCEPTED_HISTORY_SCHEMA,
        "repository_identity_digest": repository_identity_digest,
        "history_id": history_id,
        "sequence": sequence,
        "prior_history_digest": prior_history_digest,
        "live_head_digest": live_head,
        "records": records,
        "status": "CURRENT_LIVE_HEAD",
        "no_authority": dict(NO_AUTHORITY),
    }
    signatures = sign_hybrid(unsigned, signer)
    result = {**unsigned, "signatures": signatures}
    result["history_digest"] = digest(result)
    return result


def validate_accepted_package_history(
    value: Any,
    *,
    repository_identity_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    expected_history_digest: str,
    minimum_sequence: int,
) -> dict[str, Any]:
    failures: list[str] = []
    try:
        if type(value) is not dict or set(value) != _HISTORY_FIELDS:
            raise AcceptedHistoryError("accepted_history_shape_invalid")
        unsigned = {field: value[field] for field in _UNSIGNED_FIELDS}
        records = value.get("records")
        sequence = value.get("sequence")
        if (
            value.get("schema_id") != ACCEPTED_HISTORY_SCHEMA
            or value.get("repository_identity_digest") != repository_identity_digest
            or type(value.get("history_id")) is not str
            or not value["history_id"]
            or type(sequence) is not int
            or sequence < minimum_sequence
            or type(records) is not list
            or len(records) != sequence
            or value.get("status") != "CURRENT_LIVE_HEAD"
            or value.get("no_authority") != NO_AUTHORITY
        ):
            failures.append("accepted_history_contract_invalid")
        if sequence == 0:
            if value.get("prior_history_digest") != GENESIS or value.get("live_head_digest") != GENESIS:
                failures.append("accepted_history_genesis_invalid")
        elif not is_sha512(value.get("prior_history_digest")):
            failures.append("accepted_history_predecessor_invalid")
        prior_package = GENESIS
        prior_record = GENESIS
        seen_packages: set[str] = set()
        seen_replays: set[str] = set()
        seen_time_heads: set[str] = set()
        record_values: list[object] = records if type(records) is list else []
        for expected_sequence, record in enumerate(record_values, start=1):
            if type(record) is not dict or set(record) != _RECORD_FIELDS:
                failures.append("accepted_history_record_shape_invalid")
                break
            expected = _record(
                sequence=expected_sequence,
                package_digest=record.get("package_digest"),
                chain_head_digest=record.get("chain_head_digest"),
                time_head_digest=record.get("time_head_digest"),
                prior_package_digest=prior_package,
                prior_record_digest=prior_record,
            )
            if record != expected:
                failures.append("accepted_history_record_chain_invalid")
            if (
                record["package_digest"] in seen_packages
                or record["replay_id"] in seen_replays
                or record["time_head_digest"] in seen_time_heads
            ):
                failures.append("accepted_history_replay_detected")
            seen_packages.add(record["package_digest"])
            seen_replays.add(record["replay_id"])
            seen_time_heads.add(record["time_head_digest"])
            prior_package = record["package_digest"]
            prior_record = record["record_digest"]
        if value.get("live_head_digest") != prior_record:
            failures.append("accepted_history_live_head_mismatch")
        if not verify_hybrid(
            unsigned,
            value.get("signatures"),
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        ):
            failures.append("accepted_history_signature_invalid")
        calculated = digest({**unsigned, "signatures": value.get("signatures")})
        if not digest_equal(value.get("history_digest"), calculated):
            failures.append("accepted_history_digest_invalid")
        if not digest_equal(value.get("history_digest"), expected_history_digest):
            failures.append("accepted_history_rollback_or_substitution")
    except (AcceptedHistoryError, KeyError, TypeError, ValueError):
        failures.append("accepted_history_malformed")
    return {
        "status": "PASS" if not failures else "FAIL",
        "validation_failures": sorted(set(failures)),
        "history_digest": value.get("history_digest") if type(value) is dict else None,
        "sequence": value.get("sequence") if type(value) is dict else None,
        "live_head_digest": value.get("live_head_digest") if type(value) is dict else None,
        "no_authority": dict(NO_AUTHORITY),
    }


__all__ = [
    "AcceptedHistoryError",
    "advance_accepted_package_history",
    "build_accepted_history_genesis",
    "validate_accepted_package_history",
]
