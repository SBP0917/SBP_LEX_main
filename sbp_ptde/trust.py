"""Out-of-band immutable trust inputs for detached P/T/D/E verification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .canonical import (
    campaign_id,
    canonical_sha512,
    exact_fields,
    identifier,
    nonnegative_int,
    require_sha512,
    strict_json_document,
)
from .constants import MAX_EVIDENCE_ENTRIES, NO_AUTHORITY
from .errors import reject

ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID = "sbp.lex.v2.ptde.accepted-attempt-history/1"
GENESIS_SHA512 = "0" * 128
_HISTORY_FIELDS = frozenset({
    "history_id",
    "no_authority",
    "prior_history_sha512",
    "records",
    "schema_id",
    "sequence",
})
_RECORD_FIELDS = frozenset({
    "attempt_id",
    "campaign_id",
    "e_commit_oid",
    "lane_id",
    "transcript_sha512",
})


@dataclass(frozen=True, slots=True)
class AcceptedAttemptRecord:
    campaign_id: str
    lane_id: str
    attempt_id: str
    transcript_sha512: str
    e_commit_oid: str

    def as_dict(self) -> dict[str, str]:
        return {
            "attempt_id": self.attempt_id,
            "campaign_id": self.campaign_id,
            "e_commit_oid": self.e_commit_oid,
            "lane_id": self.lane_id,
            "transcript_sha512": self.transcript_sha512,
        }


@dataclass(frozen=True, slots=True)
class AcceptedAttemptHistory:
    """Deployment-pinned history snapshot; it is never derived from E."""

    history_id: str
    sequence: int
    prior_history_sha512: str
    records: tuple[AcceptedAttemptRecord, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "history_id": self.history_id,
            "no_authority": dict(NO_AUTHORITY),
            "prior_history_sha512": self.prior_history_sha512,
            "records": [record.as_dict() for record in self.records],
            "schema_id": ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID,
            "sequence": self.sequence,
        }

    def sha512(self) -> str:
        return canonical_sha512(self.as_dict())


def accepted_attempt_history_from_document(data: bytes) -> AcceptedAttemptHistory:
    value = strict_json_document(data, code="ACCEPTED_ATTEMPT_HISTORY")
    history = exact_fields(value, _HISTORY_FIELDS, code="ACCEPTED_ATTEMPT_HISTORY")
    if (
        history["schema_id"] != ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID
        or history["no_authority"] != NO_AUTHORITY
        or type(history["records"]) is not list
    ):
        raise reject("ACCEPTED_ATTEMPT_HISTORY_CONTRACT_INVALID")
    records: list[AcceptedAttemptRecord] = []
    for raw_record in history["records"]:
        record = exact_fields(
            raw_record, _RECORD_FIELDS, code="ACCEPTED_ATTEMPT_HISTORY_RECORD"
        )
        records.append(AcceptedAttemptRecord(**record))
    return AcceptedAttemptHistory(
        history_id=history["history_id"],
        sequence=history["sequence"],
        prior_history_sha512=history["prior_history_sha512"],
        records=tuple(records),
    )


def validate_accepted_attempt_history(
    value: Any,
    *,
    oid_hex_length: int,
    expected_sha512: str,
) -> AcceptedAttemptHistory:
    if type(value) is not AcceptedAttemptHistory:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_TYPE_INVALID")
    identifier(value.history_id, code="ACCEPTED_ATTEMPT_HISTORY_ID_INVALID")
    sequence = nonnegative_int(
        value.sequence, code="ACCEPTED_ATTEMPT_HISTORY_SEQUENCE_INVALID"
    )
    require_sha512(
        value.prior_history_sha512,
        "ACCEPTED_ATTEMPT_HISTORY_PRIOR_DIGEST_INVALID",
    )
    if type(value.records) is not tuple or len(value.records) > MAX_EVIDENCE_ENTRIES:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_RECORDS_INVALID")
    if sequence == 0:
        if value.prior_history_sha512 != GENESIS_SHA512 or value.records:
            raise reject("ACCEPTED_ATTEMPT_HISTORY_GENESIS_INVALID")
        expected = require_sha512(
            expected_sha512, "EXPECTED_ATTEMPT_HISTORY_DIGEST_INVALID"
        )
        if value.sha512() != expected:
            raise reject("ACCEPTED_ATTEMPT_HISTORY_NOT_OUT_OF_BAND_PINNED")
        return value
    if value.prior_history_sha512 == GENESIS_SHA512 or not value.records:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_PREDECESSOR_INVALID")

    keys: list[tuple[str, str, str, str, str]] = []
    attempts: set[str] = set()
    transcripts: set[str] = set()
    accepted_e_oids: set[str] = set()
    for record in value.records:
        if type(record) is not AcceptedAttemptRecord:
            raise reject("ACCEPTED_ATTEMPT_HISTORY_RECORD_INVALID")
        campaign_id(record.campaign_id)
        identifier(record.lane_id, code="ACCEPTED_ATTEMPT_HISTORY_LANE_ID_INVALID")
        identifier(record.attempt_id, code="ACCEPTED_ATTEMPT_HISTORY_ATTEMPT_ID_INVALID")
        require_sha512(
            record.transcript_sha512,
            "ACCEPTED_ATTEMPT_HISTORY_TRANSCRIPT_DIGEST_INVALID",
        )
        if (
            type(record.e_commit_oid) is not str
            or len(record.e_commit_oid) != oid_hex_length
            or any(character not in "0123456789abcdef" for character in record.e_commit_oid)
        ):
            raise reject("ACCEPTED_ATTEMPT_HISTORY_E_OID_INVALID")
        key = (
            record.campaign_id,
            record.lane_id,
            record.attempt_id,
            record.transcript_sha512,
            record.e_commit_oid,
        )
        keys.append(key)
        if record.attempt_id in attempts or record.transcript_sha512 in transcripts:
            raise reject("ACCEPTED_ATTEMPT_HISTORY_REPLAY_DUPLICATE")
        attempts.add(record.attempt_id)
        transcripts.add(record.transcript_sha512)
        accepted_e_oids.add(record.e_commit_oid)
    if keys != sorted(keys) or sequence != len(accepted_e_oids):
        raise reject("ACCEPTED_ATTEMPT_HISTORY_ORDER_OR_SEQUENCE_INVALID")
    expected = require_sha512(
        expected_sha512, "EXPECTED_ATTEMPT_HISTORY_DIGEST_INVALID"
    )
    if value.sha512() != expected:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_NOT_OUT_OF_BAND_PINNED")
    return value


def reject_attempt_reuse(
    history: AcceptedAttemptHistory,
    *,
    campaign: str,
    lane_results: list[dict[str, Any]],
) -> None:
    prior_attempts = {record.attempt_id for record in history.records}
    prior_transcripts = {record.transcript_sha512 for record in history.records}
    for result in lane_results:
        if (
            result["attempt_id"] in prior_attempts
            or result["transcript_sha512"] in prior_transcripts
        ):
            raise reject("E_ATTEMPT_OR_TRANSCRIPT_ALREADY_ACCEPTED")


__all__ = [
    "ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID",
    "GENESIS_SHA512",
    "AcceptedAttemptHistory",
    "AcceptedAttemptRecord",
    "accepted_attempt_history_from_document",
    "reject_attempt_reuse",
    "validate_accepted_attempt_history",
]
