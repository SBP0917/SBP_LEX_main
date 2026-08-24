"""Detached ML-KEM-1024 channel-establishment capability evidence.

This module performs no encapsulation or decapsulation and grants no admission.
It binds externally supplied transport and custody evidence to one owner-pinned
ML-KEM-1024 public key for channel establishment only.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha512
from typing import Any

from .digests import digest, digest_equal, is_sha512


MLKEM1024_EVIDENCE_SCHEMA_ID = "sbp.lex.v2.ml-kem-1024-channel-capability-evidence/2"
MLKEM1024_CONTRACT_VERSION = "SBP_LEX_V2_ML_KEM_1024_CHANNEL_CAPABILITY_V2"
MLKEM1024_ALGORITHM = "ML-KEM-1024"
MLKEM1024_PUBLIC_KEY_BYTES = 1_568
CHANNEL_CAPABILITY = "CHANNEL_ESTABLISHMENT_ONLY"
NOT_ADMITTED = "NOT_ADMITTED"
NOT_DEPLOYED = "NOT_DEPLOYED"

_FIELDS = {
    "schema_id",
    "contract_version",
    "kem_algorithm",
    "capability",
    "owner_pin_id",
    "key_epoch",
    "key_id",
    "public_key_sha512",
    "transport_id",
    "transport_binding_sha512",
    "custody_provider_id",
    "custody_attestation_sha512",
    "observed_at_ms",
    "evidence_sequence",
    "signature_capability",
    "authority_capability",
    "admission_state",
    "deployment_state",
    "external_transport_admission_required",
    "external_custody_admission_required",
    "evidence_sha512",
}


class MlKem1024CapabilityError(ValueError):
    pass


def _text(value: Any, code: str) -> str:
    if type(value) is not str or not value:
        raise MlKem1024CapabilityError(code)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise MlKem1024CapabilityError(code) from exc
    if len(encoded) > 256:
        raise MlKem1024CapabilityError(code)
    return value


@dataclass(frozen=True, slots=True)
class MlKem1024ExternalPins:
    """Out-of-band owner, key, transport and custody evidence pins."""

    owner_pin_id: str
    key_epoch: int
    public_key_bytes: bytes
    transport_id: str
    transport_binding_sha512: str
    custody_provider_id: str
    custody_attestation_sha512: str

    def __post_init__(self) -> None:
        _text(self.owner_pin_id, "owner_pin_id_invalid")
        _text(self.transport_id, "transport_id_invalid")
        _text(self.custody_provider_id, "custody_provider_id_invalid")
        if (
            type(self.key_epoch) is not int
            or not 1 <= self.key_epoch <= 18_446_744_073_709_551_615
        ):
            raise MlKem1024CapabilityError("key_epoch_invalid")
        if (
            type(self.public_key_bytes) is not bytes
            or len(self.public_key_bytes) != MLKEM1024_PUBLIC_KEY_BYTES
        ):
            raise MlKem1024CapabilityError("mlkem1024_public_key_invalid")
        if not is_sha512(self.transport_binding_sha512):
            raise MlKem1024CapabilityError("transport_binding_invalid")
        if not is_sha512(self.custody_attestation_sha512):
            raise MlKem1024CapabilityError("custody_attestation_invalid")

    @property
    def key_id(self) -> str:
        return sha512(self.public_key_bytes).hexdigest()


def build_mlkem1024_capability_evidence(
    *,
    external_pins: MlKem1024ExternalPins,
    observed_at_ms: int,
    evidence_sequence: int,
) -> dict[str, Any]:
    if type(observed_at_ms) is not int or observed_at_ms < 0:
        raise MlKem1024CapabilityError("observed_at_invalid")
    if type(evidence_sequence) is not int or evidence_sequence <= 0:
        raise MlKem1024CapabilityError("evidence_sequence_invalid")
    unsigned = {
        "schema_id": MLKEM1024_EVIDENCE_SCHEMA_ID,
        "contract_version": MLKEM1024_CONTRACT_VERSION,
        "kem_algorithm": MLKEM1024_ALGORITHM,
        "capability": CHANNEL_CAPABILITY,
        "owner_pin_id": external_pins.owner_pin_id,
        "key_epoch": external_pins.key_epoch,
        "key_id": external_pins.key_id,
        "public_key_sha512": external_pins.key_id,
        "transport_id": external_pins.transport_id,
        "transport_binding_sha512": external_pins.transport_binding_sha512,
        "custody_provider_id": external_pins.custody_provider_id,
        "custody_attestation_sha512": external_pins.custody_attestation_sha512,
        "observed_at_ms": observed_at_ms,
        "evidence_sequence": evidence_sequence,
        "signature_capability": False,
        "authority_capability": False,
        "admission_state": NOT_ADMITTED,
        "deployment_state": NOT_DEPLOYED,
        "external_transport_admission_required": True,
        "external_custody_admission_required": True,
    }
    return {**unsigned, "evidence_sha512": digest(unsigned)}


def validate_mlkem1024_capability_evidence(
    value: Any,
    *,
    external_pins: MlKem1024ExternalPins,
) -> bool:
    try:
        if type(value) is not dict or set(value) != _FIELDS:
            return False
        expected = build_mlkem1024_capability_evidence(
            external_pins=external_pins,
            observed_at_ms=value.get("observed_at_ms"),
            evidence_sequence=value.get("evidence_sequence"),
        )
        return value == expected and digest_equal(
            value.get("evidence_sha512"), expected["evidence_sha512"]
        )
    except (MlKem1024CapabilityError, TypeError, UnicodeError, ValueError):
        return False


__all__ = [
    "CHANNEL_CAPABILITY",
    "MLKEM1024_ALGORITHM",
    "MLKEM1024_CONTRACT_VERSION",
    "MLKEM1024_EVIDENCE_SCHEMA_ID",
    "MLKEM1024_PUBLIC_KEY_BYTES",
    "MlKem1024CapabilityError",
    "MlKem1024ExternalPins",
    "build_mlkem1024_capability_evidence",
    "validate_mlkem1024_capability_evidence",
]
