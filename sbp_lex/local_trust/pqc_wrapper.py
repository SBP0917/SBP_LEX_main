"""Detached exact-byte wrapper for the V2 strict dual-signature contract.

The wrapper is additive. Existing local-trust, PTDE, PVPL and supply-chain /1
documents remain opaque payload bytes. Verification requires public keys from
owner pins supplied out of band; the wrapper never carries or admits a key.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha512
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)

from .digests import canonical_bytes, digest, is_sha512

WRAPPER_SCHEMA_ID = "sbp.lex.v2.detached-strict-dual-signed-wrapper/1"
OWNER_PIN_SCHEMA_ID = "sbp.lex.v2.detached-strict-dual-owner-pin/1"
WRAPPER_CONTRACT_VERSION = "SBP_LEX_V2_DETACHED_STRICT_DUAL_WRAPPER_V1"
HYBRID_SIGNATURE_PROFILE_V2 = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1"
HYBRID_ENVELOPE_SCHEMA_ID = "sbp.lex.v2.strict-dual-signature-envelope/1"
HYBRID_DOMAIN = "SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1"
DETACHED_HYBRID_DOMAIN = HYBRID_DOMAIN
HYBRID_PREIMAGE_DOMAIN = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1\x00"
HYBRID_KEY_ID_DOMAIN = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/KEY-ID/1\x00"
DUAL_SIGNATURE_SUITE_VERSION = 1
DUAL_SIGNATURE_VERIFICATION_RULE = "ALL_LANES_REQUIRED"
DUAL_SIGNATURE_SECURITY_PROFILE = "FULL_STRENGTH_ML_DSA_87_AND_ED448"
DUAL_SIGNATURE_TRANSITION_POLICY = (
    "NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK"
)
TEST_ONLY_SIGNER = "TEST_ONLY"
TEST_ONLY_CUSTODY_CLASS = "TEST_ONLY_PROCESS_MEMORY_SOFTWARE_KEYS"
ADMISSION_STATE = "NOT_ADMITTED"
AUTHORITY_EFFECT = "NONE"
RUNTIME_ATTACHMENT = "NONE"
PUBLICATION_STATE = "NOT_ACTIVATED"
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024

ML_DSA_87_PUBLIC_KEY_BYTES = 2_592
ML_DSA_87_SIGNATURE_BYTES = 4_627
ED448_PUBLIC_KEY_BYTES = 57
ED448_SIGNATURE_BYTES = 114

_IDENTIFIER = re.compile(r"[A-Z0-9][A-Z0-9_.:-]{0,127}\Z")
_WRAPPER_FIELDS = frozenset({
    "schema_id",
    "contract_version",
    "signature_profile",
    "owner_pin_id",
    "owner_pin_sha512",
    "key_epoch",
    "purpose",
    "domain",
    "payload_encoding",
    "payload_sha512",
    "payload_b64",
    "admission_state",
    "authority_effect",
    "runtime_attachment",
    "publication_state",
    "signature",
})
_ENVELOPE_FIELDS = frozenset({
    "schema_id",
    "suite",
    "suite_version",
    "verification_rule",
    "security_profile",
    "transition_policy",
    "lane_independence_required",
    "purpose",
    "domain",
    "key_epoch",
    "context_digest",
    "payload_sha512",
    "signer_class",
    "effect_authority",
    "ordered_key_set_digest",
    "lanes",
    "signatures",
})
_DESCRIPTOR_FIELDS = frozenset({
    "ordinal",
    "algorithm",
    "provider_id",
    "key_id",
    "key_version",
    "key_epoch",
    "rotation_epoch",
    "revoked_at_epoch",
    "lifecycle_status",
    "custody_class",
    "custody_reference",
    "external_custody_admitted",
    "custody_admission_sha512",
    "non_exportable",
    "public_key_encoding",
    "signature_encoding",
})
_SIGNATURE_LANE_FIELDS = frozenset(
    {"ordinal", "algorithm", "key_id", "signature_b64"}
)
_LANE_ORDER = ("ML-DSA-87", "Ed448")


class DetachedHybridWrapperError(ValueError):
    pass


def _identifier(value: Any, *, code: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise DetachedHybridWrapperError(code)
    return value


def _purpose(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise DetachedHybridWrapperError("purpose_invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise DetachedHybridWrapperError("purpose_invalid") from exc
    if len(encoded) > 65_535:
        raise DetachedHybridWrapperError("purpose_invalid")
    return value


def _raw_public_key(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(
    value: Any,
    *,
    code: str,
    exact_bytes: int | None = None,
    maximum_bytes: int | None = None,
) -> bytes:
    if type(value) is not str or not value:
        raise DetachedHybridWrapperError(code)
    limit = exact_bytes if exact_bytes is not None else maximum_bytes
    if limit is not None and len(value) > ((limit + 2) // 3) * 4:
        raise DetachedHybridWrapperError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise DetachedHybridWrapperError(code) from exc
    if not decoded or _b64(decoded) != value:
        raise DetachedHybridWrapperError(code)
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise DetachedHybridWrapperError(code)
    if maximum_bytes is not None and len(decoded) > maximum_bytes:
        raise DetachedHybridWrapperError(code)
    return decoded


def hybrid_signature_preimage(
    payload: bytes,
    *,
    purpose: str,
    key_epoch: int,
    mldsa87_public_key_bytes: bytes,
    ed448_public_key_bytes: bytes,
    application_context: bytes,
) -> bytes:
    """Return the common Python/Rust V2 binary hybrid signing preimage."""

    checked_purpose = _purpose(purpose).encode("utf-8")
    if (
        type(payload) is not bytes
        or type(application_context) is not bytes
        or type(mldsa87_public_key_bytes) is not bytes
        or len(mldsa87_public_key_bytes) != ML_DSA_87_PUBLIC_KEY_BYTES
        or type(ed448_public_key_bytes) is not bytes
        or len(ed448_public_key_bytes) != ED448_PUBLIC_KEY_BYTES
        or type(key_epoch) is not int
        or not 1 <= key_epoch <= 18_446_744_073_709_551_615
    ):
        raise DetachedHybridWrapperError("hybrid_preimage_input_invalid")
    return b"".join(
        (
            HYBRID_PREIMAGE_DOMAIN,
            HYBRID_SIGNATURE_PROFILE_V2.encode("ascii"),
            b"\x00",
            len(checked_purpose).to_bytes(2, "big"),
            checked_purpose,
            key_epoch.to_bytes(8, "big"),
            sha512(mldsa87_public_key_bytes).digest(),
            sha512(ed448_public_key_bytes).digest(),
            sha512(payload).digest(),
            sha512(application_context).digest(),
        )
    )


@dataclass(frozen=True, slots=True)
class DetachedHybridOwnerPins:
    """Owner-selected public keys; never sourced from a signed wrapper."""

    owner_pin_id: str
    key_epoch: int
    purpose: str
    domain: str
    custody_attestation_sha512: str
    mldsa87_provider_id: str
    ed448_provider_id: str
    mldsa87_custody_reference: str
    ed448_custody_reference: str
    mldsa87_custody_attestation_sha512: str
    ed448_custody_attestation_sha512: str
    mldsa87_public_key: MLDSA87PublicKey
    ed448_public_key: Ed448PublicKey

    def __post_init__(self) -> None:
        _identifier(self.owner_pin_id, code="owner_pin_id_invalid")
        _purpose(self.purpose)
        if self.domain != HYBRID_DOMAIN:
            raise DetachedHybridWrapperError("domain_invalid")
        if (
            type(self.key_epoch) is not int
            or not 1 <= self.key_epoch <= 18_446_744_073_709_551_615
        ):
            raise DetachedHybridWrapperError("key_epoch_invalid")
        if (
            not is_sha512(self.custody_attestation_sha512)
            or not is_sha512(self.mldsa87_custody_attestation_sha512)
            or not is_sha512(self.ed448_custody_attestation_sha512)
            or len(
                {
                    self.custody_attestation_sha512,
                    self.mldsa87_custody_attestation_sha512,
                    self.ed448_custody_attestation_sha512,
                }
            )
            != 3
        ):
            raise DetachedHybridWrapperError("custody_attestation_invalid")
        for value in (
            self.mldsa87_provider_id,
            self.ed448_provider_id,
            self.mldsa87_custody_reference,
            self.ed448_custody_reference,
        ):
            _identifier(value, code="lane_custody_identity_invalid")
        if (
            self.mldsa87_provider_id == self.ed448_provider_id
            or self.mldsa87_custody_reference == self.ed448_custody_reference
        ):
            raise DetachedHybridWrapperError("lane_custody_not_independent")
        if not isinstance(self.mldsa87_public_key, MLDSA87PublicKey):
            raise DetachedHybridWrapperError("mldsa87_public_key_invalid")
        if not isinstance(self.ed448_public_key, Ed448PublicKey):
            raise DetachedHybridWrapperError("ed448_public_key_invalid")

    @property
    def mldsa87_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.mldsa87_public_key)

    @property
    def ed448_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.ed448_public_key)

    @property
    def mldsa87_key_id(self) -> str:
        return sha512(self.mldsa87_public_key_bytes).hexdigest()

    @property
    def ed448_key_id(self) -> str:
        return sha512(self.ed448_public_key_bytes).hexdigest()

    @property
    def ordered_key_set_digest(self) -> str:
        return sha512(
            HYBRID_KEY_ID_DOMAIN
            + HYBRID_SIGNATURE_PROFILE_V2.encode("ascii")
            + b"\x00"
            + bytes.fromhex(self.mldsa87_key_id)
            + bytes.fromhex(self.ed448_key_id)
        ).hexdigest()

    def _descriptor(self, ordinal: int) -> dict[str, Any]:
        provider_id = (
            self.mldsa87_provider_id if ordinal == 0 else self.ed448_provider_id
        )
        custody_reference = (
            self.mldsa87_custody_reference
            if ordinal == 0
            else self.ed448_custody_reference
        )
        return {
            "ordinal": ordinal,
            "algorithm": _LANE_ORDER[ordinal],
            "provider_id": provider_id,
            "key_id": (
                self.mldsa87_key_id if ordinal == 0 else self.ed448_key_id
            ),
            "key_version": str(self.key_epoch),
            "key_epoch": self.key_epoch,
            "rotation_epoch": self.key_epoch,
            "revoked_at_epoch": None,
            "lifecycle_status": "ACTIVE",
            "custody_class": TEST_ONLY_CUSTODY_CLASS,
            "custody_reference": custody_reference,
            "external_custody_admitted": False,
            "custody_admission_sha512": "NONE",
            "non_exportable": False,
            "public_key_encoding": "RAW",
            "signature_encoding": "RAW",
        }

    @property
    def lane_descriptors(self) -> list[dict[str, Any]]:
        return [self._descriptor(0), self._descriptor(1)]

    def public_record(self) -> dict[str, Any]:
        record = {
            "schema_id": OWNER_PIN_SCHEMA_ID,
            "contract_version": WRAPPER_CONTRACT_VERSION,
            "signature_profile": HYBRID_SIGNATURE_PROFILE_V2,
            "suite_version": DUAL_SIGNATURE_SUITE_VERSION,
            "verification_rule": DUAL_SIGNATURE_VERIFICATION_RULE,
            "security_profile": DUAL_SIGNATURE_SECURITY_PROFILE,
            "transition_policy": DUAL_SIGNATURE_TRANSITION_POLICY,
            "lane_independence_required": True,
            "owner_pin_id": self.owner_pin_id,
            "key_epoch": self.key_epoch,
            "purpose": self.purpose,
            "domain": self.domain,
            "custody_attestation_sha512": self.custody_attestation_sha512,
            "mldsa87_custody_attestation_sha512": (
                self.mldsa87_custody_attestation_sha512
            ),
            "ed448_custody_attestation_sha512": (
                self.ed448_custody_attestation_sha512
            ),
            "signer_class": TEST_ONLY_SIGNER,
            "effect_authority": False,
            "external_custody_admitted": False,
            "external_custody_admission_sha512": "NONE",
            "ordered_key_set_digest": self.ordered_key_set_digest,
            "lanes": [
                {
                    **self.lane_descriptors[0],
                    "public_key_b64": _b64(self.mldsa87_public_key_bytes),
                },
                {
                    **self.lane_descriptors[1],
                    "public_key_b64": _b64(self.ed448_public_key_bytes),
                },
            ],
            "admission_state": ADMISSION_STATE,
            "authority_effect": AUTHORITY_EFFECT,
            "runtime_attachment": RUNTIME_ATTACHMENT,
        }
        record["owner_pin_sha512"] = digest(record)
        return record

    @property
    def owner_pin_sha512(self) -> str:
        return self.public_record()["owner_pin_sha512"]

    @property
    def application_context(self) -> bytes:
        return canonical_bytes(self.public_record())

    @property
    def context_digest(self) -> str:
        return sha512(self.application_context).hexdigest()


@dataclass(frozen=True, slots=True)
class DetachedHybridSigningKeys:
    """Software signing keys for detached evidence; no custody claim is made."""

    mldsa87_private_key: MLDSA87PrivateKey
    ed448_private_key: Ed448PrivateKey

    def __post_init__(self) -> None:
        if not isinstance(self.mldsa87_private_key, MLDSA87PrivateKey):
            raise DetachedHybridWrapperError("mldsa87_private_key_invalid")
        if not isinstance(self.ed448_private_key, Ed448PrivateKey):
            raise DetachedHybridWrapperError("ed448_private_key_invalid")


def _protected(payload: bytes, pins: DetachedHybridOwnerPins) -> dict[str, Any]:
    return {
        "schema_id": HYBRID_ENVELOPE_SCHEMA_ID,
        "suite": HYBRID_SIGNATURE_PROFILE_V2,
        "suite_version": DUAL_SIGNATURE_SUITE_VERSION,
        "verification_rule": DUAL_SIGNATURE_VERIFICATION_RULE,
        "security_profile": DUAL_SIGNATURE_SECURITY_PROFILE,
        "transition_policy": DUAL_SIGNATURE_TRANSITION_POLICY,
        "lane_independence_required": True,
        "purpose": pins.purpose,
        "domain": HYBRID_DOMAIN,
        "key_epoch": pins.key_epoch,
        "context_digest": pins.context_digest,
        "payload_sha512": sha512(payload).hexdigest(),
        "signer_class": TEST_ONLY_SIGNER,
        "effect_authority": False,
        "ordered_key_set_digest": pins.ordered_key_set_digest,
        "lanes": pins.lane_descriptors,
    }


def _preimage(payload: bytes, pins: DetachedHybridOwnerPins) -> bytes:
    return hybrid_signature_preimage(
        payload,
        purpose=pins.purpose,
        key_epoch=pins.key_epoch,
        mldsa87_public_key_bytes=pins.mldsa87_public_key_bytes,
        ed448_public_key_bytes=pins.ed448_public_key_bytes,
        application_context=pins.application_context,
    )


def _unsigned_wrapper(payload: bytes, pins: DetachedHybridOwnerPins) -> dict[str, Any]:
    if type(payload) is not bytes or not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
        raise DetachedHybridWrapperError("payload_invalid")
    return {
        "schema_id": WRAPPER_SCHEMA_ID,
        "contract_version": WRAPPER_CONTRACT_VERSION,
        "signature_profile": HYBRID_SIGNATURE_PROFILE_V2,
        "owner_pin_id": pins.owner_pin_id,
        "owner_pin_sha512": pins.owner_pin_sha512,
        "key_epoch": pins.key_epoch,
        "purpose": pins.purpose,
        "domain": pins.domain,
        "payload_encoding": "BASE64_EXACT_BYTES",
        "payload_sha512": sha512(payload).hexdigest(),
        "payload_b64": _b64(payload),
        "admission_state": ADMISSION_STATE,
        "authority_effect": AUTHORITY_EFFECT,
        "runtime_attachment": RUNTIME_ATTACHMENT,
        "publication_state": PUBLICATION_STATE,
    }


def wrap_detached_payload(
    payload: bytes,
    *,
    signing_keys: DetachedHybridSigningKeys,
    owner_pins: DetachedHybridOwnerPins,
) -> dict[str, Any]:
    if (
        _raw_public_key(signing_keys.mldsa87_private_key.public_key())
        != owner_pins.mldsa87_public_key_bytes
        or _raw_public_key(signing_keys.ed448_private_key.public_key())
        != owner_pins.ed448_public_key_bytes
    ):
        raise DetachedHybridWrapperError("signing_keys_not_owner_pinned")
    unsigned = _unsigned_wrapper(payload, owner_pins)
    preimage = _preimage(payload, owner_pins)
    envelope = {
        **_protected(payload, owner_pins),
        "signatures": [
            {
                "ordinal": 0,
                "algorithm": "ML-DSA-87",
                "key_id": owner_pins.mldsa87_key_id,
                "signature_b64": _b64(
                    signing_keys.mldsa87_private_key.sign(preimage)
                ),
            },
            {
                "ordinal": 1,
                "algorithm": "Ed448",
                "key_id": owner_pins.ed448_key_id,
                "signature_b64": _b64(signing_keys.ed448_private_key.sign(preimage)),
            },
        ],
    }
    return {**unsigned, "signature": envelope}


def _validated_payload(
    wrapper: Any,
    *,
    owner_pins: DetachedHybridOwnerPins,
    expected_payload_sha512: str | None,
) -> bytes:
    if type(wrapper) is not dict or set(wrapper) != _WRAPPER_FIELDS:
        raise DetachedHybridWrapperError("wrapper_fields_invalid")
    expected_metadata = {
        "schema_id": WRAPPER_SCHEMA_ID,
        "contract_version": WRAPPER_CONTRACT_VERSION,
        "signature_profile": HYBRID_SIGNATURE_PROFILE_V2,
        "owner_pin_id": owner_pins.owner_pin_id,
        "owner_pin_sha512": owner_pins.owner_pin_sha512,
        "key_epoch": owner_pins.key_epoch,
        "purpose": owner_pins.purpose,
        "domain": owner_pins.domain,
        "payload_encoding": "BASE64_EXACT_BYTES",
        "admission_state": ADMISSION_STATE,
        "authority_effect": AUTHORITY_EFFECT,
        "runtime_attachment": RUNTIME_ATTACHMENT,
        "publication_state": PUBLICATION_STATE,
    }
    if any(wrapper.get(field) != value for field, value in expected_metadata.items()):
        raise DetachedHybridWrapperError("wrapper_owner_pin_or_metadata_mismatch")
    payload = _decode_b64(
        wrapper.get("payload_b64"),
        code="payload_encoding_invalid",
        maximum_bytes=MAX_PAYLOAD_BYTES,
    )
    actual_payload_sha512 = sha512(payload).hexdigest()
    if (
        not is_sha512(wrapper.get("payload_sha512"))
        or not hmac.compare_digest(wrapper["payload_sha512"], actual_payload_sha512)
        or (
            expected_payload_sha512 is not None
            and (
                not is_sha512(expected_payload_sha512)
                or not hmac.compare_digest(
                    actual_payload_sha512, expected_payload_sha512
                )
            )
        )
    ):
        raise DetachedHybridWrapperError("payload_sha512_mismatch")
    envelope = wrapper.get("signature")
    if type(envelope) is not dict or set(envelope) != _ENVELOPE_FIELDS:
        raise DetachedHybridWrapperError("hybrid_envelope_invalid")
    protected = _protected(payload, owner_pins)
    if any(envelope.get(field) != value for field, value in protected.items()):
        raise DetachedHybridWrapperError("hybrid_envelope_metadata_mismatch")
    if envelope.get("payload_sha512") != wrapper.get("payload_sha512"):
        raise DetachedHybridWrapperError("hybrid_payload_digest_mismatch")
    signatures = envelope.get("signatures")
    if type(signatures) is not list or len(signatures) != 2:
        raise DetachedHybridWrapperError("hybrid_signature_lanes_invalid")
    decoded_signatures: list[bytes] = []
    for ordinal, (lane, descriptor, exact_bytes) in enumerate(
        zip(
            signatures,
            owner_pins.lane_descriptors,
            (ML_DSA_87_SIGNATURE_BYTES, ED448_SIGNATURE_BYTES),
        )
    ):
        if (
            type(lane) is not dict
            or set(lane) != _SIGNATURE_LANE_FIELDS
            or lane.get("ordinal") != ordinal
            or lane.get("algorithm") != _LANE_ORDER[ordinal]
            or lane.get("key_id") != descriptor["key_id"]
        ):
            raise DetachedHybridWrapperError("hybrid_signature_lane_invalid")
        decoded_signatures.append(
            _decode_b64(
                lane.get("signature_b64"),
                code="hybrid_signature_encoding_invalid",
                exact_bytes=exact_bytes,
            )
        )
    preimage = _preimage(payload, owner_pins)
    try:
        owner_pins.mldsa87_public_key.verify(decoded_signatures[0], preimage)
        owner_pins.ed448_public_key.verify(decoded_signatures[1], preimage)
    except (InvalidSignature, ValueError) as exc:
        raise DetachedHybridWrapperError("hybrid_signature_invalid") from exc
    return payload


def verify_detached_hybrid_wrapper(
    wrapper: Any,
    *,
    owner_pins: DetachedHybridOwnerPins,
    expected_payload_sha512: str | None = None,
) -> bool:
    try:
        _validated_payload(
            wrapper,
            owner_pins=owner_pins,
            expected_payload_sha512=expected_payload_sha512,
        )
        return True
    except (DetachedHybridWrapperError, TypeError, ValueError):
        return False


def verified_detached_payload(
    wrapper: Any,
    *,
    owner_pins: DetachedHybridOwnerPins,
    expected_payload_sha512: str | None = None,
) -> bytes:
    return _validated_payload(
        wrapper,
        owner_pins=owner_pins,
        expected_payload_sha512=expected_payload_sha512,
    )


__all__ = [
    "ADMISSION_STATE",
    "AUTHORITY_EFFECT",
    "DETACHED_HYBRID_DOMAIN",
    "ED448_PUBLIC_KEY_BYTES",
    "ED448_SIGNATURE_BYTES",
    "HYBRID_DOMAIN",
    "HYBRID_ENVELOPE_SCHEMA_ID",
    "HYBRID_KEY_ID_DOMAIN",
    "HYBRID_PREIMAGE_DOMAIN",
    "HYBRID_SIGNATURE_PROFILE_V2",
    "ML_DSA_87_PUBLIC_KEY_BYTES",
    "ML_DSA_87_SIGNATURE_BYTES",
    "OWNER_PIN_SCHEMA_ID",
    "WRAPPER_CONTRACT_VERSION",
    "WRAPPER_SCHEMA_ID",
    "DetachedHybridOwnerPins",
    "DetachedHybridSigningKeys",
    "DetachedHybridWrapperError",
    "hybrid_signature_preimage",
    "verified_detached_payload",
    "verify_detached_hybrid_wrapper",
    "wrap_detached_payload",
]
