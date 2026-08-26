"""Required hybrid ML-DSA-87 + Ed448 signatures for local-trust evidence."""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping
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

from .constants import (
    DUAL_SIGNATURE_TRANSITION_POLICY,
    DUAL_SIGNATURE_VERIFICATION_RULE,
    HYBRID_SIGNATURE_PROFILE,
    PRODUCTION,
    SIGNER_CLASSES,
    SIGNING_DOMAIN,
    SIGNING_PURPOSES,
    TEST_ONLY,
    TRUST_CONTEXT_SCHEMA,
)
from .digests import canonical_bytes, digest, digest_equal, is_sha512


class LocalTrustSignatureError(ValueError):
    pass


PRODUCTION_DUAL_CUSTODY_CLASS = "INDEPENDENT_EXTERNAL_TWO_LANE_CUSTODY"


def _raw_public_key(key: Any) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def raw_public_key_key_id(key: Any) -> str:
    """Return the V2 raw-public-key identity without changing V1 records."""

    return sha512(_raw_public_key(key)).hexdigest()


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64(value: Any) -> bytes:
    if type(value) is not str or not value:
        raise LocalTrustSignatureError("signature_encoding_invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise LocalTrustSignatureError("signature_encoding_invalid") from exc


def _decode_b64_exact(value: Any, *, length: int, code: str) -> bytes:
    decoded = _decode_b64(value)
    if len(decoded) != length or not hmac.compare_digest(_b64(decoded), value):
        raise LocalTrustSignatureError(code)
    return decoded


def _bound_message(
    unsigned: Mapping[str, Any], purpose: str, context_digest: str
) -> bytes:
    if not is_sha512(context_digest):
        raise LocalTrustSignatureError("context_digest_invalid")
    return (
        SIGNING_DOMAIN
        + HYBRID_SIGNATURE_PROFILE.encode("ascii")
        + b"\x00"
        + purpose.encode("ascii")
        + b"\x00"
        + bytes.fromhex(context_digest)
        + canonical_bytes(dict(unsigned))
    )


@dataclass(frozen=True, slots=True)
class DualSignatureLaneCustody:
    """One lane's independently pinned custody and key-lifecycle record."""

    algorithm: str
    provider_id: str
    key_version: str
    key_epoch: int
    rotation_epoch: int
    custody_class: str
    custody_reference: str
    signer_class: str
    lifecycle_status: str = "ACTIVE"
    revoked_at_epoch: int | None = None
    external_custody_admitted: bool = False
    custody_admission_sha512: str = "NONE"
    non_exportable: bool = False

    def __post_init__(self) -> None:
        if (
            self.algorithm not in {"ML-DSA-87", "Ed448"}
            or not all(
                type(item) is str and bool(item)
                for item in (
                    self.provider_id,
                    self.key_version,
                    self.custody_class,
                    self.custody_reference,
                    self.signer_class,
                    self.lifecycle_status,
                )
            )
            or type(self.key_epoch) is not int
            or self.key_epoch <= 0
            or type(self.rotation_epoch) is not int
            or self.rotation_epoch <= 0
            or self.rotation_epoch > self.key_epoch
            or type(self.external_custody_admitted) is not bool
            or type(self.non_exportable) is not bool
        ):
            raise LocalTrustSignatureError("lane_custody_invalid")
        if self.lifecycle_status == "ACTIVE":
            if self.revoked_at_epoch is not None:
                raise LocalTrustSignatureError("active_lane_is_revoked")
        elif self.lifecycle_status == "REVOKED":
            if type(self.revoked_at_epoch) is not int or self.revoked_at_epoch <= 0:
                raise LocalTrustSignatureError("revocation_epoch_required")
        else:
            raise LocalTrustSignatureError("lane_lifecycle_status_invalid")
        if self.signer_class == TEST_ONLY:
            if (
                self.external_custody_admitted
                or self.custody_admission_sha512 != "NONE"
                or self.non_exportable
            ):
                raise LocalTrustSignatureError("test_lane_custody_invalid")
        elif self.signer_class == PRODUCTION:
            if (
                not self.external_custody_admitted
                or not is_sha512(self.custody_admission_sha512)
                or not self.non_exportable
            ):
                raise LocalTrustSignatureError("production_lane_custody_not_admitted")
        else:
            raise LocalTrustSignatureError("lane_signer_class_invalid")

    def public_record(self, *, key_id: str) -> dict[str, Any]:
        if not is_sha512(key_id):
            raise LocalTrustSignatureError("lane_key_id_invalid")
        return {
            "algorithm": self.algorithm,
            "provider_id": self.provider_id,
            "key_id": key_id,
            "key_version": self.key_version,
            "key_epoch": self.key_epoch,
            "rotation_epoch": self.rotation_epoch,
            "custody_class": self.custody_class,
            "custody_reference": self.custody_reference,
            "signer_class": self.signer_class,
            "lifecycle_status": self.lifecycle_status,
            "revoked_at_epoch": self.revoked_at_epoch,
            "external_custody_admitted": self.external_custody_admitted,
            "custody_admission_sha512": self.custody_admission_sha512,
            "non_exportable": self.non_exportable,
        }


def _test_lane_custody(
    *, provider_id: str, algorithm: str, key_version: str, key_epoch: int
) -> DualSignatureLaneCustody:
    token = "ml-dsa-87" if algorithm == "ML-DSA-87" else "ed448"
    return DualSignatureLaneCustody(
        algorithm=algorithm,
        provider_id=f"{provider_id}#{token}",
        key_version=f"{key_version}:{token}",
        key_epoch=key_epoch,
        rotation_epoch=key_epoch,
        custody_class="TEST_ONLY_PROCESS_MEMORY_SOFTWARE_KEYS",
        custody_reference=f"{provider_id}/process-memory/{token}",
        signer_class=TEST_ONLY,
    )


@dataclass(frozen=True, slots=True)
class HybridVerificationContext:
    """Out-of-band public trust material; artifacts cannot select these keys."""

    context_id: str
    provider_id: str
    key_id: str
    custody_class: str
    signer_class: str
    purpose: str
    mldsa87_public_key: MLDSA87PublicKey
    ed448_public_key: Ed448PublicKey
    allow_test_only: bool = False
    key_epoch: int = 1
    key_version: str = "1"
    dual_custody_admission_sha512: str = "NONE"
    mldsa87_custody: DualSignatureLaneCustody | None = None
    ed448_custody: DualSignatureLaneCustody | None = None

    def __post_init__(self) -> None:
        if not all(
            type(item) is str and bool(item)
            for item in (
                self.context_id,
                self.provider_id,
                self.key_id,
                self.custody_class,
            )
        ):
            raise LocalTrustSignatureError("trust_context_identity_invalid")
        if self.signer_class not in SIGNER_CLASSES:
            raise LocalTrustSignatureError("trust_context_signer_class_invalid")
        if self.purpose not in SIGNING_PURPOSES:
            raise LocalTrustSignatureError("trust_context_purpose_invalid")
        if self.signer_class == TEST_ONLY and not self.allow_test_only:
            raise LocalTrustSignatureError("test_only_trust_context_rejected")
        if (
            type(self.key_epoch) is not int
            or self.key_epoch <= 0
            or type(self.key_version) is not str
            or not self.key_version
            or not isinstance(self.mldsa87_public_key, MLDSA87PublicKey)
            or not isinstance(self.ed448_public_key, Ed448PublicKey)
        ):
            raise LocalTrustSignatureError("trust_context_key_lifecycle_invalid")

        mldsa87_custody = self.mldsa87_custody
        ed448_custody = self.ed448_custody
        if self.signer_class == TEST_ONLY:
            if mldsa87_custody is None:
                mldsa87_custody = _test_lane_custody(
                    provider_id=self.provider_id,
                    algorithm="ML-DSA-87",
                    key_version=self.key_version,
                    key_epoch=self.key_epoch,
                )
                object.__setattr__(self, "mldsa87_custody", mldsa87_custody)
            if ed448_custody is None:
                ed448_custody = _test_lane_custody(
                    provider_id=self.provider_id,
                    algorithm="Ed448",
                    key_version=self.key_version,
                    key_epoch=self.key_epoch,
                )
                object.__setattr__(self, "ed448_custody", ed448_custody)
        if not isinstance(
            mldsa87_custody, DualSignatureLaneCustody
        ) or not isinstance(ed448_custody, DualSignatureLaneCustody):
            raise LocalTrustSignatureError("two_lane_custody_required")
        if (
            mldsa87_custody.algorithm != "ML-DSA-87"
            or ed448_custody.algorithm != "Ed448"
            or mldsa87_custody.signer_class != self.signer_class
            or ed448_custody.signer_class != self.signer_class
            or mldsa87_custody.key_epoch != self.key_epoch
            or ed448_custody.key_epoch != self.key_epoch
            or mldsa87_custody.lifecycle_status != "ACTIVE"
            or ed448_custody.lifecycle_status != "ACTIVE"
            or mldsa87_custody.revoked_at_epoch is not None
            or ed448_custody.revoked_at_epoch is not None
        ):
            raise LocalTrustSignatureError("lane_lifecycle_invalid")
        if (
            mldsa87_custody.provider_id == ed448_custody.provider_id
            or mldsa87_custody.custody_reference
            == ed448_custody.custody_reference
        ):
            raise LocalTrustSignatureError("lane_custody_not_independent")
        if self.signer_class == TEST_ONLY:
            if self.dual_custody_admission_sha512 != "NONE":
                raise LocalTrustSignatureError("test_dual_custody_admission_invalid")
        elif (
            self.custody_class != PRODUCTION_DUAL_CUSTODY_CLASS
            or not is_sha512(self.dual_custody_admission_sha512)
            or not mldsa87_custody.external_custody_admitted
            or not ed448_custody.external_custody_admitted
            or not mldsa87_custody.non_exportable
            or not ed448_custody.non_exportable
            or mldsa87_custody.custody_admission_sha512
            == ed448_custody.custody_admission_sha512
            or self.dual_custody_admission_sha512
            in {
                mldsa87_custody.custody_admission_sha512,
                ed448_custody.custody_admission_sha512,
            }
        ):
            raise LocalTrustSignatureError("production_dual_custody_not_admitted")

    @property
    def mldsa87_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.mldsa87_public_key)

    @property
    def ed448_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.ed448_public_key)

    @property
    def mldsa87_key_id(self) -> str:
        """V2 lane key ID: SHA-512 over the exact raw public-key bytes."""

        return raw_public_key_key_id(self.mldsa87_public_key)

    @property
    def ed448_key_id(self) -> str:
        """V2 lane key ID: SHA-512 over the exact raw public-key bytes."""

        return raw_public_key_key_id(self.ed448_public_key)

    @property
    def mldsa87_fingerprint(self) -> str:
        return digest({"algorithm": "ML-DSA-87", "raw_public_key": _b64(self.mldsa87_public_key_bytes)})

    @property
    def ed448_fingerprint(self) -> str:
        return digest({"algorithm": "Ed448", "raw_public_key": _b64(self.ed448_public_key_bytes)})

    def public_record(self) -> dict[str, Any]:
        if not isinstance(
            self.mldsa87_custody, DualSignatureLaneCustody
        ) or not isinstance(self.ed448_custody, DualSignatureLaneCustody):
            raise LocalTrustSignatureError("two_lane_custody_required")
        ml_custody = self.mldsa87_custody.public_record(
            key_id=self.mldsa87_key_id
        )
        ed_custody = self.ed448_custody.public_record(key_id=self.ed448_key_id)
        record = {
            "schema_id": TRUST_CONTEXT_SCHEMA,
            "context_id": self.context_id,
            "provider_id": self.provider_id,
            "key_id": self.key_id,
            "custody_class": self.custody_class,
            "signer_class": self.signer_class,
            "purpose": self.purpose,
            "signature_profile": HYBRID_SIGNATURE_PROFILE,
            "verification_rule": DUAL_SIGNATURE_VERIFICATION_RULE,
            "transition_policy": DUAL_SIGNATURE_TRANSITION_POLICY,
            "lane_independence_required": True,
            "key_epoch": self.key_epoch,
            "key_version": self.key_version,
            "dual_custody_admission_sha512": (
                self.dual_custody_admission_sha512
            ),
            "mldsa87_public_key_b64": _b64(self.mldsa87_public_key_bytes),
            "mldsa87_fingerprint": self.mldsa87_fingerprint,
            "ed448_public_key_b64": _b64(self.ed448_public_key_bytes),
            "ed448_fingerprint": self.ed448_fingerprint,
            "mldsa87_custody": ml_custody,
            "ed448_custody": ed_custody,
            "software_custody_limitation": self.signer_class == TEST_ONLY,
            "external_custody_required": self.signer_class == PRODUCTION,
        }
        record["context_digest"] = digest(record)
        return record

    @property
    def context_digest(self) -> str:
        return self.public_record()["context_digest"]


@dataclass(frozen=True, slots=True)
class HybridSigningContext:
    """Signing keys remain in memory and are never placed in an artifact."""

    context_id: str
    provider_id: str
    key_id: str
    custody_class: str
    signer_class: str
    purpose: str
    mldsa87_private_key: MLDSA87PrivateKey
    ed448_private_key: Ed448PrivateKey
    key_epoch: int = 1
    key_version: str = "1"

    def __post_init__(self) -> None:
        if self.signer_class != TEST_ONLY:
            raise LocalTrustSignatureError("production_software_signing_forbidden")
        if self.purpose not in SIGNING_PURPOSES:
            raise LocalTrustSignatureError("signer_purpose_invalid")
        if not all(
            type(item) is str and bool(item)
            for item in (
                self.context_id,
                self.provider_id,
                self.key_id,
                self.custody_class,
            )
        ):
            raise LocalTrustSignatureError("signer_identity_invalid")
        if (
            type(self.key_epoch) is not int
            or self.key_epoch <= 0
            or type(self.key_version) is not str
            or not self.key_version
            or not isinstance(self.mldsa87_private_key, MLDSA87PrivateKey)
            or not isinstance(self.ed448_private_key, Ed448PrivateKey)
        ):
            raise LocalTrustSignatureError("signer_key_lifecycle_invalid")

    def verification_context(self, *, allow_test_only: bool = False) -> HybridVerificationContext:
        return HybridVerificationContext(
            context_id=self.context_id,
            provider_id=self.provider_id,
            key_id=self.key_id,
            custody_class=self.custody_class,
            signer_class=self.signer_class,
            purpose=self.purpose,
            mldsa87_public_key=self.mldsa87_private_key.public_key(),
            ed448_public_key=self.ed448_private_key.public_key(),
            allow_test_only=allow_test_only,
            key_epoch=self.key_epoch,
            key_version=self.key_version,
        )


_SIGNATURE_FIELDS = frozenset({
    "signature_profile",
    "verification_rule",
    "transition_policy",
    "lane_independence_required",
    "context_id",
    "context_digest",
    "provider_id",
    "key_id",
    "custody_class",
    "signer_class",
    "purpose",
    "key_epoch",
    "key_version",
    "mldsa87_custody_sha512",
    "ed448_custody_sha512",
    "dual_custody_admission_sha512",
    "mldsa87",
    "ed448",
})
_LANE_FIELDS = frozenset({"algorithm", "fingerprint", "signature_b64"})


def sign_hybrid(unsigned: Mapping[str, Any], signer: HybridSigningContext) -> dict[str, Any]:
    verification = signer.verification_context(
        allow_test_only=signer.signer_class == TEST_ONLY,
    )
    public_record = verification.public_record()
    message = _bound_message(
        unsigned, signer.purpose, verification.context_digest
    )
    return {
        "signature_profile": HYBRID_SIGNATURE_PROFILE,
        "verification_rule": DUAL_SIGNATURE_VERIFICATION_RULE,
        "transition_policy": DUAL_SIGNATURE_TRANSITION_POLICY,
        "lane_independence_required": True,
        "context_id": signer.context_id,
        "context_digest": verification.context_digest,
        "provider_id": signer.provider_id,
        "key_id": signer.key_id,
        "custody_class": signer.custody_class,
        "signer_class": signer.signer_class,
        "purpose": signer.purpose,
        "key_epoch": signer.key_epoch,
        "key_version": signer.key_version,
        "mldsa87_custody_sha512": digest(public_record["mldsa87_custody"]),
        "ed448_custody_sha512": digest(public_record["ed448_custody"]),
        "dual_custody_admission_sha512": (
            verification.dual_custody_admission_sha512
        ),
        "mldsa87": {
            "algorithm": "ML-DSA-87",
            "fingerprint": verification.mldsa87_fingerprint,
            "signature_b64": _b64(signer.mldsa87_private_key.sign(message)),
        },
        "ed448": {
            "algorithm": "Ed448",
            "fingerprint": verification.ed448_fingerprint,
            "signature_b64": _b64(signer.ed448_private_key.sign(message)),
        },
    }


def verify_hybrid(
    unsigned: Mapping[str, Any],
    signatures: Any,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
) -> bool:
    try:
        if (
            type(signatures) is not dict
            or set(signatures) != _SIGNATURE_FIELDS
            or signatures.get("signature_profile") != HYBRID_SIGNATURE_PROFILE
            or signatures.get("verification_rule")
            != DUAL_SIGNATURE_VERIFICATION_RULE
            or signatures.get("transition_policy")
            != DUAL_SIGNATURE_TRANSITION_POLICY
            or signatures.get("lane_independence_required") is not True
            or not is_sha512(owner_pinned_context_digest)
            or not digest_equal(trust_context.context_digest, owner_pinned_context_digest)
            or signatures.get("context_digest") != owner_pinned_context_digest
        ):
            return False
        expected_identity = {
            "context_id": trust_context.context_id,
            "provider_id": trust_context.provider_id,
            "key_id": trust_context.key_id,
            "custody_class": trust_context.custody_class,
            "signer_class": trust_context.signer_class,
            "purpose": trust_context.purpose,
            "key_epoch": trust_context.key_epoch,
            "key_version": trust_context.key_version,
            "dual_custody_admission_sha512": (
                trust_context.dual_custody_admission_sha512
            ),
        }
        if any(signatures.get(field) != value for field, value in expected_identity.items()):
            return False
        if trust_context.signer_class == TEST_ONLY and not trust_context.allow_test_only:
            return False
        public_record = trust_context.public_record()
        if (
            signatures.get("mldsa87_custody_sha512")
            != digest(public_record["mldsa87_custody"])
            or signatures.get("ed448_custody_sha512")
            != digest(public_record["ed448_custody"])
        ):
            return False
        ml = signatures.get("mldsa87")
        ed = signatures.get("ed448")
        if type(ml) is not dict or set(ml) != _LANE_FIELDS:
            return False
        if type(ed) is not dict or set(ed) != _LANE_FIELDS:
            return False
        if (
            ml.get("algorithm") != "ML-DSA-87"
            or ml.get("fingerprint") != trust_context.mldsa87_fingerprint
            or ed.get("algorithm") != "Ed448"
            or ed.get("fingerprint") != trust_context.ed448_fingerprint
        ):
            return False
        message = _bound_message(
            unsigned, trust_context.purpose, owner_pinned_context_digest
        )
        trust_context.mldsa87_public_key.verify(
            _decode_b64_exact(
                ml.get("signature_b64"),
                length=4_627,
                code="mldsa87_signature_encoding_invalid",
            ),
            message,
        )
        trust_context.ed448_public_key.verify(
            _decode_b64_exact(
                ed.get("signature_b64"),
                length=114,
                code="ed448_signature_encoding_invalid",
            ),
            message,
        )
        return True
    except (InvalidSignature, LocalTrustSignatureError, TypeError, ValueError):
        return False


def verification_context_from_record(
    record: Any,
    *,
    owner_pinned_context_digest: str,
    allow_test_only: bool = False,
) -> HybridVerificationContext:
    if type(record) is not dict or set(record) != {
        "schema_id", "context_id", "provider_id", "key_id", "custody_class",
        "signer_class", "purpose", "signature_profile", "mldsa87_public_key_b64",
        "mldsa87_fingerprint", "ed448_public_key_b64", "ed448_fingerprint",
        "software_custody_limitation", "external_custody_required", "context_digest",
        "verification_rule", "transition_policy", "lane_independence_required",
        "key_epoch", "key_version", "dual_custody_admission_sha512",
        "mldsa87_custody", "ed448_custody",
    }:
        raise LocalTrustSignatureError("trust_context_record_invalid")
    try:
        ml_record = record["mldsa87_custody"]
        ed_record = record["ed448_custody"]
        lane_fields = {
            "algorithm", "provider_id", "key_id", "key_version", "key_epoch",
            "rotation_epoch", "custody_class", "custody_reference",
            "signer_class", "lifecycle_status", "revoked_at_epoch",
            "external_custody_admitted", "custody_admission_sha512",
            "non_exportable",
        }
        if (
            type(ml_record) is not dict
            or set(ml_record) != lane_fields
            or type(ed_record) is not dict
            or set(ed_record) != lane_fields
        ):
            raise LocalTrustSignatureError("lane_custody_record_invalid")
        ml_custody = DualSignatureLaneCustody(
            algorithm=ml_record["algorithm"],
            provider_id=ml_record["provider_id"],
            key_version=ml_record["key_version"],
            key_epoch=ml_record["key_epoch"],
            rotation_epoch=ml_record["rotation_epoch"],
            custody_class=ml_record["custody_class"],
            custody_reference=ml_record["custody_reference"],
            signer_class=ml_record["signer_class"],
            lifecycle_status=ml_record["lifecycle_status"],
            revoked_at_epoch=ml_record["revoked_at_epoch"],
            external_custody_admitted=ml_record["external_custody_admitted"],
            custody_admission_sha512=ml_record["custody_admission_sha512"],
            non_exportable=ml_record["non_exportable"],
        )
        ed_custody = DualSignatureLaneCustody(
            algorithm=ed_record["algorithm"],
            provider_id=ed_record["provider_id"],
            key_version=ed_record["key_version"],
            key_epoch=ed_record["key_epoch"],
            rotation_epoch=ed_record["rotation_epoch"],
            custody_class=ed_record["custody_class"],
            custody_reference=ed_record["custody_reference"],
            signer_class=ed_record["signer_class"],
            lifecycle_status=ed_record["lifecycle_status"],
            revoked_at_epoch=ed_record["revoked_at_epoch"],
            external_custody_admitted=ed_record["external_custody_admitted"],
            custody_admission_sha512=ed_record["custody_admission_sha512"],
            non_exportable=ed_record["non_exportable"],
        )
        context = HybridVerificationContext(
            context_id=record["context_id"],
            provider_id=record["provider_id"],
            key_id=record["key_id"],
            custody_class=record["custody_class"],
            signer_class=record["signer_class"],
            purpose=record["purpose"],
            mldsa87_public_key=MLDSA87PublicKey.from_public_bytes(
                _decode_b64_exact(
                    record["mldsa87_public_key_b64"],
                    length=2_592,
                    code="mldsa87_public_key_encoding_invalid",
                )
            ),
            ed448_public_key=Ed448PublicKey.from_public_bytes(
                _decode_b64_exact(
                    record["ed448_public_key_b64"],
                    length=57,
                    code="ed448_public_key_encoding_invalid",
                )
            ),
            allow_test_only=allow_test_only,
            key_epoch=record["key_epoch"],
            key_version=record["key_version"],
            dual_custody_admission_sha512=record[
                "dual_custody_admission_sha512"
            ],
            mldsa87_custody=ml_custody,
            ed448_custody=ed_custody,
        )
    except (TypeError, ValueError) as exc:
        raise LocalTrustSignatureError("trust_context_public_key_invalid") from exc
    expected = context.public_record()
    if (
        record != expected
        or not digest_equal(expected["context_digest"], owner_pinned_context_digest)
        or record.get("signature_profile") != HYBRID_SIGNATURE_PROFILE
        or record.get("verification_rule") != DUAL_SIGNATURE_VERIFICATION_RULE
        or record.get("transition_policy") != DUAL_SIGNATURE_TRANSITION_POLICY
        or record.get("lane_independence_required") is not True
        or record.get("software_custody_limitation") is not (context.signer_class == TEST_ONLY)
        or record.get("external_custody_required") is not (context.signer_class == PRODUCTION)
    ):
        raise LocalTrustSignatureError("trust_context_not_owner_pinned")
    return context


__all__ = [
    "PRODUCTION_DUAL_CUSTODY_CLASS",
    "DualSignatureLaneCustody",
    "HybridSigningContext",
    "HybridVerificationContext",
    "LocalTrustSignatureError",
    "raw_public_key_key_id",
    "sign_hybrid",
    "verification_context_from_record",
    "verify_hybrid",
]
