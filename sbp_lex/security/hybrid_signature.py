"""Strict full-strength ML-DSA-87 AND Ed448 signatures for active V2 use.

The module owns only cryptographic mechanics.  Production admission remains an
out-of-band deployment decision: the included software provider is TEST_ONLY
and can never claim effect authority or external custody.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import unicodedata
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Final, Mapping, Protocol

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

from sbp_lex.assurance.envelope import canonical_json_bytes


STRICT_DUAL_SIGNATURE_SUITE_ID: Final = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1"
# Compatibility import name only. Envelopes bearing the former suite string are
# rejected; this alias does not preserve the old wire/profile semantics.
HYBRID_SUITE_ID: Final = STRICT_DUAL_SIGNATURE_SUITE_ID
RETIRED_HYBRID_SUITE_ID: Final = "SBP_LEX_V2_HYBRID_ML_DSA_87_ED448_V2"
HYBRID_ENVELOPE_SCHEMA_ID: Final = "sbp.lex.v2.strict-dual-signature-envelope/1"
HYBRID_CONTEXT_SCHEMA_ID: Final = "sbp.lex.v2.strict-dual-signature-context/1"
HYBRID_DOMAIN: Final = "SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1"
HYBRID_PREIMAGE_DOMAIN: Final = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1\x00"
HYBRID_KEY_ID_DOMAIN: Final = b"SBP-LEX/V2/STRICT-DUAL-SIGNATURE/KEY-ID/1\x00"
STRICT_DUAL_SIGNATURE_SUITE_VERSION: Final = 1
STRICT_DUAL_SIGNATURE_VERIFICATION_RULE: Final = "ALL_LANES_REQUIRED"
STRICT_DUAL_SIGNATURE_SECURITY_PROFILE: Final = (
    "FULL_STRENGTH_ML_DSA_87_AND_ED448"
)
STRICT_DUAL_SIGNATURE_TRANSITION_POLICY: Final = (
    "NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK"
)
STRICT_DUAL_SIGNATURE_STATUS: Final = "ACTIVE_REQUIRED_V2"
GENERIC_SIGNING_PURPOSE: Final = "SBP_LEX_V2_GENERIC_SIGNED_OBJECT"

TEST_ONLY_SIGNER: Final = "TEST_ONLY"
PRODUCTION_SIGNER: Final = "PRODUCTION"
TEST_ONLY_CUSTODY_CLASS: Final = "TEST_ONLY_PROCESS_MEMORY_SOFTWARE_KEYS"
PRODUCTION_DUAL_CUSTODY_CLASS: Final = "INDEPENDENT_EXTERNAL_TWO_LANE_CUSTODY"
ACTIVE_LANE_STATUS: Final = "ACTIVE"
REVOKED_LANE_STATUS: Final = "REVOKED"

ML_DSA_87_PUBLIC_KEY_BYTES: Final = 2_592
ML_DSA_87_SIGNATURE_BYTES: Final = 4_627
ED448_PUBLIC_KEY_BYTES: Final = 57
ED448_SIGNATURE_BYTES: Final = 114

_RESERVED_FIELDS = frozenset({"digest", "signature", "verified"})
_LANE_ORDER = ("ML-DSA-87", "Ed448")
_DESCRIPTOR_FIELDS = {
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
}
_CONTEXT_LANE_FIELDS = _DESCRIPTOR_FIELDS | {"public_key_b64"}
_CONTEXT_FIELDS = {
    "schema_id",
    "suite",
    "suite_version",
    "verification_rule",
    "security_profile",
    "transition_policy",
    "lane_independence_required",
    "domain",
    "provider_id",
    "key_version",
    "custody_class",
    "key_epoch",
    "signer_class",
    "effect_authority",
    "external_custody_admitted",
    "external_custody_admission_sha512",
    "ordered_key_set_digest",
    "lanes",
}
_PROTECTED_FIELDS = {
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
}
_ENVELOPE_FIELDS = _PROTECTED_FIELDS | {"signatures"}
_SIGNATURE_LANE_FIELDS = {"ordinal", "algorithm", "key_id", "signature_b64"}


class HybridSignatureError(ValueError):
    """Raised when the exact V2 hybrid signature contract is violated."""


@dataclass(frozen=True, slots=True)
class SignatureSuitePolicy:
    """Closed, versioned policy for one independently admitted signature suite."""

    suite_id: str
    suite_version: int
    required_lanes: tuple[str, str]
    verification_rule: str
    security_profile: str
    transition_policy: str
    status: str


STRICT_DUAL_SIGNATURE_POLICY: Final = SignatureSuitePolicy(
    suite_id=STRICT_DUAL_SIGNATURE_SUITE_ID,
    suite_version=STRICT_DUAL_SIGNATURE_SUITE_VERSION,
    required_lanes=("ML-DSA-87", "Ed448"),
    verification_rule=STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
    security_profile=STRICT_DUAL_SIGNATURE_SECURITY_PROFILE,
    transition_policy=STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
    status=STRICT_DUAL_SIGNATURE_STATUS,
)
ADMITTED_SIGNATURE_SUITE_POLICIES: Final = (
    STRICT_DUAL_SIGNATURE_POLICY,
)


def admitted_signature_suite_policy(suite_id: Any) -> SignatureSuitePolicy:
    """Resolve only an explicitly admitted suite; never infer a fallback."""

    for policy in ADMITTED_SIGNATURE_SUITE_POLICIES:
        if suite_id == policy.suite_id and policy.status == STRICT_DUAL_SIGNATURE_STATUS:
            return policy
    raise HybridSignatureError("SIGNATURE_SUITE_NOT_EXPLICITLY_ADMITTED")


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _sha512(value: bytes) -> str:
    return sha512(value).hexdigest()


def _is_sha512(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_b64_exact(value: Any, *, length: int, code: str) -> bytes:
    if not _text(value):
        raise HybridSignatureError(code)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HybridSignatureError(code) from exc
    if len(decoded) != length or not hmac.compare_digest(_b64(decoded), value):
        raise HybridSignatureError(code)
    return decoded


def _purpose(value: Any) -> str:
    if not _text(value) or unicodedata.normalize("NFC", value) != value:
        raise HybridSignatureError("HYBRID_SIGNATURE_PURPOSE_INVALID")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise HybridSignatureError("HYBRID_SIGNATURE_PURPOSE_INVALID") from exc
    if len(encoded) > 65_535:
        raise HybridSignatureError("HYBRID_SIGNATURE_PURPOSE_INVALID")
    return value


def _raw_public_key(key: MLDSA87PublicKey | Ed448PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True, slots=True)
class DualSignatureLaneCustody:
    """Independent custody and lifecycle record for one mandatory lane."""

    algorithm: str
    provider_id: str
    key_version: str
    key_epoch: int
    rotation_epoch: int
    custody_class: str
    custody_reference: str
    signer_class: str
    lifecycle_status: str = ACTIVE_LANE_STATUS
    revoked_at_epoch: int | None = None
    external_custody_admitted: bool = False
    custody_admission_sha512: str = "NONE"
    non_exportable: bool = False

    def __post_init__(self) -> None:
        if (
            self.algorithm not in _LANE_ORDER
            or not all(
                _text(value)
                for value in (
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
            or (
                self.revoked_at_epoch is not None
                and (
                    type(self.revoked_at_epoch) is not int
                    or self.revoked_at_epoch <= 0
                )
            )
        ):
            raise HybridSignatureError("DUAL_SIGNATURE_LANE_CUSTODY_INVALID")
        if self.lifecycle_status == ACTIVE_LANE_STATUS:
            if self.revoked_at_epoch is not None:
                raise HybridSignatureError("DUAL_SIGNATURE_ACTIVE_LANE_REVOKED")
        elif self.lifecycle_status == REVOKED_LANE_STATUS:
            if self.revoked_at_epoch is None:
                raise HybridSignatureError("DUAL_SIGNATURE_REVOCATION_EPOCH_REQUIRED")
        else:
            raise HybridSignatureError("DUAL_SIGNATURE_LANE_STATUS_INVALID")
        if self.signer_class == TEST_ONLY_SIGNER:
            if (
                self.external_custody_admitted
                or self.custody_admission_sha512 != "NONE"
                or self.non_exportable
                or self.custody_class != TEST_ONLY_CUSTODY_CLASS
            ):
                raise HybridSignatureError("DUAL_SIGNATURE_TEST_LANE_CUSTODY_INVALID")
        elif self.signer_class == PRODUCTION_SIGNER:
            if (
                not self.external_custody_admitted
                or not _is_sha512(self.custody_admission_sha512)
                or not self.non_exportable
                or self.custody_class == TEST_ONLY_CUSTODY_CLASS
            ):
                raise HybridSignatureError(
                    "DUAL_SIGNATURE_PRODUCTION_LANE_CUSTODY_NOT_ADMITTED"
                )
        else:
            raise HybridSignatureError("HYBRID_SIGNER_CLASS_INVALID")

    def descriptor(self, *, ordinal: int, key_id: str) -> dict[str, Any]:
        if self.algorithm != _LANE_ORDER[ordinal] or not _is_sha512(key_id):
            raise HybridSignatureError("DUAL_SIGNATURE_LANE_DESCRIPTOR_INVALID")
        return {
            "ordinal": ordinal,
            "algorithm": self.algorithm,
            "provider_id": self.provider_id,
            "key_id": key_id,
            "key_version": self.key_version,
            "key_epoch": self.key_epoch,
            "rotation_epoch": self.rotation_epoch,
            "revoked_at_epoch": self.revoked_at_epoch,
            "lifecycle_status": self.lifecycle_status,
            "custody_class": self.custody_class,
            "custody_reference": self.custody_reference,
            "external_custody_admitted": self.external_custody_admitted,
            "custody_admission_sha512": self.custody_admission_sha512,
            "non_exportable": self.non_exportable,
            "public_key_encoding": "RAW",
            "signature_encoding": "RAW",
        }


def _test_lane_custody(
    *, provider_id: str, algorithm: str, key_epoch: int, key_version: str
) -> DualSignatureLaneCustody:
    lane_token = "ml-dsa-87" if algorithm == "ML-DSA-87" else "ed448"
    return DualSignatureLaneCustody(
        algorithm=algorithm,
        provider_id=f"{provider_id}#{lane_token}",
        key_version=f"{key_version}:{lane_token}",
        key_epoch=key_epoch,
        rotation_epoch=key_epoch,
        custody_class=TEST_ONLY_CUSTODY_CLASS,
        custody_reference=f"{provider_id}/process-memory/{lane_token}",
        signer_class=TEST_ONLY_SIGNER,
    )


@dataclass(frozen=True, slots=True)
class HybridVerificationContext:
    """Owner-pinnable public verification material for one exact key epoch."""

    provider_id: str
    key_epoch: int
    key_version: str
    custody_class: str
    signer_class: str
    mldsa87_public_key: MLDSA87PublicKey
    ed448_public_key: Ed448PublicKey
    effect_authority: bool = False
    allow_test_only: bool = False
    external_custody_admitted: bool = False
    external_custody_admission_sha512: str = "NONE"
    mldsa87_custody: DualSignatureLaneCustody | None = None
    ed448_custody: DualSignatureLaneCustody | None = None

    def __post_init__(self) -> None:
        if (
            not all(
                _text(value)
                for value in (
                    self.provider_id,
                    self.key_version,
                    self.custody_class,
                    self.signer_class,
                )
            )
            or type(self.key_epoch) is not int
            or self.key_epoch <= 0
            or type(self.effect_authority) is not bool
            or type(self.allow_test_only) is not bool
            or type(self.external_custody_admitted) is not bool
            or not isinstance(self.mldsa87_public_key, MLDSA87PublicKey)
            or not isinstance(self.ed448_public_key, Ed448PublicKey)
        ):
            raise HybridSignatureError("HYBRID_VERIFICATION_CONTEXT_INVALID")

        mldsa87_custody = self.mldsa87_custody
        ed448_custody = self.ed448_custody
        if self.signer_class == TEST_ONLY_SIGNER:
            if mldsa87_custody is None:
                mldsa87_custody = _test_lane_custody(
                    provider_id=self.provider_id,
                    algorithm="ML-DSA-87",
                    key_epoch=self.key_epoch,
                    key_version=self.key_version,
                )
                object.__setattr__(self, "mldsa87_custody", mldsa87_custody)
            if ed448_custody is None:
                ed448_custody = _test_lane_custody(
                    provider_id=self.provider_id,
                    algorithm="Ed448",
                    key_epoch=self.key_epoch,
                    key_version=self.key_version,
                )
                object.__setattr__(self, "ed448_custody", ed448_custody)
        if not isinstance(
            mldsa87_custody, DualSignatureLaneCustody
        ) or not isinstance(ed448_custody, DualSignatureLaneCustody):
            raise HybridSignatureError("DUAL_SIGNATURE_TWO_LANE_CUSTODY_REQUIRED")
        if (
            mldsa87_custody.algorithm != "ML-DSA-87"
            or ed448_custody.algorithm != "Ed448"
            or mldsa87_custody.signer_class != self.signer_class
            or ed448_custody.signer_class != self.signer_class
            or mldsa87_custody.key_epoch != self.key_epoch
            or ed448_custody.key_epoch != self.key_epoch
            or mldsa87_custody.lifecycle_status != ACTIVE_LANE_STATUS
            or ed448_custody.lifecycle_status != ACTIVE_LANE_STATUS
            or mldsa87_custody.revoked_at_epoch is not None
            or ed448_custody.revoked_at_epoch is not None
        ):
            raise HybridSignatureError("DUAL_SIGNATURE_LANE_LIFECYCLE_INVALID")
        if (
            hmac.compare_digest(
                mldsa87_custody.provider_id, ed448_custody.provider_id
            )
            or hmac.compare_digest(
                mldsa87_custody.custody_reference,
                ed448_custody.custody_reference,
            )
        ):
            raise HybridSignatureError("DUAL_SIGNATURE_LANE_CUSTODY_NOT_INDEPENDENT")
        if self.signer_class == TEST_ONLY_SIGNER:
            if (
                not self.allow_test_only
                or self.effect_authority
                or self.external_custody_admitted
                or self.external_custody_admission_sha512 != "NONE"
                or self.custody_class != TEST_ONLY_CUSTODY_CLASS
            ):
                raise HybridSignatureError("HYBRID_TEST_ONLY_CONTEXT_INVALID")
        elif self.signer_class == PRODUCTION_SIGNER:
            if (
                not self.external_custody_admitted
                or not _is_sha512(self.external_custody_admission_sha512)
                or self.custody_class != PRODUCTION_DUAL_CUSTODY_CLASS
                or not mldsa87_custody.external_custody_admitted
                or not ed448_custody.external_custody_admitted
                or not mldsa87_custody.non_exportable
                or not ed448_custody.non_exportable
                or hmac.compare_digest(
                    mldsa87_custody.custody_admission_sha512,
                    ed448_custody.custody_admission_sha512,
                )
                or hmac.compare_digest(
                    self.external_custody_admission_sha512,
                    mldsa87_custody.custody_admission_sha512,
                )
                or hmac.compare_digest(
                    self.external_custody_admission_sha512,
                    ed448_custody.custody_admission_sha512,
                )
            ):
                raise HybridSignatureError(
                    "DUAL_SIGNATURE_PRODUCTION_INDEPENDENT_CUSTODY_NOT_ADMITTED"
                )
        else:
            raise HybridSignatureError("HYBRID_SIGNER_CLASS_INVALID")
        if (
            len(self.mldsa87_public_key_bytes) != ML_DSA_87_PUBLIC_KEY_BYTES
            or len(self.ed448_public_key_bytes) != ED448_PUBLIC_KEY_BYTES
            or hmac.compare_digest(self.mldsa87_key_id, self.ed448_key_id)
        ):
            raise HybridSignatureError("HYBRID_PUBLIC_KEY_SIZE_INVALID")

    @property
    def mldsa87_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.mldsa87_public_key)

    @property
    def ed448_public_key_bytes(self) -> bytes:
        return _raw_public_key(self.ed448_public_key)

    @property
    def mldsa87_key_id(self) -> str:
        return _sha512(self.mldsa87_public_key_bytes)

    @property
    def ed448_key_id(self) -> str:
        return _sha512(self.ed448_public_key_bytes)

    @property
    def ordered_key_set_digest(self) -> str:
        return _sha512(
            HYBRID_KEY_ID_DOMAIN
            + HYBRID_SUITE_ID.encode("ascii")
            + b"\x00"
            + bytes.fromhex(self.mldsa87_key_id)
            + bytes.fromhex(self.ed448_key_id)
        )

    @property
    def key_id(self) -> str:
        """Compatibility metadata for the ordered key-set digest."""

        return self.ordered_key_set_digest

    @property
    def lane_descriptors(self) -> list[dict[str, Any]]:
        if not isinstance(
            self.mldsa87_custody, DualSignatureLaneCustody
        ) or not isinstance(self.ed448_custody, DualSignatureLaneCustody):
            raise HybridSignatureError("DUAL_SIGNATURE_TWO_LANE_CUSTODY_REQUIRED")
        return [
            self.mldsa87_custody.descriptor(
                ordinal=0, key_id=self.mldsa87_key_id
            ),
            self.ed448_custody.descriptor(ordinal=1, key_id=self.ed448_key_id),
        ]

    def public_record(self) -> dict[str, Any]:
        lanes = []
        for descriptor, public_key in zip(
            self.lane_descriptors,
            (self.mldsa87_public_key_bytes, self.ed448_public_key_bytes),
        ):
            lanes.append({**descriptor, "public_key_b64": _b64(public_key)})
        return {
            "schema_id": HYBRID_CONTEXT_SCHEMA_ID,
            "suite": HYBRID_SUITE_ID,
            "suite_version": STRICT_DUAL_SIGNATURE_SUITE_VERSION,
            "verification_rule": STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
            "security_profile": STRICT_DUAL_SIGNATURE_SECURITY_PROFILE,
            "transition_policy": STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
            "lane_independence_required": True,
            "domain": HYBRID_DOMAIN,
            "provider_id": self.provider_id,
            "key_version": self.key_version,
            "custody_class": self.custody_class,
            "key_epoch": self.key_epoch,
            "signer_class": self.signer_class,
            "effect_authority": self.effect_authority,
            "external_custody_admitted": self.external_custody_admitted,
            "external_custody_admission_sha512": (
                self.external_custody_admission_sha512
            ),
            "ordered_key_set_digest": self.ordered_key_set_digest,
            "lanes": lanes,
        }

    @property
    def context_digest(self) -> str:
        return _sha512(canonical_json_bytes(self.public_record()))


class HybridSignatureProvider(Protocol):
    provider_id: str
    algorithm: str
    key_id: str
    key_epoch: int
    key_version: str
    custody_class: str
    signer_class: str
    effect_authority: bool

    def hybrid_verification_context(
        self, *, allow_test_only: bool = False
    ) -> HybridVerificationContext: ...

    def sign_hybrid_preimage(
        self, preimage: bytes, *, purpose: str, context_digest: str
    ) -> tuple[bytes, bytes]: ...


@dataclass(frozen=True, slots=True)
class HybridMLDSA87Ed448SoftwareProvider:
    """Strict dual signer with explicitly non-production process-memory keys."""

    _mldsa87_private_key: MLDSA87PrivateKey
    _ed448_private_key: Ed448PrivateKey
    provider_id: str
    key_epoch: int = 1
    key_version: str = "1"
    algorithm: str = HYBRID_SUITE_ID
    custody_class: str = TEST_ONLY_CUSTODY_CLASS
    signer_class: str = TEST_ONLY_SIGNER
    effect_authority: bool = False
    token_signing_admitted: bool = True
    three_p_attestation_admitted: bool = False
    framework_attestation_admitted: bool = False
    licence_attestation_admitted: bool = False
    skg_attestation_admitted: bool = False
    lifecycle_attestation_admitted: bool = False
    release_integrity_attestation_admitted: bool = False
    release_admission_attestation_admitted: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self._mldsa87_private_key, MLDSA87PrivateKey)
            or not isinstance(self._ed448_private_key, Ed448PrivateKey)
            or not _text(self.provider_id)
            or self.algorithm != HYBRID_SUITE_ID
            or self.custody_class != TEST_ONLY_CUSTODY_CLASS
            or self.signer_class != TEST_ONLY_SIGNER
            or self.effect_authority
        ):
            raise HybridSignatureError("HYBRID_SOFTWARE_PROVIDER_INVALID")
        # Exercise all structural validation at construction time.
        self.hybrid_verification_context(allow_test_only=True)

    @classmethod
    def generate(
        cls,
        *,
        provider_id: str,
        key_epoch: int = 1,
        key_version: str = "1",
        three_p_attestation_admitted: bool = False,
        framework_attestation_admitted: bool = False,
        licence_attestation_admitted: bool = False,
        skg_attestation_admitted: bool = False,
        lifecycle_attestation_admitted: bool = False,
        release_integrity_attestation_admitted: bool = False,
        release_admission_attestation_admitted: bool = False,
    ) -> "HybridMLDSA87Ed448SoftwareProvider":
        return cls(
            _mldsa87_private_key=MLDSA87PrivateKey.generate(),
            _ed448_private_key=Ed448PrivateKey.generate(),
            provider_id=provider_id,
            key_epoch=key_epoch,
            key_version=key_version,
            three_p_attestation_admitted=three_p_attestation_admitted,
            framework_attestation_admitted=framework_attestation_admitted,
            licence_attestation_admitted=licence_attestation_admitted,
            skg_attestation_admitted=skg_attestation_admitted,
            lifecycle_attestation_admitted=lifecycle_attestation_admitted,
            release_integrity_attestation_admitted=(
                release_integrity_attestation_admitted
            ),
            release_admission_attestation_admitted=(
                release_admission_attestation_admitted
            ),
        )

    @classmethod
    def from_private_keys(
        cls,
        mldsa87_private_key: MLDSA87PrivateKey,
        ed448_private_key: Ed448PrivateKey,
        *,
        provider_id: str,
        key_epoch: int = 1,
        key_version: str = "1",
        **admission_flags: bool,
    ) -> "HybridMLDSA87Ed448SoftwareProvider":
        return cls(
            _mldsa87_private_key=mldsa87_private_key,
            _ed448_private_key=ed448_private_key,
            provider_id=provider_id,
            key_epoch=key_epoch,
            key_version=key_version,
            **admission_flags,
        )

    @property
    def key_id(self) -> str:
        return self.hybrid_verification_context(allow_test_only=True).key_id

    def hybrid_verification_context(
        self, *, allow_test_only: bool = False
    ) -> HybridVerificationContext:
        return HybridVerificationContext(
            provider_id=self.provider_id,
            key_epoch=self.key_epoch,
            key_version=self.key_version,
            custody_class=self.custody_class,
            signer_class=self.signer_class,
            mldsa87_public_key=self._mldsa87_private_key.public_key(),
            ed448_public_key=self._ed448_private_key.public_key(),
            effect_authority=self.effect_authority,
            allow_test_only=allow_test_only,
        )

    def sign_hybrid_preimage(
        self, preimage: bytes, *, purpose: str, context_digest: str
    ) -> tuple[bytes, bytes]:
        if type(preimage) is not bytes or not preimage:
            raise HybridSignatureError("HYBRID_SIGNING_PREIMAGE_INVALID")
        _purpose(purpose)
        context = self.hybrid_verification_context(allow_test_only=True)
        if not hmac.compare_digest(context.context_digest, context_digest):
            raise HybridSignatureError("HYBRID_SIGNING_CONTEXT_MISMATCH")
        return (
            self._mldsa87_private_key.sign(preimage),
            self._ed448_private_key.sign(preimage),
        )


def is_hybrid_provider(provider: Any) -> bool:
    if provider is None:
        return False
    try:
        admitted_signature_suite_policy(getattr(provider, "algorithm", None))
    except HybridSignatureError:
        return False
    return callable(
        getattr(provider, "hybrid_verification_context", None)
    ) and callable(getattr(provider, "sign_hybrid_preimage", None))


def hybrid_envelope_shape_exact(value: Any) -> bool:
    """Validate the closed envelope shape and fixed encodings without trust."""

    try:
        if (
            type(value) is not dict
            or set(value) != _ENVELOPE_FIELDS
            or value.get("schema_id") != HYBRID_ENVELOPE_SCHEMA_ID
            or value.get("suite") != HYBRID_SUITE_ID
            or value.get("suite_version") != STRICT_DUAL_SIGNATURE_SUITE_VERSION
            or value.get("verification_rule")
            != STRICT_DUAL_SIGNATURE_VERIFICATION_RULE
            or value.get("security_profile")
            != STRICT_DUAL_SIGNATURE_SECURITY_PROFILE
            or value.get("transition_policy")
            != STRICT_DUAL_SIGNATURE_TRANSITION_POLICY
            or value.get("lane_independence_required") is not True
            or value.get("domain") != HYBRID_DOMAIN
            or _purpose(value.get("purpose")) != value.get("purpose")
            or type(value.get("key_epoch")) is not int
            or value["key_epoch"] <= 0
            or not _is_sha512(value.get("context_digest"))
            or not _is_sha512(value.get("payload_sha512"))
            or not _is_sha512(value.get("ordered_key_set_digest"))
            or value.get("signer_class") not in {
                TEST_ONLY_SIGNER,
                PRODUCTION_SIGNER,
            }
            or type(value.get("effect_authority")) is not bool
            or type(value.get("lanes")) is not list
            or len(value["lanes"]) != 2
            or type(value.get("signatures")) is not list
            or len(value["signatures"]) != 2
        ):
            return False
        for ordinal, (descriptor, signature) in enumerate(
            zip(value["lanes"], value["signatures"])
        ):
            if (
                type(descriptor) is not dict
                or set(descriptor) != _DESCRIPTOR_FIELDS
                or descriptor.get("ordinal") != ordinal
                or descriptor.get("algorithm") != _LANE_ORDER[ordinal]
                or not all(
                    _text(descriptor.get(field))
                    for field in (
                        "provider_id",
                        "key_id",
                        "key_version",
                        "custody_class",
                        "custody_reference",
                        "lifecycle_status",
                        "public_key_encoding",
                        "signature_encoding",
                    )
                )
                or descriptor.get("key_epoch") != value.get("key_epoch")
                or type(descriptor.get("rotation_epoch")) is not int
                or descriptor["rotation_epoch"] <= 0
                or descriptor["rotation_epoch"] > descriptor["key_epoch"]
                or descriptor.get("revoked_at_epoch") is not None
                or descriptor.get("lifecycle_status") != ACTIVE_LANE_STATUS
                or type(descriptor.get("external_custody_admitted")) is not bool
                or type(descriptor.get("non_exportable")) is not bool
                or not (
                    descriptor.get("custody_admission_sha512") == "NONE"
                    or _is_sha512(descriptor.get("custody_admission_sha512"))
                )
                or descriptor.get("public_key_encoding") != "RAW"
                or descriptor.get("signature_encoding") != "RAW"
                or not _is_sha512(descriptor.get("key_id"))
                or type(signature) is not dict
                or set(signature) != _SIGNATURE_LANE_FIELDS
                or signature.get("ordinal") != ordinal
                or signature.get("algorithm") != _LANE_ORDER[ordinal]
                or signature.get("key_id") != descriptor.get("key_id")
            ):
                return False
        if (
            value["lanes"][0]["provider_id"]
            == value["lanes"][1]["provider_id"]
            or value["lanes"][0]["custody_reference"]
            == value["lanes"][1]["custody_reference"]
        ):
            return False
        _decode_b64_exact(
            value["signatures"][0]["signature_b64"],
            length=ML_DSA_87_SIGNATURE_BYTES,
            code="HYBRID_ML_DSA_87_SIGNATURE_ENCODING_INVALID",
        )
        _decode_b64_exact(
            value["signatures"][1]["signature_b64"],
            length=ED448_SIGNATURE_BYTES,
            code="HYBRID_ED448_SIGNATURE_ENCODING_INVALID",
        )
        return True
    except (HybridSignatureError, KeyError, TypeError, ValueError):
        return False


def _payload(payload: Any) -> dict[str, Any]:
    if type(payload) is not dict:
        raise TypeError("SIGNED_PAYLOAD_MUST_BE_EXACT_DICT")
    if _RESERVED_FIELDS.intersection(payload):
        raise HybridSignatureError("SIGNED_PAYLOAD_CONTAINS_RESERVED_FIELD")
    canonical_json_bytes(payload)
    return payload


def _protected(
    *,
    context: HybridVerificationContext,
    purpose: str,
    payload_sha512: str,
) -> dict[str, Any]:
    return {
        "schema_id": HYBRID_ENVELOPE_SCHEMA_ID,
        "suite": HYBRID_SUITE_ID,
        "suite_version": STRICT_DUAL_SIGNATURE_SUITE_VERSION,
        "verification_rule": STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
        "security_profile": STRICT_DUAL_SIGNATURE_SECURITY_PROFILE,
        "transition_policy": STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
        "lane_independence_required": True,
        "purpose": _purpose(purpose),
        "domain": HYBRID_DOMAIN,
        "key_epoch": context.key_epoch,
        "context_digest": context.context_digest,
        "payload_sha512": payload_sha512,
        "signer_class": context.signer_class,
        "effect_authority": context.effect_authority,
        "ordered_key_set_digest": context.ordered_key_set_digest,
        "lanes": context.lane_descriptors,
    }


def hybrid_signature_preimage(
    payload: Mapping[str, Any], protected: Mapping[str, Any]
) -> bytes:
    purpose = _purpose(protected.get("purpose"))
    purpose_bytes = purpose.encode("utf-8")
    lanes = protected.get("lanes")
    if (
        protected.get("suite") != HYBRID_SUITE_ID
        or protected.get("suite_version") != STRICT_DUAL_SIGNATURE_SUITE_VERSION
        or protected.get("verification_rule")
        != STRICT_DUAL_SIGNATURE_VERIFICATION_RULE
        or protected.get("security_profile")
        != STRICT_DUAL_SIGNATURE_SECURITY_PROFILE
        or protected.get("transition_policy")
        != STRICT_DUAL_SIGNATURE_TRANSITION_POLICY
        or protected.get("lane_independence_required") is not True
        or protected.get("domain") != HYBRID_DOMAIN
        or type(lanes) is not list
        or len(lanes) != 2
        or type(protected.get("key_epoch")) is not int
        or protected["key_epoch"] <= 0
        or protected["key_epoch"] > 0xFFFF_FFFF_FFFF_FFFF
        or not _is_sha512(protected.get("payload_sha512"))
        or not _is_sha512(protected.get("context_digest"))
        or any(type(lane) is not dict for lane in lanes)
        or lanes[0].get("algorithm") != "ML-DSA-87"
        or lanes[1].get("algorithm") != "Ed448"
        or lanes[0].get("ordinal") != 0
        or lanes[1].get("ordinal") != 1
        or lanes[0].get("key_epoch") != protected.get("key_epoch")
        or lanes[1].get("key_epoch") != protected.get("key_epoch")
        or lanes[0].get("lifecycle_status") != ACTIVE_LANE_STATUS
        or lanes[1].get("lifecycle_status") != ACTIVE_LANE_STATUS
        or lanes[0].get("revoked_at_epoch") is not None
        or lanes[1].get("revoked_at_epoch") is not None
        or lanes[0].get("provider_id") == lanes[1].get("provider_id")
        or lanes[0].get("custody_reference")
        == lanes[1].get("custody_reference")
        or not _is_sha512(lanes[0].get("key_id"))
        or not _is_sha512(lanes[1].get("key_id"))
    ):
        raise HybridSignatureError("HYBRID_SIGNATURE_PREIMAGE_FIELDS_INVALID")
    payload_bytes = canonical_json_bytes(dict(payload))
    if _sha512(payload_bytes) != protected["payload_sha512"]:
        raise HybridSignatureError("HYBRID_SIGNATURE_PAYLOAD_DIGEST_MISMATCH")
    return (
        HYBRID_PREIMAGE_DOMAIN
        + HYBRID_SUITE_ID.encode("ascii")
        + b"\x00"
        + len(purpose_bytes).to_bytes(2, "big")
        + purpose_bytes
        + protected["key_epoch"].to_bytes(8, "big")
        + bytes.fromhex(lanes[0]["key_id"])
        + bytes.fromhex(lanes[1]["key_id"])
        + bytes.fromhex(protected["payload_sha512"])
        + bytes.fromhex(protected["context_digest"])
    )


def build_hybrid_signed_object(
    payload: dict[str, Any],
    *,
    provider: HybridSignatureProvider,
    purpose: str = GENERIC_SIGNING_PURPOSE,
) -> dict[str, Any]:
    checked_payload = _payload(payload)
    if not is_hybrid_provider(provider):
        raise HybridSignatureError("HYBRID_SIGNATURE_PROVIDER_REQUIRED")
    context = provider.hybrid_verification_context(allow_test_only=True)
    payload_bytes = canonical_json_bytes(checked_payload)
    payload_sha512 = _sha512(payload_bytes)
    protected = _protected(
        context=context,
        purpose=purpose,
        payload_sha512=payload_sha512,
    )
    preimage = hybrid_signature_preimage(checked_payload, protected)
    signatures = provider.sign_hybrid_preimage(
        preimage,
        purpose=protected["purpose"],
        context_digest=context.context_digest,
    )
    if (
        type(signatures) is not tuple
        or len(signatures) != 2
        or type(signatures[0]) is not bytes
        or type(signatures[1]) is not bytes
        or len(signatures[0]) != ML_DSA_87_SIGNATURE_BYTES
        or len(signatures[1]) != ED448_SIGNATURE_BYTES
    ):
        raise HybridSignatureError("HYBRID_SIGNATURE_PROVIDER_RESULT_INVALID")
    envelope = {
        **protected,
        "signatures": [
            {
                "ordinal": 0,
                "algorithm": "ML-DSA-87",
                "key_id": context.mldsa87_key_id,
                "signature_b64": _b64(signatures[0]),
            },
            {
                "ordinal": 1,
                "algorithm": "Ed448",
                "key_id": context.ed448_key_id,
                "signature_b64": _b64(signatures[1]),
            },
        ],
    }
    return {
        **checked_payload,
        "digest": payload_sha512,
        "signature": envelope,
        "verified": False,
    }


def verify_hybrid_signed_object(
    value: Any,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    expected_purpose: str = GENERIC_SIGNING_PURPOSE,
    require_effect_authority: bool = False,
) -> bool:
    try:
        if (
            type(value) is not dict
            or value.get("verified") is not False
            or not isinstance(trust_context, HybridVerificationContext)
            or not _is_sha512(owner_pinned_context_digest)
            or not hmac.compare_digest(
                trust_context.context_digest, owner_pinned_context_digest
            )
        ):
            return False
        signature = value.get("signature")
        if type(signature) is not dict or set(signature) != _ENVELOPE_FIELDS:
            return False
        payload = {
            key: item for key, item in value.items() if key not in _RESERVED_FIELDS
        }
        payload_bytes = canonical_json_bytes(payload)
        payload_sha512 = _sha512(payload_bytes)
        if (
            value.get("digest") != payload_sha512
            or signature.get("schema_id") != HYBRID_ENVELOPE_SCHEMA_ID
            or signature.get("suite") != HYBRID_SUITE_ID
            or signature.get("suite_version")
            != STRICT_DUAL_SIGNATURE_SUITE_VERSION
            or signature.get("verification_rule")
            != STRICT_DUAL_SIGNATURE_VERIFICATION_RULE
            or signature.get("security_profile")
            != STRICT_DUAL_SIGNATURE_SECURITY_PROFILE
            or signature.get("transition_policy")
            != STRICT_DUAL_SIGNATURE_TRANSITION_POLICY
            or signature.get("lane_independence_required") is not True
            or signature.get("purpose") != _purpose(expected_purpose)
            or signature.get("domain") != HYBRID_DOMAIN
            or signature.get("key_epoch") != trust_context.key_epoch
            or signature.get("context_digest") != owner_pinned_context_digest
            or signature.get("payload_sha512") != payload_sha512
            or signature.get("signer_class") != trust_context.signer_class
            or signature.get("effect_authority") is not trust_context.effect_authority
            or signature.get("ordered_key_set_digest")
            != trust_context.ordered_key_set_digest
            or signature.get("lanes") != trust_context.lane_descriptors
            or (require_effect_authority and not trust_context.effect_authority)
        ):
            return False
        if trust_context.signer_class == TEST_ONLY_SIGNER:
            if not trust_context.allow_test_only or require_effect_authority:
                return False
        elif (
            trust_context.signer_class != PRODUCTION_SIGNER
            or not trust_context.external_custody_admitted
            or not _is_sha512(trust_context.external_custody_admission_sha512)
        ):
            return False
        lanes = signature.get("signatures")
        if type(lanes) is not list or len(lanes) != 2:
            return False
        for ordinal, (lane, descriptor) in enumerate(
            zip(lanes, trust_context.lane_descriptors)
        ):
            if (
                type(lane) is not dict
                or set(lane) != _SIGNATURE_LANE_FIELDS
                or lane.get("ordinal") != ordinal
                or lane.get("algorithm") != _LANE_ORDER[ordinal]
                or lane.get("key_id") != descriptor["key_id"]
            ):
                return False
        mldsa_signature = _decode_b64_exact(
            lanes[0]["signature_b64"],
            length=ML_DSA_87_SIGNATURE_BYTES,
            code="HYBRID_ML_DSA_87_SIGNATURE_ENCODING_INVALID",
        )
        ed448_signature = _decode_b64_exact(
            lanes[1]["signature_b64"],
            length=ED448_SIGNATURE_BYTES,
            code="HYBRID_ED448_SIGNATURE_ENCODING_INVALID",
        )
        protected = {key: signature[key] for key in _PROTECTED_FIELDS}
        preimage = hybrid_signature_preimage(payload, protected)
        trust_context.mldsa87_public_key.verify(mldsa_signature, preimage)
        trust_context.ed448_public_key.verify(ed448_signature, preimage)
        return True
    except (
        HybridSignatureError,
        AttributeError,
        InvalidSignature,
        KeyError,
        TypeError,
        ValueError,
    ):
        return False


def verification_context_from_record(
    record: Any,
    *,
    owner_pinned_context_digest: str,
    allow_test_only: bool = False,
) -> HybridVerificationContext:
    if type(record) is not dict or set(record) != _CONTEXT_FIELDS:
        raise HybridSignatureError("HYBRID_CONTEXT_RECORD_INVALID")
    lanes = record.get("lanes")
    if type(lanes) is not list or len(lanes) != 2:
        raise HybridSignatureError("HYBRID_CONTEXT_LANES_INVALID")
    for ordinal, lane in enumerate(lanes):
        if (
            type(lane) is not dict
            or set(lane) != _CONTEXT_LANE_FIELDS
            or lane.get("ordinal") != ordinal
            or lane.get("algorithm") != _LANE_ORDER[ordinal]
        ):
            raise HybridSignatureError("HYBRID_CONTEXT_LANE_INVALID")
    ml_bytes = _decode_b64_exact(
        lanes[0]["public_key_b64"],
        length=ML_DSA_87_PUBLIC_KEY_BYTES,
        code="HYBRID_ML_DSA_87_PUBLIC_KEY_ENCODING_INVALID",
    )
    ed_bytes = _decode_b64_exact(
        lanes[1]["public_key_b64"],
        length=ED448_PUBLIC_KEY_BYTES,
        code="HYBRID_ED448_PUBLIC_KEY_ENCODING_INVALID",
    )
    try:
        mldsa87_custody = DualSignatureLaneCustody(
            algorithm=lanes[0]["algorithm"],
            provider_id=lanes[0]["provider_id"],
            key_version=lanes[0]["key_version"],
            key_epoch=lanes[0]["key_epoch"],
            rotation_epoch=lanes[0]["rotation_epoch"],
            custody_class=lanes[0]["custody_class"],
            custody_reference=lanes[0]["custody_reference"],
            signer_class=record["signer_class"],
            lifecycle_status=lanes[0]["lifecycle_status"],
            revoked_at_epoch=lanes[0]["revoked_at_epoch"],
            external_custody_admitted=lanes[0]["external_custody_admitted"],
            custody_admission_sha512=lanes[0]["custody_admission_sha512"],
            non_exportable=lanes[0]["non_exportable"],
        )
        ed448_custody = DualSignatureLaneCustody(
            algorithm=lanes[1]["algorithm"],
            provider_id=lanes[1]["provider_id"],
            key_version=lanes[1]["key_version"],
            key_epoch=lanes[1]["key_epoch"],
            rotation_epoch=lanes[1]["rotation_epoch"],
            custody_class=lanes[1]["custody_class"],
            custody_reference=lanes[1]["custody_reference"],
            signer_class=record["signer_class"],
            lifecycle_status=lanes[1]["lifecycle_status"],
            revoked_at_epoch=lanes[1]["revoked_at_epoch"],
            external_custody_admitted=lanes[1]["external_custody_admitted"],
            custody_admission_sha512=lanes[1]["custody_admission_sha512"],
            non_exportable=lanes[1]["non_exportable"],
        )
        context = HybridVerificationContext(
            provider_id=record["provider_id"],
            key_epoch=record["key_epoch"],
            key_version=record["key_version"],
            custody_class=record["custody_class"],
            signer_class=record["signer_class"],
            mldsa87_public_key=MLDSA87PublicKey.from_public_bytes(ml_bytes),
            ed448_public_key=Ed448PublicKey.from_public_bytes(ed_bytes),
            effect_authority=record["effect_authority"],
            allow_test_only=allow_test_only,
            external_custody_admitted=record["external_custody_admitted"],
            external_custody_admission_sha512=record[
                "external_custody_admission_sha512"
            ],
            mldsa87_custody=mldsa87_custody,
            ed448_custody=ed448_custody,
        )
    except (TypeError, ValueError) as exc:
        raise HybridSignatureError("HYBRID_CONTEXT_PUBLIC_KEY_INVALID") from exc
    if (
        record != context.public_record()
        or not _is_sha512(owner_pinned_context_digest)
        or not hmac.compare_digest(
            context.context_digest, owner_pinned_context_digest
        )
    ):
        raise HybridSignatureError("HYBRID_CONTEXT_NOT_OWNER_PINNED")
    return context


# Clear V2 names for new callers. Historical ``Hybrid*`` class names remain as
# source-level aliases only; they do not admit the retired wire-suite string.
StrictDualMLDSA87Ed448SoftwareProvider = HybridMLDSA87Ed448SoftwareProvider
StrictDualSignatureVerificationContext = HybridVerificationContext


__all__ = [
    "ACTIVE_LANE_STATUS",
    "ADMITTED_SIGNATURE_SUITE_POLICIES",
    "DualSignatureLaneCustody",
    "ED448_PUBLIC_KEY_BYTES",
    "ED448_SIGNATURE_BYTES",
    "GENERIC_SIGNING_PURPOSE",
    "HYBRID_CONTEXT_SCHEMA_ID",
    "HYBRID_DOMAIN",
    "HYBRID_ENVELOPE_SCHEMA_ID",
    "HYBRID_KEY_ID_DOMAIN",
    "HYBRID_PREIMAGE_DOMAIN",
    "HYBRID_SUITE_ID",
    "HybridMLDSA87Ed448SoftwareProvider",
    "HybridSignatureError",
    "HybridSignatureProvider",
    "HybridVerificationContext",
    "ML_DSA_87_PUBLIC_KEY_BYTES",
    "ML_DSA_87_SIGNATURE_BYTES",
    "PRODUCTION_SIGNER",
    "PRODUCTION_DUAL_CUSTODY_CLASS",
    "RETIRED_HYBRID_SUITE_ID",
    "REVOKED_LANE_STATUS",
    "STRICT_DUAL_SIGNATURE_POLICY",
    "STRICT_DUAL_SIGNATURE_SECURITY_PROFILE",
    "STRICT_DUAL_SIGNATURE_STATUS",
    "STRICT_DUAL_SIGNATURE_SUITE_ID",
    "STRICT_DUAL_SIGNATURE_SUITE_VERSION",
    "STRICT_DUAL_SIGNATURE_TRANSITION_POLICY",
    "STRICT_DUAL_SIGNATURE_VERIFICATION_RULE",
    "SignatureSuitePolicy",
    "StrictDualMLDSA87Ed448SoftwareProvider",
    "StrictDualSignatureVerificationContext",
    "TEST_ONLY_CUSTODY_CLASS",
    "TEST_ONLY_SIGNER",
    "build_hybrid_signed_object",
    "admitted_signature_suite_policy",
    "hybrid_signature_preimage",
    "hybrid_envelope_shape_exact",
    "is_hybrid_provider",
    "verification_context_from_record",
    "verify_hybrid_signed_object",
]
