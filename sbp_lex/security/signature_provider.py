from __future__ import annotations

import base64
import binascii
import hmac
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Dict, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.hybrid_signature import (
    GENERIC_SIGNING_PURPOSE,
    HYBRID_ENVELOPE_SCHEMA_ID,
    HYBRID_SUITE_ID,
    HybridMLDSA87Ed448SoftwareProvider,
    HybridSignatureError,
    HybridVerificationContext,
    build_hybrid_signed_object,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)


class SignatureProviderUnavailable(RuntimeError):
    """Raised when signing is attempted without an injected real provider."""


class SignatureProvider(Protocol):
    provider_id: str
    algorithm: str
    key_id: str
    custody_class: str
    token_signing_admitted: bool
    three_p_attestation_admitted: bool
    framework_attestation_admitted: bool
    licence_attestation_admitted: bool
    skg_attestation_admitted: bool
    lifecycle_attestation_admitted: bool
    effect_authority: bool

    def sign(self, message: bytes, *, key_id: str) -> bytes: ...

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class Ed25519SoftwareProvider:
    """Real Ed25519 provider with a caller-supplied private key.

    The implementation performs genuine Ed25519 signing. Its process-memory
    custody class can authenticate internal V2 tokens but can never satisfy the
    separate hardware-custody or effect-authority lanes.
    """

    _private_key: Ed25519PrivateKey
    provider_id: str
    key_id: str
    algorithm: str = "Ed25519"
    custody_class: str = "PROCESS_MEMORY_SOFTWARE_KEY"
    signature_profile: str = "ED25519_LEGACY_V1"
    legacy_non_effect_only: bool = True
    signer_class: str = "TEST_ONLY"
    token_signing_admitted: bool = True
    three_p_attestation_admitted: bool = False
    framework_attestation_admitted: bool = False
    licence_attestation_admitted: bool = False
    skg_attestation_admitted: bool = False
    lifecycle_attestation_admitted: bool = False
    effect_authority: bool = False

    @classmethod
    def from_private_key(
        cls,
        private_key: Ed25519PrivateKey,
        *,
        three_p_attestation_admitted: bool = False,
        framework_attestation_admitted: bool = False,
        licence_attestation_admitted: bool = False,
        skg_attestation_admitted: bool = False,
        lifecycle_attestation_admitted: bool = False,
    ) -> "Ed25519SoftwareProvider":
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("ED25519_PRIVATE_KEY_REQUIRED")
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = sha512(public_bytes).hexdigest()
        return cls(
            _private_key=private_key,
            provider_id=f"ed25519-software:{fingerprint}",
            key_id=fingerprint,
            three_p_attestation_admitted=three_p_attestation_admitted,
            framework_attestation_admitted=framework_attestation_admitted,
            licence_attestation_admitted=licence_attestation_admitted,
            skg_attestation_admitted=skg_attestation_admitted,
            lifecycle_attestation_admitted=lifecycle_attestation_admitted,
        )

    @classmethod
    def from_encrypted_pem(
        cls,
        pem: bytes,
        *,
        password: bytes,
        three_p_attestation_admitted: bool = False,
        framework_attestation_admitted: bool = False,
        licence_attestation_admitted: bool = False,
        skg_attestation_admitted: bool = False,
        lifecycle_attestation_admitted: bool = False,
    ) -> "Ed25519SoftwareProvider":
        if type(pem) is not bytes or not pem:
            raise ValueError("ENCRYPTED_PRIVATE_KEY_PEM_REQUIRED")
        if type(password) is not bytes or not password:
            raise ValueError("PRIVATE_KEY_PASSWORD_REQUIRED")
        key = serialization.load_pem_private_key(pem, password=password)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("ED25519_PRIVATE_KEY_REQUIRED")
        return cls.from_private_key(
            key,
            three_p_attestation_admitted=three_p_attestation_admitted,
            framework_attestation_admitted=framework_attestation_admitted,
            licence_attestation_admitted=licence_attestation_admitted,
            skg_attestation_admitted=skg_attestation_admitted,
            lifecycle_attestation_admitted=lifecycle_attestation_admitted,
        )

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise ValueError("SIGNING_KEY_ID_MISMATCH")
        if type(message) is not bytes or not message:
            raise ValueError("SIGNING_MESSAGE_INVALID")
        return self._private_key.sign(message)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        if type(message) is not bytes or not message:
            return False
        if type(signature) is not bytes or not signature:
            return False
        try:
            self.public_key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


_RESERVED_FIELDS = frozenset({"digest", "signature", "verified"})
_FORBIDDEN_PROVIDER_TERMS = ("TEST", "MOCK", "STUB", "FIXTURE", "PLACEHOLDER")


def _payload_bytes(payload: Dict[str, Any]) -> bytes:
    if type(payload) is not dict:
        raise TypeError("SIGNED_PAYLOAD_MUST_BE_EXACT_DICT")
    if _RESERVED_FIELDS.intersection(payload):
        raise ValueError("SIGNED_PAYLOAD_CONTAINS_RESERVED_FIELD")
    return canonical_json_bytes(payload)


def _provider_metadata(
    provider: SignatureProvider | None,
) -> tuple[str, str, str, str, bool]:
    if provider is None:
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_NOT_INJECTED")
    provider_id = getattr(provider, "provider_id", None)
    algorithm = getattr(provider, "algorithm", None)
    key_id = getattr(provider, "key_id", None)
    custody_class = getattr(provider, "custody_class", None)
    if not all(
        type(value) is str and value
        for value in (provider_id, algorithm, key_id, custody_class)
    ):
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_METADATA_INVALID")
    if getattr(provider, "token_signing_admitted", None) is not True:
        raise SignatureProviderUnavailable("TOKEN_SIGNING_PROVIDER_NOT_ADMITTED")
    if (
        algorithm != "Ed25519"
        or getattr(provider, "legacy_non_effect_only", True) is not True
        or getattr(provider, "effect_authority", None) is True
    ):
        raise SignatureProviderUnavailable("LEGACY_SIGNATURE_PROVIDER_NOT_ADMITTED")
    if (
        not isinstance(provider_id, str)
        or not isinstance(algorithm, str)
        or not isinstance(key_id, str)
        or not isinstance(custody_class, str)
    ):
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_METADATA_INVALID")
    joined = "|".join((provider_id, algorithm, key_id, custody_class)).upper()
    if any(term in joined for term in _FORBIDDEN_PROVIDER_TERMS):
        raise SignatureProviderUnavailable("NONPRODUCTION_PROVIDER_METADATA_REJECTED")
    if not callable(getattr(provider, "sign", None)) or not callable(
        getattr(provider, "verify", None)
    ):
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_METHODS_MISSING")
    return (
        provider_id,
        algorithm,
        key_id,
        custody_class,
        getattr(provider, "effect_authority", None) is True,
    )


def compute_digest(payload: Dict[str, Any]) -> str:
    """Canonical payload digest. The digest is never treated as a signature."""

    return sha512(_payload_bytes(payload)).hexdigest()


def build_signed_object(
    payload: Dict[str, Any],
    *,
    provider: SignatureProvider | None,
    purpose: str = GENERIC_SIGNING_PURPOSE,
) -> Dict[str, Any]:
    """Build an exact V2 hybrid object; never downgrade to legacy signing."""

    if provider is None:
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_NOT_INJECTED")
    if is_hybrid_provider(provider):
        try:
            return build_hybrid_signed_object(
                payload,
                provider=provider,
                purpose=purpose,
            )
        except (HybridSignatureError, TypeError, ValueError) as exc:
            raise SignatureProviderUnavailable(str(exc)) from exc

    raise SignatureProviderUnavailable("HYBRID_SIGNATURE_PROVIDER_REQUIRED")


def build_legacy_non_effect_signed_object(
    payload: Dict[str, Any],
    *,
    provider: SignatureProvider | None,
) -> Dict[str, Any]:
    """Build the historical Ed25519 v1 envelope for explicit inspection only."""

    provider_id, algorithm, key_id, custody_class, effect_authority = (
        _provider_metadata(provider)
    )
    if provider is None:
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_NOT_INJECTED")
    payload_bytes = _payload_bytes(payload)
    signature_bytes = provider.sign(payload_bytes, key_id=key_id)
    if type(signature_bytes) is not bytes or not signature_bytes:
        raise SignatureProviderUnavailable("SIGNATURE_PROVIDER_RETURNED_INVALID_BYTES")
    return {
        **payload,
        "digest": sha512(payload_bytes).hexdigest(),
        "signature": {
            "provider_id": provider_id,
            "algorithm": algorithm,
            "key_id": key_id,
            "custody_class": custody_class,
            "effect_authority": effect_authority,
            "signature_b64": base64.b64encode(signature_bytes).decode("ascii"),
        },
        "verified": False,
    }


def verify_signed_object(
    obj: Dict[str, Any],
    *,
    provider: SignatureProvider | None,
    require_effect_authority: bool = False,
    purpose: str = GENERIC_SIGNING_PURPOSE,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
    allow_legacy_non_effect: bool = False,
) -> bool:
    """Verify an exact hybrid envelope or an explicit legacy non-effect v1 object."""

    signature = obj.get("signature") if type(obj) is dict else None
    if (
        type(signature) is dict
        and signature.get("schema_id") == HYBRID_ENVELOPE_SCHEMA_ID
    ):
        try:
            context = trust_context
            if (
                not isinstance(context, HybridVerificationContext)
                or type(owner_pinned_context_digest) is not str
            ):
                return False
            return verify_hybrid_signed_object(
                obj,
                trust_context=context,
                owner_pinned_context_digest=owner_pinned_context_digest,
                expected_purpose=purpose,
                require_effect_authority=require_effect_authority,
            )
        except (HybridSignatureError, TypeError, ValueError):
            return False

    if not allow_legacy_non_effect or require_effect_authority:
        return False

    try:
        expected_metadata = _provider_metadata(provider)
    except SignatureProviderUnavailable:
        return False
    if (
        type(obj) is not dict
        or "digest" not in obj
        or "signature" not in obj
        or obj.get("verified") is not False
    ):
        return False
    signature = obj.get("signature")
    expected_fields = {
        "provider_id",
        "algorithm",
        "key_id",
        "custody_class",
        "effect_authority",
        "signature_b64",
    }
    if type(signature) is not dict or set(signature) != expected_fields:
        return False
    metadata_fields = (
        signature.get("provider_id"),
        signature.get("algorithm"),
        signature.get("key_id"),
        signature.get("custody_class"),
        signature.get("effect_authority") is True,
    )
    if metadata_fields != expected_metadata:
        return False
    if require_effect_authority and metadata_fields[-1] is not True:
        return False

    payload = {key: value for key, value in obj.items() if key not in _RESERVED_FIELDS}
    try:
        payload_bytes = _payload_bytes(payload)
    except (TypeError, ValueError):
        return False
    observed_digest = obj.get("digest")
    expected_digest = sha512(payload_bytes).hexdigest()
    if type(observed_digest) is not str or not hmac.compare_digest(
        observed_digest,
        expected_digest,
    ):
        return False
    encoded = signature.get("signature_b64")
    if type(encoded) is not str or not encoded:
        return False
    try:
        signature_bytes = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        if provider is None:
            return False
        return provider.verify(
            payload_bytes,
            signature_bytes,
            key_id=signature["key_id"],
        ) is True
    except Exception:
        return False


def verify_legacy_non_effect_signed_object(
    obj: Dict[str, Any],
    *,
    provider: SignatureProvider | None,
) -> bool:
    """Verify only the historical Ed25519 v1 non-effect envelope.

    This deliberately named compatibility API is not an authority, admission,
    token, permit, execution, or physical-effect verification boundary.
    """

    signature = obj.get("signature") if type(obj) is dict else None
    if (
        type(signature) is not dict
        or signature.get("algorithm") != "Ed25519"
        or signature.get("effect_authority") is not False
    ):
        return False
    return verify_signed_object(
        obj,
        provider=provider,
        require_effect_authority=False,
        allow_legacy_non_effect=True,
    )


__all__ = [
    "Ed25519SoftwareProvider",
    "GENERIC_SIGNING_PURPOSE",
    "HYBRID_SUITE_ID",
    "HybridMLDSA87Ed448SoftwareProvider",
    "HybridVerificationContext",
    "SignatureProvider",
    "SignatureProviderUnavailable",
    "build_legacy_non_effect_signed_object",
    "build_signed_object",
    "compute_digest",
    "verify_signed_object",
    "verify_legacy_non_effect_signed_object",
]
