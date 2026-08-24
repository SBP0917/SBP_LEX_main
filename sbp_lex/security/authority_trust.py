from __future__ import annotations

"""Deployment-owned trust boundary for V2 authority provenance.

This is an implementation-defined mechanical contract.  It authenticates
externally supplied evidence; it does not define an authority hierarchy,
jurisdiction rule, classification taxonomy, policy, legal precedence, or
issuer semantics.
"""

import base64
import binascii
import hmac
import os
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    HybridSignatureError,
    HybridVerificationContext,
    is_hybrid_provider,
)
from sbp_lex.security.integrity import canonical_integrity_hash, is_sha512
from sbp_lex.security.signature_provider import (
    GENERIC_SIGNING_PURPOSE,
    verify_signed_object,
)


AUTHORITY_TRUST_CONTEXT_SCHEMA_ID: Final = (
    "sbp.lex.v2.authority-provenance-trust-context/1"
)
AUTHORITY_CLOCK_RECEIPT_SCHEMA_ID: Final = (
    "sbp.lex.v2.authority-provenance-clock-receipt/1"
)
AUTHORITY_REGISTRY_HEAD_SCHEMA_ID: Final = (
    "sbp.lex.v2.authority-provenance-registry-head/1"
)

AUTHORITY_TRUST_ROLE_OWNER: Final = "owner"
AUTHORITY_TRUST_ROLE_IDENTITY: Final = "sovereign_identity"
AUTHORITY_TRUST_ROLE_BOUNDARY: Final = "authority_boundary"
AUTHORITY_TRUST_ROLE_SKG: Final = "skg_authority"
AUTHORITY_TRUST_ROLE_PROVENANCE: Final = "authority_provenance"
AUTHORITY_TRUST_ROLE_CLOCK: Final = "trusted_clock"
AUTHORITY_TRUST_ROLE_REGISTRY: Final = "authority_registry"
AUTHORITY_TRUST_REQUIRED_ROLES: Final = (
    AUTHORITY_TRUST_ROLE_IDENTITY,
    AUTHORITY_TRUST_ROLE_BOUNDARY,
    AUTHORITY_TRUST_ROLE_SKG,
    AUTHORITY_TRUST_ROLE_PROVENANCE,
    AUTHORITY_TRUST_ROLE_CLOCK,
    AUTHORITY_TRUST_ROLE_REGISTRY,
)

TEST_ONLY_FIXTURE_CLASS: Final = "TEST_ONLY_NONPRODUCTION_FIXTURE"
_MODE_PRODUCTION: Final = "PRODUCTION"
_MODE_TEST_ONLY: Final = "TEST_ONLY"
_RUNTIME_MODE: Final = os.environ.get(
    "SBP_LEX_AUTHORITY_PROVENANCE_RUNTIME_MODE", _MODE_PRODUCTION
)
_PRODUCTION_CONTEXT_ID: Final = os.environ.get(
    "SBP_LEX_AUTHORITY_PROVENANCE_CONTEXT_ID"
)
_PRODUCTION_CONTEXT_DIGEST: Final = os.environ.get(
    "SBP_LEX_AUTHORITY_PROVENANCE_CONTEXT_DIGEST"
)
_PRODUCTION_OWNER_PUBLIC_KEY_HEX: Final = os.environ.get(
    "SBP_LEX_AUTHORITY_PROVENANCE_OWNER_PUBLIC_KEY_HEX"
)
_PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST: Final = os.environ.get(
    "SBP_LEX_AUTHORITY_PROVENANCE_OWNER_HYBRID_CONTEXT_DIGEST"
)

_SIGNED_FIELDS = frozenset({"digest", "signature", "verified"})
_SIGNATURE_FIELDS = {
    "provider_id",
    "algorithm",
    "key_id",
    "custody_class",
    "effect_authority",
    "signature_b64",
}


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _public_key_bytes(provider: Any) -> bytes | None:
    try:
        key = getattr(provider, "public_key")
        if callable(key):
            key = key()
        if not isinstance(key, Ed25519PublicKey):
            return None
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:
        return None


def _hybrid_verification_context(
    provider: Any,
) -> HybridVerificationContext | None:
    if not is_hybrid_provider(provider):
        return None
    try:
        context = provider.hybrid_verification_context(
            allow_test_only=_RUNTIME_MODE == _MODE_TEST_ONLY
        )
        return context if isinstance(context, HybridVerificationContext) else None
    except (HybridSignatureError, TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class AuthorityTrustRolePin:
    role: str
    provider_id: str
    algorithm: str
    key_id: str
    custody_class: str
    effect_authority: bool
    ed25519_public_key: bytes | None
    public_key_sha512: str
    evaluator_id: str
    evaluator_version: str
    authority_credential_id: str
    hybrid_verification_context: HybridVerificationContext | None = None

    def __post_init__(self) -> None:
        if (
            not all(
                _text(value)
                for value in (
                    self.role,
                    self.provider_id,
                    self.algorithm,
                    self.key_id,
                    self.custody_class,
                    self.evaluator_id,
                    self.evaluator_version,
                    self.authority_credential_id,
                )
            )
            or type(self.effect_authority) is not bool
        ):
            raise ValueError("AUTHORITY_TRUST_ROLE_PIN_INVALID")
        if self.algorithm == "Ed25519":
            if (
                type(self.ed25519_public_key) is not bytes
                or len(self.ed25519_public_key) != 32
                or self.hybrid_verification_context is not None
                or not is_sha512(self.public_key_sha512)
                or sha512(self.ed25519_public_key).hexdigest()
                != self.public_key_sha512
                or self.key_id != self.public_key_sha512
            ):
                raise ValueError("AUTHORITY_TRUST_ROLE_PIN_INVALID")
        elif self.algorithm == HYBRID_SUITE_ID:
            context = self.hybrid_verification_context
            if (
                self.ed25519_public_key is not None
                or not isinstance(context, HybridVerificationContext)
                or self.provider_id != context.provider_id
                or self.key_id != context.key_id
                or self.custody_class != context.custody_class
                or self.effect_authority is not context.effect_authority
                or self.public_key_sha512 != context.context_digest
            ):
                raise ValueError("AUTHORITY_TRUST_ROLE_PIN_INVALID")
        else:
            raise ValueError("AUTHORITY_TRUST_ROLE_PIN_INVALID")

    def document(self) -> dict[str, Any]:
        common = {
            "role": self.role,
            "provider_id": self.provider_id,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "custody_class": self.custody_class,
            "effect_authority": self.effect_authority,
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "authority_credential_id": self.authority_credential_id,
        }
        if self.algorithm == HYBRID_SUITE_ID:
            context = self.hybrid_verification_context
            assert context is not None
            return {
                **common,
                "hybrid_context": context.public_record(),
                "hybrid_context_digest": context.context_digest,
            }
        assert self.ed25519_public_key is not None
        return {
            **common,
            "ed25519_public_key_hex": self.ed25519_public_key.hex(),
            "public_key_sha512": self.public_key_sha512,
        }


@dataclass(frozen=True, slots=True)
class AuthorityProvenanceTrustContext:
    context_id: str
    context_version: str
    role_pins: tuple[AuthorityTrustRolePin, ...]
    minimum_clock_sequence: int
    minimum_registry_sequence: int
    minimum_registry_head_digest: str
    signed_context_record: dict[str, Any]
    context_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "signed_context_record", _deep_exact(self.signed_context_record)
        )
        if (
            not _text(self.context_id)
            or not _text(self.context_version)
            or tuple(pin.role for pin in self.role_pins)
            != AUTHORITY_TRUST_REQUIRED_ROLES
            or type(self.minimum_clock_sequence) is not int
            or self.minimum_clock_sequence < 0
            or type(self.minimum_registry_sequence) is not int
            or self.minimum_registry_sequence < 0
            or not is_sha512(self.minimum_registry_head_digest)
            or not is_sha512(self.context_digest)
        ):
            raise ValueError("AUTHORITY_TRUST_CONTEXT_INVALID")

    def role_pin(self, role: str) -> AuthorityTrustRolePin | None:
        return next((pin for pin in self.role_pins if pin.role == role), None)


@dataclass(frozen=True, slots=True)
class AuthorityProvenanceDependencies:
    fixed_context_id: str
    owner_pinned_context_digest: str

    def __post_init__(self) -> None:
        if not _text(self.fixed_context_id) or not is_sha512(
            self.owner_pinned_context_digest
        ):
            raise ValueError("AUTHORITY_PROVENANCE_DEPENDENCY_PIN_INVALID")


class AuthorityTrustedClock(Protocol):
    def current_time_receipt(
        self, *, context_id: str, request_fingerprint: str
    ) -> dict[str, Any]: ...


class AuthorityRegistryHeadProvider(Protocol):
    def current_registry_head(
        self, *, context_id: str, request_fingerprint: str
    ) -> dict[str, Any]: ...


class AuthorityProvenanceEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_credential_id: str

    def evaluate_authority_provenance(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class _RegisteredBoundary:
    context: AuthorityProvenanceTrustContext
    evaluator: Any
    trusted_clock: Any
    registry_head_provider: Any
    dependency_ids: tuple[int, int, int]


_BOUNDARIES: dict[str, _RegisteredBoundary] = {}
_TEST_ONLY_PINS: tuple[str, str, bytes | str] | None = None


def _deep_exact(value: Any) -> Any:
    # Canonical round-trip gives an immutable-by-alias JSON-compatible copy.
    import json

    return json.loads(canonical_json_bytes(value))


def verify_pinned_signed_object(
    value: dict[str, Any],
    *,
    role_pin: AuthorityTrustRolePin,
    purpose: str = GENERIC_SIGNING_PURPOSE,
) -> bool:
    """Verify with immutable pinned public material, never signer callbacks."""

    try:
        if role_pin.algorithm == HYBRID_SUITE_ID:
            context = role_pin.hybrid_verification_context
            return (
                context is not None
                and verify_signed_object(
                    value,
                    provider=None,
                    trust_context=context,
                    owner_pinned_context_digest=context.context_digest,
                    purpose=purpose,
                    allow_legacy_non_effect=False,
                )
            )
        # Ed25519 v1 is retained only for explicitly TEST_ONLY legacy
        # verification. Production authority admission can never use it.
        if _RUNTIME_MODE != _MODE_TEST_ONLY:
            return False
        if type(value) is not dict or not _SIGNED_FIELDS.issubset(value):
            return False
        signature = value.get("signature")
        if type(signature) is not dict or set(signature) != _SIGNATURE_FIELDS:
            return False
        if (
            signature.get("provider_id") != role_pin.provider_id
            or signature.get("algorithm") != role_pin.algorithm
            or signature.get("key_id") != role_pin.key_id
            or signature.get("custody_class") != role_pin.custody_class
            or signature.get("effect_authority") is not role_pin.effect_authority
        ):
            return False
        payload = {
            key: item for key, item in value.items() if key not in _SIGNED_FIELDS
        }
        payload_bytes = canonical_json_bytes(payload)
        digest = sha512(payload_bytes).hexdigest()
        if not hmac.compare_digest(value.get("digest", ""), digest):
            return False
        encoded = signature.get("signature_b64")
        if not _text(encoded):
            return False
        signature_bytes = base64.b64decode(encoded, validate=True)
        if role_pin.ed25519_public_key is None:
            return False
        Ed25519PublicKey.from_public_bytes(role_pin.ed25519_public_key).verify(
            signature_bytes, payload_bytes
        )
        return True
    except (InvalidSignature, binascii.Error, TypeError, ValueError):
        return False


def _owner_pin(owner_provider: Any) -> AuthorityTrustRolePin | None:
    hybrid_context = _hybrid_verification_context(owner_provider)
    if hybrid_context is not None:
        try:
            return AuthorityTrustRolePin(
                role=AUTHORITY_TRUST_ROLE_OWNER,
                provider_id=hybrid_context.provider_id,
                algorithm=HYBRID_SUITE_ID,
                key_id=hybrid_context.key_id,
                custody_class=hybrid_context.custody_class,
                effect_authority=hybrid_context.effect_authority,
                ed25519_public_key=None,
                public_key_sha512=hybrid_context.context_digest,
                evaluator_id="DEPLOYMENT_OWNER",
                evaluator_version="2",
                authority_credential_id="DEPLOYMENT_OWNER_HYBRID_PIN",
                hybrid_verification_context=hybrid_context,
            )
        except ValueError:
            return None
    raw = _public_key_bytes(owner_provider)
    values = (
        getattr(owner_provider, "provider_id", None),
        getattr(owner_provider, "algorithm", None),
        getattr(owner_provider, "key_id", None),
        getattr(owner_provider, "custody_class", None),
    )
    if raw is None or not all(_text(value) for value in values):
        return None
    try:
        return AuthorityTrustRolePin(
            role=AUTHORITY_TRUST_ROLE_OWNER,
            provider_id=values[0],
            algorithm=values[1],
            key_id=values[2],
            custody_class=values[3],
            effect_authority=(
                getattr(owner_provider, "effect_authority", None) is True
            ),
            ed25519_public_key=raw,
            public_key_sha512=sha512(raw).hexdigest(),
            evaluator_id="DEPLOYMENT_OWNER",
            evaluator_version="1",
            authority_credential_id="DEPLOYMENT_OWNER_PIN",
        )
    except ValueError:
        return None


def role_pin_from_provider(
    *,
    role: str,
    provider: Any,
    evaluator_id: str,
    evaluator_version: str,
    authority_credential_id: str,
) -> AuthorityTrustRolePin:
    """Build pin material; registration still requires independent owner pins."""

    hybrid_context = _hybrid_verification_context(provider)
    if hybrid_context is not None:
        return AuthorityTrustRolePin(
            role=role,
            provider_id=hybrid_context.provider_id,
            algorithm=HYBRID_SUITE_ID,
            key_id=hybrid_context.key_id,
            custody_class=hybrid_context.custody_class,
            effect_authority=hybrid_context.effect_authority,
            ed25519_public_key=None,
            public_key_sha512=hybrid_context.context_digest,
            evaluator_id=evaluator_id,
            evaluator_version=evaluator_version,
            authority_credential_id=authority_credential_id,
            hybrid_verification_context=hybrid_context,
        )
    raw = _public_key_bytes(provider)
    if raw is None:
        raise ValueError("AUTHORITY_TRUST_PROVIDER_PUBLIC_KEY_INVALID")
    return AuthorityTrustRolePin(
        role=role,
        provider_id=getattr(provider, "provider_id", None),
        algorithm=getattr(provider, "algorithm", None),
        key_id=getattr(provider, "key_id", None),
        custody_class=getattr(provider, "custody_class", None),
        effect_authority=(getattr(provider, "effect_authority", None) is True),
        ed25519_public_key=raw,
        public_key_sha512=sha512(raw).hexdigest(),
        evaluator_id=evaluator_id,
        evaluator_version=evaluator_version,
        authority_credential_id=authority_credential_id,
    )


def authority_trust_context_payload(
    *,
    context_id: str,
    context_version: str,
    role_pins: tuple[AuthorityTrustRolePin, ...],
    minimum_clock_sequence: int,
    minimum_registry_sequence: int,
    minimum_registry_head_digest: str,
) -> dict[str, Any]:
    return {
        "schema_id": AUTHORITY_TRUST_CONTEXT_SCHEMA_ID,
        "context_id": context_id,
        "context_version": context_version,
        "role_pins": [pin.document() for pin in role_pins],
        "minimum_clock_sequence": minimum_clock_sequence,
        "minimum_registry_sequence": minimum_registry_sequence,
        "minimum_registry_head_digest": minimum_registry_head_digest,
        "authority_semantics_externally_supplied": True,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
        "downstream_override_permitted": False,
    }


def _register(
    *,
    expected_pins: tuple[str, str, bytes | str],
    signed_context_record: dict[str, Any],
    owner_provider: Any,
    role_pins: tuple[AuthorityTrustRolePin, ...],
    evaluator: Any,
    trusted_clock: Any,
    registry_head_provider: Any,
    require_test_fixtures: bool,
) -> AuthorityProvenanceTrustContext:
    context_id, context_digest, owner_public_key = expected_pins
    owner_pin = _owner_pin(owner_provider)
    observed_owner_key: bytes | str | None = None
    if owner_pin is not None:
        observed_owner_key = (
            owner_pin.hybrid_verification_context.context_digest
            if owner_pin.hybrid_verification_context is not None
            else owner_pin.ed25519_public_key
        )
    payload = {
        key: value
        for key, value in signed_context_record.items()
        if key not in _SIGNED_FIELDS
    } if type(signed_context_record) is dict else None
    if (
        owner_pin is None
        or observed_owner_key != owner_public_key
        or type(payload) is not dict
        or payload.get("context_id") != context_id
        or signed_context_record.get("digest") != context_digest
        or not verify_pinned_signed_object(
            signed_context_record, role_pin=owner_pin
        )
        or tuple(pin.role for pin in role_pins) != AUTHORITY_TRUST_REQUIRED_ROLES
        or payload.get("role_pins") != [pin.document() for pin in role_pins]
    ):
        raise ValueError("AUTHORITY_TRUST_DEPLOYMENT_PIN_MISMATCH")
    dependencies = (evaluator, trusted_clock, registry_head_provider)
    if require_test_fixtures and any(
        getattr(dependency, "fixture_class", None) != TEST_ONLY_FIXTURE_CLASS
        for dependency in dependencies
    ):
        raise ValueError("AUTHORITY_TRUST_TEST_FIXTURE_MARKER_REQUIRED")
    if context_id in _BOUNDARIES:
        raise ValueError("AUTHORITY_TRUST_CONTEXT_ALREADY_REGISTERED")
    context = AuthorityProvenanceTrustContext(
        context_id=context_id,
        context_version=payload.get("context_version"),
        role_pins=role_pins,
        minimum_clock_sequence=payload.get("minimum_clock_sequence"),
        minimum_registry_sequence=payload.get("minimum_registry_sequence"),
        minimum_registry_head_digest=payload.get(
            "minimum_registry_head_digest"
        ),
        signed_context_record=signed_context_record,
        context_digest=context_digest,
    )
    _BOUNDARIES[context_id] = _RegisteredBoundary(
        context=context,
        evaluator=evaluator,
        trusted_clock=trusted_clock,
        registry_head_provider=registry_head_provider,
        dependency_ids=tuple(id(item) for item in dependencies),
    )
    return context


def install_production_authority_trust_context(
    *,
    signed_context_record: dict[str, Any],
    owner_provider: Any,
    role_pins: tuple[AuthorityTrustRolePin, ...],
    evaluator: Any,
    trusted_clock: Any,
    registry_head_provider: Any,
) -> AuthorityProvenanceTrustContext:
    if _RUNTIME_MODE != _MODE_PRODUCTION:
        raise RuntimeError("PRODUCTION_AUTHORITY_TRUST_API_DISABLED")
    if (
        not _text(_PRODUCTION_CONTEXT_ID)
        or not is_sha512(_PRODUCTION_CONTEXT_DIGEST)
        or not is_sha512(_PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST)
        or not is_hybrid_provider(owner_provider)
    ):
        raise RuntimeError("PRODUCTION_AUTHORITY_TRUST_PINS_MISSING")
    return _register(
        expected_pins=(
            _PRODUCTION_CONTEXT_ID,
            _PRODUCTION_CONTEXT_DIGEST,
            _PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST,
        ),
        signed_context_record=signed_context_record,
        owner_provider=owner_provider,
        role_pins=role_pins,
        evaluator=evaluator,
        trusted_clock=trusted_clock,
        registry_head_provider=registry_head_provider,
        require_test_fixtures=False,
    )


def _install_test_only_authority_trust_pins(
    *, context_id: str, context_digest: str, owner_public_key_hex: str
) -> None:
    global _TEST_ONLY_PINS
    if _RUNTIME_MODE != _MODE_TEST_ONLY:
        raise RuntimeError("TEST_ONLY_AUTHORITY_TRUST_API_DISABLED")
    try:
        owner_key: bytes | str = (
            owner_public_key_hex
            if is_sha512(owner_public_key_hex)
            else bytes.fromhex(owner_public_key_hex)
        )
    except ValueError as exc:
        raise ValueError("TEST_ONLY_AUTHORITY_TRUST_PINS_INVALID") from exc
    pins = (context_id, context_digest, owner_key)
    if (
        not _text(context_id)
        or not is_sha512(context_digest)
        or (
            type(owner_key) is bytes
            and len(owner_key) != 32
        )
        or (
            type(owner_key) is str
            and not is_sha512(owner_key)
        )
    ):
        raise ValueError("TEST_ONLY_AUTHORITY_TRUST_PINS_INVALID")
    if _TEST_ONLY_PINS is not None and _TEST_ONLY_PINS != pins:
        raise ValueError("TEST_ONLY_AUTHORITY_TRUST_PINS_ALREADY_FIXED")
    _TEST_ONLY_PINS = pins


def _register_test_only_authority_trust_context(
    *,
    signed_context_record: dict[str, Any],
    owner_provider: Any,
    role_pins: tuple[AuthorityTrustRolePin, ...],
    evaluator: Any,
    trusted_clock: Any,
    registry_head_provider: Any,
) -> AuthorityProvenanceTrustContext:
    if _RUNTIME_MODE != _MODE_TEST_ONLY:
        raise RuntimeError("TEST_ONLY_AUTHORITY_TRUST_API_DISABLED")
    if _TEST_ONLY_PINS is None:
        raise ValueError("TEST_ONLY_AUTHORITY_TRUST_PINS_REQUIRED")
    return _register(
        expected_pins=_TEST_ONLY_PINS,
        signed_context_record=signed_context_record,
        owner_provider=owner_provider,
        role_pins=role_pins,
        evaluator=evaluator,
        trusted_clock=trusted_clock,
        registry_head_provider=registry_head_provider,
        require_test_fixtures=True,
    )


def _reset_test_only_authority_trust() -> None:
    global _TEST_ONLY_PINS
    if _RUNTIME_MODE != _MODE_TEST_ONLY:
        raise RuntimeError("TEST_ONLY_AUTHORITY_TRUST_API_DISABLED")
    _BOUNDARIES.clear()
    _TEST_ONLY_PINS = None


def resolve_authority_trust_boundary(
    dependencies: AuthorityProvenanceDependencies | None,
) -> _RegisteredBoundary | None:
    if not isinstance(dependencies, AuthorityProvenanceDependencies):
        return None
    boundary = _BOUNDARIES.get(dependencies.fixed_context_id)
    if (
        boundary is None
        or boundary.context.context_digest
        != dependencies.owner_pinned_context_digest
        or boundary.dependency_ids
        != (
            id(boundary.evaluator),
            id(boundary.trusted_clock),
            id(boundary.registry_head_provider),
        )
    ):
        return None
    return boundary


def provider_matches_role(
    provider: Any,
    *,
    dependencies: AuthorityProvenanceDependencies | None,
    role: str,
) -> bool:
    boundary = resolve_authority_trust_boundary(dependencies)
    pin = boundary.context.role_pin(role) if boundary else None
    hybrid_context = _hybrid_verification_context(provider)
    if pin is not None and pin.algorithm == HYBRID_SUITE_ID:
        return (
            hybrid_context is not None
            and pin.hybrid_verification_context is not None
            and hybrid_context.context_digest
            == pin.hybrid_verification_context.context_digest
            and hybrid_context.provider_id == pin.provider_id
            and hybrid_context.key_id == pin.key_id
            and hybrid_context.custody_class == pin.custody_class
        )
    raw = _public_key_bytes(provider)
    return (
        pin is not None
        and raw == pin.ed25519_public_key
        and getattr(provider, "provider_id", None) == pin.provider_id
        and getattr(provider, "algorithm", None) == pin.algorithm
        and getattr(provider, "key_id", None) == pin.key_id
        and getattr(provider, "custody_class", None) == pin.custody_class
    )


def _receipt_exact(
    receipt: Any,
    *,
    pin: AuthorityTrustRolePin,
    schema_id: str,
    context_id: str,
    request_fingerprint: str,
) -> bool:
    payload_fields = {
        "schema_id",
        "context_id",
        "request_fingerprint",
        "sequence",
        "previous_digest",
        "observed_at",
    }
    if schema_id == AUTHORITY_REGISTRY_HEAD_SCHEMA_ID:
        payload_fields.add("head_digest")
    return (
        type(receipt) is dict
        and set(receipt) == payload_fields | _SIGNED_FIELDS
        and receipt.get("schema_id") == schema_id
        and receipt.get("context_id") == context_id
        and receipt.get("request_fingerprint") == request_fingerprint
        and type(receipt.get("sequence")) is int
        and receipt["sequence"] >= 0
        and is_sha512(receipt.get("previous_digest"))
        and type(receipt.get("observed_at")) is int
        and receipt["observed_at"] >= 0
        and (
            schema_id != AUTHORITY_REGISTRY_HEAD_SCHEMA_ID
            or is_sha512(receipt.get("head_digest"))
        )
        and verify_pinned_signed_object(receipt, role_pin=pin)
    )


def current_authority_trust_evidence(
    *,
    dependencies: AuthorityProvenanceDependencies | None,
    request_fingerprint: str,
) -> tuple[
    AuthorityProvenanceTrustContext,
    dict[str, Any],
    dict[str, Any],
] | None:
    try:
        boundary = resolve_authority_trust_boundary(dependencies)
        if boundary is None or not is_sha512(request_fingerprint):
            return None
        context = boundary.context
        clock_pin = context.role_pin(AUTHORITY_TRUST_ROLE_CLOCK)
        registry_pin = context.role_pin(AUTHORITY_TRUST_ROLE_REGISTRY)
        if clock_pin is None or registry_pin is None:
            return None
        clock = boundary.trusted_clock.current_time_receipt(
            context_id=context.context_id,
            request_fingerprint=request_fingerprint,
        )
        registry = boundary.registry_head_provider.current_registry_head(
            context_id=context.context_id,
            request_fingerprint=request_fingerprint,
        )
        if (
            not _receipt_exact(
                clock,
                pin=clock_pin,
                schema_id=AUTHORITY_CLOCK_RECEIPT_SCHEMA_ID,
                context_id=context.context_id,
                request_fingerprint=request_fingerprint,
            )
            or not _receipt_exact(
                registry,
                pin=registry_pin,
                schema_id=AUTHORITY_REGISTRY_HEAD_SCHEMA_ID,
                context_id=context.context_id,
                request_fingerprint=request_fingerprint,
            )
            or clock["sequence"] < context.minimum_clock_sequence
            or registry["sequence"] < context.minimum_registry_sequence
            or (
                registry["sequence"] == context.minimum_registry_sequence
                and registry["head_digest"]
                != context.minimum_registry_head_digest
            )
            or registry["observed_at"] != clock["observed_at"]
        ):
            return None
        return context, clock, registry
    except Exception:
        return None


def authority_trust_evidence_still_current(
    *,
    dependencies: AuthorityProvenanceDependencies | None,
    request_fingerprint: str,
    clock_receipt: dict[str, Any],
    registry_head: dict[str, Any],
) -> bool:
    current = current_authority_trust_evidence(
        dependencies=dependencies,
        request_fingerprint=request_fingerprint,
    )
    return (
        current is not None
        and current[1] == clock_receipt
        and current[2] == registry_head
    )


__all__ = [
    "AUTHORITY_CLOCK_RECEIPT_SCHEMA_ID",
    "AUTHORITY_REGISTRY_HEAD_SCHEMA_ID",
    "AUTHORITY_TRUST_CONTEXT_SCHEMA_ID",
    "AUTHORITY_TRUST_REQUIRED_ROLES",
    "AUTHORITY_TRUST_ROLE_BOUNDARY",
    "AUTHORITY_TRUST_ROLE_CLOCK",
    "AUTHORITY_TRUST_ROLE_IDENTITY",
    "AUTHORITY_TRUST_ROLE_PROVENANCE",
    "AUTHORITY_TRUST_ROLE_REGISTRY",
    "AUTHORITY_TRUST_ROLE_SKG",
    "AuthorityProvenanceDependencies",
    "AuthorityProvenanceTrustContext",
    "AuthorityTrustRolePin",
    "TEST_ONLY_FIXTURE_CLASS",
    "authority_trust_context_payload",
    "authority_trust_evidence_still_current",
    "current_authority_trust_evidence",
    "install_production_authority_trust_context",
    "provider_matches_role",
    "resolve_authority_trust_boundary",
    "role_pin_from_provider",
    "verify_pinned_signed_object",
]
