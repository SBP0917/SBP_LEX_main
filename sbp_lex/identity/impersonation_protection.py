"""Implementation-defined V2 impersonation-protection mechanics.

The deployment trust root is one immutable :class:`ImpersonationTrustContext`.
Request callers do not select its owner pin, providers, live registry, replay
store, clock, or upstream verifiers independently.  The context resolves one
owner-signed record against deployment-pinned context and owner-key digests.

The component authenticates a pseudonymous proof-of-possession boundary.  It
does not establish biometric identity, issue identity, or grant access,
authority, a licence, execution authority, effect authority, or bypass.

Private composition-root isolation, durable production replay storage, and
signing-key custody are deployment dependencies and are not proven here.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import os
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Final, Protocol, TypeGuard

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.governance.three_p_doctrine import THREE_P_DOCTRINE_ID
from sbp_lex.identity.sovereign_identity import IDENTITY_VERIFIED
from sbp_lex.interface.authority_boundary import (
    BOUNDARY_PASS,
    STAKEHOLDER_CLASSES,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    PRODUCTION_SIGNER,
    HybridSignatureError,
    HybridVerificationContext,
    is_hybrid_provider,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    verify_signed_object,
)

IMPERSONATION_PROTECTION_CONTRACT_ID: Final = "SBP_LEX_V2_IMPERSONATION_PROTECTION"
IMPERSONATION_PROTECTION_SCHEMA_STATUS: Final = (
    "IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_SCHEMA"
)
IMPERSONATION_PROTECTION_SEMANTICS: Final = (
    "NO_BIOMETRIC_PROOF_NO_IDENTITY_ISSUANCE_NO_AUTHORITY_GRANT"
)
IMPERSONATION_PROTECTION_STAGE: Final = "impersonation_protection:proof_of_possession"

TRUST_CONTEXT_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_TRUST_CONTEXT"
LIVE_REGISTRY_SCHEMA: Final = "SBP_LEX_V2_LIVE_TRUST_REGISTRY_RECORD"
POSSESSION_PROOF_SCHEMA: Final = "SBP_LEX_V2_SUBJECT_POSSESSION_PROOF"
REPLAY_CLAIM_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_REPLAY_CLAIM"
REPLAY_HEAD_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_REPLAY_HEAD"
UPSTREAM_HASH_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_UPSTREAM_BINDING"
CLOCK_RECORD_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_AUTHENTICATED_CLOCK"
CLOCK_HEAD_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_DURABLE_CLOCK_HEAD"
CLOCK_HEAD_TRANSITION_SCHEMA: Final = (
    "SBP_LEX_V2_IMPERSONATION_DURABLE_CLOCK_HEAD_TRANSITION"
)
UPSTREAM_RECEIPT_SCHEMA: Final = (
    "SBP_LEX_V2_IMPERSONATION_UPSTREAM_VERIFICATION_RECEIPT"
)
REPLAY_PERSISTENCE_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_REPLAY_PERSISTENCE_RECEIPT"
_DURABLE_ANCHOR_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_DURABLE_STORE_ANCHOR"

IMPERSONATION_SIGNING_PURPOSES: Final = {
    TRUST_CONTEXT_SCHEMA: "SBP_LEX_V2_IMPERSONATION:TRUST_CONTEXT",
    LIVE_REGISTRY_SCHEMA: "SBP_LEX_V2_IMPERSONATION:LIVE_REGISTRY",
    POSSESSION_PROOF_SCHEMA: "SBP_LEX_V2_IMPERSONATION:POSSESSION_PROOF",
    REPLAY_CLAIM_SCHEMA: "SBP_LEX_V2_IMPERSONATION:REPLAY_CLAIM",
    REPLAY_HEAD_SCHEMA: "SBP_LEX_V2_IMPERSONATION:REPLAY_HEAD",
    CLOCK_RECORD_SCHEMA: "SBP_LEX_V2_IMPERSONATION:CLOCK_RECORD",
    CLOCK_HEAD_SCHEMA: "SBP_LEX_V2_IMPERSONATION:CLOCK_HEAD",
    CLOCK_HEAD_TRANSITION_SCHEMA: "SBP_LEX_V2_IMPERSONATION:CLOCK_TRANSITION",
    UPSTREAM_RECEIPT_SCHEMA: "SBP_LEX_V2_IMPERSONATION:UPSTREAM_RECEIPT",
    REPLAY_PERSISTENCE_SCHEMA: "SBP_LEX_V2_IMPERSONATION:REPLAY_PERSISTENCE",
    _DURABLE_ANCHOR_SCHEMA: "SBP_LEX_V2_IMPERSONATION:DURABLE_STORE_ANCHOR",
}


def impersonation_signing_purpose(schema: Any) -> str:
    """Return the exact signature domain for an impersonation record schema."""

    if type(schema) is not str or schema not in IMPERSONATION_SIGNING_PURPOSES:
        raise ValueError("IMPERSONATION_SIGNING_SCHEMA_NOT_ADMITTED")
    return IMPERSONATION_SIGNING_PURPOSES[schema]


SOVEREIGN_IDENTITY_COMPONENT: Final = "sovereign_identity"
AUTHORITY_BOUNDARY_COMPONENT: Final = "authority_boundary"

IMPERSONATION_PASS: Final = "PASS"
IMPERSONATION_DENY: Final = "DENY"
TRUST_ACTIVE: Final = "ACTIVE"
TRUST_REVOKED: Final = "REVOKED"
REPLAY_CLAIMED: Final = "CLAIMED"

NO_AUTHORIZATION_EFFECT: Final = {
    "access_granted": False,
    "authority_granted": False,
    "licence_granted": False,
    "execution_authority_granted": False,
    "effect_authority_granted": False,
    "pipeline_bypass_permitted": False,
}

DEPLOYMENT_DEPENDENCIES: Final = {
    "private_composition_root_isolation": "DEPLOYMENT_REQUIRED_NOT_PROVEN",
    "owner_pinned_live_registry": (
        "REPOSITORY_IMPLEMENTED_DEPLOYMENT_ADMISSION_REQUIRED"
    ),
    "durable_production_replay_storage": (
        "REPOSITORY_IMPLEMENTED_DEPLOYMENT_ADMISSION_REQUIRED"
    ),
    "authenticated_trusted_time_source": (
        "REPOSITORY_IMPLEMENTED_EXTERNAL_SOURCE_ADMISSION_REQUIRED"
    ),
    "durable_clock_head_storage": (
        "REPOSITORY_IMPLEMENTED_DEPLOYMENT_ADMISSION_REQUIRED"
    ),
    "signing_key_custody": "EXTERNAL_HSM_OR_EQUIVALENT_REQUIRED_NOT_PROVEN",
}

_RUNTIME_MODE_PRODUCTION: Final = "PRODUCTION"
_RUNTIME_MODE_TEST_ONLY: Final = "TEST_ONLY"
_RUNTIME_MODE: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_RUNTIME_MODE",
    _RUNTIME_MODE_PRODUCTION,
)
_PRODUCTION_CONTEXT_ID: Final = os.environ.get("SBP_LEX_IMPERSONATION_CONTEXT_ID")
_PRODUCTION_CONTEXT_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_CONTEXT_DIGEST"
)
_PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_OWNER_HYBRID_CONTEXT_DIGEST"
)
_PRODUCTION_REGISTRY_ADMISSION_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_REGISTRY_ADMISSION_DIGEST"
)
_PRODUCTION_REPLAY_ADMISSION_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_REPLAY_ADMISSION_DIGEST"
)
_PRODUCTION_TRUSTED_CLOCK_ADMISSION_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_TRUSTED_CLOCK_ADMISSION_DIGEST"
)
_PRODUCTION_CLOCK_HEAD_ADMISSION_DIGEST: Final = os.environ.get(
    "SBP_LEX_IMPERSONATION_CLOCK_HEAD_ADMISSION_DIGEST"
)

_PROVIDER_BINDING_FIELDS: Final = {
    "provider_id",
    "algorithm",
    "key_id",
    "custody_class",
    "effect_authority",
    "ed25519_public_key_fingerprint",
}
_VERIFIER_BINDING_FIELDS: Final = {
    "verifier_id",
    "verifier_version",
    "hash_stage",
    "receipt_provider_binding",
}
_CONTEXT_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "schema_status",
    "semantics",
    "three_p_doctrine_id",
    "context_id",
    "context_version",
    "context_sequence",
    "prior_context_digest",
    "owner_id",
    "registry_id",
    "owner_provider_binding",
    "registry_provider_binding",
    "subject_provider_binding",
    "replay_provider_binding",
    "clock_provider_binding",
    "clock_head_provider_binding",
    "subject_id",
    "participant_id",
    "stakeholder_class",
    "role_id",
    "mandate_id",
    "mandate_actions",
    "mandate_jurisdictions",
    "jurisdiction",
    "audience",
    "maximum_proof_age_ms",
    "minimum_registry_sequence",
    "minimum_authority_sequence",
    "minimum_revocation_sequence",
    "replay_namespace",
    "pseudonym_key_id",
    "sovereign_identity_verifier",
    "authority_boundary_verifier",
    "trusted_clock_id",
    "trusted_clock_version",
    "clock_head_id",
    "clock_head_version",
    "minimum_clock_sequence",
    "valid_from_ms",
    "valid_until_ms",
    "authorization_effect",
    "deployment_dependencies",
}
_SIGNED_FIELDS: Final = {"digest", "signature", "verified"}
_CONTEXT_FIELDS: Final = _CONTEXT_PAYLOAD_FIELDS | _SIGNED_FIELDS
_LIVE_REGISTRY_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "schema_status",
    "semantics",
    "context_id",
    "context_digest",
    "registry_id",
    "registry_sequence",
    "subject_id",
    "participant_id",
    "stakeholder_class",
    "role_id",
    "mandate_id",
    "mandate_actions",
    "mandate_jurisdictions",
    "jurisdiction",
    "subject_provider_binding",
    "authority_sequence",
    "revocation_status",
    "revocation_sequence",
    "valid_from_ms",
    "valid_until_ms",
}
_LIVE_REGISTRY_FIELDS: Final = _LIVE_REGISTRY_PAYLOAD_FIELDS | _SIGNED_FIELDS
_PROOF_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "schema_status",
    "semantics",
    "context_id",
    "context_digest",
    "registry_record_digest",
    "subject_id",
    "participant_id",
    "stakeholder_class",
    "role_id",
    "mandate_id",
    "requested_action",
    "jurisdiction",
    "subject_provider_binding",
    "challenge",
    "request_fingerprint",
    "session_id",
    "audience",
    "issued_at_ms",
    "expires_at_ms",
    "registry_sequence",
    "authority_sequence",
    "revocation_sequence",
    "sovereign_identity_digest",
    "authority_boundary_digest",
    "prior_impersonation_digest",
}
_PROOF_FIELDS: Final = _PROOF_PAYLOAD_FIELDS | _SIGNED_FIELDS
_UPSTREAM_BINDING_FIELDS: Final = {
    "component_id",
    "verifier_id",
    "verifier_version",
    "record_digest",
    "trace_digest",
    "component_digest",
    "hash_binding_entry_hash",
    "verification_receipt_digest",
}
_SNAPSHOT_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "semantics",
    "stage",
    "evaluation_sequence",
    "evaluation_time",
    "clock_sequence",
    "clock_record_digest",
    "clock_head_sequence",
    "clock_head_digest",
    "clock_transition_receipt",
    "clock_transition_receipt_digest",
    "pre_evaluation_state_hash",
    "request_fingerprint",
    "context_id",
    "context_digest",
    "subject_binding_digest",
    "session_binding_digest",
    "challenge_binding_digest",
    "sovereign_identity_binding",
    "authority_boundary_binding",
    "prior_impersonation_digest",
}
_REPLAY_CLAIM_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "namespace",
    "replay_key",
    "claim_sequence",
    "prior_claim_receipt_digest",
    "pre_claim_head_digest",
    "claimed_at_ms",
    "expires_at_ms",
    "request_fingerprint",
    "snapshot_digest",
    "registry_record_digest",
    "possession_proof_digest",
    "subject_binding_digest",
    "session_binding_digest",
    "challenge_binding_digest",
    "registry_sequence",
    "authority_sequence",
    "revocation_sequence",
    "clock_sequence",
    "clock_record_digest",
    "result",
    "authorization_effect",
}
_REPLAY_CLAIM_FIELDS: Final = _REPLAY_CLAIM_PAYLOAD_FIELDS | _SIGNED_FIELDS
_REPLAY_HEAD_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "namespace",
    "subject_binding_digest",
    "registry_sequence",
    "authority_sequence",
    "revocation_sequence",
    "claim_sequence",
    "latest_claim_receipt_digest",
    "observed_at_ms",
    "authorization_effect",
}
_REPLAY_HEAD_FIELDS: Final = _REPLAY_HEAD_PAYLOAD_FIELDS | _SIGNED_FIELDS
_CLOCK_RECORD_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "clock_id",
    "clock_version",
    "clock_sequence",
    "prior_clock_record_digest",
    "now_ms",
    "authorization_effect",
}
_CLOCK_RECORD_FIELDS: Final = _CLOCK_RECORD_PAYLOAD_FIELDS | _SIGNED_FIELDS
_CLOCK_HEAD_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "head_id",
    "head_version",
    "head_sequence",
    "clock_sequence",
    "clock_record_digest",
    "prior_clock_record_digest",
    "latest_transition_receipt_digest",
    "observed_at_ms",
    "authorization_effect",
}
_CLOCK_HEAD_FIELDS: Final = _CLOCK_HEAD_PAYLOAD_FIELDS | _SIGNED_FIELDS
_CLOCK_HEAD_TRANSITION_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "head_id",
    "head_version",
    "head_sequence",
    "prior_head_digest",
    "clock_sequence",
    "clock_record_digest",
    "prior_clock_record_digest",
    "observed_at_ms",
    "result",
    "authorization_effect",
}
_CLOCK_HEAD_TRANSITION_FIELDS: Final = (
    _CLOCK_HEAD_TRANSITION_PAYLOAD_FIELDS | _SIGNED_FIELDS
)
_UPSTREAM_RECEIPT_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "component_id",
    "verifier_id",
    "verifier_version",
    "request_fingerprint",
    "evaluation_time",
    "pre_evaluation_state_hash",
    "record_digest",
    "trace_digest",
    "component_digest",
    "hash_binding_entry_hash",
    "upstream_payload_digest",
    "result",
    "authorization_effect",
}
_UPSTREAM_RECEIPT_FIELDS: Final = _UPSTREAM_RECEIPT_PAYLOAD_FIELDS | _SIGNED_FIELDS
_REPLAY_PERSISTENCE_PAYLOAD_FIELDS: Final = {
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "namespace",
    "replay_key",
    "claim_receipt_digest",
    "subject_binding_digest",
    "claim_sequence",
    "current_head_digest",
    "registry_sequence",
    "authority_sequence",
    "revocation_sequence",
    "observed_at_ms",
    "persisted",
    "authorization_effect",
}
_REPLAY_PERSISTENCE_FIELDS: Final = _REPLAY_PERSISTENCE_PAYLOAD_FIELDS | _SIGNED_FIELDS
_FALSE_FLAG_FIELDS: Final = {
    "biometric_proof_established",
    "identity_issued",
    "identity_label_grants_access",
    "role_label_grants_authority",
    "mandate_label_grants_authority",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
}
_RECORD_FIELDS: Final = {
    "contract_id",
    "schema_status",
    "semantics",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "context_id",
    "context_digest",
    "registry_record_digest",
    "possession_proof_digest",
    "replay_key",
    "replay_claim_receipt",
    "replay_claim_receipt_digest",
    "replay_head_digest",
    "replay_persistence_receipt_digest",
    "registry_sequence",
    "authority_sequence",
    "revocation_status",
    "revocation_sequence",
    "deployment_dependencies",
} | _FALSE_FLAG_FIELDS


class OwnerPinnedTrustRegistry(Protocol):
    def lookup_identity(
        self,
        *,
        subject_id: str,
        participant_id: str,
    ) -> dict[str, Any]: ...


class DurableImpersonationReplayGuard(Protocol):
    def current_head(
        self,
        *,
        namespace: str,
        subject_binding_digest: str,
        observed_at_ms: int,
    ) -> dict[str, Any]: ...

    def claim_once(self, *, claim: dict[str, Any]) -> dict[str, Any]: ...

    def is_claimed(
        self,
        *,
        namespace: str,
        replay_key: str,
        receipt_digest: str,
        subject_binding_digest: str,
        observed_at_ms: int,
        current_head_digest: str,
    ) -> dict[str, Any]: ...


class AuthenticatedUpstreamVerifier(Protocol):
    verifier_id: str
    verifier_version: str

    def verify_authenticated(
        self,
        *,
        state: dict[str, Any],
        dependencies: Any,
        expected_receipt: dict[str, Any],
    ) -> dict[str, Any]: ...


class ImpersonationTrustedClock(Protocol):
    clock_id: str
    clock_version: str

    def current_time_record(
        self,
        *,
        context_id: str,
        context_digest: str,
    ) -> dict[str, Any]: ...


class DurableImpersonationClockHead(Protocol):
    head_id: str
    head_version: str

    def current_head(
        self,
        *,
        context_id: str,
        context_digest: str,
    ) -> dict[str, Any]: ...

    def advance_once(self, *, transition: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class _DeploymentPins:
    context_id: str
    context_digest: str
    owner_public_key: bytes | None
    owner_hybrid_context_digest: str | None


@dataclass(frozen=True, slots=True)
class _RegisteredCompositionBoundary:
    context_id: str
    context_digest: str
    owner_provider_binding_digest: str
    signed_context_record_digest: str
    _dependencies: tuple[tuple[str, Any], ...]
    _public_keys: tuple[tuple[str, bytes], ...]
    _pseudonym_key: bytes


_REGISTERED_COMPOSITION_BOUNDARIES: dict[
    str,
    _RegisteredCompositionBoundary,
] = {}
_TEST_ONLY_DEPLOYMENT_PINS: _DeploymentPins | None = None


def _test_only_mode_required() -> None:
    if _RUNTIME_MODE != _RUNTIME_MODE_TEST_ONLY:
        raise RuntimeError("TEST_ONLY_IMPERSONATION_API_DISABLED_IN_PRODUCTION")


def _pins_from_values(
    *,
    context_id: Any,
    context_digest: Any,
    owner_public_key_hex: Any = None,
    owner_hybrid_context_digest: Any = None,
) -> _DeploymentPins:
    if not _text(context_id) or not is_sha512(context_digest):
        raise ValueError("IMPERSONATION_DEPLOYMENT_PINS_INVALID")
    owner_public_key: bytes | None = None
    if owner_public_key_hex is not None:
        try:
            owner_public_key = bytes.fromhex(owner_public_key_hex)
        except (TypeError, ValueError) as exc:
            raise ValueError("IMPERSONATION_DEPLOYMENT_PINS_INVALID") from exc
        if len(owner_public_key) != 32:
            raise ValueError("IMPERSONATION_DEPLOYMENT_PINS_INVALID")
    if (owner_public_key is None) == (not is_sha512(owner_hybrid_context_digest)):
        raise ValueError("IMPERSONATION_DEPLOYMENT_PINS_INVALID")
    return _DeploymentPins(
        context_id=context_id,
        context_digest=context_digest,
        owner_public_key=owner_public_key,
        owner_hybrid_context_digest=(
            owner_hybrid_context_digest
            if is_sha512(owner_hybrid_context_digest)
            else None
        ),
    )


def _install_test_only_impersonation_deployment_pins(
    *,
    context_id: str,
    context_digest: str,
    owner_public_key_hex: str,
) -> None:
    """Install explicit TEST_ONLY stand-ins for externally fixed deployment pins."""

    _test_only_mode_required()
    global _TEST_ONLY_DEPLOYMENT_PINS
    pins = _pins_from_values(
        context_id=context_id,
        context_digest=context_digest,
        owner_public_key_hex=owner_public_key_hex,
    )
    if _TEST_ONLY_DEPLOYMENT_PINS is not None and _TEST_ONLY_DEPLOYMENT_PINS != pins:
        raise ValueError("TEST_ONLY_IMPERSONATION_DEPLOYMENT_PINS_ALREADY_FIXED")
    _TEST_ONLY_DEPLOYMENT_PINS = pins


def _reset_test_only_impersonation_composition_boundaries(
    *,
    clear_pins: bool = True,
) -> None:
    _test_only_mode_required()
    _REGISTERED_COMPOSITION_BOUNDARIES.clear()
    if clear_pins:
        global _TEST_ONLY_DEPLOYMENT_PINS
        _TEST_ONLY_DEPLOYMENT_PINS = None


def _register_impersonation_composition_boundary(
    *,
    pins: _DeploymentPins,
    signed_context_record: dict[str, Any],
    owner_provider: SignatureProvider,
    registry_provider: SignatureProvider,
    subject_provider: SignatureProvider,
    replay_provider: SignatureProvider,
    registry: OwnerPinnedTrustRegistry,
    replay_guard: DurableImpersonationReplayGuard,
    sovereign_identity_verifier: AuthenticatedUpstreamVerifier,
    sovereign_identity_dependencies: Any,
    authority_boundary_verifier: AuthenticatedUpstreamVerifier,
    authority_boundary_dependencies: Any,
    trusted_clock: ImpersonationTrustedClock,
    clock_head_provider: DurableImpersonationClockHead,
    pseudonym_key: bytes,
    require_test_fixtures: bool,
) -> None:
    dependencies = {
        "owner_provider": owner_provider,
        "registry_provider": registry_provider,
        "subject_provider": subject_provider,
        "replay_provider": replay_provider,
        "registry": registry,
        "replay_guard": replay_guard,
        "sovereign_identity_verifier": sovereign_identity_verifier,
        "sovereign_identity_dependencies": sovereign_identity_dependencies,
        "authority_boundary_verifier": authority_boundary_verifier,
        "authority_boundary_dependencies": authority_boundary_dependencies,
        "trusted_clock": trusted_clock,
        "clock_head_provider": clock_head_provider,
    }
    if (
        type(signed_context_record) is not dict
        or type(pseudonym_key) is not bytes
        or len(pseudonym_key) < 32
        or (
            require_test_fixtures
            and any(
                getattr(value, "fixture_class", None)
                != "TEST_ONLY_NONPRODUCTION_FIXTURE"
                for value in dependencies.values()
            )
        )
    ):
        raise ValueError("IMPERSONATION_COMPOSITION_INVALID")
    context_id = signed_context_record.get("context_id")
    context_digest = signed_context_record.get("digest")
    owner_public_key = _signature_public_material(
        owner_provider,
        allow_legacy_non_effect=require_test_fixtures,
    )
    owner_hybrid_context = _hybrid_verification_context(
        owner_provider,
        allow_test_only=require_test_fixtures,
    )
    if (
        context_id != pins.context_id
        or context_digest != pins.context_digest
        or (require_test_fixtures and owner_public_key != pins.owner_public_key)
        or (
            not require_test_fixtures
            and (
                owner_hybrid_context is None
                or owner_hybrid_context.signer_class != PRODUCTION_SIGNER
                or owner_hybrid_context.context_digest
                != pins.owner_hybrid_context_digest
            )
        )
        or owner_public_key is None
        or not _verify_with_exact_ed25519_key(
            signed_context_record,
            provider=owner_provider,
            exact_public_key=owner_public_key,
        )
    ):
        raise ValueError("IMPERSONATION_DEPLOYMENT_PIN_MISMATCH")
    if context_id in _REGISTERED_COMPOSITION_BOUNDARIES:
        raise ValueError("IMPERSONATION_COMPOSITION_ALREADY_REGISTERED")
    providers = {
        "owner_provider": owner_provider,
        "registry_provider": registry_provider,
        "subject_provider": subject_provider,
        "replay_provider": replay_provider,
        "clock_provider": trusted_clock,
        "clock_head_provider": clock_head_provider,
        "sovereign_receipt_provider": sovereign_identity_dependencies,
        "authority_receipt_provider": authority_boundary_dependencies,
    }
    public_keys: dict[str, bytes] = {}
    for role, provider in providers.items():
        public_key = _signature_public_material(
            provider,
            allow_legacy_non_effect=require_test_fixtures,
        )
        hybrid_context = _hybrid_verification_context(
            provider,
            allow_test_only=require_test_fixtures,
        )
        if public_key is None:
            raise ValueError("IMPERSONATION_PUBLIC_KEY_INVALID")
        if not require_test_fixtures and (
            hybrid_context is None or hybrid_context.signer_class != PRODUCTION_SIGNER
        ):
            raise ValueError("IMPERSONATION_PRODUCTION_HYBRID_REQUIRED")
        public_keys[role] = public_key
    if len(set(public_keys.values())) != len(public_keys):
        raise ValueError("IMPERSONATION_COMPOSITION_KEYS_NOT_SEPARATE")
    _REGISTERED_COMPOSITION_BOUNDARIES[context_id] = _RegisteredCompositionBoundary(
        context_id=context_id,
        context_digest=context_digest,
        owner_provider_binding_digest=canonical_integrity_hash(
            signed_context_record.get("owner_provider_binding")
        ),
        signed_context_record_digest=canonical_integrity_hash(signed_context_record),
        _dependencies=tuple(dependencies.items()),
        _public_keys=tuple(public_keys.items()),
        _pseudonym_key=bytes(pseudonym_key),
    )


def _validate_production_durable_boundary_admissions(
    *,
    registry_provider: SignatureProvider,
    replay_provider: SignatureProvider,
    registry: OwnerPinnedTrustRegistry,
    replay_guard: DurableImpersonationReplayGuard,
    trusted_clock: ImpersonationTrustedClock,
    clock_head_provider: DurableImpersonationClockHead,
) -> None:
    from sbp_lex.identity.durable_boundaries import (
        AuthenticatedMonotonicClock,
        SQLiteImpersonationClockHead,
        SQLiteImpersonationReplayGuard,
        SQLiteOwnerPinnedTrustRegistry,
    )

    boundaries = (
        (
            registry,
            SQLiteOwnerPinnedTrustRegistry,
            _PRODUCTION_REGISTRY_ADMISSION_DIGEST,
            registry_provider,
        ),
        (
            replay_guard,
            SQLiteImpersonationReplayGuard,
            _PRODUCTION_REPLAY_ADMISSION_DIGEST,
            replay_provider,
        ),
        (
            trusted_clock,
            AuthenticatedMonotonicClock,
            _PRODUCTION_TRUSTED_CLOCK_ADMISSION_DIGEST,
            trusted_clock,
        ),
        (
            clock_head_provider,
            SQLiteImpersonationClockHead,
            _PRODUCTION_CLOCK_HEAD_ADMISSION_DIGEST,
            clock_head_provider,
        ),
    )
    for boundary, expected_type, admitted_digest, expected_provider in boundaries:
        admission_method = getattr(boundary, "production_admission_record", None)
        validate_method = getattr(boundary, "validate_store", None)
        if (
            type(boundary) is not expected_type
            or getattr(boundary, "fixture_class", None) != "PRODUCTION_BOUNDARY"
            or not is_sha512(admitted_digest)
            or not callable(admission_method)
            or not callable(validate_method)
        ):
            raise ValueError(
                "IMPERSONATION_PRODUCTION_DURABLE_BOUNDARY_ADMISSION_INVALID"
            )
        try:
            admission_record = admission_method()
            store_valid = validate_method()
            expected_provider_context = _hybrid_verification_context(
                expected_provider,
                allow_test_only=False,
            )
        except Exception as exc:
            raise ValueError(
                "IMPERSONATION_PRODUCTION_DURABLE_BOUNDARY_ADMISSION_INVALID"
            ) from exc
        if (
            store_valid is not True
            or type(admission_record) is not dict
            or admission_record.get("fixture_class") != "PRODUCTION_BOUNDARY"
            or expected_provider_context is None
            or admission_record.get("owner_pinned_signer_context_digest")
            != expected_provider_context.context_digest
            or canonical_integrity_hash(admission_record) != admitted_digest
        ):
            raise ValueError(
                "IMPERSONATION_PRODUCTION_DURABLE_BOUNDARY_ADMISSION_INVALID"
            )


def install_production_impersonation_composition_boundary(
    *,
    signed_context_record: dict[str, Any],
    owner_provider: SignatureProvider,
    registry_provider: SignatureProvider,
    subject_provider: SignatureProvider,
    replay_provider: SignatureProvider,
    registry: OwnerPinnedTrustRegistry,
    replay_guard: DurableImpersonationReplayGuard,
    sovereign_identity_verifier: AuthenticatedUpstreamVerifier,
    sovereign_identity_dependencies: Any,
    authority_boundary_verifier: AuthenticatedUpstreamVerifier,
    authority_boundary_dependencies: Any,
    trusted_clock: ImpersonationTrustedClock,
    clock_head_provider: DurableImpersonationClockHead,
    pseudonym_key: bytes,
) -> None:
    if _RUNTIME_MODE != _RUNTIME_MODE_PRODUCTION:
        raise RuntimeError("PRODUCTION_IMPERSONATION_API_DISABLED_IN_TEST_ONLY_MODE")
    pins = _pins_from_values(
        context_id=_PRODUCTION_CONTEXT_ID,
        context_digest=_PRODUCTION_CONTEXT_DIGEST,
        owner_hybrid_context_digest=(_PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST),
    )
    _validate_production_durable_boundary_admissions(
        registry_provider=registry_provider,
        replay_provider=replay_provider,
        registry=registry,
        replay_guard=replay_guard,
        trusted_clock=trusted_clock,
        clock_head_provider=clock_head_provider,
    )
    _register_impersonation_composition_boundary(
        pins=pins,
        signed_context_record=signed_context_record,
        owner_provider=owner_provider,
        registry_provider=registry_provider,
        subject_provider=subject_provider,
        replay_provider=replay_provider,
        registry=registry,
        replay_guard=replay_guard,
        sovereign_identity_verifier=sovereign_identity_verifier,
        sovereign_identity_dependencies=sovereign_identity_dependencies,
        authority_boundary_verifier=authority_boundary_verifier,
        authority_boundary_dependencies=authority_boundary_dependencies,
        trusted_clock=trusted_clock,
        clock_head_provider=clock_head_provider,
        pseudonym_key=pseudonym_key,
        require_test_fixtures=False,
    )


def _register_test_only_impersonation_composition_boundary(
    *,
    signed_context_record: dict[str, Any],
    owner_provider: SignatureProvider,
    registry_provider: SignatureProvider,
    subject_provider: SignatureProvider,
    replay_provider: SignatureProvider,
    registry: OwnerPinnedTrustRegistry,
    replay_guard: DurableImpersonationReplayGuard,
    sovereign_identity_verifier: AuthenticatedUpstreamVerifier,
    sovereign_identity_dependencies: Any,
    authority_boundary_verifier: AuthenticatedUpstreamVerifier,
    authority_boundary_dependencies: Any,
    trusted_clock: ImpersonationTrustedClock,
    clock_head_provider: DurableImpersonationClockHead,
    pseudonym_key: bytes,
) -> None:
    """Install one explicit TEST_ONLY composition boundary.

    Production registration uses the separate externally pinned production
    installer and cannot call this test-only path.
    """

    _test_only_mode_required()
    if _TEST_ONLY_DEPLOYMENT_PINS is None:
        raise ValueError("TEST_ONLY_IMPERSONATION_DEPLOYMENT_PINS_REQUIRED")
    _register_impersonation_composition_boundary(
        pins=_TEST_ONLY_DEPLOYMENT_PINS,
        signed_context_record=signed_context_record,
        owner_provider=owner_provider,
        registry_provider=registry_provider,
        subject_provider=subject_provider,
        replay_provider=replay_provider,
        registry=registry,
        replay_guard=replay_guard,
        sovereign_identity_verifier=sovereign_identity_verifier,
        sovereign_identity_dependencies=sovereign_identity_dependencies,
        authority_boundary_verifier=authority_boundary_verifier,
        authority_boundary_dependencies=authority_boundary_dependencies,
        trusted_clock=trusted_clock,
        clock_head_provider=clock_head_provider,
        pseudonym_key=pseudonym_key,
        require_test_fixtures=True,
    )


class ImpersonationTrustContext:
    """One deployment-owned, attribute-immutable impersonation trust root.

    The ``pinned_*`` values are deployment pins, not values resolved from the
    signed context record.  A resolved record and all runtime dependencies must
    match those independent pins exactly.
    """

    _pinned_context_id: str
    _pinned_context_digest: str
    _pinned_owner_provider_binding: dict[str, Any]
    _signed_context_record: dict[str, Any]
    _owner_provider: SignatureProvider
    _registry_provider: SignatureProvider
    _subject_provider: SignatureProvider
    _replay_provider: SignatureProvider
    _registry: OwnerPinnedTrustRegistry
    _replay_guard: DurableImpersonationReplayGuard
    _sovereign_identity_verifier: AuthenticatedUpstreamVerifier
    _sovereign_identity_dependencies: Any
    _authority_boundary_verifier: AuthenticatedUpstreamVerifier
    _authority_boundary_dependencies: Any
    _trusted_clock: ImpersonationTrustedClock
    _clock_head_provider: DurableImpersonationClockHead
    _composition_boundary: _RegisteredCompositionBoundary | None
    _sealed: bool

    __slots__ = (
        "_authority_boundary_dependencies",
        "_authority_boundary_verifier",
        "_clock_head_provider",
        "_composition_boundary",
        "_owner_provider",
        "_pinned_context_digest",
        "_pinned_context_id",
        "_pinned_owner_provider_binding",
        "_registry",
        "_registry_provider",
        "_replay_guard",
        "_replay_provider",
        "_sealed",
        "_signed_context_record",
        "_sovereign_identity_dependencies",
        "_sovereign_identity_verifier",
        "_subject_provider",
        "_trusted_clock",
    )

    def __init__(
        self,
        *,
        pinned_context_id: str,
        pinned_context_digest: str,
        pinned_owner_provider_binding: dict[str, Any],
        signed_context_record: dict[str, Any],
        owner_provider: SignatureProvider,
        registry_provider: SignatureProvider,
        subject_provider: SignatureProvider,
        replay_provider: SignatureProvider,
        registry: OwnerPinnedTrustRegistry,
        replay_guard: DurableImpersonationReplayGuard,
        sovereign_identity_verifier: AuthenticatedUpstreamVerifier,
        sovereign_identity_dependencies: Any,
        authority_boundary_verifier: AuthenticatedUpstreamVerifier,
        authority_boundary_dependencies: Any,
        trusted_clock: ImpersonationTrustedClock,
        clock_head_provider: DurableImpersonationClockHead,
    ) -> None:
        object.__setattr__(self, "_pinned_context_id", pinned_context_id)
        object.__setattr__(self, "_pinned_context_digest", pinned_context_digest)
        object.__setattr__(
            self,
            "_pinned_owner_provider_binding",
            deepcopy(pinned_owner_provider_binding),
        )
        object.__setattr__(
            self,
            "_signed_context_record",
            deepcopy(signed_context_record),
        )
        object.__setattr__(self, "_owner_provider", owner_provider)
        object.__setattr__(self, "_registry_provider", registry_provider)
        object.__setattr__(self, "_subject_provider", subject_provider)
        object.__setattr__(self, "_replay_provider", replay_provider)
        object.__setattr__(self, "_registry", registry)
        object.__setattr__(self, "_replay_guard", replay_guard)
        object.__setattr__(
            self,
            "_sovereign_identity_verifier",
            sovereign_identity_verifier,
        )
        object.__setattr__(
            self,
            "_sovereign_identity_dependencies",
            sovereign_identity_dependencies,
        )
        object.__setattr__(
            self,
            "_authority_boundary_verifier",
            authority_boundary_verifier,
        )
        object.__setattr__(
            self,
            "_authority_boundary_dependencies",
            authority_boundary_dependencies,
        )
        object.__setattr__(self, "_trusted_clock", trusted_clock)
        object.__setattr__(self, "_clock_head_provider", clock_head_provider)
        object.__setattr__(
            self,
            "_composition_boundary",
            _REGISTERED_COMPOSITION_BOUNDARIES.get(pinned_context_id),
        )
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("IMPERSONATION_TRUST_CONTEXT_IMMUTABLE")

    @property
    def pinned_context_id(self) -> str:
        return self._pinned_context_id

    @property
    def pinned_context_digest(self) -> str:
        return self._pinned_context_digest

    @property
    def pinned_owner_provider_binding(self) -> dict[str, Any]:
        return deepcopy(self._pinned_owner_provider_binding)

    @property
    def signed_context_record(self) -> dict[str, Any]:
        return deepcopy(self._signed_context_record)

    @property
    def owner_provider(self) -> SignatureProvider:
        return self._owner_provider

    @property
    def registry_provider(self) -> SignatureProvider:
        return self._registry_provider

    @property
    def subject_provider(self) -> SignatureProvider:
        return self._subject_provider

    @property
    def replay_provider(self) -> SignatureProvider:
        return self._replay_provider

    @property
    def registry(self) -> OwnerPinnedTrustRegistry:
        return self._registry

    @property
    def replay_guard(self) -> DurableImpersonationReplayGuard:
        return self._replay_guard

    @property
    def sovereign_identity_verifier(self) -> AuthenticatedUpstreamVerifier:
        return self._sovereign_identity_verifier

    @property
    def sovereign_identity_dependencies(self) -> Any:
        return self._sovereign_identity_dependencies

    @property
    def authority_boundary_verifier(self) -> AuthenticatedUpstreamVerifier:
        return self._authority_boundary_verifier

    @property
    def authority_boundary_dependencies(self) -> Any:
        return self._authority_boundary_dependencies

    @property
    def trusted_clock(self) -> ImpersonationTrustedClock:
        return self._trusted_clock

    @property
    def clock_head_provider(self) -> DurableImpersonationClockHead:
        return self._clock_head_provider


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _text_list(value: Any) -> bool:
    return (
        type(value) is list
        and bool(value)
        and all(_text(item) for item in value)
        and value == sorted(set(value))
    )


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _safe_attribute(value: Any, name: str) -> Any:
    try:
        return getattr(value, name)
    except Exception:  # noqa: BLE001
        return None


def _ed25519_public_key_bytes(provider: Any) -> bytes | None:
    key = _safe_attribute(provider, "public_key")
    if callable(key):
        try:
            key = key()
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(key, Ed25519PublicKey):
        return None
    try:
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:  # noqa: BLE001
        return None


def _hybrid_verification_context(
    provider: Any,
    *,
    allow_test_only: bool,
) -> HybridVerificationContext | None:
    if not is_hybrid_provider(provider):
        return None
    try:
        context = provider.hybrid_verification_context(allow_test_only=allow_test_only)
    except (HybridSignatureError, TypeError, ValueError):
        return None
    except Exception:  # noqa: BLE001
        return None
    if (
        not isinstance(context, HybridVerificationContext)
        or context.provider_id != _safe_attribute(provider, "provider_id")
        or context.ordered_key_set_digest != _safe_attribute(provider, "key_id")
        or context.custody_class != _safe_attribute(provider, "custody_class")
        or context.effect_authority is not False
        or _safe_attribute(provider, "effect_authority") is not False
    ):
        return None
    return context


def _signature_public_material(
    provider: Any,
    *,
    allow_legacy_non_effect: bool,
) -> bytes | None:
    context = _hybrid_verification_context(
        provider,
        allow_test_only=allow_legacy_non_effect,
    )
    if context is not None:
        return canonical_json_bytes(context.public_record())
    if not allow_legacy_non_effect:
        return None
    return _ed25519_public_key_bytes(provider)


def _verify_with_exact_ed25519_key(
    value: Any,
    *,
    provider: Any,
    exact_public_key: bytes,
) -> bool:
    try:
        allow_legacy = _RUNTIME_MODE == _RUNTIME_MODE_TEST_ONLY
        public_material = _signature_public_material(
            provider,
            allow_legacy_non_effect=allow_legacy,
        )
        if (
            type(value) is not dict
            or public_material != exact_public_key
            or _provider_binding(provider) is None
            or value.get("verified") is not False
        ):
            return False
        hybrid_context = _hybrid_verification_context(
            provider,
            allow_test_only=allow_legacy,
        )
        if hybrid_context is not None:
            return verify_signed_object(
                value,
                provider=None,
                purpose=impersonation_signing_purpose(value.get("schema")),
                trust_context=hybrid_context,
                owner_pinned_context_digest=hybrid_context.context_digest,
                allow_legacy_non_effect=False,
            )
        if not allow_legacy:
            return False
        signature = value.get("signature")
        if (
            type(signature) is not dict
            or signature.get("algorithm") != "Ed25519"
            or signature.get("provider_id") != _safe_attribute(provider, "provider_id")
            or signature.get("key_id") != _safe_attribute(provider, "key_id")
            or signature.get("custody_class")
            != _safe_attribute(provider, "custody_class")
            or signature.get("effect_authority") is not False
        ):
            return False
        payload = {
            key: item for key, item in value.items() if key not in _SIGNED_FIELDS
        }
        payload_bytes = canonical_json_bytes(payload)
        if value.get("digest") != sha512(payload_bytes).hexdigest():
            return False
        encoded = signature.get("signature_b64")
        if type(encoded) is not str or not encoded:
            return False
        raw_signature = base64.b64decode(encoded, validate=True)
        Ed25519PublicKey.from_public_bytes(exact_public_key).verify(
            raw_signature,
            payload_bytes,
        )
        return (
            _signature_public_material(
                provider,
                allow_legacy_non_effect=True,
            )
            == exact_public_key
        )
    except (
        InvalidSignature,
        binascii.Error,
        TypeError,
        ValueError,
    ):
        return False
    except Exception:  # noqa: BLE001
        return False


def _registered_boundary_matches(context: Any) -> bool:
    if type(context) is not ImpersonationTrustContext:
        return False
    boundary = context._composition_boundary
    if boundary is None:
        return False
    if _REGISTERED_COMPOSITION_BOUNDARIES.get(boundary.context_id) is not boundary:
        return False
    exact = {
        "owner_provider": context.owner_provider,
        "registry_provider": context.registry_provider,
        "subject_provider": context.subject_provider,
        "replay_provider": context.replay_provider,
        "registry": context.registry,
        "replay_guard": context.replay_guard,
        "sovereign_identity_verifier": context.sovereign_identity_verifier,
        "sovereign_identity_dependencies": (context.sovereign_identity_dependencies),
        "authority_boundary_verifier": context.authority_boundary_verifier,
        "authority_boundary_dependencies": (context.authority_boundary_dependencies),
        "trusted_clock": context.trusted_clock,
        "clock_head_provider": context.clock_head_provider,
    }
    dependencies = dict(boundary._dependencies)
    if any(dependencies.get(role) is not value for role, value in exact.items()):
        return False
    if (
        context.pinned_context_id != boundary.context_id
        or context.pinned_context_digest != boundary.context_digest
        or _safe_hash(context.pinned_owner_provider_binding)
        != boundary.owner_provider_binding_digest
        or _safe_hash(context.signed_context_record)
        != boundary.signed_context_record_digest
    ):
        return False
    providers = {
        "owner_provider": context.owner_provider,
        "registry_provider": context.registry_provider,
        "subject_provider": context.subject_provider,
        "replay_provider": context.replay_provider,
        "clock_provider": context.trusted_clock,
        "clock_head_provider": context.clock_head_provider,
        "sovereign_receipt_provider": context.sovereign_identity_dependencies,
        "authority_receipt_provider": context.authority_boundary_dependencies,
    }
    public_keys = dict(boundary._public_keys)
    return all(
        _signature_public_material(
            provider,
            allow_legacy_non_effect=(_RUNTIME_MODE == _RUNTIME_MODE_TEST_ONLY),
        )
        == public_keys.get(role)
        for role, provider in providers.items()
    )


def _pseudonymous_binding(
    context: ImpersonationTrustContext,
    *,
    purpose: str,
    value: Any,
) -> str | None:
    boundary = context._composition_boundary
    if boundary is None:
        return None
    try:
        message = canonical_json_bytes(
            {
                "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                "context_id": boundary.context_id,
                "purpose": purpose,
                "value": value,
            }
        )
        return hmac.new(boundary._pseudonym_key, message, sha512).hexdigest()
    except Exception:  # noqa: BLE001
        return None


def _state_hash(value: Any) -> bool:
    return value == GENESIS_HASH or is_sha512(value)


def _provider_binding(
    provider: (
        SignatureProvider
        | ImpersonationTrustedClock
        | DurableImpersonationClockHead
        | None
    ),
) -> dict[str, Any] | None:
    if provider is None:
        return None
    allow_legacy = _RUNTIME_MODE == _RUNTIME_MODE_TEST_ONLY
    hybrid_context = _hybrid_verification_context(
        provider,
        allow_test_only=allow_legacy,
    )
    public_key = _signature_public_material(
        provider,
        allow_legacy_non_effect=allow_legacy,
    )
    binding = {
        "provider_id": _safe_attribute(provider, "provider_id"),
        "algorithm": _safe_attribute(provider, "algorithm"),
        "key_id": _safe_attribute(provider, "key_id"),
        "custody_class": _safe_attribute(provider, "custody_class"),
        "effect_authority": _safe_attribute(provider, "effect_authority"),
        "ed25519_public_key_fingerprint": (
            hybrid_context.context_digest
            if hybrid_context is not None
            else sha512(public_key).hexdigest()
            if public_key is not None
            else None
        ),
    }
    if (
        not all(
            _text(binding[field])
            for field in _PROVIDER_BINDING_FIELDS - {"effect_authority"}
        )
        or binding["effect_authority"] is not False
        or binding["algorithm"] not in {"Ed25519", HYBRID_SUITE_ID}
        or (
            binding["algorithm"] == "Ed25519"
            and (
                not allow_legacy
                or not callable(_safe_attribute(provider, "sign"))
                or not callable(_safe_attribute(provider, "verify"))
            )
        )
        or (binding["algorithm"] == HYBRID_SUITE_ID and hybrid_context is None)
    ):
        return None
    return binding


def _provider_binding_exact(value: Any) -> TypeGuard[dict[str, Any]]:
    return (
        type(value) is dict
        and set(value) == _PROVIDER_BINDING_FIELDS
        and all(
            _text(value.get(field))
            for field in _PROVIDER_BINDING_FIELDS - {"effect_authority"}
        )
        and value.get("effect_authority") is False
    )


def _verifier_binding_exact(value: Any) -> TypeGuard[dict[str, Any]]:
    return (
        type(value) is dict
        and set(value) == _VERIFIER_BINDING_FIELDS
        and all(
            _text(value.get(field))
            for field in ("verifier_id", "verifier_version", "hash_stage")
        )
        and _provider_binding_exact(value.get("receipt_provider_binding"))
    )


def _clock_record_error(
    context: Any,
    *,
    minimum_sequence: int = 0,
) -> tuple[dict[str, Any] | None, str | None]:
    if type(context) is not ImpersonationTrustContext:
        return None, "IMPERSONATION_DEPLOYMENT_CONTEXT_REQUIRED"
    boundary = context._composition_boundary
    if boundary is None or not _registered_boundary_matches(context):
        return None, "IMPERSONATION_COMPOSITION_BOUNDARY_NOT_REGISTERED"
    method = _safe_attribute(context.trusted_clock, "current_time_record")
    if not callable(method):
        return None, "IMPERSONATION_TRUSTED_CLOCK_UNAVAILABLE"
    try:
        record = method(
            context_id=boundary.context_id,
            context_digest=boundary.context_digest,
        )
    except Exception:  # noqa: BLE001
        return None, "IMPERSONATION_TRUSTED_CLOCK_UNAVAILABLE"
    if type(record) is not dict or set(record) != _CLOCK_RECORD_FIELDS:
        return None, "IMPERSONATION_TRUSTED_CLOCK_RECORD_INVALID"
    if not _verify_with_exact_ed25519_key(
        record,
        provider=context.trusted_clock,
        exact_public_key=dict(boundary._public_keys)["clock_provider"],
    ):
        return None, "IMPERSONATION_TRUSTED_CLOCK_SIGNATURE_INVALID"
    exact = {
        "schema": CLOCK_RECORD_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": boundary.context_id,
        "context_digest": boundary.context_digest,
        "clock_id": _safe_attribute(context.trusted_clock, "clock_id"),
        "clock_version": _safe_attribute(
            context.trusted_clock,
            "clock_version",
        ),
        "authorization_effect": NO_AUTHORIZATION_EFFECT,
    }
    sequence = record.get("clock_sequence")
    prior = record.get("prior_clock_record_digest")
    if (
        any(record.get(field) != value for field, value in exact.items())
        or type(sequence) is not int
        or sequence < max(1, minimum_sequence)
        or type(record.get("now_ms")) is not int
        or record["now_ms"] < 0
        or (sequence == 1 and prior != GENESIS_HASH)
        or (sequence > 1 and not is_sha512(prior))
    ):
        return None, "IMPERSONATION_TRUSTED_CLOCK_RECORD_INVALID"
    return record, None


def _clock_head_error(
    head: Any,
    *,
    context_record: dict[str, Any],
    context: ImpersonationTrustContext,
) -> str | None:
    if type(head) is not dict or set(head) != _CLOCK_HEAD_FIELDS:
        return "IMPERSONATION_CLOCK_HEAD_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        head,
        provider=context.clock_head_provider,
        exact_public_key=dict(boundary._public_keys)["clock_head_provider"],
    ):
        return "IMPERSONATION_CLOCK_HEAD_SIGNATURE_INVALID"
    exact = {
        "schema": CLOCK_HEAD_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "head_id": context_record["clock_head_id"],
        "head_version": context_record["clock_head_version"],
        "authorization_effect": NO_AUTHORIZATION_EFFECT,
    }
    if any(head.get(field) != value for field, value in exact.items()):
        return "IMPERSONATION_CLOCK_HEAD_BINDING_INVALID"
    head_sequence = head.get("head_sequence")
    clock_sequence = head.get("clock_sequence")
    observed_at_ms = head.get("observed_at_ms")
    if (
        type(head_sequence) is not int
        or type(clock_sequence) is not int
        or type(observed_at_ms) is not int
        or min(head_sequence, clock_sequence, observed_at_ms) < 0
        or head_sequence != clock_sequence
    ):
        return "IMPERSONATION_CLOCK_HEAD_SEQUENCE_INVALID"
    if head_sequence == 0:
        if (
            any(
                head.get(field) != GENESIS_HASH
                for field in (
                    "clock_record_digest",
                    "prior_clock_record_digest",
                    "latest_transition_receipt_digest",
                )
            )
            or observed_at_ms != 0
        ):
            return "IMPERSONATION_CLOCK_HEAD_GENESIS_INVALID"
    elif (
        not is_sha512(head.get("clock_record_digest"))
        or not is_sha512(head.get("latest_transition_receipt_digest"))
        or (
            clock_sequence == 1
            and head.get("prior_clock_record_digest") != GENESIS_HASH
        )
        or (clock_sequence > 1 and not is_sha512(head.get("prior_clock_record_digest")))
    ):
        return "IMPERSONATION_CLOCK_HEAD_DIGEST_INVALID"
    return None


def _clock_transition_error(
    receipt: Any,
    *,
    expected_transition: dict[str, Any],
    context: ImpersonationTrustContext,
) -> str | None:
    if type(receipt) is not dict or set(receipt) != _CLOCK_HEAD_TRANSITION_FIELDS:
        return "IMPERSONATION_CLOCK_TRANSITION_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        receipt,
        provider=context.clock_head_provider,
        exact_public_key=dict(boundary._public_keys)["clock_head_provider"],
    ):
        return "IMPERSONATION_CLOCK_TRANSITION_SIGNATURE_INVALID"
    if any(receipt.get(field) != value for field, value in expected_transition.items()):
        return "IMPERSONATION_CLOCK_TRANSITION_BINDING_INVALID"
    return None


def _admit_clock_record(
    *,
    context: ImpersonationTrustContext,
    context_record: dict[str, Any],
    clock_record: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        pre_head = context.clock_head_provider.current_head(
            context_id=context_record["context_id"],
            context_digest=context_record["digest"],
        )
    except Exception:  # noqa: BLE001
        return None, "IMPERSONATION_CLOCK_HEAD_UNAVAILABLE"
    reason = _clock_head_error(
        pre_head,
        context_record=context_record,
        context=context,
    )
    if reason is not None:
        return None, reason
    clock_record_digest = _safe_hash(clock_record)
    if (
        clock_record["clock_sequence"] != pre_head["clock_sequence"] + 1
        or clock_record["prior_clock_record_digest"] != pre_head["clock_record_digest"]
        or clock_record_digest is None
    ):
        return None, "IMPERSONATION_CLOCK_HISTORY_NOT_MONOTONIC"
    transition = {
        "schema": CLOCK_HEAD_TRANSITION_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "head_id": context_record["clock_head_id"],
        "head_version": context_record["clock_head_version"],
        "head_sequence": pre_head["head_sequence"] + 1,
        "prior_head_digest": _safe_hash(pre_head),
        "clock_sequence": clock_record["clock_sequence"],
        "clock_record_digest": clock_record_digest,
        "prior_clock_record_digest": clock_record["prior_clock_record_digest"],
        "observed_at_ms": clock_record["now_ms"],
        "result": "ADVANCED",
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
    }
    try:
        receipt = context.clock_head_provider.advance_once(
            transition=deepcopy(transition)
        )
    except Exception:  # noqa: BLE001
        return None, "IMPERSONATION_CLOCK_TRANSITION_UNAVAILABLE"
    reason = _clock_transition_error(
        receipt,
        expected_transition=transition,
        context=context,
    )
    if reason is not None:
        return None, reason
    receipt_digest = _safe_hash(receipt)
    try:
        post_head = context.clock_head_provider.current_head(
            context_id=context_record["context_id"],
            context_digest=context_record["digest"],
        )
    except Exception:  # noqa: BLE001
        return None, "IMPERSONATION_CLOCK_HEAD_UNAVAILABLE"
    reason = _clock_head_error(
        post_head,
        context_record=context_record,
        context=context,
    )
    expected_post = {
        "head_sequence": transition["head_sequence"],
        "clock_sequence": transition["clock_sequence"],
        "clock_record_digest": transition["clock_record_digest"],
        "prior_clock_record_digest": transition["prior_clock_record_digest"],
        "latest_transition_receipt_digest": receipt_digest,
        "observed_at_ms": transition["observed_at_ms"],
    }
    if reason is not None or any(
        post_head.get(field) != value for field, value in expected_post.items()
    ):
        return None, reason or "IMPERSONATION_CLOCK_TRANSITION_NOT_DURABLE"
    return {
        "clock_head_sequence": post_head["head_sequence"],
        "clock_head_digest": _safe_hash(post_head),
        "clock_transition_receipt": deepcopy(receipt),
        "clock_transition_receipt_digest": receipt_digest,
    }, None


def _terminal_clock_head_error(
    *,
    context: ImpersonationTrustContext,
    context_record: dict[str, Any],
    expected: dict[str, Any],
) -> str | None:
    try:
        head = context.clock_head_provider.current_head(
            context_id=context_record["context_id"],
            context_digest=context_record["digest"],
        )
    except Exception:  # noqa: BLE001
        return "IMPERSONATION_CLOCK_HEAD_UNAVAILABLE"
    reason = _clock_head_error(
        head,
        context_record=context_record,
        context=context,
    )
    if reason is not None:
        return reason
    if (
        head["head_sequence"] != expected["clock_head_sequence"]
        or _safe_hash(head) != expected["clock_head_digest"]
        or head["latest_transition_receipt_digest"]
        != expected["clock_transition_receipt_digest"]
    ):
        return "IMPERSONATION_CLOCK_HEAD_CHANGED_DURING_EVALUATION"
    return None


def _context_error(
    context: Any,
    *,
    now_ms: int,
    clock_sequence: int,
) -> tuple[dict[str, Any] | None, str | None]:
    if type(context) is not ImpersonationTrustContext:
        return None, "IMPERSONATION_DEPLOYMENT_CONTEXT_REQUIRED"
    if not _registered_boundary_matches(context):
        return None, "IMPERSONATION_COMPOSITION_BOUNDARY_NOT_REGISTERED"
    boundary = context._composition_boundary
    if boundary is None:
        return None, "IMPERSONATION_COMPOSITION_BOUNDARY_NOT_REGISTERED"
    record = context.signed_context_record
    if type(record) is not dict or set(record) != _CONTEXT_FIELDS:
        return None, "IMPERSONATION_CONTEXT_SHAPE_INVALID"
    if (
        record.get("context_id") != context.pinned_context_id
        or record.get("digest") != context.pinned_context_digest
        or _safe_hash(
            {key: value for key, value in record.items() if key not in _SIGNED_FIELDS}
        )
        != context.pinned_context_digest
        or record.get("owner_provider_binding") != context.pinned_owner_provider_binding
    ):
        return None, "IMPERSONATION_DEPLOYMENT_CONTEXT_PIN_MISMATCH"
    if (
        record.get("schema") != TRUST_CONTEXT_SCHEMA
        or record.get("contract_id") != IMPERSONATION_PROTECTION_CONTRACT_ID
        or record.get("schema_status") != IMPERSONATION_PROTECTION_SCHEMA_STATUS
        or record.get("semantics") != IMPERSONATION_PROTECTION_SEMANTICS
        or record.get("three_p_doctrine_id") != THREE_P_DOCTRINE_ID
        or record.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or record.get("deployment_dependencies") != DEPLOYMENT_DEPENDENCIES
        or record.get("verified") is not False
        or not _verify_with_exact_ed25519_key(
            record,
            provider=context.owner_provider,
            exact_public_key=dict(boundary._public_keys)["owner_provider"],
        )
    ):
        return None, "IMPERSONATION_CONTEXT_OWNER_SIGNATURE_INVALID"
    text_fields = (
        "context_id",
        "context_version",
        "owner_id",
        "registry_id",
        "subject_id",
        "participant_id",
        "role_id",
        "mandate_id",
        "jurisdiction",
        "audience",
        "replay_namespace",
        "trusted_clock_id",
        "trusted_clock_version",
        "clock_head_id",
        "clock_head_version",
        "pseudonym_key_id",
    )
    if any(not _text(record.get(field)) for field in text_fields):
        return None, "IMPERSONATION_CONTEXT_IDENTITY_INVALID"
    if (
        type(record.get("context_sequence")) is not int
        or record["context_sequence"] < 1
        or (
            record["context_sequence"] == 1
            and record.get("prior_context_digest") != GENESIS_HASH
        )
        or (
            record["context_sequence"] > 1
            and not is_sha512(record.get("prior_context_digest"))
        )
        or record.get("stakeholder_class") not in STAKEHOLDER_CLASSES
        or not _text_list(record.get("mandate_actions"))
        or not _text_list(record.get("mandate_jurisdictions"))
        or record["jurisdiction"] not in record["mandate_jurisdictions"]
    ):
        return None, "IMPERSONATION_CONTEXT_MANDATE_INVALID"
    integer_fields = (
        "maximum_proof_age_ms",
        "minimum_registry_sequence",
        "minimum_authority_sequence",
        "minimum_revocation_sequence",
        "minimum_clock_sequence",
        "valid_from_ms",
        "valid_until_ms",
    )
    if any(type(record.get(field)) is not int for field in integer_fields):
        return None, "IMPERSONATION_CONTEXT_LIFECYCLE_INVALID"
    if (
        record["maximum_proof_age_ms"] <= 0
        or min(
            record["minimum_registry_sequence"],
            record["minimum_authority_sequence"],
            record["minimum_revocation_sequence"],
            record["valid_from_ms"],
        )
        < 0
        or record["valid_until_ms"] <= record["valid_from_ms"]
        or not record["valid_from_ms"] <= now_ms < record["valid_until_ms"]
        or clock_sequence < record["minimum_clock_sequence"]
        or record["pseudonym_key_id"] != sha512(boundary._pseudonym_key).hexdigest()
    ):
        return None, "IMPERSONATION_CONTEXT_NOT_CURRENT"
    bindings = (
        ("owner_provider_binding", context.owner_provider),
        ("registry_provider_binding", context.registry_provider),
        ("subject_provider_binding", context.subject_provider),
        ("replay_provider_binding", context.replay_provider),
        ("clock_provider_binding", context.trusted_clock),
        ("clock_head_provider_binding", context.clock_head_provider),
    )
    for field, provider in bindings:
        if not _provider_binding_exact(record.get(field)):
            return None, "IMPERSONATION_CONTEXT_PROVIDER_BINDING_INVALID"
        if record[field] != _provider_binding(provider):
            return None, "IMPERSONATION_CONTEXT_PROVIDER_SUBSTITUTION"
    public_key_fingerprints = [
        record[field]["ed25519_public_key_fingerprint"] for field, _ in bindings
    ]
    if len(set(public_key_fingerprints)) != len(public_key_fingerprints):
        return None, "IMPERSONATION_CONTEXT_KEYS_NOT_SEPARATE"
    verifier_bindings = (
        ("sovereign_identity_verifier", context.sovereign_identity_verifier),
        ("authority_boundary_verifier", context.authority_boundary_verifier),
    )
    for field, verifier in verifier_bindings:
        expected = record.get(field)
        receipt_provider = (
            context.sovereign_identity_dependencies
            if field == "sovereign_identity_verifier"
            else context.authority_boundary_dependencies
        )
        if (
            not _verifier_binding_exact(expected)
            or _safe_attribute(verifier, "verifier_id") != expected["verifier_id"]
            or _safe_attribute(verifier, "verifier_version")
            != expected["verifier_version"]
            or not callable(_safe_attribute(verifier, "verify_authenticated"))
            or expected["receipt_provider_binding"]
            != _provider_binding(receipt_provider)
        ):
            return None, "IMPERSONATION_CONTEXT_UPSTREAM_VERIFIER_INVALID"
    clock = context.trusted_clock
    if (
        _safe_attribute(clock, "clock_id") != record["trusted_clock_id"]
        or _safe_attribute(clock, "clock_version") != record["trusted_clock_version"]
        or record["clock_provider_binding"] != _provider_binding(clock)
        or not callable(_safe_attribute(clock, "current_time_record"))
    ):
        return None, "IMPERSONATION_CONTEXT_CLOCK_INVALID"
    clock_head = context.clock_head_provider
    if (
        _safe_attribute(clock_head, "head_id") != record["clock_head_id"]
        or _safe_attribute(clock_head, "head_version") != record["clock_head_version"]
        or record["clock_head_provider_binding"] != _provider_binding(clock_head)
        or not callable(_safe_attribute(clock_head, "current_head"))
        or not callable(_safe_attribute(clock_head, "advance_once"))
    ):
        return None, "IMPERSONATION_CONTEXT_CLOCK_HEAD_INVALID"
    if (
        not callable(_safe_attribute(context.registry, "lookup_identity"))
        or not callable(_safe_attribute(context.replay_guard, "current_head"))
        or not callable(_safe_attribute(context.replay_guard, "claim_once"))
        or not callable(_safe_attribute(context.replay_guard, "is_claimed"))
    ):
        return None, "IMPERSONATION_CONTEXT_DEPENDENCY_INVALID"
    return record, None


def impersonation_upstream_hash_payload(
    state: dict[str, Any],
    *,
    component_id: str,
    context_id: str,
    context_digest: str,
) -> dict[str, Any]:
    """Return the exact upstream receipt payload required by this boundary."""

    if component_id == SOVEREIGN_IDENTITY_COMPONENT:
        trace = state.get("sovereign_identity_trace")
        record = state.get("sovereign_identity_record")
        component_digest = state.get("sovereign_identity_digest")
        result = state.get("sovereign_identity_result")
    elif component_id == AUTHORITY_BOUNDARY_COMPONENT:
        trace = state.get("authority_boundary_trace")
        record = state.get("authority_boundary_record")
        component_digest = state.get("authority_boundary_digest")
        result = state.get("authority_boundary_result")
    else:
        trace = None
        record = None
        component_digest = None
        result = None
    return {
        "schema": UPSTREAM_HASH_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_id,
        "context_digest": context_digest,
        "component_id": component_id,
        "request_fingerprint": state.get("request_fingerprint"),
        "record_digest": _safe_hash(record),
        "trace_digest": _safe_hash(trace),
        "component_digest": component_digest,
        "result": result,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
    }


def _upstream_binding(
    state: dict[str, Any],
    *,
    component_id: str,
    context: ImpersonationTrustContext,
    context_record: dict[str, Any],
) -> tuple[dict[str, Any] | None, str | None]:
    if component_id == SOVEREIGN_IDENTITY_COMPONENT:
        verifier = context.sovereign_identity_verifier
        dependencies = context.sovereign_identity_dependencies
        verifier_record = context_record["sovereign_identity_verifier"]
        trace = state.get("sovereign_identity_trace")
        record = state.get("sovereign_identity_record")
        component_digest = state.get("sovereign_identity_digest")
        expected_component_digest = _safe_hash(trace)
        expected_result = IDENTITY_VERIFIED
        actual_result = state.get("sovereign_identity_result")
        false_fields = (
            "biometric_proof_established",
            "access_granted",
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_authority_granted",
        )
    else:
        verifier = context.authority_boundary_verifier
        dependencies = context.authority_boundary_dependencies
        verifier_record = context_record["authority_boundary_verifier"]
        trace = state.get("authority_boundary_trace")
        record = state.get("authority_boundary_record")
        component_digest = state.get("authority_boundary_digest")
        expected_component_digest = _safe_hash(record)
        expected_result = BOUNDARY_PASS
        actual_result = state.get("authority_boundary_result")
        false_fields = (
            "stakeholder_label_grants_rights",
            "authority_granted",
            "licence_granted",
            "execution_authority_granted",
            "effect_authority_granted",
            "pipeline_bypass_permitted",
        )
    if (
        type(trace) is not list
        or not trace
        or type(record) is not dict
        or record != trace[-1]
        or actual_result != expected_result
        or record.get("result") != expected_result
        or component_digest != expected_component_digest
        or not is_sha512(component_digest)
        or any(record.get(field) is not False for field in false_fields)
    ):
        return None, f"IMPERSONATION_{component_id.upper()}_STRUCTURE_INVALID"
    chain = state.get("hash_chain")
    if not verify_hash_chain_entries(chain, state.get("state_hash")):
        return None, "IMPERSONATION_UPSTREAM_HASH_CHAIN_INVALID"
    if type(chain) is not list:
        return None, "IMPERSONATION_UPSTREAM_HASH_CHAIN_INVALID"
    payload = impersonation_upstream_hash_payload(
        state,
        component_id=component_id,
        context_id=context_record["context_id"],
        context_digest=context_record["digest"],
    )
    expected_payload_hash = _safe_hash(payload)
    matches = [
        entry
        for entry in chain
        if entry.get("stage") == verifier_record["hash_stage"]
        and entry.get("payload_hash") == expected_payload_hash
    ]
    if len(matches) != 1 or not is_sha512(matches[0].get("hash")):
        return None, f"IMPERSONATION_{component_id.upper()}_HASH_BINDING_INVALID"
    expected_receipt = {
        "schema": UPSTREAM_RECEIPT_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "component_id": component_id,
        "verifier_id": verifier_record["verifier_id"],
        "verifier_version": verifier_record["verifier_version"],
        "request_fingerprint": state.get("request_fingerprint"),
        "evaluation_time": state.get("evaluation_time"),
        "pre_evaluation_state_hash": state.get("state_hash"),
        "record_digest": _safe_hash(record),
        "trace_digest": _safe_hash(trace),
        "component_digest": component_digest,
        "hash_binding_entry_hash": matches[0]["hash"],
        "upstream_payload_digest": expected_payload_hash,
        "result": expected_result,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
    }
    try:
        receipt = verifier.verify_authenticated(
            state=deepcopy(state),
            dependencies=dependencies,
            expected_receipt=deepcopy(expected_receipt),
        )
    except Exception:  # noqa: BLE001
        receipt = None
    boundary = context._composition_boundary
    receipt_key_role = (
        "sovereign_receipt_provider"
        if component_id == SOVEREIGN_IDENTITY_COMPONENT
        else "authority_receipt_provider"
    )
    if (
        boundary is None
        or type(receipt) is not dict
        or set(receipt) != _UPSTREAM_RECEIPT_FIELDS
        or any(receipt.get(field) != value for field, value in expected_receipt.items())
        or not _verify_with_exact_ed25519_key(
            receipt,
            provider=dependencies,
            exact_public_key=dict(boundary._public_keys)[receipt_key_role],
        )
    ):
        return None, f"IMPERSONATION_{component_id.upper()}_NOT_AUTHENTICATED"
    binding = {
        "component_id": component_id,
        "verifier_id": verifier_record["verifier_id"],
        "verifier_version": verifier_record["verifier_version"],
        "record_digest": _safe_hash(record),
        "trace_digest": _safe_hash(trace),
        "component_digest": component_digest,
        "hash_binding_entry_hash": matches[0]["hash"],
        "verification_receipt_digest": _safe_hash(receipt),
    }
    return binding, None


def _live_bindings(
    state: dict[str, Any],
    context_record: dict[str, Any],
    context: ImpersonationTrustContext,
) -> tuple[dict[str, Any] | None, str | None]:
    if state.get("identity") != {"subject_id": context_record["subject_id"]}:
        return None, "IMPERSONATION_SUBJECT_IDENTITY_MISMATCH"
    exact = {
        "participant_id": context_record["participant_id"],
        "stakeholder_class": context_record["stakeholder_class"],
        "participant_role": context_record["role_id"],
        "participant_mandate_id": context_record["mandate_id"],
        "requested_jurisdiction": context_record["jurisdiction"],
    }
    if any(state.get(field) != value for field, value in exact.items()):
        return None, "IMPERSONATION_LIVE_ROLE_MANDATE_BINDING_MISMATCH"
    action = state.get("action")
    if action not in context_record["mandate_actions"]:
        return None, "IMPERSONATION_ACTION_OUTSIDE_MANDATE"
    session_id = state.get("impersonation_session_id")
    audience = state.get("impersonation_audience")
    challenge = state.get("impersonation_challenge")
    if (
        not _text(session_id)
        or audience != context_record["audience"]
        or not is_sha512(challenge)
        or not is_sha512(state.get("request_fingerprint"))
        or not _state_hash(state.get("state_hash"))
    ):
        return None, "IMPERSONATION_LIVE_INPUT_BINDING_INVALID"
    subject_binding_digest = _pseudonymous_binding(
        context,
        purpose="subject_role_mandate_action",
        value={
            "subject_id": context_record["subject_id"],
            "participant_id": context_record["participant_id"],
            "stakeholder_class": context_record["stakeholder_class"],
            "role_id": context_record["role_id"],
            "mandate_id": context_record["mandate_id"],
            "requested_action": action,
            "jurisdiction": context_record["jurisdiction"],
        },
    )
    session_binding_digest = _pseudonymous_binding(
        context,
        purpose="session_audience",
        value={"session_id": session_id, "audience": audience},
    )
    challenge_binding_digest = _pseudonymous_binding(
        context,
        purpose="challenge",
        value={"challenge": challenge},
    )
    if not all(
        is_sha512(value)
        for value in (
            subject_binding_digest,
            session_binding_digest,
            challenge_binding_digest,
        )
    ):
        return None, "IMPERSONATION_PSEUDONYMOUS_BINDING_INVALID"
    return {
        "subject_binding_digest": subject_binding_digest,
        "session_binding_digest": session_binding_digest,
        "challenge_binding_digest": challenge_binding_digest,
        "session_id": session_id,
        "audience": audience,
        "challenge": challenge,
        "requested_action": action,
    }, None


def _snapshot(
    state: dict[str, Any],
    *,
    context_record: dict[str, Any],
    live: dict[str, Any],
    sovereign_binding: dict[str, Any],
    authority_binding: dict[str, Any],
    evaluation_time: int,
    clock_sequence: int,
    clock_record_digest: str,
    clock_head_sequence: int,
    clock_head_digest: str,
    clock_transition_receipt: dict[str, Any],
    clock_transition_receipt_digest: str,
    sequence: int,
    prior_digest: str | None,
) -> dict[str, Any]:
    return {
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "stage": IMPERSONATION_PROTECTION_STAGE,
        "evaluation_sequence": sequence,
        "evaluation_time": evaluation_time,
        "clock_sequence": clock_sequence,
        "clock_record_digest": clock_record_digest,
        "clock_head_sequence": clock_head_sequence,
        "clock_head_digest": clock_head_digest,
        "clock_transition_receipt": deepcopy(clock_transition_receipt),
        "clock_transition_receipt_digest": clock_transition_receipt_digest,
        "pre_evaluation_state_hash": state.get("state_hash"),
        "request_fingerprint": state.get("request_fingerprint"),
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "subject_binding_digest": live["subject_binding_digest"],
        "session_binding_digest": live["session_binding_digest"],
        "challenge_binding_digest": live["challenge_binding_digest"],
        "sovereign_identity_binding": deepcopy(sovereign_binding),
        "authority_boundary_binding": deepcopy(authority_binding),
        "prior_impersonation_digest": prior_digest,
    }


def _snapshot_exact(value: Any) -> TypeGuard[dict[str, Any]]:
    if type(value) is not dict or set(value) != _SNAPSHOT_FIELDS:
        return False
    if (
        value.get("contract_id") != IMPERSONATION_PROTECTION_CONTRACT_ID
        or value.get("schema_status") != IMPERSONATION_PROTECTION_SCHEMA_STATUS
        or value.get("semantics") != IMPERSONATION_PROTECTION_SEMANTICS
        or value.get("stage") != IMPERSONATION_PROTECTION_STAGE
        or type(value.get("evaluation_sequence")) is not int
        or value["evaluation_sequence"] < 1
        or type(value.get("evaluation_time")) is not int
        or value["evaluation_time"] < 0
        or type(value.get("clock_sequence")) is not int
        or value["clock_sequence"] < 1
        or not is_sha512(value.get("clock_record_digest"))
        or type(value.get("clock_head_sequence")) is not int
        or value["clock_head_sequence"] < 1
        or not is_sha512(value.get("clock_head_digest"))
        or type(value.get("clock_transition_receipt")) is not dict
        or set(value["clock_transition_receipt"]) != _CLOCK_HEAD_TRANSITION_FIELDS
        or _safe_hash(value["clock_transition_receipt"])
        != value.get("clock_transition_receipt_digest")
        or not is_sha512(value.get("clock_transition_receipt_digest"))
        or not _state_hash(value.get("pre_evaluation_state_hash"))
        or not is_sha512(value.get("request_fingerprint"))
        or not _text(value.get("context_id"))
        or not is_sha512(value.get("context_digest"))
        or not all(
            is_sha512(value.get(field))
            for field in (
                "subject_binding_digest",
                "session_binding_digest",
                "challenge_binding_digest",
            )
        )
        or (
            value.get("prior_impersonation_digest") is not None
            and not is_sha512(value.get("prior_impersonation_digest"))
        )
    ):
        return False
    for field, component in (
        ("sovereign_identity_binding", SOVEREIGN_IDENTITY_COMPONENT),
        ("authority_boundary_binding", AUTHORITY_BOUNDARY_COMPONENT),
    ):
        binding = value.get(field)
        if (
            type(binding) is not dict
            or set(binding) != _UPSTREAM_BINDING_FIELDS
            or binding.get("component_id") != component
            or not all(
                _text(binding.get(item)) for item in ("verifier_id", "verifier_version")
            )
            or not all(
                is_sha512(binding.get(item))
                for item in (
                    "record_digest",
                    "trace_digest",
                    "component_digest",
                    "hash_binding_entry_hash",
                )
            )
        ):
            return False
    return True


def _registry_error(
    record: Any,
    *,
    context_record: dict[str, Any],
    registry_provider: SignatureProvider,
    context: ImpersonationTrustContext,
    now_ms: int,
) -> str | None:
    if type(record) is not dict or set(record) != _LIVE_REGISTRY_FIELDS:
        return "IMPERSONATION_REGISTRY_RECORD_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        record,
        provider=registry_provider,
        exact_public_key=dict(boundary._public_keys)["registry_provider"],
    ):
        return "IMPERSONATION_REGISTRY_RECORD_SIGNATURE_INVALID"
    exact = {
        "schema": LIVE_REGISTRY_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "registry_id": context_record["registry_id"],
        "subject_id": context_record["subject_id"],
        "participant_id": context_record["participant_id"],
        "stakeholder_class": context_record["stakeholder_class"],
        "role_id": context_record["role_id"],
        "mandate_id": context_record["mandate_id"],
        "mandate_actions": context_record["mandate_actions"],
        "mandate_jurisdictions": context_record["mandate_jurisdictions"],
        "jurisdiction": context_record["jurisdiction"],
        "subject_provider_binding": context_record["subject_provider_binding"],
    }
    if any(record.get(field) != expected for field, expected in exact.items()):
        return "IMPERSONATION_REGISTRY_BINDING_MISMATCH"
    sequence_requirements = (
        ("registry_sequence", "minimum_registry_sequence"),
        ("authority_sequence", "minimum_authority_sequence"),
        ("revocation_sequence", "minimum_revocation_sequence"),
    )
    if any(
        type(record.get(field)) is not int or record[field] < context_record[minimum]
        for field, minimum in sequence_requirements
    ):
        return "IMPERSONATION_REGISTRY_SEQUENCE_INVALID"
    if record.get("revocation_status") != TRUST_ACTIVE:
        return "IMPERSONATION_TRUST_REVOKED_OR_INDETERMINATE"
    valid_from = record.get("valid_from_ms")
    valid_until = record.get("valid_until_ms")
    if (
        type(valid_from) is not int
        or type(valid_until) is not int
        or valid_from < 0
        or valid_until <= valid_from
        or not valid_from <= now_ms < valid_until
    ):
        return "IMPERSONATION_REGISTRY_RECORD_NOT_CURRENT"
    return None


def _proof_error(
    proof: Any,
    *,
    context_record: dict[str, Any],
    registry_record: dict[str, Any],
    registry_digest: str,
    state: dict[str, Any],
    live: dict[str, Any],
    snapshot: dict[str, Any],
    subject_provider: SignatureProvider,
    context: ImpersonationTrustContext,
    now_ms: int,
) -> str | None:
    if type(proof) is not dict or set(proof) != _PROOF_FIELDS:
        return "IMPERSONATION_POSSESSION_PROOF_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        proof,
        provider=subject_provider,
        exact_public_key=dict(boundary._public_keys)["subject_provider"],
    ):
        return "IMPERSONATION_POSSESSION_PROOF_SIGNATURE_INVALID"
    expected = {
        "schema": POSSESSION_PROOF_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "registry_record_digest": registry_digest,
        "subject_id": context_record["subject_id"],
        "participant_id": context_record["participant_id"],
        "stakeholder_class": context_record["stakeholder_class"],
        "role_id": context_record["role_id"],
        "mandate_id": context_record["mandate_id"],
        "requested_action": live["requested_action"],
        "jurisdiction": context_record["jurisdiction"],
        "subject_provider_binding": context_record["subject_provider_binding"],
        "challenge": state["impersonation_challenge"],
        "request_fingerprint": snapshot["request_fingerprint"],
        "session_id": state["impersonation_session_id"],
        "audience": context_record["audience"],
        "registry_sequence": registry_record["registry_sequence"],
        "authority_sequence": registry_record["authority_sequence"],
        "revocation_sequence": registry_record["revocation_sequence"],
        "sovereign_identity_digest": snapshot["sovereign_identity_binding"][
            "component_digest"
        ],
        "authority_boundary_digest": snapshot["authority_boundary_binding"][
            "component_digest"
        ],
        "prior_impersonation_digest": snapshot["prior_impersonation_digest"],
    }
    if any(proof.get(field) != value for field, value in expected.items()):
        return "IMPERSONATION_POSSESSION_PROOF_BINDING_MISMATCH"
    issued_at = proof.get("issued_at_ms")
    expires_at = proof.get("expires_at_ms")
    maximum_age = context_record["maximum_proof_age_ms"]
    if type(issued_at) is not int or type(expires_at) is not int:
        return "IMPERSONATION_POSSESSION_PROOF_TIME_INVALID"
    if issued_at > now_ms:
        return "IMPERSONATION_POSSESSION_PROOF_FUTURE"
    if expires_at <= issued_at or now_ms >= expires_at:
        return "IMPERSONATION_POSSESSION_PROOF_EXPIRED"
    if now_ms - issued_at > maximum_age or expires_at - issued_at > maximum_age:
        return "IMPERSONATION_POSSESSION_PROOF_STALE"
    if (
        issued_at < registry_record["valid_from_ms"]
        or expires_at > registry_record["valid_until_ms"]
    ):
        return "IMPERSONATION_POSSESSION_PROOF_OUTSIDE_TRUST_WINDOW"
    return None


def _replay_key(
    *,
    context_record: dict[str, Any],
    snapshot: dict[str, Any],
    context: ImpersonationTrustContext,
) -> str:
    value = _pseudonymous_binding(
        context,
        purpose="durable_replay_key",
        value={
            "context_id": context_record["context_id"],
            "context_digest": context_record["digest"],
            "request_fingerprint": snapshot["request_fingerprint"],
            "subject_binding_digest": snapshot["subject_binding_digest"],
            "session_binding_digest": snapshot["session_binding_digest"],
            "challenge_binding_digest": snapshot["challenge_binding_digest"],
        },
    )
    if value is None:
        raise ValueError("IMPERSONATION_REPLAY_KEY_UNAVAILABLE")
    return value


def _head_error(
    head: Any,
    *,
    context_record: dict[str, Any],
    subject_binding_digest: str,
    replay_provider: SignatureProvider,
    context: ImpersonationTrustContext,
    now_ms: int,
) -> str | None:
    if type(head) is not dict or set(head) != _REPLAY_HEAD_FIELDS:
        return "IMPERSONATION_REPLAY_HEAD_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        head,
        provider=replay_provider,
        exact_public_key=dict(boundary._public_keys)["replay_provider"],
    ):
        return "IMPERSONATION_REPLAY_HEAD_SIGNATURE_INVALID"
    exact = {
        "schema": REPLAY_HEAD_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "namespace": context_record["replay_namespace"],
        "subject_binding_digest": subject_binding_digest,
        "observed_at_ms": now_ms,
        "authorization_effect": NO_AUTHORIZATION_EFFECT,
    }
    if any(head.get(field) != value for field, value in exact.items()):
        return "IMPERSONATION_REPLAY_HEAD_BINDING_INVALID"
    integer_fields = (
        "registry_sequence",
        "authority_sequence",
        "revocation_sequence",
        "claim_sequence",
    )
    if any(
        type(head.get(field)) is not int or head[field] < 0 for field in integer_fields
    ):
        return "IMPERSONATION_REPLAY_HEAD_SEQUENCE_INVALID"
    latest = head.get("latest_claim_receipt_digest")
    if latest != GENESIS_HASH and not is_sha512(latest):
        return "IMPERSONATION_REPLAY_HEAD_DIGEST_INVALID"
    if head["claim_sequence"] == 0 and latest != GENESIS_HASH:
        return "IMPERSONATION_REPLAY_HEAD_GENESIS_INVALID"
    if head["claim_sequence"] > 0 and not is_sha512(latest):
        return "IMPERSONATION_REPLAY_HEAD_DIGEST_REQUIRED"
    return None


def _receipt_error(
    receipt: Any,
    *,
    expected_claim: dict[str, Any],
    replay_provider: SignatureProvider,
    context: ImpersonationTrustContext,
) -> str | None:
    if type(receipt) is not dict or set(receipt) != _REPLAY_CLAIM_FIELDS:
        return "IMPERSONATION_REPLAY_RECEIPT_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        receipt,
        provider=replay_provider,
        exact_public_key=dict(boundary._public_keys)["replay_provider"],
    ):
        return "IMPERSONATION_REPLAY_RECEIPT_SIGNATURE_INVALID"
    if any(receipt.get(field) != value for field, value in expected_claim.items()):
        return "IMPERSONATION_REPLAY_RECEIPT_BINDING_INVALID"
    return None


def _persistence_error(
    receipt: Any,
    *,
    context_record: dict[str, Any],
    replay_provider: SignatureProvider,
    context: ImpersonationTrustContext,
    replay_key: str,
    claim_receipt_digest: str,
    subject_binding_digest: str,
    claim_sequence: int,
    current_head_digest: str,
    registry_sequence: int,
    authority_sequence: int,
    revocation_sequence: int,
    observed_at_ms: int,
) -> str | None:
    if type(receipt) is not dict or set(receipt) != _REPLAY_PERSISTENCE_FIELDS:
        return "IMPERSONATION_REPLAY_PERSISTENCE_SHAPE_INVALID"
    boundary = context._composition_boundary
    if boundary is None or not _verify_with_exact_ed25519_key(
        receipt,
        provider=replay_provider,
        exact_public_key=dict(boundary._public_keys)["replay_provider"],
    ):
        return "IMPERSONATION_REPLAY_PERSISTENCE_SIGNATURE_INVALID"
    exact = {
        "schema": REPLAY_PERSISTENCE_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": context_record["context_id"],
        "context_digest": context_record["digest"],
        "namespace": context_record["replay_namespace"],
        "replay_key": replay_key,
        "claim_receipt_digest": claim_receipt_digest,
        "subject_binding_digest": subject_binding_digest,
        "claim_sequence": claim_sequence,
        "current_head_digest": current_head_digest,
        "registry_sequence": registry_sequence,
        "authority_sequence": authority_sequence,
        "revocation_sequence": revocation_sequence,
        "observed_at_ms": observed_at_ms,
        "persisted": True,
        "authorization_effect": NO_AUTHORIZATION_EFFECT,
    }
    if any(receipt.get(field) != value for field, value in exact.items()):
        return "IMPERSONATION_REPLAY_PERSISTENCE_BINDING_INVALID"
    return None


def _record(
    *,
    sequence: int,
    result: str,
    reason: str,
    snapshot: dict[str, Any] | None,
    context_record: dict[str, Any] | None,
    registry_record: dict[str, Any] | None,
    registry_digest: str | None,
    proof_digest: str | None,
    replay_key: str | None,
    receipt: dict[str, Any] | None,
    head_digest: str | None,
    persistence_receipt_digest: str | None,
) -> dict[str, Any]:
    return {
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "stage": IMPERSONATION_PROTECTION_STAGE,
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot) if snapshot else None,
        "context_id": context_record.get("context_id") if context_record else None,
        "context_digest": context_record.get("digest") if context_record else None,
        "registry_record_digest": registry_digest,
        "possession_proof_digest": proof_digest,
        "replay_key": replay_key,
        "replay_claim_receipt": deepcopy(receipt),
        "replay_claim_receipt_digest": _safe_hash(receipt) if receipt else None,
        "replay_head_digest": head_digest,
        "replay_persistence_receipt_digest": persistence_receipt_digest,
        "registry_sequence": (
            registry_record.get("registry_sequence") if registry_record else None
        ),
        "authority_sequence": (
            registry_record.get("authority_sequence") if registry_record else None
        ),
        "revocation_status": (
            registry_record.get("revocation_status") if registry_record else None
        ),
        "revocation_sequence": (
            registry_record.get("revocation_sequence") if registry_record else None
        ),
        "deployment_dependencies": dict(DEPLOYMENT_DEPENDENCIES),
        "biometric_proof_established": False,
        "identity_issued": False,
        "identity_label_grants_access": False,
        "role_label_grants_authority": False,
        "mandate_label_grants_authority": False,
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority_granted": False,
        "pipeline_bypass_permitted": False,
    }


def _apply(state: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    trace = state.get("impersonation_protection_trace")
    if type(trace) is not list:
        trace = []
        state["impersonation_protection_trace"] = trace
    trace.append(record)
    state["impersonation_protection_record"] = deepcopy(record)
    state["impersonation_protection_digest"] = canonical_integrity_hash(trace)
    state["impersonation_protection_result"] = record["result"]
    state["impersonation_protection_reason"] = record["reason"]
    for field in _FALSE_FLAG_FIELDS:
        state[f"impersonation_{field}"] = False
    return state


def _structured_deny(
    state: Any,
    *,
    reason: str,
    sequence: int = 1,
    context_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = state if type(state) is dict else {}
    return _apply(
        target,
        _record(
            sequence=sequence,
            result=IMPERSONATION_DENY,
            reason=reason,
            snapshot=None,
            context_record=context_record,
            registry_record=None,
            registry_digest=None,
            proof_digest=None,
            replay_key=None,
            receipt=None,
            head_digest=None,
            persistence_receipt_digest=None,
        ),
    )


def evaluate_impersonation_protection(
    state: Any,
    *,
    possession_proof: dict[str, Any] | None,
    trust_context: ImpersonationTrustContext | None,
) -> dict[str, Any]:
    """Evaluate and durably claim one owner-context-bound possession proof."""

    if type(state) is not dict:
        return _structured_deny(state, reason="IMPERSONATION_STATE_NOT_DICT")
    trace = state.get("impersonation_protection_trace")
    if trace is None:
        trace = []
        state["impersonation_protection_trace"] = trace
    if type(trace) is not list:
        state["impersonation_protection_trace"] = []
        return _structured_deny(state, reason="IMPERSONATION_TRACE_INVALID")
    sequence = len(trace) + 1
    prior_digest = _safe_hash(trace) if trace else None
    if trace and prior_digest is None:
        return _structured_deny(
            state,
            reason="IMPERSONATION_PRIOR_TRACE_NOT_HASHABLE",
            sequence=sequence,
        )
    clock_record, clock_reason = _clock_record_error(trust_context)
    if clock_reason is not None or clock_record is None:
        return _structured_deny(
            state,
            reason=clock_reason or "IMPERSONATION_TRUSTED_CLOCK_UNAVAILABLE",
            sequence=sequence,
        )
    now_ms = clock_record["now_ms"]
    context_record, reason = _context_error(
        trust_context,
        now_ms=now_ms,
        clock_sequence=clock_record["clock_sequence"],
    )
    if (
        reason is not None
        or context_record is None
        or type(trust_context) is not ImpersonationTrustContext
    ):
        return _structured_deny(
            state,
            reason=reason or "IMPERSONATION_DEPLOYMENT_CONTEXT_REQUIRED",
            sequence=sequence,
        )
    if state.get("evaluation_time") != now_ms:
        return _structured_deny(
            state,
            reason="IMPERSONATION_TRUSTED_TIME_BINDING_MISMATCH",
            sequence=sequence,
            context_record=context_record,
        )
    if trace and trace[-1].get("result") != IMPERSONATION_PASS:
        return _structured_deny(
            state,
            reason="IMPERSONATION_PRIOR_EVALUATION_NOT_PASS",
            sequence=sequence,
            context_record=context_record,
        )
    clock_admission, reason = _admit_clock_record(
        context=trust_context,
        context_record=context_record,
        clock_record=clock_record,
    )
    if reason is not None or clock_admission is None:
        return _structured_deny(
            state,
            reason=reason or "IMPERSONATION_CLOCK_HEAD_UNAVAILABLE",
            sequence=sequence,
            context_record=context_record,
        )
    try:
        return _evaluate_valid_context(
            state,
            possession_proof=possession_proof,
            trust_context=trust_context,
            context_record=context_record,
            now_ms=now_ms,
            clock_record=clock_record,
            clock_admission=clock_admission,
            sequence=sequence,
            prior_digest=prior_digest,
        )
    except Exception:  # noqa: BLE001
        return _structured_deny(
            state,
            reason="IMPERSONATION_DEPENDENCY_OR_EVIDENCE_FAILURE",
            sequence=sequence,
            context_record=context_record,
        )


def _evaluate_valid_context(
    state: dict[str, Any],
    *,
    possession_proof: dict[str, Any] | None,
    trust_context: ImpersonationTrustContext,
    context_record: dict[str, Any],
    now_ms: int,
    clock_record: dict[str, Any],
    clock_admission: dict[str, Any],
    sequence: int,
    prior_digest: str | None,
) -> dict[str, Any]:
    live, reason = _live_bindings(state, context_record, trust_context)
    safe_live: dict[str, Any] = live if type(live) is dict else {}
    if reason is None and type(live) is not dict:
        reason = "IMPERSONATION_LIVE_BINDINGS_INVALID"
    sovereign_binding: dict[str, Any] | None = None
    safe_sovereign_binding: dict[str, Any] = {}
    authority_binding: dict[str, Any] | None = None
    safe_authority_binding: dict[str, Any] = {}
    if reason is None:
        sovereign_binding, reason = _upstream_binding(
            state,
            component_id=SOVEREIGN_IDENTITY_COMPONENT,
            context=trust_context,
            context_record=context_record,
        )
        if type(sovereign_binding) is dict:
            safe_sovereign_binding = sovereign_binding
        elif reason is None:
            reason = "IMPERSONATION_SOVEREIGN_IDENTITY_BINDING_INVALID"
    if reason is None:
        authority_binding, reason = _upstream_binding(
            state,
            component_id=AUTHORITY_BOUNDARY_COMPONENT,
            context=trust_context,
            context_record=context_record,
        )
        if type(authority_binding) is dict:
            safe_authority_binding = authority_binding
        elif reason is None:
            reason = "IMPERSONATION_AUTHORITY_BOUNDARY_BINDING_INVALID"
    snapshot: dict[str, Any] | None = None
    safe_snapshot: dict[str, Any] = {}
    clock_record_digest = _safe_hash(clock_record)
    if reason is None and clock_record_digest is None:
        reason = "IMPERSONATION_TRUSTED_CLOCK_RECORD_INVALID"
    if reason is None:
        safe_snapshot = _snapshot(
            state,
            context_record=context_record,
            live=safe_live,
            sovereign_binding=safe_sovereign_binding,
            authority_binding=safe_authority_binding,
            evaluation_time=now_ms,
            clock_sequence=clock_record["clock_sequence"],
            clock_record_digest=clock_record_digest or "",
            clock_head_sequence=clock_admission["clock_head_sequence"],
            clock_head_digest=clock_admission["clock_head_digest"],
            clock_transition_receipt=clock_admission["clock_transition_receipt"],
            clock_transition_receipt_digest=clock_admission[
                "clock_transition_receipt_digest"
            ],
            sequence=sequence,
            prior_digest=prior_digest,
        )
        snapshot = safe_snapshot
        if not _snapshot_exact(safe_snapshot):
            reason = "IMPERSONATION_SNAPSHOT_INVALID"
    registry_record: dict[str, Any] | None = None
    safe_registry_record: dict[str, Any] = {}
    if reason is None:
        candidate = trust_context.registry.lookup_identity(
            subject_id=context_record["subject_id"],
            participant_id=context_record["participant_id"],
        )
        registry_record = candidate if type(candidate) is dict else None
        safe_registry_record = registry_record if registry_record is not None else {}
        reason = _registry_error(
            registry_record,
            context_record=context_record,
            registry_provider=trust_context.registry_provider,
            context=trust_context,
            now_ms=now_ms,
        )
    registry_digest = _safe_hash(registry_record) if registry_record else None
    safe_registry_digest = registry_digest or ""
    safe_possession_proof = possession_proof if type(possession_proof) is dict else {}
    if reason is None:
        reason = _proof_error(
            possession_proof,
            context_record=context_record,
            registry_record=safe_registry_record,
            registry_digest=safe_registry_digest,
            state=state,
            live=safe_live,
            snapshot=safe_snapshot,
            subject_provider=trust_context.subject_provider,
            context=trust_context,
            now_ms=now_ms,
        )
    pre_head: dict[str, Any] | None = None
    safe_pre_head: dict[str, Any] = {}
    if reason is None:
        pre_head = trust_context.replay_guard.current_head(
            namespace=context_record["replay_namespace"],
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            observed_at_ms=now_ms,
        )
        safe_pre_head = pre_head if type(pre_head) is dict else {}
        reason = _head_error(
            pre_head,
            context_record=context_record,
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            replay_provider=trust_context.replay_provider,
            context=trust_context,
            now_ms=now_ms,
        )
    if reason is None:
        current_sequences = (
            safe_registry_record["registry_sequence"],
            safe_registry_record["authority_sequence"],
            safe_registry_record["revocation_sequence"],
        )
        stored_sequences = (
            safe_pre_head["registry_sequence"],
            safe_pre_head["authority_sequence"],
            safe_pre_head["revocation_sequence"],
        )
        if any(
            current < stored
            for current, stored in zip(current_sequences, stored_sequences)
        ):
            reason = "IMPERSONATION_DURABLE_SEQUENCE_ROLLBACK"
    replay_key: str | None = None
    safe_replay_key = ""
    receipt: dict[str, Any] | None = None
    safe_receipt: dict[str, Any] = {}
    post_head: dict[str, Any] | None = None
    safe_post_head: dict[str, Any] = {}
    proof_digest = _safe_hash(possession_proof) if possession_proof else None
    if reason is None:
        replay_key = _replay_key(
            context_record=context_record,
            snapshot=safe_snapshot,
            context=trust_context,
        )
        safe_replay_key = replay_key or ""
        claim = {
            "schema": REPLAY_CLAIM_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": context_record["context_id"],
            "context_digest": context_record["digest"],
            "namespace": context_record["replay_namespace"],
            "replay_key": replay_key,
            "claim_sequence": safe_pre_head["claim_sequence"] + 1,
            "prior_claim_receipt_digest": safe_pre_head["latest_claim_receipt_digest"],
            "pre_claim_head_digest": _safe_hash(safe_pre_head),
            "claimed_at_ms": now_ms,
            "expires_at_ms": safe_possession_proof["expires_at_ms"],
            "request_fingerprint": safe_snapshot["request_fingerprint"],
            "snapshot_digest": _safe_hash(safe_snapshot),
            "registry_record_digest": safe_registry_digest,
            "possession_proof_digest": proof_digest,
            "subject_binding_digest": safe_snapshot["subject_binding_digest"],
            "session_binding_digest": safe_snapshot["session_binding_digest"],
            "challenge_binding_digest": safe_snapshot["challenge_binding_digest"],
            "registry_sequence": safe_registry_record["registry_sequence"],
            "authority_sequence": safe_registry_record["authority_sequence"],
            "revocation_sequence": safe_registry_record["revocation_sequence"],
            "clock_sequence": clock_record["clock_sequence"],
            "clock_record_digest": _safe_hash(clock_record),
            "result": REPLAY_CLAIMED,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        receipt = trust_context.replay_guard.claim_once(claim=deepcopy(claim))
        safe_receipt = receipt if type(receipt) is dict else {}
        reason = _receipt_error(
            receipt,
            expected_claim=claim,
            replay_provider=trust_context.replay_provider,
            context=trust_context,
        )
    if reason is None:
        post_head = trust_context.replay_guard.current_head(
            namespace=context_record["replay_namespace"],
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            observed_at_ms=now_ms,
        )
        safe_post_head = post_head if type(post_head) is dict else {}
        reason = _head_error(
            post_head,
            context_record=context_record,
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            replay_provider=trust_context.replay_provider,
            context=trust_context,
            now_ms=now_ms,
        )
    receipt_digest = _safe_hash(receipt) if receipt else None
    post_head_digest = _safe_hash(post_head) if post_head else None
    if reason is None and (
        safe_post_head["registry_sequence"] != safe_registry_record["registry_sequence"]
        or safe_post_head["authority_sequence"]
        != safe_registry_record["authority_sequence"]
        or safe_post_head["revocation_sequence"]
        != safe_registry_record["revocation_sequence"]
        or safe_post_head["claim_sequence"] != safe_receipt["claim_sequence"]
        or safe_post_head["latest_claim_receipt_digest"] != receipt_digest
    ):
        reason = "IMPERSONATION_DURABLE_REPLAY_RECEIPT_NOT_CURRENT"
    persistence_receipt = None
    if reason is None:
        safe_receipt_digest = receipt_digest or ""
        safe_post_head_digest = post_head_digest or ""
        persistence_receipt = trust_context.replay_guard.is_claimed(
            namespace=context_record["replay_namespace"],
            replay_key=safe_replay_key,
            receipt_digest=safe_receipt_digest,
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            observed_at_ms=now_ms,
            current_head_digest=safe_post_head_digest,
        )
        reason = _persistence_error(
            persistence_receipt,
            context_record=context_record,
            replay_provider=trust_context.replay_provider,
            context=trust_context,
            replay_key=safe_replay_key,
            claim_receipt_digest=safe_receipt_digest,
            subject_binding_digest=safe_snapshot["subject_binding_digest"],
            claim_sequence=safe_receipt["claim_sequence"],
            current_head_digest=safe_post_head_digest,
            registry_sequence=safe_registry_record["registry_sequence"],
            authority_sequence=safe_registry_record["authority_sequence"],
            revocation_sequence=safe_registry_record["revocation_sequence"],
            observed_at_ms=now_ms,
        )
    if reason is None:
        reason = _terminal_clock_head_error(
            context=trust_context,
            context_record=context_record,
            expected=clock_admission,
        )

    result = IMPERSONATION_PASS if reason is None else IMPERSONATION_DENY
    record = _record(
        sequence=sequence,
        result=result,
        reason=reason or "IMPERSONATION_PROTECTION_COMPLETED",
        snapshot=snapshot,
        context_record=context_record,
        registry_record=registry_record,
        registry_digest=registry_digest,
        proof_digest=proof_digest,
        replay_key=replay_key,
        receipt=receipt,
        head_digest=post_head_digest,
        persistence_receipt_digest=(
            _safe_hash(persistence_receipt) if persistence_receipt else None
        ),
    )
    return _apply(state, record)


def verify_impersonation_protection(
    state: Any,
    *,
    trust_context: ImpersonationTrustContext | None,
) -> bool:
    """Verify the current pseudonymous receipt against all live trust state."""

    try:
        if (
            type(state) is not dict
            or type(trust_context) is not ImpersonationTrustContext
        ):
            return False
        clock_record, clock_error = _clock_record_error(trust_context)
        if clock_error is not None or clock_record is None:
            return False
        now_ms = clock_record["now_ms"]
        context_record, error = _context_error(
            trust_context,
            now_ms=now_ms,
            clock_sequence=clock_record["clock_sequence"],
        )
        if error is not None or context_record is None:
            return False
        trace = state.get("impersonation_protection_trace")
        latest = state.get("impersonation_protection_record")
        if (
            type(trace) is not list
            or not trace
            or type(latest) is not dict
            or latest != trace[-1]
            or state.get("impersonation_protection_digest") != _safe_hash(trace)
            or state.get("impersonation_protection_result") != IMPERSONATION_PASS
            or latest.get("result") != IMPERSONATION_PASS
            or latest.get("reason") != "IMPERSONATION_PROTECTION_COMPLETED"
            or set(latest) != _RECORD_FIELDS
            or latest.get("deployment_dependencies") != DEPLOYMENT_DEPENDENCIES
            or any(latest.get(field) is not False for field in _FALSE_FLAG_FIELDS)
            or any(
                state.get(f"impersonation_{field}") is not False
                for field in _FALSE_FLAG_FIELDS
            )
        ):
            return False
        prefix: list[dict[str, Any]] = []
        for sequence, record in enumerate(trace, start=1):
            if type(record) is not dict or set(record) != _RECORD_FIELDS:
                return False
            snapshot = record.get("evaluation_snapshot")
            if not _snapshot_exact(snapshot):
                return False
            if (
                record.get("evaluation_sequence") != sequence
                or any(record.get(field) is not False for field in _FALSE_FLAG_FIELDS)
                or record.get("result") != IMPERSONATION_PASS
                or record.get("deployment_dependencies") != DEPLOYMENT_DEPENDENCIES
                or snapshot["evaluation_sequence"] != sequence
                or snapshot["prior_impersonation_digest"]
                != (_safe_hash(prefix) if prefix else None)
                or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
                or record.get("context_id") != context_record["context_id"]
                or record.get("context_digest") != context_record["digest"]
            ):
                return False
            prefix.append(record)
        live, error = _live_bindings(state, context_record, trust_context)
        if error is not None or type(live) is not dict:
            return False
        sovereign_binding, error = _upstream_binding(
            state,
            component_id=SOVEREIGN_IDENTITY_COMPONENT,
            context=trust_context,
            context_record=context_record,
        )
        if error is not None or type(sovereign_binding) is not dict:
            return False
        authority_binding, error = _upstream_binding(
            state,
            component_id=AUTHORITY_BOUNDARY_COMPONENT,
            context=trust_context,
            context_record=context_record,
        )
        if error is not None or type(authority_binding) is not dict:
            return False
        audited_snapshot = latest["evaluation_snapshot"]
        if type(audited_snapshot) is not dict:
            return False
        if (
            state.get("evaluation_time") != audited_snapshot["evaluation_time"]
            or clock_record["clock_sequence"] != audited_snapshot["clock_sequence"]
            or now_ms != audited_snapshot["evaluation_time"]
            or _safe_hash(clock_record) != audited_snapshot["clock_record_digest"]
        ):
            return False
        clock_head = trust_context.clock_head_provider.current_head(
            context_id=context_record["context_id"],
            context_digest=context_record["digest"],
        )
        if type(clock_head) is not dict:
            return False
        if (
            _clock_head_error(
                clock_head,
                context_record=context_record,
                context=trust_context,
            )
            is not None
            or clock_head["head_sequence"] != audited_snapshot["clock_head_sequence"]
            or _safe_hash(clock_head) != audited_snapshot["clock_head_digest"]
            or clock_head["clock_record_digest"]
            != audited_snapshot["clock_record_digest"]
            or clock_head["latest_transition_receipt_digest"]
            != audited_snapshot["clock_transition_receipt_digest"]
        ):
            return False
        transition_receipt = audited_snapshot["clock_transition_receipt"]
        if type(transition_receipt) is not dict:
            return False
        prior_head_digest = transition_receipt.get("prior_head_digest")
        if not is_sha512(prior_head_digest):
            return False
        expected_transition = {
            "schema": CLOCK_HEAD_TRANSITION_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": context_record["context_id"],
            "context_digest": context_record["digest"],
            "head_id": context_record["clock_head_id"],
            "head_version": context_record["clock_head_version"],
            "head_sequence": audited_snapshot["clock_head_sequence"],
            "prior_head_digest": prior_head_digest,
            "clock_sequence": audited_snapshot["clock_sequence"],
            "clock_record_digest": audited_snapshot["clock_record_digest"],
            "prior_clock_record_digest": clock_record["prior_clock_record_digest"],
            "observed_at_ms": audited_snapshot["evaluation_time"],
            "result": "ADVANCED",
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        if (
            _clock_transition_error(
                transition_receipt,
                expected_transition=expected_transition,
                context=trust_context,
            )
            is not None
        ):
            return False
        current_snapshot = _snapshot(
            state,
            context_record=context_record,
            live=live,
            sovereign_binding=sovereign_binding,
            authority_binding=authority_binding,
            evaluation_time=audited_snapshot["evaluation_time"],
            clock_sequence=audited_snapshot["clock_sequence"],
            clock_record_digest=audited_snapshot["clock_record_digest"],
            clock_head_sequence=audited_snapshot["clock_head_sequence"],
            clock_head_digest=audited_snapshot["clock_head_digest"],
            clock_transition_receipt=audited_snapshot["clock_transition_receipt"],
            clock_transition_receipt_digest=audited_snapshot[
                "clock_transition_receipt_digest"
            ],
            sequence=len(trace),
            prior_digest=_safe_hash(trace[:-1]) if len(trace) > 1 else None,
        )
        if current_snapshot != audited_snapshot:
            return False
        registry_record = trust_context.registry.lookup_identity(
            subject_id=context_record["subject_id"],
            participant_id=context_record["participant_id"],
        )
        if type(registry_record) is not dict:
            return False
        if (
            _registry_error(
                registry_record,
                context_record=context_record,
                registry_provider=trust_context.registry_provider,
                context=trust_context,
                now_ms=now_ms,
            )
            is not None
        ):
            return False
        if latest.get("registry_record_digest") != _safe_hash(registry_record):
            return False
        receipt = latest.get("replay_claim_receipt")
        if type(receipt) is not dict:
            return False
        receipt_digest = _safe_hash(receipt)
        if (
            receipt_digest is None
            or latest.get("replay_claim_receipt_digest") != receipt_digest
            or latest.get("possession_proof_digest")
            != receipt.get("possession_proof_digest")
            or latest.get("replay_key") != receipt.get("replay_key")
            or now_ms >= receipt.get("expires_at_ms")
        ):
            return False
        expected_claim = {key: receipt[key] for key in _REPLAY_CLAIM_PAYLOAD_FIELDS}
        if (
            _receipt_error(
                receipt,
                expected_claim=expected_claim,
                replay_provider=trust_context.replay_provider,
                context=trust_context,
            )
            is not None
        ):
            return False
        exact_receipt_bindings = {
            "context_id": context_record["context_id"],
            "context_digest": context_record["digest"],
            "namespace": context_record["replay_namespace"],
            "replay_key": _replay_key(
                context_record=context_record,
                snapshot=current_snapshot,
                context=trust_context,
            ),
            "request_fingerprint": current_snapshot["request_fingerprint"],
            "snapshot_digest": _safe_hash(current_snapshot),
            "registry_record_digest": _safe_hash(registry_record),
            "subject_binding_digest": current_snapshot["subject_binding_digest"],
            "session_binding_digest": current_snapshot["session_binding_digest"],
            "challenge_binding_digest": current_snapshot["challenge_binding_digest"],
            "registry_sequence": registry_record["registry_sequence"],
            "authority_sequence": registry_record["authority_sequence"],
            "revocation_sequence": registry_record["revocation_sequence"],
            "clock_sequence": current_snapshot["clock_sequence"],
            "clock_record_digest": current_snapshot["clock_record_digest"],
            "claimed_at_ms": current_snapshot["evaluation_time"],
            "result": REPLAY_CLAIMED,
            "authorization_effect": NO_AUTHORIZATION_EFFECT,
        }
        if any(
            receipt.get(field) != value
            for field, value in exact_receipt_bindings.items()
        ):
            return False
        if (
            type(receipt.get("claim_sequence")) is not int
            or receipt["claim_sequence"] < 1
            or not is_sha512(receipt.get("pre_claim_head_digest"))
            or (
                receipt["prior_claim_receipt_digest"] != GENESIS_HASH
                and not is_sha512(receipt["prior_claim_receipt_digest"])
            )
            or not receipt["claimed_at_ms"] <= now_ms < receipt["expires_at_ms"]
        ):
            return False
        head = trust_context.replay_guard.current_head(
            namespace=context_record["replay_namespace"],
            subject_binding_digest=current_snapshot["subject_binding_digest"],
            observed_at_ms=now_ms,
        )
        if type(head) is not dict:
            return False
        if (
            _head_error(
                head,
                context_record=context_record,
                subject_binding_digest=current_snapshot["subject_binding_digest"],
                replay_provider=trust_context.replay_provider,
                context=trust_context,
                now_ms=now_ms,
            )
            is not None
        ):
            return False
        if (
            head["registry_sequence"] != registry_record["registry_sequence"]
            or head["authority_sequence"] != registry_record["authority_sequence"]
            or head["revocation_sequence"] != registry_record["revocation_sequence"]
            or head["claim_sequence"] < receipt["claim_sequence"]
        ):
            return False
        head_digest = _safe_hash(head)
        if head_digest is None:
            return False
        persistence_receipt = trust_context.replay_guard.is_claimed(
            namespace=context_record["replay_namespace"],
            replay_key=receipt["replay_key"],
            receipt_digest=receipt_digest,
            subject_binding_digest=current_snapshot["subject_binding_digest"],
            observed_at_ms=now_ms,
            current_head_digest=head_digest,
        )
        if (
            _persistence_error(
                persistence_receipt,
                context_record=context_record,
                replay_provider=trust_context.replay_provider,
                context=trust_context,
                replay_key=receipt["replay_key"],
                claim_receipt_digest=receipt_digest,
                subject_binding_digest=current_snapshot["subject_binding_digest"],
                claim_sequence=receipt["claim_sequence"],
                current_head_digest=head_digest,
                registry_sequence=registry_record["registry_sequence"],
                authority_sequence=registry_record["authority_sequence"],
                revocation_sequence=registry_record["revocation_sequence"],
                observed_at_ms=now_ms,
            )
            is not None
        ):
            return False
        return (
            latest.get("registry_sequence") == registry_record["registry_sequence"]
            and latest.get("authority_sequence")
            == registry_record["authority_sequence"]
            and latest.get("revocation_status") == TRUST_ACTIVE
            and latest.get("revocation_sequence")
            == registry_record["revocation_sequence"]
        )
    except Exception:  # noqa: BLE001
        return False


def impersonation_protection_hash_payload(
    state: dict[str, Any],
) -> dict[str, Any]:
    record = state.get("impersonation_protection_record", {})
    if type(record) is not dict:
        record = {}
    return {
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "reason": record.get("reason"),
        "context_id": record.get("context_id"),
        "context_digest": record.get("context_digest"),
        "record_digest": _safe_hash(record),
        "trace_digest": state.get("impersonation_protection_digest"),
        "registry_record_digest": record.get("registry_record_digest"),
        "possession_proof_digest": record.get("possession_proof_digest"),
        "replay_claim_receipt_digest": record.get("replay_claim_receipt_digest"),
        "registry_sequence": record.get("registry_sequence"),
        "authority_sequence": record.get("authority_sequence"),
        "revocation_sequence": record.get("revocation_sequence"),
        **dict(NO_AUTHORIZATION_EFFECT),
    }


__all__ = [
    "AUTHORITY_BOUNDARY_COMPONENT",
    "CLOCK_HEAD_SCHEMA",
    "CLOCK_HEAD_TRANSITION_SCHEMA",
    "CLOCK_RECORD_SCHEMA",
    "DEPLOYMENT_DEPENDENCIES",
    "IMPERSONATION_DENY",
    "IMPERSONATION_PASS",
    "IMPERSONATION_PROTECTION_CONTRACT_ID",
    "IMPERSONATION_PROTECTION_SCHEMA_STATUS",
    "IMPERSONATION_PROTECTION_SEMANTICS",
    "IMPERSONATION_PROTECTION_STAGE",
    "IMPERSONATION_SIGNING_PURPOSES",
    "LIVE_REGISTRY_SCHEMA",
    "NO_AUTHORIZATION_EFFECT",
    "POSSESSION_PROOF_SCHEMA",
    "REPLAY_CLAIMED",
    "REPLAY_CLAIM_SCHEMA",
    "REPLAY_HEAD_SCHEMA",
    "REPLAY_PERSISTENCE_SCHEMA",
    "SOVEREIGN_IDENTITY_COMPONENT",
    "TRUST_ACTIVE",
    "TRUST_CONTEXT_SCHEMA",
    "TRUST_REVOKED",
    "UPSTREAM_RECEIPT_SCHEMA",
    "AuthenticatedUpstreamVerifier",
    "DurableImpersonationClockHead",
    "DurableImpersonationReplayGuard",
    "ImpersonationTrustContext",
    "ImpersonationTrustedClock",
    "OwnerPinnedTrustRegistry",
    "evaluate_impersonation_protection",
    "impersonation_protection_hash_payload",
    "impersonation_signing_purpose",
    "impersonation_upstream_hash_payload",
    "install_production_impersonation_composition_boundary",
    "verify_impersonation_protection",
]
