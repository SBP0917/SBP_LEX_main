"""Fail-closed Australian minor-account access evidence boundary.

This module proves only its local evidence contract.  The private composition
root, durable production replay/revocation storage, trusted-clock operation,
and private signing/pseudonymisation-key custody are deployment dependencies;
they are not established by this Python module.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    PRODUCTION_SIGNER,
    HybridSignatureError,
    HybridVerificationContext,
    verify_hybrid_signed_object,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)

MINIMUM_ACCOUNT_AGE: Final = 16

RESULT_PASS: Final = "PASS"
RESULT_DENY: Final = "DENY"
RESULT_ESCALATE: Final = "ESCALATE"
RESULT_NOT_APPLICABLE: Final = "NOT_APPLICABLE"

AGE_UNDER_16: Final = "UNDER_16"
AGE_AT_LEAST_16: Final = "AT_LEAST_16"
AGE_INDETERMINATE: Final = "INDETERMINATE"

SERVICE_IN_SCOPE: Final = "IN_SCOPE"
SERVICE_OUT_OF_SCOPE: Final = "OUT_OF_SCOPE"
RESIDENCE_AUSTRALIA: Final = "AUSTRALIA"
RESIDENCE_OUTSIDE_AUSTRALIA: Final = "OUTSIDE_AUSTRALIA"
ACTION_CREATE_OR_MAINTAIN_ACCOUNT: Final = "CREATE_OR_MAINTAIN_ACCOUNT"
ACTION_OUT_OF_SCOPE: Final = "OUT_OF_SCOPE"

AGE_ASSURANCE_USE_SCOPE: Final = "AGE_ASSURANCE_ONLY"
DISCLOSURE_SCOPE: Final = "PROHIBITED_EXCEPT_AS_REQUIRED_BY_LAW"

LANES: Final = (
    "SERVICE_SCOPE",
    "ORDINARY_RESIDENCE",
    "ACCOUNT_ACTION",
    "AGE_ASSURANCE",
    "METHOD_PRIVACY_POLICY",
    "PRIVACY_DESTRUCTION",
)
SCOPE_LANES: Final = LANES[:3]
AGE_PRIVACY_LANES: Final = LANES[3:]

SCHEMA: Final = "SBP-LEX-AU-MINOR-ACCESS-V3"
AUSTRALIAN_MINOR_ACCESS_STAGE: Final = "australian_minor_access"
PRODUCTION_MODE: Final = "PRODUCTION"
TEST_ONLY_MODE: Final = "TEST_ONLY"
AUSTRALIAN_MINOR_ACCESS_OWNER_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_OWNER"
)
AUSTRALIAN_MINOR_ACCESS_REGISTRY_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_REGISTRY"
)
AUSTRALIAN_MINOR_ACCESS_CLOCK_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_CLOCK"
)
AUSTRALIAN_MINOR_ACCESS_REVOCATION_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_REVOCATION"
)
AUSTRALIAN_MINOR_ACCESS_REPLAY_HEAD_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_REPLAY_HEAD"
)
AUSTRALIAN_MINOR_ACCESS_REPLAY_RECEIPT_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_REPLAY_RECEIPT"
)
AUSTRALIAN_MINOR_ACCESS_DURABLE_PROVIDER_ADMISSION_PURPOSE: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_DURABLE_PROVIDER_ADMISSION"
)
AUSTRALIAN_MINOR_ACCESS_LANE_PURPOSE_PREFIX: Final = (
    "SBP_LEX_V2_AUSTRALIAN_MINOR_ACCESS_LANE:"
)
DEPLOYMENT_DEPENDENCIES: Final = (
    "Production owner pins and composition installation must be sealed outside "
    "runtime caller input; the production installer requires externally supplied "
    "hybrid verification contexts and independent owner-pin digests.",
    "Replay and revocation stores must be durable, transactional production "
    "services whose persisted heads survive process and host restarts.",
    "Owner, registry, revocation, clock, replay, and lane signing keys require "
    "deployment-controlled private-key custody; the pinned pseudonymisation key "
    "requires protected process-memory custody for module-owned HMAC operation.",
    "The signed clock source and its rollback-resistant sequence state are "
    "deployment dependencies.",
)


class AustralianMinorAccessError(RuntimeError):
    """The compliance evidence contract could not be established."""


_BINDING_KEYS = {
    "provider_id",
    "credential_id",
    "algorithm",
    "public_key_hex",
    "key_fingerprint",
    "custody_class",
    "effect_authority",
}
_SIGNATURE_KEYS = {
    "provider_id",
    "credential_id",
    "algorithm",
    "key_fingerprint",
    "custody_class",
    "effect_authority",
    "signature_b64",
}
_ENVELOPE_KEYS = {"payload", "payload_digest", "signature"}
_HYBRID_RESERVED_FIELDS = {"digest", "signature", "verified"}
_OWNER_KEYS = {
    "schema",
    "context_id",
    "status",
    "valid_from",
    "valid_until",
    "composition_sequence",
    "revocation_sequence",
    "registry_digest",
    "revocation_head_digest",
    "registry_binding",
    "revocation_binding",
    "replay_binding",
    "clock_binding",
    "lane_bindings",
    "registry_store_id",
    "registry_store_version",
    "revocation_store_id",
    "revocation_store_version",
    "replay_store_id",
    "replay_store_version",
    "clock_source_id",
    "clock_source_version",
    "clock_head_digest",
    "clock_sequence",
    "pseudonymizer_binding",
    "deployment_mode",
    "effect_authority",
}
_REGISTRY_KEYS = {
    "schema",
    "context_id",
    "registry_id",
    "registry_version",
    "registry_sequence",
    "decision_sequence_head",
    "decision_digest_head",
    "revocation_sequence",
    "status",
    "valid_from",
    "valid_until",
    "lane_binding_digests",
    "effect_authority",
}
_REVOCATION_KEYS = {
    "schema",
    "context_id",
    "registry_digest",
    "head_sequence",
    "revocation_sequence",
    "registry_sequence",
    "prior_head_digest",
    "revoked_evidence_digests",
    "issued_at",
    "expires_at",
    "status",
    "effect_authority",
}
_CLOCK_KEYS = {
    "schema",
    "context_id",
    "source_id",
    "source_version",
    "time_sequence",
    "prior_evidence_digest",
    "observed_at",
    "status",
    "effect_authority",
}
_EVIDENCE_KEYS = {
    "schema",
    "context_id",
    "lane",
    "provider_id",
    "credential_id",
    "key_fingerprint",
    "evidence_sequence",
    "registry_digest",
    "revocation_head_digest",
    "request_fingerprint",
    "minor_access_request_binding_digest",
    "subject_session_binding_digest",
    "stage",
    "issued_at",
    "expires_at",
    "status",
    "result",
    "details",
    "effect_authority",
}
_REPLAY_HEAD_KEYS = {
    "schema",
    "context_id",
    "store_id",
    "store_version",
    "namespace",
    "subject_session_binding_digest",
    "sequence",
    "head_digest",
    "observed_at",
    "status",
    "effect_authority",
}
_REPLAY_RECEIPT_KEYS = {
    "schema",
    "context_id",
    "store_id",
    "store_version",
    "namespace",
    "replay_key",
    "request_fingerprint",
    "minor_access_request_binding_digest",
    "subject_session_binding_digest",
    "stage",
    "prior_head_digest",
    "sequence",
    "registry_digest",
    "revocation_head_digest",
    "evidence_bundle_digest",
    "decision_digest",
    "claimed_at",
    "status",
    "effect_authority",
}
_DURABLE_PROVIDER_ADMISSION_SCHEMA: Final = (
    "SBP-LEX-AU-MINOR-DURABLE-PROVIDER-ADMISSION-V1"
)
_DURABLE_PROVIDER_KINDS: Final = ("clock", "revocation", "replay")
_DURABLE_PROVIDER_ADMISSION_KEYS = {
    "schema",
    "context_id",
    "provider_kind",
    "provider_id",
    "provider_version",
    "storage_class",
    "durability_evidence_sha512",
    "admission_sequence",
    "status",
    "restart_durable",
    "transactional",
    "corruption_fail_closed",
    "rollback_protected",
    "production_durable_storage_admitted",
    "effect_authority",
}
_SUCCESS_RECORD_KEYS = {
    "schema",
    "stage",
    "context_id",
    "context_digest",
    "owner_composition_sequence",
    "registry",
    "registry_digest",
    "revocation_head",
    "revocation_head_digest",
    "clock_receipt",
    "clock_receipt_digest",
    "snapshot",
    "evidence",
    "evidence_bundle_digest",
    "decision_digest",
    "replay_receipt",
    "replay_post_head",
    "replay",
    "result",
    "applicable",
    "age_assurance_result",
    "reason",
    "privacy_data_destroyed",
    "youth_penalty_applied",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority",
    "record_digest",
}
_FAIL_RECORD_KEYS = {
    "schema",
    "stage",
    "result",
    "applicable",
    "age_assurance_result",
    "reason",
    "access_granted",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority",
    "record_digest",
}
_SNAPSHOT_KEYS = {
    "request_fingerprint",
    "minor_access_request_binding_digest",
    "subject_session_binding_digest",
    "service_binding_digest",
    "stage",
    "pseudonymizer_id",
    "pseudonymizer_version",
    "pseudonymization_key_id",
    "pseudonymization_key_fingerprint",
}


def _exact_dict(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AustralianMinorAccessError(f"MALFORMED_{label}")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AustralianMinorAccessError(f"INVALID_{label}")
    return value


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AustralianMinorAccessError(f"INVALID_{label}")
    return value


def _false(value: Any, label: str) -> None:
    if value is not False:
        raise AustralianMinorAccessError(f"AUTHORITY_PRESENT_{label}")


def _raw_key(
    binding: dict[str, Any],
    label: str,
    *,
    allow_legacy_test_only: bool = False,
) -> bytes:
    _exact_dict(binding, _BINDING_KEYS, f"{label}_BINDING")
    for field in ("provider_id", "credential_id", "custody_class"):
        _text(binding[field], f"{label}_{field.upper()}")
    if (
        binding["algorithm"] != "Ed25519"
        or allow_legacy_test_only is not True
    ):
        raise AustralianMinorAccessError(f"UNSUPPORTED_{label}_ALGORITHM")
    _false(binding["effect_authority"], label)
    try:
        raw = bytes.fromhex(_text(binding["public_key_hex"], f"{label}_PUBLIC_KEY"))
    except ValueError as exc:
        raise AustralianMinorAccessError(f"INVALID_{label}_PUBLIC_KEY") from exc
    if len(raw) != 32:
        raise AustralianMinorAccessError(f"INVALID_{label}_PUBLIC_KEY")
    fingerprint = sha512(raw).hexdigest()
    if not hmac.compare_digest(fingerprint, _text(binding["key_fingerprint"], f"{label}_FINGERPRINT")):
        raise AustralianMinorAccessError(f"INVALID_{label}_FINGERPRINT")
    return raw


def _production_binding_exact(
    binding: Any,
    *,
    label: str,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> dict[str, Any]:
    checked = _exact_dict(binding, _BINDING_KEYS, f"{label}_BINDING")
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or trust_context.signer_class != PRODUCTION_SIGNER
        or trust_context.allow_test_only
        or trust_context.effect_authority is not False
        or not trust_context.external_custody_admitted
        or type(owner_pinned_context_digest) is not str
        or not is_sha512(owner_pinned_context_digest)
        or not hmac.compare_digest(
            trust_context.context_digest,
            owner_pinned_context_digest,
        )
    ):
        raise AustralianMinorAccessError(f"UNTRUSTED_{label}_HYBRID_CONTEXT")
    expected_public_hex = (
        trust_context.mldsa87_public_key_bytes
        + trust_context.ed448_public_key_bytes
    ).hex()
    expected = {
        "provider_id": trust_context.provider_id,
        "algorithm": HYBRID_SUITE_ID,
        "public_key_hex": expected_public_hex,
        "key_fingerprint": trust_context.context_digest,
        "custody_class": trust_context.custody_class,
        "effect_authority": False,
    }
    _text(checked.get("credential_id"), f"{label}_CREDENTIAL_ID")
    if any(checked.get(field) != value for field, value in expected.items()):
        raise AustralianMinorAccessError(f"UNTRUSTED_{label}_HYBRID_BINDING")
    return checked


def _hybrid_binding(
    trust_context: HybridVerificationContext,
    *,
    credential_id: str,
) -> dict[str, Any]:
    return {
        "provider_id": trust_context.provider_id,
        "credential_id": credential_id,
        "algorithm": HYBRID_SUITE_ID,
        "public_key_hex": (
            trust_context.mldsa87_public_key_bytes
            + trust_context.ed448_public_key_bytes
        ).hex(),
        "key_fingerprint": trust_context.context_digest,
        "custody_class": trust_context.custody_class,
        "effect_authority": False,
    }


def _verify_signed(
    envelope: Any,
    binding: dict[str, Any],
    *,
    payload_keys: set[str],
    label: str,
    allow_legacy_test_only: bool = False,
    deployment_mode: str = TEST_ONLY_MODE,
    hybrid_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
    expected_purpose: str | None = None,
) -> dict[str, Any]:
    if deployment_mode == PRODUCTION_MODE:
        if allow_legacy_test_only:
            raise AustralianMinorAccessError(f"LEGACY_{label}_PRODUCTION_REJECTED")
        if type(envelope) is not dict:
            raise AustralianMinorAccessError(f"MALFORMED_{label}_ENVELOPE")
        payload = _exact_dict(
            {
                key: value
                for key, value in envelope.items()
                if key not in _HYBRID_RESERVED_FIELDS
            },
            payload_keys,
            f"{label}_PAYLOAD",
        )
        _production_binding_exact(
            binding,
            label=label,
            trust_context=hybrid_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
        if (
            not isinstance(hybrid_trust_context, HybridVerificationContext)
            or type(owner_pinned_context_digest) is not str
        ):
            raise AustralianMinorAccessError(
                f"UNTRUSTED_{label}_HYBRID_CONTEXT"
            )
        if not isinstance(expected_purpose, str) or not expected_purpose:
            raise AustralianMinorAccessError(f"INVALID_{label}_PURPOSE")
        try:
            valid = verify_hybrid_signed_object(
                envelope,
                trust_context=hybrid_trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
                expected_purpose=expected_purpose,
                require_effect_authority=False,
            )
        except (HybridSignatureError, TypeError, ValueError) as exc:
            raise AustralianMinorAccessError(
                f"INVALID_{label}_HYBRID_SIGNATURE"
            ) from exc
        if not valid:
            raise AustralianMinorAccessError(f"INVALID_{label}_HYBRID_SIGNATURE")
        return payload
    if deployment_mode != TEST_ONLY_MODE or allow_legacy_test_only is not True:
        raise AustralianMinorAccessError(f"LEGACY_{label}_NOT_TEST_ONLY")
    env = _exact_dict(envelope, _ENVELOPE_KEYS, f"{label}_ENVELOPE")
    payload = _exact_dict(env["payload"], payload_keys, f"{label}_PAYLOAD")
    digest = canonical_integrity_hash(payload)
    if not is_sha512(digest) or not hmac.compare_digest(digest, _text(env["payload_digest"], f"{label}_DIGEST")):
        raise AustralianMinorAccessError(f"INVALID_{label}_DIGEST")
    signature = _exact_dict(env["signature"], _SIGNATURE_KEYS, f"{label}_SIGNATURE")
    for field in ("provider_id", "credential_id", "algorithm", "key_fingerprint", "custody_class", "effect_authority"):
        if signature[field] != binding[field]:
            raise AustralianMinorAccessError(f"UNTRUSTED_{label}_SIGNER")
    raw = _raw_key(
        binding,
        label,
        allow_legacy_test_only=allow_legacy_test_only,
    )
    try:
        encoded = base64.b64decode(_text(signature["signature_b64"], f"{label}_SIGNATURE"), validate=True)
        Ed25519PublicKey.from_public_bytes(raw).verify(encoded, canonical_json_bytes(payload))
    except (ValueError, binascii.Error, InvalidSignature) as exc:
        raise AustralianMinorAccessError(f"INVALID_{label}_SIGNATURE") from exc
    return payload


def _envelope_digest(envelope: dict[str, Any]) -> str:
    return canonical_integrity_hash(envelope)


class _EvidenceResolver(Protocol):
    def resolve(self, snapshot: dict[str, Any]) -> dict[str, Any]: ...


class _TrustedClock(Protocol):
    id: str
    version: str

    def current_time_chain(self, context_id: str) -> list[dict[str, Any]]: ...

    def is_current(self, context_id: str, digest: str, sequence: int) -> bool: ...


class _RevocationStore(Protocol):
    id: str
    version: str

    def current_head_chain(self, context_id: str) -> list[dict[str, Any]]: ...

    def is_current(self, context_id: str, digest: str, sequence: int) -> bool: ...


class _ReplayStore(Protocol):
    id: str
    version: str

    def current_head(
        self,
        namespace: str,
        subject_binding: str,
        now: int,
    ) -> dict[str, Any]: ...

    def claim_once(self, claim: dict[str, Any]) -> dict[str, Any]: ...

    def is_claimed(
        self,
        namespace: str,
        replay_key: str,
        receipt_digest: str,
    ) -> bool: ...

    def persisted_receipt(
        self,
        namespace: str,
        replay_key: str,
    ) -> dict[str, Any] | None: ...


@dataclass(frozen=True, slots=True)
class _DeploymentComposition:
    context_id: str
    context_digest: str
    deployment_mode: str
    owner: dict[str, Any]
    registry: dict[str, Any]
    registry_payload: dict[str, Any]
    revocation_store: _RevocationStore
    replay_store: _ReplayStore
    clock: _TrustedClock
    pseudonymization_key: bytes
    resolvers: dict[str, _EvidenceResolver]
    bindings: dict[str, dict[str, Any]]
    hybrid_trust_contexts: dict[str, HybridVerificationContext]
    owner_pinned_context_digests: dict[str, str]


_ACTIVE_COMPOSITION: _DeploymentComposition | None = None


def _install_australian_minor_access_deployment(
    composition: dict[str, Any],
    *,
    fixed_context_id: str,
    fixed_context_digest: str,
    owner_public_key_hex: str | None,
    test_only: bool,
    owner_trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
    signer_trust_contexts: dict[str, HybridVerificationContext] | None = None,
    signer_owner_pinned_context_digests: dict[str, str] | None = None,
) -> None:
    """Install one sealed TEST_ONLY legacy or PRODUCTION hybrid composition."""

    global _ACTIVE_COMPOSITION
    if _ACTIVE_COMPOSITION is not None:
        raise AustralianMinorAccessError("DEPLOYMENT_ALREADY_REGISTERED")
    deployment_mode = TEST_ONLY_MODE if test_only else PRODUCTION_MODE
    trust_names = {"registry", "revocation", "replay", "clock", *LANES}
    hybrid_contexts: dict[str, HybridVerificationContext] = {}
    hybrid_pins: dict[str, str] = {}
    if test_only:
        if any(
            value is not None
            for value in (
                owner_trust_context,
                owner_pinned_context_digest,
                signer_trust_contexts,
                signer_owner_pinned_context_digests,
            )
        ):
            raise AustralianMinorAccessError(
                "PRODUCTION_HYBRID_TRUST_NOT_ADMITTED_IN_TEST_ONLY"
            )
    else:
        if (
            type(signer_trust_contexts) is not dict
            or set(signer_trust_contexts) != trust_names
            or type(signer_owner_pinned_context_digests) is not dict
            or set(signer_owner_pinned_context_digests) != trust_names
        ):
            raise AustralianMinorAccessError(
                "PRODUCTION_HYBRID_TRUST_BUNDLE_REQUIRED"
            )
        hybrid_contexts = dict(signer_trust_contexts)
        hybrid_pins = dict(signer_owner_pinned_context_digests)
    required = {
        "owner_record",
        "registry",
        "revocation_store",
        "replay_store",
        "clock",
        "pseudonymization_key",
        "resolvers",
    }
    _exact_dict(composition, required, "DEPLOYMENT_COMPOSITION")
    if test_only:
        try:
            owner_raw = bytes.fromhex(owner_public_key_hex or "")
        except (TypeError, ValueError) as exc:
            raise AustralianMinorAccessError("INVALID_OWNER_PIN") from exc
        if len(owner_raw) != 32:
            raise AustralianMinorAccessError("INVALID_OWNER_PIN")
        owner_binding = {
            "provider_id": "DEPLOYMENT_OWNER",
            "credential_id": f"owner:{sha512(owner_raw).hexdigest()}",
            "algorithm": "Ed25519",
            "public_key_hex": owner_raw.hex(),
            "key_fingerprint": sha512(owner_raw).hexdigest(),
            "custody_class": "DEPLOYMENT_OWNER_ROOT",
            "effect_authority": False,
        }
        owner = _verify_signed(
            composition["owner_record"],
            owner_binding,
            payload_keys=_OWNER_KEYS,
            label="OWNER",
            allow_legacy_test_only=True,
            deployment_mode=TEST_ONLY_MODE,
        )
    else:
        if not isinstance(owner_trust_context, HybridVerificationContext):
            raise AustralianMinorAccessError(
                "PRODUCTION_OWNER_HYBRID_CONTEXT_REQUIRED"
            )
        owner_binding = _hybrid_binding(
            owner_trust_context,
            credential_id=f"owner:{owner_trust_context.context_digest}",
        )
        owner = _verify_signed(
            composition["owner_record"],
            owner_binding,
            payload_keys=_OWNER_KEYS,
            label="OWNER",
            deployment_mode=PRODUCTION_MODE,
            hybrid_trust_context=owner_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            expected_purpose=AUSTRALIAN_MINOR_ACCESS_OWNER_PURPOSE,
        )
    if owner["schema"] != SCHEMA or owner["context_id"] != fixed_context_id:
        raise AustralianMinorAccessError("OWNER_CONTEXT_PIN_MISMATCH")
    actual_context_digest = _envelope_digest(composition["owner_record"])
    if not is_sha512(fixed_context_digest) or not hmac.compare_digest(actual_context_digest, fixed_context_digest):
        raise AustralianMinorAccessError("OWNER_CONTEXT_DIGEST_MISMATCH")
    if owner["status"] != "ACTIVE" or owner["effect_authority"] is not False:
        raise AustralianMinorAccessError("OWNER_CONTEXT_INACTIVE")
    if owner["deployment_mode"] != deployment_mode:
        raise AustralianMinorAccessError("OWNER_DEPLOYMENT_MODE_MISMATCH")
    _integer(owner["valid_from"], "OWNER_VALID_FROM")
    _integer(owner["valid_until"], "OWNER_VALID_UNTIL")
    if owner["valid_until"] <= owner["valid_from"]:
        raise AustralianMinorAccessError("OWNER_VALIDITY_INVALID")
    _integer(owner["composition_sequence"], "COMPOSITION_SEQUENCE", 1)
    _integer(owner["revocation_sequence"], "OWNER_REVOCATION_SEQUENCE")

    bindings: dict[str, dict[str, Any]] = {}
    for name in ("registry", "revocation", "replay", "clock"):
        binding = deepcopy(owner[f"{name}_binding"])
        if test_only:
            _raw_key(binding, name.upper(), allow_legacy_test_only=True)
        else:
            _production_binding_exact(
                binding,
                label=name.upper(),
                trust_context=hybrid_contexts[name],
                owner_pinned_context_digest=hybrid_pins[name],
            )
        bindings[name] = binding
    lane_bindings = owner["lane_bindings"]
    if not isinstance(lane_bindings, dict) or set(lane_bindings) != set(LANES):
        raise AustralianMinorAccessError("INVALID_LANE_BINDINGS")
    for lane in LANES:
        binding = deepcopy(lane_bindings[lane])
        if test_only:
            _raw_key(binding, lane, allow_legacy_test_only=True)
        else:
            _production_binding_exact(
                binding,
                label=lane,
                trust_context=hybrid_contexts[lane],
                owner_pinned_context_digest=hybrid_pins[lane],
            )
        bindings[lane] = binding

    lane_provider_ids = [bindings[lane]["provider_id"] for lane in LANES]
    lane_key_ids = [bindings[lane]["key_fingerprint"] for lane in LANES]
    lane_credentials = [bindings[lane]["credential_id"] for lane in LANES]
    if len(set(lane_provider_ids)) != len(LANES):
        raise AustralianMinorAccessError("LANE_PROVIDER_REUSE")
    if len(set(lane_key_ids)) != len(LANES):
        raise AustralianMinorAccessError("LANE_KEY_REUSE")
    if len(set(lane_credentials)) != len(LANES):
        raise AustralianMinorAccessError("LANE_CREDENTIAL_REUSE")

    all_bindings = list(bindings.values()) + [owner_binding]
    for field, code in (
        ("provider_id", "SIGNER_PROVIDER_REUSE"),
        ("key_fingerprint", "SIGNER_KEY_REUSE"),
        ("credential_id", "SIGNER_CREDENTIAL_REUSE"),
    ):
        values = [binding[field] for binding in all_bindings]
        if len(values) != len(set(values)):
            raise AustralianMinorAccessError(code)

    registry_payload = _verify_signed(
        composition["registry"],
        bindings["registry"],
        payload_keys=_REGISTRY_KEYS,
        label="REGISTRY",
        allow_legacy_test_only=test_only,
        deployment_mode=deployment_mode,
        hybrid_trust_context=hybrid_contexts.get("registry"),
        owner_pinned_context_digest=hybrid_pins.get("registry"),
        expected_purpose=AUSTRALIAN_MINOR_ACCESS_REGISTRY_PURPOSE,
    )
    registry_digest = _envelope_digest(composition["registry"])
    if not hmac.compare_digest(registry_digest, owner["registry_digest"]):
        raise AustralianMinorAccessError("REGISTRY_DIGEST_MISMATCH")
    if registry_payload["schema"] != SCHEMA or registry_payload["context_id"] != fixed_context_id:
        raise AustralianMinorAccessError("REGISTRY_CONTEXT_MISMATCH")
    if registry_payload["status"] != "ACTIVE" or registry_payload["effect_authority"] is not False:
        raise AustralianMinorAccessError("REGISTRY_INACTIVE")
    if registry_payload["registry_id"] != owner["registry_store_id"] or registry_payload["registry_version"] != owner["registry_store_version"]:
        raise AustralianMinorAccessError("REGISTRY_IDENTITY_MISMATCH")
    expected_lane_digests = {lane: canonical_integrity_hash(bindings[lane]) for lane in LANES}
    if registry_payload["lane_binding_digests"] != expected_lane_digests:
        raise AustralianMinorAccessError("REGISTRY_LANE_BINDINGS_MISMATCH")
    if registry_payload["revocation_sequence"] != owner["revocation_sequence"]:
        raise AustralianMinorAccessError("REGISTRY_REVOCATION_SEQUENCE_MISMATCH")

    pseudonym_binding = _exact_dict(
        owner["pseudonymizer_binding"],
        {"pseudonymizer_id", "version", "key_id", "key_fingerprint"},
        "PSEUDONYMIZER_BINDING",
    )
    for key in pseudonym_binding:
        _text(pseudonym_binding[key], f"PSEUDONYMIZER_{key.upper()}")
    pseudonymization_key = composition["pseudonymization_key"]
    if type(pseudonymization_key) is not bytes or len(pseudonymization_key) < 32:
        raise AustralianMinorAccessError("PSEUDONYMIZATION_KEY_INVALID")
    if sha512(pseudonymization_key).hexdigest() != pseudonym_binding["key_fingerprint"]:
        raise AustralianMinorAccessError("PSEUDONYMIZATION_KEY_PIN_MISMATCH")

    resolvers = composition["resolvers"]
    if not isinstance(resolvers, dict) or set(resolvers) != set(LANES):
        raise AustralianMinorAccessError("INVALID_RESOLVER_COMPOSITION")
    if any(not callable(getattr(resolvers[lane], "resolve", None)) for lane in LANES):
        raise AustralianMinorAccessError("RESOLVER_UNAVAILABLE")

    for obj, prefix in (
        (composition["revocation_store"], "revocation_store"),
        (composition["replay_store"], "replay_store"),
        (composition["clock"], "clock_source"),
    ):
        for suffix in ("id", "version"):
            expected = owner[f"{prefix}_{suffix}"]
            if getattr(obj, suffix, None) != expected:
                raise AustralianMinorAccessError(f"{prefix.upper()}_IDENTITY_MISMATCH")

    _ACTIVE_COMPOSITION = _DeploymentComposition(
        context_id=fixed_context_id,
        context_digest=fixed_context_digest,
        deployment_mode=deployment_mode,
        owner=deepcopy(owner),
        registry=deepcopy(composition["registry"]),
        registry_payload=deepcopy(registry_payload),
        revocation_store=composition["revocation_store"],
        replay_store=composition["replay_store"],
        clock=composition["clock"],
        pseudonymization_key=bytes(pseudonymization_key),
        resolvers=dict(resolvers),
        bindings=bindings,
        hybrid_trust_contexts=hybrid_contexts,
        owner_pinned_context_digests=hybrid_pins,
    )


def _install_australian_minor_access_deployment_for_tests(
    composition: dict[str, Any],
    *,
    fixed_context_id: str,
    fixed_context_digest: str,
    owner_public_key_hex: str,
    test_only: bool,
) -> None:
    """Install the explicit legacy TEST_ONLY, non-effect compatibility model."""

    if test_only is not True:
        raise AustralianMinorAccessError("TEST_ONLY_INSTALL_REQUIRED")
    _install_australian_minor_access_deployment(
        composition,
        fixed_context_id=fixed_context_id,
        fixed_context_digest=fixed_context_digest,
        owner_public_key_hex=owner_public_key_hex,
        test_only=True,
    )


def _verify_durable_provider_admissions(
    composition: dict[str, Any],
    *,
    fixed_context_id: str,
    admissions: dict[str, dict[str, Any]] | None,
    owner_pinned_admission_digests: dict[str, str] | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    prohibited_context_digests: set[str],
) -> None:
    """Verify external, independently pinned production-store admissions."""

    if (
        type(admissions) is not dict
        or set(admissions) != set(_DURABLE_PROVIDER_KINDS)
        or not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
    ):
        raise AustralianMinorAccessError(
            "PRODUCTION_DURABLE_PROVIDER_ADMISSION_REQUIRED"
        )
    if (
        trust_context.signer_class != PRODUCTION_SIGNER
        or trust_context.allow_test_only
        or trust_context.effect_authority is not False
        or not trust_context.external_custody_admitted
        or not is_sha512(owner_pinned_context_digest)
        or not hmac.compare_digest(
            trust_context.context_digest, owner_pinned_context_digest
        )
    ):
        raise AustralianMinorAccessError(
            "PRODUCTION_DURABLE_PROVIDER_ADMISSION_PIN_INVALID"
        )
    if trust_context.context_digest in prohibited_context_digests:
        raise AustralianMinorAccessError(
            "PRODUCTION_DURABLE_PROVIDER_ADMISSION_NOT_INDEPENDENT"
        )
    if (
        type(owner_pinned_admission_digests) is not dict
        or set(owner_pinned_admission_digests)
        != set(_DURABLE_PROVIDER_KINDS)
        or any(
            not is_sha512(value)
            for value in owner_pinned_admission_digests.values()
        )
    ):
        raise AustralianMinorAccessError(
            "PRODUCTION_DURABLE_PROVIDER_DOCUMENT_PINS_REQUIRED"
        )

    providers = {
        "clock": composition.get("clock"),
        "revocation": composition.get("revocation_store"),
        "replay": composition.get("replay_store"),
    }
    seen_evidence: set[str] = set()
    for kind in _DURABLE_PROVIDER_KINDS:
        signed = admissions[kind]
        if (
            type(signed) is not dict
            or set(signed)
            != _DURABLE_PROVIDER_ADMISSION_KEYS | _HYBRID_RESERVED_FIELDS
            or not verify_hybrid_signed_object(
                signed,
                trust_context=trust_context,
                owner_pinned_context_digest=owner_pinned_context_digest,
                expected_purpose=(
                    AUSTRALIAN_MINOR_ACCESS_DURABLE_PROVIDER_ADMISSION_PURPOSE
                ),
            )
        ):
            raise AustralianMinorAccessError(
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_INVALID"
            )
        if not hmac.compare_digest(
            canonical_integrity_hash(signed),
            owner_pinned_admission_digests[kind],
        ):
            raise AustralianMinorAccessError(
                "PRODUCTION_DURABLE_PROVIDER_DOCUMENT_PIN_MISMATCH"
            )
        provider = providers[kind]
        if (
            signed["schema"] != _DURABLE_PROVIDER_ADMISSION_SCHEMA
            or signed["context_id"] != fixed_context_id
            or signed["provider_kind"] != kind
            or signed["provider_id"] != getattr(provider, "id", None)
            or signed["provider_version"] != getattr(provider, "version", None)
            or type(signed["storage_class"]) is not str
            or not signed["storage_class"]
            or not is_sha512(signed["durability_evidence_sha512"])
            or type(signed["admission_sequence"]) is not int
            or signed["admission_sequence"] < 1
            or signed["status"] != "ACTIVE"
            or signed["restart_durable"] is not True
            or signed["transactional"] is not True
            or signed["corruption_fail_closed"] is not True
            or signed["rollback_protected"] is not True
            or signed["production_durable_storage_admitted"] is not True
            or signed["effect_authority"] is not False
        ):
            raise AustralianMinorAccessError(
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_CLAIMS_INVALID"
            )
        evidence_digest = signed["durability_evidence_sha512"]
        if evidence_digest in seen_evidence:
            raise AustralianMinorAccessError(
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_EVIDENCE_REUSED"
            )
        seen_evidence.add(evidence_digest)


def install_australian_minor_access_production(
    composition: dict[str, Any],
    *,
    fixed_context_id: str,
    fixed_context_digest: str,
    owner_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    signer_trust_contexts: dict[str, HybridVerificationContext],
    signer_owner_pinned_context_digests: dict[str, str],
    durable_provider_admissions: dict[str, dict[str, Any]] | None = None,
    durable_provider_owner_pinned_admission_digests: dict[str, str] | None = None,
    durable_provider_trust_context: HybridVerificationContext | None = None,
    durable_provider_owner_pinned_context_digest: str | None = None,
) -> None:
    """Install externally owner-pinned production hybrid verification roots."""

    candidate_contexts: list[object] = [owner_trust_context]
    if type(signer_trust_contexts) is dict:
        candidate_contexts.extend(signer_trust_contexts.values())
    prohibited_context_digests = {
        context.context_digest
        for context in candidate_contexts
        if isinstance(context, HybridVerificationContext)
    }
    _verify_durable_provider_admissions(
        composition,
        fixed_context_id=fixed_context_id,
        admissions=durable_provider_admissions,
        owner_pinned_admission_digests=(
            durable_provider_owner_pinned_admission_digests
        ),
        trust_context=durable_provider_trust_context,
        owner_pinned_context_digest=(
            durable_provider_owner_pinned_context_digest
        ),
        prohibited_context_digests=prohibited_context_digests,
    )

    _install_australian_minor_access_deployment(
        composition,
        fixed_context_id=fixed_context_id,
        fixed_context_digest=fixed_context_digest,
        owner_public_key_hex=None,
        test_only=False,
        owner_trust_context=owner_trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        signer_trust_contexts=signer_trust_contexts,
        signer_owner_pinned_context_digests=(
            signer_owner_pinned_context_digests
        ),
    )


def _clear_australian_minor_access_deployment_for_tests(*, test_only: bool) -> None:
    """Test isolation hook; it must not be exposed to untrusted production code."""

    global _ACTIVE_COMPOSITION
    if test_only is not True:
        raise AustralianMinorAccessError("TEST_ONLY_RESET_REQUIRED")
    if _ACTIVE_COMPOSITION is not None and _ACTIVE_COMPOSITION.owner["deployment_mode"] != "TEST_ONLY":
        raise AustralianMinorAccessError("PRODUCTION_CONTEXT_RESET_PROHIBITED")
    _ACTIVE_COMPOSITION = None


def _composition() -> _DeploymentComposition:
    if _ACTIVE_COMPOSITION is None:
        raise AustralianMinorAccessError("DEPLOYMENT_NOT_REGISTERED")
    return _ACTIVE_COMPOSITION


def _signature_contract(label: str) -> tuple[str, str]:
    if label == "CLOCK":
        return "clock", AUSTRALIAN_MINOR_ACCESS_CLOCK_PURPOSE
    if label == "REVOCATION_HEAD":
        return "revocation", AUSTRALIAN_MINOR_ACCESS_REVOCATION_PURPOSE
    if label == "REPLAY_HEAD":
        return "replay", AUSTRALIAN_MINOR_ACCESS_REPLAY_HEAD_PURPOSE
    if label == "REPLAY_RECEIPT":
        return "replay", AUSTRALIAN_MINOR_ACCESS_REPLAY_RECEIPT_PURPOSE
    if label in LANES:
        return label, f"{AUSTRALIAN_MINOR_ACCESS_LANE_PURPOSE_PREFIX}{label}"
    raise AustralianMinorAccessError("UNKNOWN_SIGNATURE_CONTRACT")


def _verify_composition_signed(
    comp: _DeploymentComposition,
    envelope: Any,
    *,
    payload_keys: set[str],
    label: str,
) -> dict[str, Any]:
    binding_name, purpose = _signature_contract(label)
    return _verify_signed(
        envelope,
        comp.bindings[binding_name],
        payload_keys=payload_keys,
        label=label,
        allow_legacy_test_only=comp.deployment_mode == TEST_ONLY_MODE,
        deployment_mode=comp.deployment_mode,
        hybrid_trust_context=comp.hybrid_trust_contexts.get(binding_name),
        owner_pinned_context_digest=(
            comp.owner_pinned_context_digests.get(binding_name)
        ),
        expected_purpose=purpose,
    )


def _signed_payload(
    comp: _DeploymentComposition,
    envelope: dict[str, Any],
) -> dict[str, Any]:
    if comp.deployment_mode == TEST_ONLY_MODE:
        payload = envelope.get("payload")
    elif comp.deployment_mode == PRODUCTION_MODE:
        payload = {
            key: value
            for key, value in envelope.items()
            if key not in _HYBRID_RESERVED_FIELDS
        }
    else:
        raise AustralianMinorAccessError("DEPLOYMENT_MODE_INVALID")
    if type(payload) is not dict:
        raise AustralianMinorAccessError("SIGNED_PAYLOAD_INVALID")
    return payload


def _trusted_time(
    comp: _DeploymentComposition,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    chain = comp.clock.current_time_chain(comp.context_id)
    if type(chain) is not list or not chain:
        raise AustralianMinorAccessError("CLOCK_CHAIN_UNAVAILABLE")
    verified: list[dict[str, Any]] = []
    previous_digest = GENESIS_HASH
    previous_sequence = 0
    previous_time = -1
    for index, envelope in enumerate(chain):
        payload = _verify_composition_signed(
            comp,
            envelope,
            payload_keys=_CLOCK_KEYS,
            label="CLOCK",
        )
        digest = _envelope_digest(envelope)
        if (
            payload["schema"] != SCHEMA
            or payload["context_id"] != comp.context_id
            or payload["source_id"] != comp.owner["clock_source_id"]
            or payload["source_version"] != comp.owner["clock_source_version"]
            or payload["status"] != "ACTIVE"
            or payload["effect_authority"] is not False
            or payload["prior_evidence_digest"] != previous_digest
            or payload["time_sequence"] != previous_sequence + 1
            or not _nondecreasing_time(payload["observed_at"], previous_time)
        ):
            raise AustralianMinorAccessError("CLOCK_CHAIN_INVALID")
        if index == 0 and (
            digest != comp.owner["clock_head_digest"]
            or payload["time_sequence"] != comp.owner["clock_sequence"]
        ):
            raise AustralianMinorAccessError("CLOCK_OWNER_ANCHOR_MISMATCH")
        verified.append(deepcopy(envelope))
        previous_digest = digest
        previous_sequence = payload["time_sequence"]
        previous_time = payload["observed_at"]
    envelope = verified[-1]
    payload = _signed_payload(comp, chain[-1])
    if not comp.clock.is_current(
        comp.context_id,
        _envelope_digest(envelope),
        payload["time_sequence"],
    ):
        raise AustralianMinorAccessError("CLOCK_HEAD_NOT_DURABLE_CURRENT")
    now = payload["observed_at"]
    if not (comp.owner["valid_from"] <= now <= comp.owner["valid_until"]):
        raise AustralianMinorAccessError("OWNER_CONTEXT_EXPIRED")
    registry = comp.registry_payload
    if not (registry["valid_from"] <= now <= registry["valid_until"]):
        raise AustralianMinorAccessError("REGISTRY_EXPIRED")
    return deepcopy(envelope), deepcopy(payload), verified


def _nondecreasing_time(value: Any, previous: int) -> bool:
    return _nonnegative_clock(value) and value >= previous


def _nonnegative_clock(value: Any) -> bool:
    return type(value) is int and value >= 0


def _live_revocation(
    comp: _DeploymentComposition, now: int
) -> tuple[dict[str, Any], dict[str, Any], str, list[dict[str, Any]]]:
    chain = comp.revocation_store.current_head_chain(comp.context_id)
    if type(chain) is not list or not chain:
        raise AustralianMinorAccessError("REVOCATION_CHAIN_UNAVAILABLE")
    verified: list[dict[str, Any]] = []
    previous_digest = GENESIS_HASH
    previous_sequence = 0
    previous_revoked: set[str] = set()
    for index, envelope in enumerate(chain):
        payload = _verify_composition_signed(
            comp,
            envelope,
            payload_keys=_REVOCATION_KEYS,
            label="REVOCATION_HEAD",
        )
        digest = _envelope_digest(envelope)
        revoked = payload["revoked_evidence_digests"]
        if (
            payload["schema"] != SCHEMA
            or payload["context_id"] != comp.context_id
            or payload["registry_digest"] != comp.owner["registry_digest"]
            or payload["registry_sequence"] != comp.registry_payload["registry_sequence"]
            or payload["status"] != "ACTIVE"
            or payload["effect_authority"] is not False
            or payload["prior_head_digest"] != previous_digest
            or payload["head_sequence"] != previous_sequence + 1
            or type(revoked) is not list
            or revoked != sorted(set(revoked))
            or any(not is_sha512(item) for item in revoked)
            or not previous_revoked.issubset(set(revoked))
        ):
            raise AustralianMinorAccessError("REVOCATION_CHAIN_INVALID")
        if index == 0 and (
            digest != comp.owner["revocation_head_digest"]
            or payload["revocation_sequence"] != comp.owner["revocation_sequence"]
        ):
            raise AustralianMinorAccessError("REVOCATION_OWNER_ANCHOR_MISMATCH")
        if index > 0 and payload["revocation_sequence"] < _signed_payload(
            comp, chain[index - 1]
        )["revocation_sequence"]:
            raise AustralianMinorAccessError("REVOCATION_SEQUENCE_ROLLBACK")
        verified.append(deepcopy(envelope))
        previous_digest = digest
        previous_sequence = payload["head_sequence"]
        previous_revoked = set(revoked)
    envelope = verified[-1]
    payload = _signed_payload(comp, chain[-1])
    digest = _envelope_digest(envelope)
    if not comp.revocation_store.is_current(
        comp.context_id,
        digest,
        payload["head_sequence"],
    ):
        raise AustralianMinorAccessError("REVOCATION_HEAD_NOT_DURABLE_CURRENT")
    if not (payload["issued_at"] <= now <= payload["expires_at"]):
        raise AustralianMinorAccessError("REVOCATION_HEAD_STALE")
    return deepcopy(envelope), deepcopy(payload), digest, verified


def _pseudonym(comp: _DeploymentComposition, label: str, payload: dict[str, Any]) -> str:
    return hmac.new(
        comp.pseudonymization_key,
        label.encode("utf-8") + b"\x00" + canonical_json_bytes(deepcopy(payload)),
        sha512,
    ).hexdigest()


def _snapshot(state: dict[str, Any], stage: str, comp: _DeploymentComposition) -> dict[str, Any]:
    for field in ("subject_id", "session_id", "service_id", "request_nonce"):
        _text(state.get(field), field.upper())
    request_fingerprint = state.get("request_fingerprint")
    if not is_sha512(request_fingerprint):
        raise AustralianMinorAccessError("CANONICAL_REQUEST_FINGERPRINT_INVALID")
    minor_access_request_binding_digest = _pseudonym(
        comp,
        "AU_MINOR_REQUEST",
        {
            "subject_id": state["subject_id"],
            "session_id": state["session_id"],
            "service_id": state["service_id"],
            "request_nonce": state["request_nonce"],
            "stage": stage,
        },
    )
    binding = _pseudonym(
        comp,
        "AU_MINOR_SUBJECT_SESSION",
        {"subject_id": state["subject_id"], "session_id": state["session_id"]},
    )
    service_binding = _pseudonym(comp, "AU_MINOR_SERVICE", {"service_id": state["service_id"]})
    return {
        "request_fingerprint": request_fingerprint,
        "minor_access_request_binding_digest": minor_access_request_binding_digest,
        "subject_session_binding_digest": binding,
        "service_binding_digest": service_binding,
        "stage": stage,
        "pseudonymizer_id": comp.owner["pseudonymizer_binding"]["pseudonymizer_id"],
        "pseudonymizer_version": comp.owner["pseudonymizer_binding"]["version"],
        "pseudonymization_key_id": comp.owner["pseudonymizer_binding"]["key_id"],
        "pseudonymization_key_fingerprint": comp.owner["pseudonymizer_binding"]["key_fingerprint"],
    }


def _evidence(
    comp: _DeploymentComposition,
    snapshot: dict[str, Any],
    stage: str,
    now: int,
    revocation_digest: str,
    revoked: set[str],
    lanes: tuple[str, ...],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    envelopes: dict[str, dict[str, Any]] = {}
    payloads: dict[str, dict[str, Any]] = {}
    for lane in lanes:
        envelope = comp.resolvers[lane].resolve(deepcopy(snapshot))
        payload = _verify_composition_signed(
            comp,
            envelope,
            payload_keys=_EVIDENCE_KEYS,
            label=lane,
        )
        binding = comp.bindings[lane]
        if (
            payload["schema"] != SCHEMA
            or payload["context_id"] != comp.context_id
            or payload["lane"] != lane
            or payload["provider_id"] != binding["provider_id"]
            or payload["credential_id"] != binding["credential_id"]
            or payload["key_fingerprint"] != binding["key_fingerprint"]
            or payload["registry_digest"] != comp.owner["registry_digest"]
            or payload["revocation_head_digest"] != revocation_digest
            or payload["request_fingerprint"] != snapshot["request_fingerprint"]
            or payload["minor_access_request_binding_digest"]
            != snapshot["minor_access_request_binding_digest"]
            or payload["subject_session_binding_digest"] != snapshot["subject_session_binding_digest"]
            or payload["stage"] != stage
            or payload["status"] != "ACTIVE"
            or payload["effect_authority"] is not False
        ):
            raise AustralianMinorAccessError(f"{lane}_CONTEXT_MISMATCH")
        _integer(payload["evidence_sequence"], f"{lane}_SEQUENCE", 1)
        if not (payload["issued_at"] <= now <= payload["expires_at"]):
            raise AustralianMinorAccessError(f"{lane}_EVIDENCE_STALE")
        digest = _envelope_digest(envelope)
        if digest in revoked:
            raise AustralianMinorAccessError(f"{lane}_EVIDENCE_REVOKED")
        envelopes[lane] = deepcopy(envelope)
        payloads[lane] = payload
    return envelopes, payloads


def _scope_applicable(payloads: dict[str, dict[str, Any]]) -> bool:
    expected_details = {
        "SERVICE_SCOPE": ("service_scope_code", payloads["SERVICE_SCOPE"]["result"]),
        "ORDINARY_RESIDENCE": (
            "ordinary_residence_code",
            payloads["ORDINARY_RESIDENCE"]["result"],
        ),
        "ACCOUNT_ACTION": ("account_action_code", payloads["ACCOUNT_ACTION"]["result"]),
    }
    for lane, (field, result) in expected_details.items():
        if payloads[lane]["details"] != {field: result}:
            raise AustralianMinorAccessError(f"{lane}_DETAILS_INVALID")
    service = payloads["SERVICE_SCOPE"]["result"]
    residence = payloads["ORDINARY_RESIDENCE"]["result"]
    action = payloads["ACCOUNT_ACTION"]["result"]
    if service not in {SERVICE_IN_SCOPE, SERVICE_OUT_OF_SCOPE}:
        raise AustralianMinorAccessError("SERVICE_SCOPE_INDETERMINATE")
    if residence not in {RESIDENCE_AUSTRALIA, RESIDENCE_OUTSIDE_AUSTRALIA}:
        raise AustralianMinorAccessError("RESIDENCE_INDETERMINATE")
    if action not in {ACTION_CREATE_OR_MAINTAIN_ACCOUNT, ACTION_OUT_OF_SCOPE}:
        raise AustralianMinorAccessError("ACCOUNT_ACTION_INDETERMINATE")
    return not (
        service == SERVICE_OUT_OF_SCOPE
        or residence == RESIDENCE_OUTSIDE_AUSTRALIA
        or action == ACTION_OUT_OF_SCOPE
    )


def _privacy_contract(payloads: dict[str, dict[str, Any]], now: int) -> None:
    policy = payloads["METHOD_PRIVACY_POLICY"]["details"]
    _exact_dict(
        policy,
        {
            "method_class",
            "government_id_used",
            "digital_id_used",
            "reasonable_non_government_id_alternative_available",
            "government_id_required",
            "digital_id_required",
            "privacy_preserving",
            "raw_date_of_birth_retained",
            "use_scope",
            "disclosure_scope",
            "retain_only_until_destruction",
            "youth_penalty_applied",
        },
        "METHOD_PRIVACY_POLICY_DETAILS",
    )
    if not isinstance(policy["method_class"], str) or not policy["method_class"]:
        raise AustralianMinorAccessError("METHOD_CLASS_INVALID")
    booleans = (
        "government_id_used",
        "digital_id_used",
        "reasonable_non_government_id_alternative_available",
        "government_id_required",
        "digital_id_required",
        "privacy_preserving",
        "raw_date_of_birth_retained",
        "retain_only_until_destruction",
        "youth_penalty_applied",
    )
    if any(not isinstance(policy[field], bool) for field in booleans):
        raise AustralianMinorAccessError("PRIVACY_POLICY_BOOLEAN_INVALID")
    if (policy["government_id_used"] or policy["digital_id_used"]) and not policy[
        "reasonable_non_government_id_alternative_available"
    ]:
        raise AustralianMinorAccessError("REASONABLE_ALTERNATIVE_REQUIRED")
    if (
        policy["government_id_required"]
        or policy["digital_id_required"]
        or not policy["privacy_preserving"]
        or policy["raw_date_of_birth_retained"]
        or not policy["retain_only_until_destruction"]
        or policy["youth_penalty_applied"]
        or policy["use_scope"] != AGE_ASSURANCE_USE_SCOPE
        or policy["disclosure_scope"] != DISCLOSURE_SCOPE
    ):
        raise AustralianMinorAccessError("PRIVACY_POLICY_PROHIBITED")

    destruction = payloads["PRIVACY_DESTRUCTION"]["details"]
    _exact_dict(
        destruction,
        {"destroyed", "retained", "destruction_scope", "destroyed_at", "destruction_receipt_id"},
        "PRIVACY_DESTRUCTION_DETAILS",
    )
    if (
        destruction["destroyed"] is not True
        or destruction["retained"] is not False
        or destruction["destruction_scope"] != AGE_ASSURANCE_USE_SCOPE
        or not isinstance(destruction["destruction_receipt_id"], str)
        or not destruction["destruction_receipt_id"]
        or not isinstance(destruction["destroyed_at"], int)
        or destruction["destroyed_at"] > now
    ):
        raise AustralianMinorAccessError("PRIVACY_DESTRUCTION_NOT_PROVEN")


def _decision(payloads: dict[str, dict[str, Any]], now: int) -> tuple[str, bool, str]:
    if not _scope_applicable(payloads):
        return RESULT_NOT_APPLICABLE, False, AGE_INDETERMINATE

    _privacy_contract(payloads, now)
    if (
        payloads["METHOD_PRIVACY_POLICY"]["result"] != "COMPLIANT"
        or payloads["PRIVACY_DESTRUCTION"]["result"] != "DESTROYED"
    ):
        raise AustralianMinorAccessError("PRIVACY_RESULT_INVALID")
    age_details = _exact_dict(
        payloads["AGE_ASSURANCE"]["details"],
        {"threshold", "raw_date_of_birth_present"},
        "AGE_ASSURANCE_DETAILS",
    )
    if age_details["threshold"] != MINIMUM_ACCOUNT_AGE or age_details["raw_date_of_birth_present"] is not False:
        raise AustralianMinorAccessError("AGE_THRESHOLD_OR_PRIVACY_INVALID")
    age = payloads["AGE_ASSURANCE"]["result"]
    if age == AGE_UNDER_16:
        return RESULT_DENY, True, age
    if age == AGE_AT_LEAST_16:
        return RESULT_PASS, True, age
    raise AustralianMinorAccessError("AGE_ASSURANCE_INDETERMINATE")


def _replay_head(
    comp: _DeploymentComposition,
    namespace: str,
    subject_binding: str,
    now: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    envelope = comp.replay_store.current_head(namespace, subject_binding, now)
    payload = _verify_composition_signed(
        comp,
        envelope,
        payload_keys=_REPLAY_HEAD_KEYS,
        label="REPLAY_HEAD",
    )
    if (
        payload["schema"] != SCHEMA
        or payload["context_id"] != comp.context_id
        or payload["store_id"] != comp.owner["replay_store_id"]
        or payload["store_version"] != comp.owner["replay_store_version"]
        or payload["namespace"] != namespace
        or payload["subject_session_binding_digest"] != subject_binding
        or type(payload["observed_at"]) is not int
        or payload["observed_at"] > now
        or payload["status"] != "ACTIVE"
        or payload["effect_authority"] is not False
        or not is_sha512(payload["head_digest"])
    ):
        raise AustralianMinorAccessError("REPLAY_HEAD_CONTEXT_MISMATCH")
    _integer(payload["sequence"], "REPLAY_HEAD_SEQUENCE")
    return deepcopy(envelope), payload


def _claim_replay(
    comp: _DeploymentComposition,
    snapshot: dict[str, Any],
    stage: str,
    now: int,
    registry_digest: str,
    revocation_digest: str,
    evidence_digest: str,
    decision_digest: str,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    namespace = "AUSTRALIAN_MINOR_ACCESS"
    pre_envelope, pre = _replay_head(comp, namespace, snapshot["subject_session_binding_digest"], now)
    replay_key = _pseudonym(
        comp,
        "AU_MINOR_REPLAY",
        {
            "request_fingerprint": snapshot["request_fingerprint"],
            "minor_access_request_binding_digest": snapshot[
                "minor_access_request_binding_digest"
            ],
            "stage": stage,
        },
    )
    claim = {
        "schema": SCHEMA,
        "context_id": comp.context_id,
        "store_id": comp.owner["replay_store_id"],
        "store_version": comp.owner["replay_store_version"],
        "namespace": namespace,
        "replay_key": replay_key,
        "request_fingerprint": snapshot["request_fingerprint"],
        "minor_access_request_binding_digest": snapshot[
            "minor_access_request_binding_digest"
        ],
        "subject_session_binding_digest": snapshot["subject_session_binding_digest"],
        "stage": stage,
        "prior_head_digest": pre["head_digest"],
        "sequence": pre["sequence"] + 1,
        "registry_digest": registry_digest,
        "revocation_head_digest": revocation_digest,
        "evidence_bundle_digest": evidence_digest,
        "decision_digest": decision_digest,
        "claimed_at": now,
        "status": "PERSISTED",
        "effect_authority": False,
    }
    receipt = comp.replay_store.claim_once(deepcopy(claim))
    receipt_payload = _verify_composition_signed(
        comp,
        receipt,
        payload_keys=_REPLAY_RECEIPT_KEYS,
        label="REPLAY_RECEIPT",
    )
    if receipt_payload != claim:
        raise AustralianMinorAccessError("REPLAY_RECEIPT_CLAIM_MISMATCH")
    receipt_digest = _envelope_digest(receipt)
    if not comp.replay_store.is_claimed(namespace, replay_key, receipt_digest):
        raise AustralianMinorAccessError("REPLAY_RECEIPT_NOT_DURABLE")
    if comp.replay_store.persisted_receipt(namespace, replay_key) != receipt:
        raise AustralianMinorAccessError("REPLAY_PERSISTED_RECEIPT_MISMATCH")
    post_envelope, post = _replay_head(comp, namespace, snapshot["subject_session_binding_digest"], now)
    expected_head = canonical_integrity_hash(
        {"prior_head_digest": pre["head_digest"], "receipt_digest": receipt_digest, "sequence": claim["sequence"]}
    )
    if post["sequence"] != claim["sequence"] or post["head_digest"] != expected_head:
        raise AustralianMinorAccessError("REPLAY_TRANSITION_NOT_PERSISTED")
    return deepcopy(receipt), deepcopy(post_envelope), {
        "replay_key": replay_key,
        "receipt_digest": receipt_digest,
        "pre_head_digest": pre["head_digest"],
        "post_head_digest": _envelope_digest(post_envelope),
        "sequence": claim["sequence"],
    }


def _record_digest(record: dict[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "record_digest"}
    return canonical_integrity_hash(payload)


def _fail_record(stage: str) -> dict[str, Any]:
    record = {
        "schema": SCHEMA,
        "stage": stage,
        "result": RESULT_ESCALATE,
        "applicable": None,
        "age_assurance_result": AGE_INDETERMINATE,
        "reason": "AUTHENTICATED_EVIDENCE_UNAVAILABLE",
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority": False,
    }
    record["record_digest"] = _record_digest(record)
    return record


def evaluate_australian_minor_access(state: dict[str, Any], *, stage: str) -> dict[str, Any]:
    """Evaluate only authenticated evidence from the sealed deployment context."""

    safe_stage = stage if type(stage) is str and bool(stage) else "INVALID_STAGE"
    try:
        if type(state) is not dict or safe_stage == "INVALID_STAGE":
            raise AustralianMinorAccessError("INVALID_EVALUATION_INPUT")
        comp = _composition()
        clock_envelope, clock, _ = _trusted_time(comp)
        now = clock["observed_at"]
        revocation_envelope, revocation, revocation_digest, _ = _live_revocation(comp, now)
        snapshot = _snapshot(state, safe_stage, comp)
        evidence, payloads = _evidence(
            comp,
            snapshot,
            safe_stage,
            now,
            revocation_digest,
            set(revocation["revoked_evidence_digests"]),
            SCOPE_LANES,
        )
        if _scope_applicable(payloads):
            age_evidence, age_payloads = _evidence(
                comp,
                snapshot,
                safe_stage,
                now,
                revocation_digest,
                set(revocation["revoked_evidence_digests"]),
                AGE_PRIVACY_LANES,
            )
            evidence.update(age_evidence)
            payloads.update(age_payloads)
        result, applicable, age = _decision(payloads, now)
        evidence_digest = canonical_integrity_hash(evidence)
        decision_core = {
            "context_digest": comp.context_digest,
            "registry_digest": comp.owner["registry_digest"],
            "revocation_head_digest": revocation_digest,
            "clock_digest": _envelope_digest(clock_envelope),
            "snapshot": snapshot,
            "evidence_bundle_digest": evidence_digest,
            "result": result,
            "applicable": applicable,
            "age_assurance_result": age,
        }
        decision_digest = canonical_integrity_hash(decision_core)
        replay_receipt, replay_head, replay = _claim_replay(
            comp,
            snapshot,
            safe_stage,
            now,
            comp.owner["registry_digest"],
            revocation_digest,
            evidence_digest,
            decision_digest,
        )
        record = {
            "schema": SCHEMA,
            "stage": safe_stage,
            "context_id": comp.context_id,
            "context_digest": comp.context_digest,
            "owner_composition_sequence": comp.owner["composition_sequence"],
            "registry": deepcopy(comp.registry),
            "registry_digest": comp.owner["registry_digest"],
            "revocation_head": revocation_envelope,
            "revocation_head_digest": revocation_digest,
            "clock_receipt": clock_envelope,
            "clock_receipt_digest": _envelope_digest(clock_envelope),
            "snapshot": snapshot,
            "evidence": evidence,
            "evidence_bundle_digest": evidence_digest,
            "decision_digest": decision_digest,
            "replay_receipt": replay_receipt,
            "replay_post_head": replay_head,
            "replay": replay,
            "result": result,
            "applicable": applicable,
            "age_assurance_result": age,
            "reason": "AUTHENTICATED_DETERMINATION",
            "privacy_data_destroyed": True if applicable else None,
            "youth_penalty_applied": False,
            "access_granted": False,
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority": False,
        }
        record["record_digest"] = _record_digest(record)
    except Exception:
        record = _fail_record(safe_stage)
    if type(state) is dict:
        state["australian_minor_access"] = deepcopy(record)
    return deepcopy(record)


def _verify_australian_minor_access_core(state: dict[str, Any]) -> bool:
    """Remeasure the stored result against current signed trust and replay state."""

    try:
        comp = _composition()
        record = state["australian_minor_access"]
        if (
            type(record) is not dict
            or set(record) != _SUCCESS_RECORD_KEYS
            or record.get("result") == RESULT_ESCALATE
        ):
            return False
        if record.get("record_digest") != _record_digest(record):
            return False
        recorded_revocation_head = record.get("revocation_head")
        recorded_clock_receipt = record.get("clock_receipt")
        if (
            type(recorded_revocation_head) is not dict
            or type(recorded_clock_receipt) is not dict
        ):
            return False
        if (
            record.get("context_id") != comp.context_id
            or record.get("schema") != SCHEMA
            or not _text(record.get("stage"), "STAGE")
            or record.get("context_digest") != comp.context_digest
            or record.get("owner_composition_sequence")
            != comp.owner["composition_sequence"]
            or record.get("registry") != comp.registry
            or record.get("registry_digest") != comp.owner["registry_digest"]
            or _envelope_digest(recorded_revocation_head)
            != record.get("revocation_head_digest")
            or _envelope_digest(recorded_clock_receipt)
            != record.get("clock_receipt_digest")
            or record.get("reason") != "AUTHENTICATED_DETERMINATION"
            or record.get("privacy_data_destroyed")
            != (True if record.get("applicable") is True else None)
            or record.get("access_granted") is not False
            or record.get("authority_granted") is not False
            or record.get("licence_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("effect_authority") is not False
            or record.get("youth_penalty_applied") is not False
        ):
            return False
        clock_envelope, clock, clock_chain = _trusted_time(comp)
        if record["clock_receipt"] not in clock_chain:
            return False
        _, revocation, revocation_digest, revocation_chain = _live_revocation(
            comp, clock["observed_at"]
        )
        record_revocation_digest = record["revocation_head_digest"]
        if record["revocation_head"] not in revocation_chain:
            return False
        snapshot = record["snapshot"]
        if (
            type(snapshot) is not dict
            or set(snapshot) != _SNAPSHOT_KEYS
            or snapshot != _snapshot(state, record["stage"], comp)
            or snapshot.get("stage") != record["stage"]
            or not all(
                is_sha512(snapshot.get(field))
                for field in (
                    "request_fingerprint",
                    "minor_access_request_binding_digest",
                    "subject_session_binding_digest",
                    "service_binding_digest",
                    "pseudonymization_key_fingerprint",
                )
            )
            or snapshot.get("pseudonymization_key_fingerprint")
            != comp.owner["pseudonymizer_binding"]["key_fingerprint"]
            or snapshot.get("pseudonymizer_id")
            != comp.owner["pseudonymizer_binding"]["pseudonymizer_id"]
            or snapshot.get("pseudonymizer_version")
            != comp.owner["pseudonymizer_binding"]["version"]
            or snapshot.get("pseudonymization_key_id")
            != comp.owner["pseudonymizer_binding"]["key_id"]
        ):
            return False
        evidence = record["evidence"]
        if canonical_integrity_hash(evidence) != record["evidence_bundle_digest"]:
            return False
        payloads: dict[str, dict[str, Any]] = {}
        revoked = set(revocation["revoked_evidence_digests"])
        expected_lanes = LANES if record.get("applicable") is True else SCOPE_LANES
        if set(evidence) != set(expected_lanes):
            return False
        for lane in expected_lanes:
            env = evidence[lane]
            payload = _verify_composition_signed(
                comp,
                env,
                payload_keys=_EVIDENCE_KEYS,
                label=lane,
            )
            if (
                payload["request_fingerprint"] != snapshot["request_fingerprint"]
                or payload["minor_access_request_binding_digest"]
                != snapshot["minor_access_request_binding_digest"]
                or payload["subject_session_binding_digest"] != snapshot["subject_session_binding_digest"]
                or payload["stage"] != record["stage"]
                or payload["revocation_head_digest"] != record_revocation_digest
                or _envelope_digest(env) in revoked
            ):
                return False
            payloads[lane] = payload
        result, applicable, age = _decision(payloads, clock["observed_at"])
        if (result, applicable, age) != (
            record["result"],
            record["applicable"],
            record["age_assurance_result"],
        ):
            return False
        decision_core = {
            "context_digest": comp.context_digest,
            "registry_digest": comp.owner["registry_digest"],
            "revocation_head_digest": record_revocation_digest,
            "clock_digest": _envelope_digest(record["clock_receipt"]),
            "snapshot": snapshot,
            "evidence_bundle_digest": record["evidence_bundle_digest"],
            "result": result,
            "applicable": applicable,
            "age_assurance_result": age,
        }
        if canonical_integrity_hash(decision_core) != record["decision_digest"]:
            return False
        receipt = record["replay_receipt"]
        receipt_payload = _verify_composition_signed(
            comp,
            receipt,
            payload_keys=_REPLAY_RECEIPT_KEYS,
            label="REPLAY_RECEIPT",
        )
        replay = record["replay"]
        if (
            type(replay) is not dict
            or set(replay)
            != {
                "replay_key",
                "receipt_digest",
                "pre_head_digest",
                "post_head_digest",
                "sequence",
            }
            or replay["post_head_digest"]
            != _envelope_digest(record["replay_post_head"])
            or receipt_payload["sequence"] != replay["sequence"]
            or receipt_payload["replay_key"] != replay["replay_key"]
            or receipt_payload["prior_head_digest"] != replay["pre_head_digest"]
        ):
            return False
        receipt_digest = _envelope_digest(receipt)
        if (
            receipt_digest != replay["receipt_digest"]
            or receipt_payload["schema"] != SCHEMA
            or receipt_payload["context_id"] != comp.context_id
            or receipt_payload["store_id"] != comp.owner["replay_store_id"]
            or receipt_payload["store_version"] != comp.owner["replay_store_version"]
            or receipt_payload["namespace"] != "AUSTRALIAN_MINOR_ACCESS"
            or receipt_payload["request_fingerprint"]
            != snapshot["request_fingerprint"]
            or receipt_payload["subject_session_binding_digest"]
            != snapshot["subject_session_binding_digest"]
            or receipt_payload["stage"] != record["stage"]
            or receipt_payload["registry_digest"] != comp.owner["registry_digest"]
            or receipt_payload["claimed_at"]
            != _signed_payload(comp, record["clock_receipt"])["observed_at"]
            or receipt_payload["status"] != "PERSISTED"
            or receipt_payload["effect_authority"] is not False
            or receipt_payload["minor_access_request_binding_digest"]
            != snapshot["minor_access_request_binding_digest"]
            or receipt_payload["decision_digest"] != record["decision_digest"]
            or receipt_payload["evidence_bundle_digest"] != record["evidence_bundle_digest"]
            or receipt_payload["revocation_head_digest"] != record_revocation_digest
            or not comp.replay_store.is_claimed(receipt_payload["namespace"], receipt_payload["replay_key"], receipt_digest)
            or comp.replay_store.persisted_receipt(
                receipt_payload["namespace"], receipt_payload["replay_key"]
            )
            != receipt
        ):
            return False
        _, live_head = _replay_head(
            comp,
            receipt_payload["namespace"],
            snapshot["subject_session_binding_digest"],
            clock["observed_at"],
        )
        recorded_head = _verify_composition_signed(
            comp,
            record["replay_post_head"],
            payload_keys=_REPLAY_HEAD_KEYS,
            label="REPLAY_HEAD",
        )
        if (
            live_head["sequence"] != receipt_payload["sequence"]
            or live_head != recorded_head
        ):
            return False
        return True
    except Exception:
        return False


def _hash_binding_payload(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_digest": record["record_digest"],
        "result": record["result"],
        "access_granted": False,
        "authority_granted": False,
        "licence_granted": False,
        "execution_authority_granted": False,
        "effect_authority": False,
    }


def _verify_hash_binding(state: dict[str, Any]) -> bool:
    try:
        chain = state.get("hash_chain")
        state_hash = state.get("state_hash")
        if type(chain) is not list:
            return False
        if not verify_hash_chain_entries(chain, state_hash):
            return False
        index = state.get("australian_minor_access_hash_binding_index")
        binding_hash = state.get("australian_minor_access_hash_binding_hash")
        if (
            type(index) is not int
            or index < 0
            or not is_sha512(binding_hash)
            or index >= len(chain)
        ):
            return False
        bindings = [
            (candidate_index, entry)
            for candidate_index, entry in enumerate(chain)
            if type(entry) is dict
            and entry.get("stage") == AUSTRALIAN_MINOR_ACCESS_STAGE
        ]
        if len(bindings) != 1 or bindings[0][0] != index:
            return False
        entry = bindings[0][1]
        record = state.get("australian_minor_access")
        if type(record) is not dict:
            return False
        payload = _hash_binding_payload(record)
        return (
            entry is chain[index]
            and entry["hash"] == binding_hash
            and entry["payload_hash"] == canonical_integrity_hash(payload)
            and entry["previous_hash"]
            == (GENESIS_HASH if index == 0 else chain[index - 1]["hash"])
        )
    except Exception:
        return False


def verify_australian_minor_access(state: dict[str, Any]) -> bool:
    """Require the result and its one exact canonical chronological binding."""

    return _verify_australian_minor_access_core(state) and _verify_hash_binding(state)


def bind_australian_minor_access_hash(state: dict[str, Any]) -> dict[str, Any]:
    """Append one canonical determination binding at the current chain tail."""

    if not _verify_australian_minor_access_core(state):
        raise AustralianMinorAccessError("UNVERIFIED_DETERMINATION")
    chain = state.get("hash_chain")
    state_hash = state.get("state_hash")
    if "expected_hash_binding_index" in state:
        raise AustralianMinorAccessError("CALLER_SUPPLIED_HASH_INDEX_REJECTED")
    if type(chain) is not list:
        raise AustralianMinorAccessError("HASH_CHAIN_INVALID")
    if chain:
        if not verify_hash_chain_entries(chain, state_hash):
            raise AustralianMinorAccessError("HASH_CHAIN_INVALID")
        previous_hash = chain[-1]["hash"]
    else:
        if state_hash != GENESIS_HASH:
            raise AustralianMinorAccessError("HASH_CHAIN_INVALID")
        previous_hash = GENESIS_HASH
    if (
        state.get("australian_minor_access_hash_binding_index") is not None
        or state.get("australian_minor_access_hash_binding_hash") is not None
        or any(
            type(entry) is dict
            and entry.get("stage") == AUSTRALIAN_MINOR_ACCESS_STAGE
            for entry in chain
        )
    ):
        raise AustralianMinorAccessError("HASH_BINDING_ALREADY_PRESENT")
    index = len(chain)
    try:
        entry = build_hash_chain_entry(
            previous_hash=previous_hash,
            stage=AUSTRALIAN_MINOR_ACCESS_STAGE,
            payload=_hash_binding_payload(state["australian_minor_access"]),
        )
    except Exception as exc:
        raise AustralianMinorAccessError("HASH_BINDING_BUILD_FAILED") from exc
    chain.append(entry)
    state["state_hash"] = entry["hash"]
    state["australian_minor_access_hash_binding_index"] = index
    state["australian_minor_access_hash_binding_hash"] = entry["hash"]
    if not verify_australian_minor_access(state):
        raise AustralianMinorAccessError("HASH_BINDING_VERIFICATION_FAILED")
    return deepcopy(entry)


__all__ = [
    "ACTION_CREATE_OR_MAINTAIN_ACCOUNT",
    "ACTION_OUT_OF_SCOPE",
    "AGE_AT_LEAST_16",
    "AGE_INDETERMINATE",
    "AGE_UNDER_16",
    "AUSTRALIAN_MINOR_ACCESS_STAGE",
    "AustralianMinorAccessError",
    "DEPLOYMENT_DEPENDENCIES",
    "DISCLOSURE_SCOPE",
    "LANES",
    "MINIMUM_ACCOUNT_AGE",
    "RESIDENCE_AUSTRALIA",
    "RESIDENCE_OUTSIDE_AUSTRALIA",
    "RESULT_DENY",
    "RESULT_ESCALATE",
    "RESULT_NOT_APPLICABLE",
    "RESULT_PASS",
    "SERVICE_IN_SCOPE",
    "SERVICE_OUT_OF_SCOPE",
    "bind_australian_minor_access_hash",
    "evaluate_australian_minor_access",
    "verify_australian_minor_access",
]
