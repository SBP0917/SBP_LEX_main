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
from hashlib import sha512
from typing import Any, Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
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
DEPLOYMENT_DEPENDENCIES: Final = (
    "Production owner pins and composition installation must be sealed outside "
    "runtime caller input; this module exposes only a TEST_ONLY bootstrap hook.",
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


def _verify_signed(
    envelope: Any,
    binding: dict[str, Any],
    *,
    payload_keys: set[str],
    label: str,
    allow_legacy_test_only: bool = False,
) -> dict[str, Any]:
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


class _DeploymentComposition:
    __slots__ = (
        "context_id",
        "context_digest",
        "owner",
        "registry",
        "registry_payload",
        "revocation_store",
        "replay_store",
        "clock",
        "pseudonymization_key",
        "resolvers",
        "bindings",
    )

    def __init__(self, **values: Any) -> None:
        for key, value in values.items():
            object.__setattr__(self, key, value)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("deployment composition is immutable")


_ACTIVE_COMPOSITION: _DeploymentComposition | None = None


def _install_australian_minor_access_deployment_for_tests(
    composition: dict[str, Any],
    *,
    fixed_context_id: str,
    fixed_context_digest: str,
    owner_public_key_hex: str,
    test_only: bool,
) -> None:
    """TEST_ONLY bootstrap hook; no runtime production installer is exposed."""

    global _ACTIVE_COMPOSITION
    if test_only is not True:
        raise AustralianMinorAccessError("TEST_ONLY_INSTALL_REQUIRED")
    if _ACTIVE_COMPOSITION is not None:
        raise AustralianMinorAccessError("DEPLOYMENT_ALREADY_REGISTERED")
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
    try:
        owner_raw = bytes.fromhex(owner_public_key_hex)
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
    )
    if owner["schema"] != SCHEMA or owner["context_id"] != fixed_context_id:
        raise AustralianMinorAccessError("OWNER_CONTEXT_PIN_MISMATCH")
    actual_context_digest = _envelope_digest(composition["owner_record"])
    if not is_sha512(fixed_context_digest) or not hmac.compare_digest(actual_context_digest, fixed_context_digest):
        raise AustralianMinorAccessError("OWNER_CONTEXT_DIGEST_MISMATCH")
    if owner["status"] != "ACTIVE" or owner["effect_authority"] is not False:
        raise AustralianMinorAccessError("OWNER_CONTEXT_INACTIVE")
    if owner["deployment_mode"] != "TEST_ONLY":
        raise AustralianMinorAccessError("TEST_ONLY_CONTEXT_REQUIRED")
    _integer(owner["valid_from"], "OWNER_VALID_FROM")
    _integer(owner["valid_until"], "OWNER_VALID_UNTIL")
    if owner["valid_until"] <= owner["valid_from"]:
        raise AustralianMinorAccessError("OWNER_VALIDITY_INVALID")
    _integer(owner["composition_sequence"], "COMPOSITION_SEQUENCE", 1)
    _integer(owner["revocation_sequence"], "OWNER_REVOCATION_SEQUENCE")

    bindings: dict[str, dict[str, Any]] = {}
    for name in ("registry", "revocation", "replay", "clock"):
        binding = deepcopy(owner[f"{name}_binding"])
        _raw_key(binding, name.upper(), allow_legacy_test_only=True)
        bindings[name] = binding
    lane_bindings = owner["lane_bindings"]
    if not isinstance(lane_bindings, dict) or set(lane_bindings) != set(LANES):
        raise AustralianMinorAccessError("INVALID_LANE_BINDINGS")
    for lane in LANES:
        binding = deepcopy(lane_bindings[lane])
        _raw_key(binding, lane, allow_legacy_test_only=True)
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
        allow_legacy_test_only=True,
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
        owner=deepcopy(owner),
        registry=deepcopy(composition["registry"]),
        registry_payload=deepcopy(registry_payload),
        revocation_store=composition["revocation_store"],
        replay_store=composition["replay_store"],
        clock=composition["clock"],
        pseudonymization_key=bytes(pseudonymization_key),
        resolvers=dict(resolvers),
        bindings=bindings,
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
        payload = _verify_signed(
            envelope,
            comp.bindings["clock"],
            payload_keys=_CLOCK_KEYS,
            label="CLOCK",
            allow_legacy_test_only=True,
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
    payload = chain[-1]["payload"]
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
        payload = _verify_signed(
            envelope,
            comp.bindings["revocation"],
            payload_keys=_REVOCATION_KEYS,
            label="REVOCATION_HEAD",
            allow_legacy_test_only=True,
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
        if index > 0 and payload["revocation_sequence"] < chain[index - 1]["payload"]["revocation_sequence"]:
            raise AustralianMinorAccessError("REVOCATION_SEQUENCE_ROLLBACK")
        verified.append(deepcopy(envelope))
        previous_digest = digest
        previous_sequence = payload["head_sequence"]
        previous_revoked = set(revoked)
    envelope = verified[-1]
    payload = chain[-1]["payload"]
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
        payload = _verify_signed(
            envelope,
            comp.bindings[lane],
            payload_keys=_EVIDENCE_KEYS,
            label=lane,
            allow_legacy_test_only=True,
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
    payload = _verify_signed(
        envelope,
        comp.bindings["replay"],
        payload_keys=_REPLAY_HEAD_KEYS,
        label="REPLAY_HEAD",
        allow_legacy_test_only=True,
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
    receipt_payload = _verify_signed(
        receipt,
        comp.bindings["replay"],
        payload_keys=_REPLAY_RECEIPT_KEYS,
        label="REPLAY_RECEIPT",
        allow_legacy_test_only=True,
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
        if (
            record.get("context_id") != comp.context_id
            or record.get("schema") != SCHEMA
            or not _text(record.get("stage"), "STAGE")
            or record.get("context_digest") != comp.context_digest
            or record.get("owner_composition_sequence")
            != comp.owner["composition_sequence"]
            or record.get("registry") != comp.registry
            or record.get("registry_digest") != comp.owner["registry_digest"]
            or _envelope_digest(record.get("revocation_head"))
            != record.get("revocation_head_digest")
            or _envelope_digest(record.get("clock_receipt"))
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
            payload = _verify_signed(
                env,
                comp.bindings[lane],
                payload_keys=_EVIDENCE_KEYS,
                label=lane,
                allow_legacy_test_only=True,
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
        receipt_payload = _verify_signed(
            receipt,
            comp.bindings["replay"],
            payload_keys=_REPLAY_RECEIPT_KEYS,
            label="REPLAY_RECEIPT",
            allow_legacy_test_only=True,
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
            != record["clock_receipt"]["payload"]["observed_at"]
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
        live_head_envelope, live_head = _replay_head(
            comp,
            receipt_payload["namespace"],
            snapshot["subject_session_binding_digest"],
            clock["observed_at"],
        )
        if (
            live_head["sequence"] != receipt_payload["sequence"]
            or live_head_envelope != record["replay_post_head"]
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
