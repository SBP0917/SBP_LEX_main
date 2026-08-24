"""Implementation-defined V2 mechanical contract for filed Claim 16.

Each segment is independently encrypted and authenticated with AES-256-GCM.
The complete ciphertext manifest and its recipient, jurisdiction, policy and
revocation bindings are signed by an injected exchange-envelope authority.

This module does not implement or prove transport security, durable key
custody, or distributed enforcement.  Those remain explicit external trust
boundaries.  A valid envelope grants no access, authority, licence, execution,
or effect permission.
"""

from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from hashlib import sha512
import hmac
import os
from threading import Lock
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sbp_lex.security.hybrid_signature import (
    HybridSignatureError,
    HybridSignatureProvider,
    HybridVerificationContext,
    build_hybrid_signed_object,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)
from sbp_lex.security.integrity import (
    IntegrityContractError,
    canonical_integrity_bytes,
    canonical_integrity_hash,
    is_sha512,
)


SCHEMA_ID = "V2_IMPLEMENTATION_DEFINED_SEGMENTED_EXCHANGE_V1"
EXCHANGE_AUTHORITY_ROLE = "V2_SEGMENTED_EXCHANGE_ENVELOPE_AUTHORITY"
EXCHANGE_SIGNING_PURPOSE = "SBP_LEX_V2_SEGMENTED_EXCHANGE_ENVELOPE"
EXCHANGE_ACTIVE = "ACTIVE"
EXCHANGE_REVOKED = "REVOKED"

EXTERNAL_BOUNDARIES = {
    "transport": "EXTERNAL_AND_UNPROVEN",
    "durable_key_custody": "EXTERNAL_AND_UNPROVEN",
    "distributed_enforcement": "EXTERNAL_AND_UNPROVEN",
}

NO_AUTHORIZATION_EFFECT = {
    "access_granted": False,
    "authority_granted": False,
    "licence_granted": False,
    "execution_authority_granted": False,
    "effect_authority_granted": False,
}

_SIGNED_ENVELOPE_FIELDS = {
    "schema_id",
    "external_boundaries",
    "envelope_authority",
    "bindings",
    "binding_digest",
    "segment_manifest",
    "segment_manifest_digest",
    "segments",
    "authorization_effect",
    "digest",
    "signature",
    "verified",
}

_BINDING_FIELDS = {
    "exchange_id",
    "request_fingerprint",
    "evaluation_time",
    "prior_exchange_digest",
    "sender_id",
    "recipient_id",
    "jurisdiction",
    "policy_id",
    "policy_digest",
    "revocation_status",
    "revocation_sequence",
    "segment_count",
}

_SEGMENT_FIELDS = {
    "segment_id",
    "segment_index",
    "key_id",
    "nonce_b64",
    "ciphertext_b64",
    "aad_digest",
    "ciphertext_digest",
}

_RECORD_FIELDS = {
    "result",
    "envelope",
    "envelope_digest",
    "audit_digests",
}


class SegmentedExchangeRejected(ValueError):
    """Fail-closed result; no plaintext is returned on rejection."""


class ExchangeAttestationProvider(HybridSignatureProvider, Protocol):
    exchange_attestation_admitted: bool


class ExchangeEnvelopeAuthority(Protocol):
    exchange_authority_id: str
    exchange_authority_version: str
    exchange_authority_role: str
    exchange_authority_credential_id: str


class SegmentKeyResolver(Protocol):
    key_resolver_id: str

    def resolve_segment_key(
        self,
        *,
        exchange_id: str,
        segment_id: str,
        sender_id: str,
        recipient_id: str,
        jurisdiction: str,
        policy_id: str,
        policy_digest: str,
    ) -> tuple[str, bytes] | None: ...


class ExchangeReplayGuard(Protocol):
    def consume(
        self,
        *,
        exchange_id: str,
        envelope_digest: str,
        revocation_scope: str,
        revocation_sequence: int,
    ) -> bool: ...


class InMemoryExchangeReplayGuard:
    """Process-local replay and rollback protection.

    This guard is real for one process lifetime but is not durable or
    distributed.  A deployment must inject a durable equivalent before making
    a distributed-enforcement claim.
    """

    def __init__(self) -> None:
        self._consumed_exchange_ids: set[str] = set()
        self._highest_revocation_sequence: dict[str, int] = {}
        self._lock = Lock()

    def consume(
        self,
        *,
        exchange_id: str,
        envelope_digest: str,
        revocation_scope: str,
        revocation_sequence: int,
    ) -> bool:
        if not is_sha512(envelope_digest):
            return False
        with self._lock:
            if exchange_id in self._consumed_exchange_ids:
                return False
            highest = self._highest_revocation_sequence.get(revocation_scope)
            if highest is not None and revocation_sequence < highest:
                return False
            self._consumed_exchange_ids.add(exchange_id)
            self._highest_revocation_sequence[revocation_scope] = (
                revocation_sequence
                if highest is None
                else max(highest, revocation_sequence)
            )
            return True


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _authority_metadata(
    authority: ExchangeEnvelopeAuthority | None,
) -> dict[str, str] | None:
    values = {
        "authority_id": getattr(authority, "exchange_authority_id", None),
        "authority_version": getattr(
            authority, "exchange_authority_version", None
        ),
        "authority_role": getattr(authority, "exchange_authority_role", None),
        "authority_credential_id": getattr(
            authority, "exchange_authority_credential_id", None
        ),
    }
    if (
        not all(_text(value) for value in values.values())
        or values["authority_role"] != EXCHANGE_AUTHORITY_ROLE
    ):
        return None
    return values


def _provider_admitted(provider: ExchangeAttestationProvider | None) -> bool:
    return (
        is_hybrid_provider(provider)
        and getattr(provider, "exchange_attestation_admitted", None) is True
    )


def _trust_context_owner_pinned(
    context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    return (
        isinstance(context, HybridVerificationContext)
        and is_sha512(owner_pinned_context_digest)
        and hmac.compare_digest(
            context.context_digest, owner_pinned_context_digest
        )
    )


def _resolver_admitted(resolver: SegmentKeyResolver | None) -> bool:
    return (
        resolver is not None
        and _text(getattr(resolver, "key_resolver_id", None))
        and callable(getattr(resolver, "resolve_segment_key", None))
    )


def _decode_base64(value: Any, *, reason: str) -> bytes:
    if not _text(value):
        raise SegmentedExchangeRejected(reason)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SegmentedExchangeRejected(reason) from exc


def _key_material(
    resolver: SegmentKeyResolver,
    *,
    bindings: dict[str, Any],
    segment_id: str,
) -> tuple[str, bytes]:
    try:
        material = resolver.resolve_segment_key(
            exchange_id=bindings["exchange_id"],
            segment_id=segment_id,
            sender_id=bindings["sender_id"],
            recipient_id=bindings["recipient_id"],
            jurisdiction=bindings["jurisdiction"],
            policy_id=bindings["policy_id"],
            policy_digest=bindings["policy_digest"],
        )
    except Exception as exc:
        raise SegmentedExchangeRejected("EXCHANGE_KEY_RESOLUTION_FAILED") from exc
    if (
        type(material) is not tuple
        or len(material) != 2
        or not _text(material[0])
        or type(material[1]) is not bytes
        or len(material[1]) != 32
    ):
        raise SegmentedExchangeRejected("EXCHANGE_AES256_KEY_UNAVAILABLE")
    return material


def _segment_aad(
    bindings: dict[str, Any],
    *,
    segment_id: str,
    segment_index: int,
    key_id: str,
) -> dict[str, Any]:
    return {
        "schema_id": SCHEMA_ID,
        "exchange_id": bindings["exchange_id"],
        "request_fingerprint": bindings["request_fingerprint"],
        "evaluation_time": bindings["evaluation_time"],
        "prior_exchange_digest": bindings["prior_exchange_digest"],
        "sender_id": bindings["sender_id"],
        "recipient_id": bindings["recipient_id"],
        "jurisdiction": bindings["jurisdiction"],
        "policy_id": bindings["policy_id"],
        "policy_digest": bindings["policy_digest"],
        "revocation_status": bindings["revocation_status"],
        "revocation_sequence": bindings["revocation_sequence"],
        "segment_count": bindings["segment_count"],
        "segment_id": segment_id,
        "segment_index": segment_index,
        "key_id": key_id,
    }


def _build_bindings(
    *,
    exchange_id: str,
    request_fingerprint: str,
    evaluation_time: int,
    prior_exchange_digest: str | None,
    sender_id: str,
    recipient_id: str,
    jurisdiction: str,
    policy_id: str,
    policy_digest: str,
    revocation_status: str,
    revocation_sequence: int,
    segment_count: int,
) -> dict[str, Any]:
    bindings = {
        "exchange_id": exchange_id,
        "request_fingerprint": request_fingerprint,
        "evaluation_time": evaluation_time,
        "prior_exchange_digest": prior_exchange_digest,
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "jurisdiction": jurisdiction,
        "policy_id": policy_id,
        "policy_digest": policy_digest,
        "revocation_status": revocation_status,
        "revocation_sequence": revocation_sequence,
        "segment_count": segment_count,
    }
    if (
        not all(
            _text(bindings[field])
            for field in (
                "exchange_id",
                "sender_id",
                "recipient_id",
                "jurisdiction",
                "policy_id",
            )
        )
        or not is_sha512(request_fingerprint)
        or not is_sha512(policy_digest)
        or (
            prior_exchange_digest is not None
            and not is_sha512(prior_exchange_digest)
        )
        or type(evaluation_time) is not int
        or evaluation_time < 0
        or revocation_status not in {EXCHANGE_ACTIVE, EXCHANGE_REVOKED}
        or type(revocation_sequence) is not int
        or revocation_sequence < 0
        or type(segment_count) is not int
        or segment_count < 1
    ):
        raise SegmentedExchangeRejected("EXCHANGE_BINDINGS_INVALID")
    if revocation_status != EXCHANGE_ACTIVE:
        raise SegmentedExchangeRejected("EXCHANGE_AUTHORITY_REVOKED")
    return bindings


def _segments_input_exact(segments: Any) -> list[dict[str, Any]]:
    if type(segments) is not list or not segments:
        raise SegmentedExchangeRejected("EXCHANGE_SEGMENTS_REQUIRED")
    identifiers: set[str] = set()
    result: list[dict[str, Any]] = []
    for segment in segments:
        if type(segment) is not dict or set(segment) != {"segment_id", "plaintext"}:
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_INPUT_INVALID")
        segment_id = segment.get("segment_id")
        plaintext = segment.get("plaintext")
        if (
            not _text(segment_id)
            or segment_id in identifiers
            or type(plaintext) is not bytes
            or not plaintext
        ):
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_INPUT_INVALID")
        identifiers.add(segment_id)
        result.append({"segment_id": segment_id, "plaintext": plaintext})
    return result


def build_segmented_exchange(
    *,
    exchange_id: str,
    request_fingerprint: str,
    evaluation_time: int,
    sender_id: str,
    recipient_id: str,
    jurisdiction: str,
    policy_id: str,
    policy_digest: str,
    revocation_status: str,
    revocation_sequence: int,
    segments: list[dict[str, Any]],
    authority: ExchangeEnvelopeAuthority | None,
    attestation_provider: ExchangeAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    key_resolver: SegmentKeyResolver | None,
    prior_exchange_digest: str | None = None,
) -> dict[str, Any]:
    """Encrypt, authenticate and sign one segmented exchange envelope."""

    authority_metadata = _authority_metadata(authority)
    if authority_metadata is None:
        raise SegmentedExchangeRejected("EXCHANGE_AUTHORITY_NOT_INJECTED")
    if not _provider_admitted(attestation_provider):
        raise SegmentedExchangeRejected(
            "EXCHANGE_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        )
    if not _trust_context_owner_pinned(
        attestation_trust_context, owner_pinned_context_digest
    ):
        raise SegmentedExchangeRejected(
            "EXCHANGE_OWNER_PIN_NOT_INJECTED_OR_INVALID"
        )
    if not _resolver_admitted(key_resolver):
        raise SegmentedExchangeRejected("EXCHANGE_KEY_RESOLVER_NOT_INJECTED")
    inputs = _segments_input_exact(segments)
    bindings = _build_bindings(
        exchange_id=exchange_id,
        request_fingerprint=request_fingerprint,
        evaluation_time=evaluation_time,
        prior_exchange_digest=prior_exchange_digest,
        sender_id=sender_id,
        recipient_id=recipient_id,
        jurisdiction=jurisdiction,
        policy_id=policy_id,
        policy_digest=policy_digest,
        revocation_status=revocation_status,
        revocation_sequence=revocation_sequence,
        segment_count=len(inputs),
    )

    encrypted_segments: list[dict[str, Any]] = []
    seen_nonces: set[bytes] = set()
    for index, segment in enumerate(inputs):
        key_id, key = _key_material(
            key_resolver,
            bindings=bindings,
            segment_id=segment["segment_id"],
        )
        nonce = os.urandom(12)
        while nonce in seen_nonces:
            nonce = os.urandom(12)
        seen_nonces.add(nonce)
        aad = _segment_aad(
            bindings,
            segment_id=segment["segment_id"],
            segment_index=index,
            key_id=key_id,
        )
        ciphertext = AESGCM(key).encrypt(
            nonce,
            segment["plaintext"],
            canonical_integrity_bytes(aad),
        )
        encrypted_segments.append(
            {
                "segment_id": segment["segment_id"],
                "segment_index": index,
                "key_id": key_id,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
                "aad_digest": canonical_integrity_hash(aad),
                "ciphertext_digest": sha512(ciphertext).hexdigest(),
            }
        )

    manifest = [segment["segment_id"] for segment in encrypted_segments]
    payload = {
        "schema_id": SCHEMA_ID,
        "external_boundaries": deepcopy(EXTERNAL_BOUNDARIES),
        "envelope_authority": authority_metadata,
        "bindings": bindings,
        "binding_digest": canonical_integrity_hash(bindings),
        "segment_manifest": manifest,
        "segment_manifest_digest": canonical_integrity_hash(
            encrypted_segments
        ),
        "segments": encrypted_segments,
        "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
    }
    try:
        envelope = build_hybrid_signed_object(
            payload,
            provider=attestation_provider,
            purpose=EXCHANGE_SIGNING_PURPOSE,
        )
    except (HybridSignatureError, TypeError, ValueError) as exc:
        raise SegmentedExchangeRejected("EXCHANGE_ENVELOPE_SIGNING_FAILED") from exc
    if not verify_hybrid_signed_object(
        envelope,
        trust_context=attestation_trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=EXCHANGE_SIGNING_PURPOSE,
        require_effect_authority=False,
    ):
        raise SegmentedExchangeRejected("EXCHANGE_SIGNER_NOT_OWNER_PINNED")
    envelope_digest = canonical_integrity_hash(envelope)
    return {
        "result": "SEALED",
        "envelope": envelope,
        "envelope_digest": envelope_digest,
        "audit_digests": {
            "binding_digest": payload["binding_digest"],
            "segment_manifest_digest": payload["segment_manifest_digest"],
            "envelope_digest": envelope_digest,
        },
    }


def _verified_envelope(
    record: Any,
    *,
    authority: ExchangeEnvelopeAuthority | None,
    attestation_provider: ExchangeAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    authority_metadata = _authority_metadata(authority)
    if authority_metadata is None:
        raise SegmentedExchangeRejected("EXCHANGE_AUTHORITY_NOT_INJECTED")
    if not _provider_admitted(attestation_provider):
        raise SegmentedExchangeRejected(
            "EXCHANGE_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        )
    if not _trust_context_owner_pinned(
        attestation_trust_context, owner_pinned_context_digest
    ):
        raise SegmentedExchangeRejected(
            "EXCHANGE_OWNER_PIN_NOT_INJECTED_OR_INVALID"
        )
    if type(record) is not dict or set(record) != _RECORD_FIELDS:
        raise SegmentedExchangeRejected("EXCHANGE_RECORD_SHAPE_INVALID")
    envelope = record.get("envelope")
    if (
        record.get("result") != "SEALED"
        or type(envelope) is not dict
        or set(envelope) != _SIGNED_ENVELOPE_FIELDS
        or envelope.get("verified") is not False
        or envelope.get("schema_id") != SCHEMA_ID
        or envelope.get("external_boundaries") != EXTERNAL_BOUNDARIES
        or envelope.get("envelope_authority") != authority_metadata
        or envelope.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or not verify_hybrid_signed_object(
            envelope,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
            expected_purpose=EXCHANGE_SIGNING_PURPOSE,
            require_effect_authority=False,
        )
    ):
        raise SegmentedExchangeRejected("EXCHANGE_ENVELOPE_ATTESTATION_INVALID")
    envelope_digest = _safe_hash(envelope)
    if envelope_digest is None or record.get("envelope_digest") != envelope_digest:
        raise SegmentedExchangeRejected("EXCHANGE_ENVELOPE_DIGEST_INVALID")
    bindings = envelope.get("bindings")
    segments = envelope.get("segments")
    if (
        type(bindings) is not dict
        or set(bindings) != _BINDING_FIELDS
        or envelope.get("binding_digest") != _safe_hash(bindings)
        or type(segments) is not list
        or not segments
        or envelope.get("segment_manifest_digest") != _safe_hash(segments)
    ):
        raise SegmentedExchangeRejected("EXCHANGE_SIGNED_CONTENT_INVALID")
    expected_audit = {
        "binding_digest": envelope["binding_digest"],
        "segment_manifest_digest": envelope["segment_manifest_digest"],
        "envelope_digest": envelope_digest,
    }
    if record.get("audit_digests") != expected_audit:
        raise SegmentedExchangeRejected("EXCHANGE_AUDIT_DIGEST_INVALID")
    return envelope, bindings


def verify_and_decrypt_segmented_exchange(
    record: dict[str, Any],
    *,
    expected_sender_id: str,
    expected_recipient_id: str,
    expected_jurisdiction: str,
    expected_policy_id: str,
    expected_policy_digest: str,
    authority: ExchangeEnvelopeAuthority | None,
    attestation_provider: ExchangeAttestationProvider | None,
    attestation_trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
    key_resolver: SegmentKeyResolver | None,
    replay_guard: ExchangeReplayGuard | None,
) -> dict[str, Any]:
    """Verify all bindings and AEAD tags, then atomically consume the envelope."""

    if not _resolver_admitted(key_resolver):
        raise SegmentedExchangeRejected("EXCHANGE_KEY_RESOLVER_NOT_INJECTED")
    if replay_guard is None or not callable(getattr(replay_guard, "consume", None)):
        raise SegmentedExchangeRejected("EXCHANGE_REPLAY_GUARD_NOT_INJECTED")
    envelope, bindings = _verified_envelope(
        record,
        authority=authority,
        attestation_provider=attestation_provider,
        attestation_trust_context=attestation_trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    expected_bindings = {
        "sender_id": expected_sender_id,
        "recipient_id": expected_recipient_id,
        "jurisdiction": expected_jurisdiction,
        "policy_id": expected_policy_id,
        "policy_digest": expected_policy_digest,
    }
    if (
        not all(_text(value) for value in expected_bindings.values())
        or not is_sha512(expected_policy_digest)
        or any(bindings.get(field) != value for field, value in expected_bindings.items())
    ):
        raise SegmentedExchangeRejected("EXCHANGE_LIVE_BINDING_MISMATCH")
    if (
        bindings.get("revocation_status") != EXCHANGE_ACTIVE
        or type(bindings.get("revocation_sequence")) is not int
        or bindings["revocation_sequence"] < 0
    ):
        raise SegmentedExchangeRejected("EXCHANGE_AUTHORITY_REVOKED")

    segments = envelope["segments"]
    manifest = envelope.get("segment_manifest")
    if (
        type(manifest) is not list
        or len(manifest) != bindings.get("segment_count")
        or len(segments) != bindings.get("segment_count")
        or manifest != [segment.get("segment_id") for segment in segments]
        or len(set(manifest)) != len(manifest)
    ):
        raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_MANIFEST_INVALID")

    plaintext_segments: list[dict[str, Any]] = []
    seen_nonces: set[bytes] = set()
    for index, segment in enumerate(segments):
        if (
            type(segment) is not dict
            or set(segment) != _SEGMENT_FIELDS
            or segment.get("segment_index") != index
            or segment.get("segment_id") != manifest[index]
            or not _text(segment.get("key_id"))
        ):
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_ORDER_INVALID")
        nonce = _decode_base64(
            segment.get("nonce_b64"), reason="EXCHANGE_SEGMENT_NONCE_INVALID"
        )
        ciphertext = _decode_base64(
            segment.get("ciphertext_b64"),
            reason="EXCHANGE_SEGMENT_CIPHERTEXT_INVALID",
        )
        if len(nonce) != 12 or nonce in seen_nonces:
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_NONCE_INVALID")
        seen_nonces.add(nonce)
        if sha512(ciphertext).hexdigest() != segment.get("ciphertext_digest"):
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_CIPHERTEXT_TAMPER")
        key_id, key = _key_material(
            key_resolver,
            bindings=bindings,
            segment_id=segment["segment_id"],
        )
        if key_id != segment["key_id"]:
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_KEY_ID_MISMATCH")
        aad = _segment_aad(
            bindings,
            segment_id=segment["segment_id"],
            segment_index=index,
            key_id=key_id,
        )
        if canonical_integrity_hash(aad) != segment.get("aad_digest"):
            raise SegmentedExchangeRejected("EXCHANGE_SEGMENT_AAD_TAMPER")
        try:
            plaintext = AESGCM(key).decrypt(
                nonce,
                ciphertext,
                canonical_integrity_bytes(aad),
            )
        except InvalidTag as exc:
            raise SegmentedExchangeRejected(
                "EXCHANGE_SEGMENT_AUTHENTICATION_FAILED"
            ) from exc
        plaintext_segments.append(
            {"segment_id": segment["segment_id"], "plaintext": plaintext}
        )

    authority_metadata = envelope["envelope_authority"]
    revocation_scope = "|".join(
        (
            authority_metadata["authority_id"],
            authority_metadata["authority_credential_id"],
        )
    )
    try:
        consumed = replay_guard.consume(
            exchange_id=bindings["exchange_id"],
            envelope_digest=record["envelope_digest"],
            revocation_scope=revocation_scope,
            revocation_sequence=bindings["revocation_sequence"],
        )
    except Exception as exc:
        raise SegmentedExchangeRejected("EXCHANGE_REPLAY_GUARD_FAILED") from exc
    if consumed is not True:
        raise SegmentedExchangeRejected("EXCHANGE_REPLAY_OR_REVOCATION_ROLLBACK")

    return {
        "result": "DECRYPTED",
        "exchange_id": bindings["exchange_id"],
        "segments": plaintext_segments,
        "audit_digests": deepcopy(record["audit_digests"]),
        "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
    }
