"""Owner-pinned implementation-defined V2 digital-provenance control.

The verifier authenticates one deterministic source-to-runtime lineage. Trust
is rooted in one deployment-supplied, owner-pinned trust context, an
independently signed registry snapshot, separately signed credential
inclusions, immutable measured hybrid public-key contexts, signed clock evidence, an
authenticated live revocation head, and a durable atomic sequence/replay
context.

The private composition root and genuinely durable production storage remain
deployment dependencies. This module verifies their explicit contracts; it
does not claim to create process isolation or durable storage.

Passing authenticates lineage only. It grants no legal truth, semantic truth,
Governance ALLOW, licence, execution/effect authority, or bypass.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha512
from typing import Any, Final, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.hybrid_signature import (
    GENERIC_SIGNING_PURPOSE,
    HYBRID_SUITE_ID,
    PRODUCTION_SIGNER,
    HybridSignatureError,
    HybridVerificationContext,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
)
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    build_legacy_non_effect_signed_object,
)


DIGITAL_PROVENANCE_CONTRACT_ID: Final = "SBP_LEX_DIGITAL_PROVENANCE_V2"
DIGITAL_PROVENANCE_SCHEMA_STATUS: Final = "IMPLEMENTATION_DEFINED_V2_MECHANICS"
DIGITAL_PROVENANCE_PROOF_SCOPE: Final = (
    "LINEAGE_AUTHENTICATION_ONLY_NOT_SUBSTANTIVE_TRUTH_OR_AUTHORITY"
)
OWNER_PIN_SCHEMA: Final = "SBP_LEX_PROVENANCE_OWNER_PIN_V1"
REGISTRY_SNAPSHOT_SCHEMA: Final = "SBP_LEX_PROVENANCE_REGISTRY_SNAPSHOT_V1"
CREDENTIAL_INCLUSION_SCHEMA: Final = "SBP_LEX_PROVENANCE_CREDENTIAL_INCLUSION_V1"
VERIFICATION_RECEIPT_SCHEMA: Final = "SBP_LEX_PROVENANCE_VERIFICATION_RECEIPT_V2"
REVOCATION_HEAD_SCHEMA: Final = "SBP_LEX_PROVENANCE_REVOCATION_HEAD_V1"
DURABLE_TRANSITION_RECEIPT_SCHEMA: Final = (
    "SBP_LEX_PROVENANCE_DURABLE_TRANSITION_RECEIPT_V1"
)
DURABLE_LIVE_HEADS_SCHEMA: Final = "SBP_LEX_PROVENANCE_DURABLE_LIVE_HEADS_V1"
CLOCK_EVIDENCE_SCHEMA: Final = "SBP_LEX_PROVENANCE_CLOCK_EVIDENCE_V1"
PROVENANCE_REGISTRY_AUTHORITY_ROLE: Final = "PROVENANCE_REGISTRY_SNAPSHOT_AUTHORITY"

ACTIVE: Final = "ACTIVE"
REVOKED: Final = "REVOKED"
ADMIT: Final = "ADMIT_LINEAGE_ONLY"
DENY: Final = "DENY"

DURABLE_CLAIMED: Final = "CLAIMED"
DURABLE_ALREADY_CLAIMED: Final = "ALREADY_CLAIMED"
DURABLE_ROLLBACK: Final = "ROLLBACK"
DURABLE_CONFLICT: Final = "CONFLICT"
PRODUCTION_MODE: Final = "PRODUCTION"
TEST_ONLY_MODE: Final = "TEST_ONLY"
_PRODUCTION_DURABLE_STORAGE_CLASSES: Final = {
    "EXTERNAL_TRANSACTIONAL_DURABLE_ATOMIC_STORE",
    "TPM_SEALED_DURABLE_ATOMIC_STORE",
}
_FORBIDDEN_PRODUCTION_STORAGE_TERMS: Final = {
    "TEST", "MEMORY", "MOCK", "STUB", "FIXTURE", "PLACEHOLDER",
    "SELF_ATTESTED",
}

PROVENANCE_GRAPH_SIGNER_ROLE: Final = "PROVENANCE_GRAPH_AUTHORITY"
PROVENANCE_NODE_TYPES: Final = (
    "authoritative_source",
    "extraction_transformation_toolchain",
    "generated_artifact",
    "release_manifest",
    "runtime_measurement",
)
PROVENANCE_NODE_SIGNER_ROLES: Final = {
    "authoritative_source": "AUTHORITATIVE_SOURCE_AUTHORITY",
    "extraction_transformation_toolchain": "TRANSFORMATION_TOOLCHAIN_AUTHORITY",
    "generated_artifact": "ARTIFACT_BUILD_AUTHORITY",
    "release_manifest": "RELEASE_MANIFEST_AUTHORITY",
    "runtime_measurement": "RUNTIME_MEASUREMENT_AUTHORITY",
}
PROVENANCE_EDGE_RELATIONS: Final = (
    "SOURCE_TRANSFORMED_BY",
    "TRANSFORMATION_GENERATED",
    "ARTIFACT_DECLARED_IN_RELEASE",
    "RELEASE_MEASURED_AT_RUNTIME",
)
REQUIRED_SIGNER_ROLES: Final = (
    PROVENANCE_GRAPH_SIGNER_ROLE,
    *(PROVENANCE_NODE_SIGNER_ROLES[kind] for kind in PROVENANCE_NODE_TYPES),
)
NO_AUTHORIZATION_EFFECT: Final = {
    "legal_truth_proven": False,
    "semantic_correctness_proven": False,
    "governance_allow_granted": False,
    "licence_granted": False,
    "execution_authority_granted": False,
    "effect_authority_granted": False,
    "pipeline_bypass_permitted": False,
}

_SIGNED_RESERVED_FIELDS: Final = {"digest", "signature", "verified"}
_OWNER_PIN_FIELDS: Final = {
    "schema_id", "pin_id", "registry_id", "registry_context",
    "authority_role", "authority_credential_id", "provider_id", "algorithm",
    "key_id", "public_key_fingerprint", "custody_class", "effect_authority",
}
_REGISTRY_SNAPSHOT_FIELDS: Final = {
    "schema_id", "registry_id", "registry_version", "registry_context",
    "snapshot_sequence", "prior_snapshot_digest", "issued_at", "effective_from",
    "effective_until", "status", "revocation_sequence", "owner_pin_digest",
    "authority_role", "authority_credential_id", "credential_inclusions",
    "inclusion_set_digest", "authorization_effect", "digest", "signature", "verified",
}
_CREDENTIAL_INCLUSION_FIELDS: Final = {
    "schema_id", "registry_id", "registry_version", "registry_context",
    "snapshot_sequence", "inclusion_sequence", "credential_id",
    "credential_digest", "signer_role", "status", "effective_from",
    "effective_until", "revocation_status", "revocation_sequence", "provider_id",
    "algorithm", "key_id", "public_key_fingerprint", "custody_class",
    "effect_authority", "authorization_effect", "digest", "signature", "verified",
}
_GRAPH_FIELDS: Final = {
    "contract_id", "schema_status", "proof_scope", "graph_id", "graph_version",
    "request_fingerprint", "evaluation_time", "sequence", "revocation_status",
    "revocation_sequence", "prior_provenance_digest", "owner_pin_digest",
    "registry_id", "registry_version", "registry_context", "registry_snapshot_digest",
    "signer_role", "authority_credential_id", "authority_credential_digest",
    "credential_inclusion_digest", "declared_transformation_ids", "nodes", "edges",
    "release_manifest_digest", "runtime_measurement_digest", "lineage_only",
    *NO_AUTHORIZATION_EFFECT, "digest", "signature", "verified",
}
_NODE_FIELDS: Final = {
    "node_id", "node_type", "content_digest", "recorded_at", "effective_from",
    "effective_until", "effective_status", "sequence", "revocation_status",
    "revocation_sequence", "signer_role", "authority_credential_id",
    "authority_credential_digest", "credential_inclusion_digest", "attributes",
    "digest", "signature", "verified",
}
_EDGE_FIELDS: Final = {
    "edge_id", "sequence", "from_node_id", "to_node_id", "relation",
    "from_content_digest", "to_content_digest",
}
_ATTRIBUTE_FIELDS: Final = {
    "authoritative_source": {
        "source_authority_id", "source_authority_credential_digest",
        "source_uri", "source_version",
    },
    "extraction_transformation_toolchain": {
        "transformation_id", "tool_id", "tool_version", "tool_digest",
        "config_digest", "dependency_digests", "declared_input_digest",
        "declared_output_digest",
    },
    "generated_artifact": {"artifact_id", "artifact_version", "derivation_digest"},
    "release_manifest": {
        "release_id", "release_version", "release_manifest_digest",
        "artifact_content_digest",
    },
    "runtime_measurement": {
        "runtime_id", "runtime_environment_digest", "release_manifest_digest",
        "runtime_measurement_digest",
    },
}
_DURABLE_CLAIM_FIELDS: Final = {
    "contract_id", "stream_id", "registry_context", "owner_pin_digest",
    "request_fingerprint", "graph_id", "graph_digest", "provenance_sequence",
    "prior_provenance_digest", "provenance_revocation_sequence",
    "registry_snapshot_digest", "registry_snapshot_sequence",
    "prior_registry_snapshot_digest", "registry_revocation_sequence",
    "evaluation_time", "release_manifest_digest", "runtime_measurement_digest",
    "current_revocation_head_digest",
    "current_clock_evidence_digest",
}
_CLOCK_EVIDENCE_FIELDS: Final = {
    "schema_id", "context_id", "clock_id", "clock_sequence",
    "observed_at", "status", "authorization_effect", "digest", "signature",
    "verified",
}
_REVOCATION_HEAD_FIELDS: Final = {
    "schema_id", "registry_id", "registry_context", "snapshot_digest",
    "snapshot_sequence", "revocation_sequence", "observed_at",
    "owner_pin_digest", "authority_role", "authority_credential_id",
    "authorization_effect", "digest", "signature", "verified",
}
_HEAD_FIELDS: Final = {"sequence", "digest", "revocation_sequence"}
_DURABLE_TRANSITION_FIELDS: Final = {
    "schema_id", "context_id", "claim_digest", "result",
    "transition_sequence", "previous_state_digest", "state_digest",
    "stream_id", "previous_stream_head", "current_stream_head",
    "previous_registry_head", "current_registry_head", "evaluation_time",
    "revocation_head_digest", "authorization_effect", "digest", "signature",
    "verified",
}
_DURABLE_LIVE_HEADS_FIELDS: Final = {
    "schema_id", "context_id", "transition_sequence", "state_digest",
    "stream_id", "stream_head", "registry_head", "last_evaluation_time",
    "revocation_head_digest", "queried_claim_digest", "is_claimed",
    "authorization_effect", "digest", "signature", "verified",
}
_VERIFICATION_RECEIPT_FIELDS: Final = {
    "schema_id", "contract_id", "schema_status", "proof_scope", "result",
    "reason", "evaluation_time", "request_fingerprint", "graph_id",
    "graph_digest", "provenance_sequence", "prior_provenance_digest",
    "provenance_revocation_sequence", "registry_snapshot_digest",
    "release_manifest_digest", "runtime_measurement_digest",
    "owner_pin_digest", "registry_context", "registry_snapshot_sequence",
    "registry_revocation_sequence", "clock_id", "durable_context_id",
    "durable_claim_result", "durable_claim_digest",
    "durable_transition_receipt_digest", "durable_live_heads_digest",
    "revocation_head_digest", "deployment_trust_context_id", "trace_digest",
    "clock_evidence_digest", "deployment_mode",
    "production_durable_storage_proven_by_module",
    "lineage_authenticated", "lineage_only", *NO_AUTHORIZATION_EFFECT,
    "digest", "signature", "verified",
}


class ProvenanceAttestationProvider(SignatureProvider, Protocol):
    provenance_attestation_admitted: bool
    public_key: Ed25519PublicKey


class ProvenanceRegistryAuthorityProvider(SignatureProvider, Protocol):
    provenance_registry_attestation_admitted: bool
    public_key: Ed25519PublicKey


class ProvenanceProviderResolver(Protocol):
    provider_resolution_admitted: bool
    resolver_id: str
    registry_context: str

    def resolve_provider(
        self, *, credential_id: str, signer_role: str
    ) -> ProvenanceAttestationProvider | None: ...


class ProvenanceTrustedClock(SignatureProvider, Protocol):
    trusted_clock_admitted: bool
    trusted_clock_attestation_admitted: bool
    clock_id: str
    public_key: Ed25519PublicKey

    def current_time_evidence(self, *, context_id: str) -> dict[str, Any]: ...


class ProvenanceRevocationHeadSource(Protocol):
    revocation_head_source_admitted: bool
    source_id: str
    registry_context: str

    def current_revocation_head(
        self, *, registry_id: str, registry_context: str
    ) -> dict[str, Any]: ...


class DurableProvenanceContext(Protocol):
    durable_atomic_claim_admitted: bool
    production_durable_storage_admitted: bool
    durable_storage_class: str
    durable_storage_external_attestation_admitted: bool
    durable_transition_attestation_admitted: bool
    context_id: str
    public_key: Ed25519PublicKey

    def claim_next(
        self, *, claim: dict[str, Any], revocation_head_digest: str
    ) -> dict[str, Any]: ...

    def read_live_heads(
        self, *, stream_id: str, claim_digest: str
    ) -> dict[str, Any]: ...

    def is_claimed(self, *, claim_digest: str) -> bool: ...


class ProvenanceVerificationReceiptProvider(SignatureProvider, Protocol):
    provenance_verification_receipt_admitted: bool
    public_key: Ed25519PublicKey


@dataclass(frozen=True, slots=True)
class _PinnedEd25519Binding:
    provider_id: str
    algorithm: str
    key_id: str
    custody_class: str
    effect_authority: bool
    public_key_bytes: bytes
    public_key_fingerprint: str
    hybrid_context: HybridVerificationContext | None = None
    legacy_non_effect_only: bool = False

    @property
    def public_key(self) -> Ed25519PublicKey:
        if self.algorithm != "Ed25519" or self.legacy_non_effect_only is not True:
            raise ValueError("PROVENANCE_LEGACY_PUBLIC_KEY_NOT_ADMITTED")
        return Ed25519PublicKey.from_public_bytes(self.public_key_bytes)


@dataclass(frozen=True, slots=True)
class ProvenanceDeploymentTrustContext:
    """One fixed trust bundle supplied by a private deployment composition root."""

    context_id: str
    registry_context: str
    _owner_pin_bytes: bytes
    registry_authority_provider: ProvenanceRegistryAuthorityProvider
    provider_resolver: ProvenanceProviderResolver
    trusted_clock: ProvenanceTrustedClock
    revocation_head_source: ProvenanceRevocationHeadSource
    durable_context: DurableProvenanceContext
    verification_receipt_provider: ProvenanceVerificationReceiptProvider
    registry_authority_binding: _PinnedEd25519Binding
    durable_context_binding: _PinnedEd25519Binding
    verification_receipt_binding: _PinnedEd25519Binding
    trusted_clock_binding: _PinnedEd25519Binding
    deployment_mode: str = PRODUCTION_MODE
    private_composition_root_required: bool = True
    production_durable_storage_required: bool = True

    @property
    def owner_pin(self) -> dict[str, Any]:
        return json.loads(self._owner_pin_bytes.decode("utf-8"))

    @classmethod
    def create(
        cls,
        *,
        context_id: str,
        registry_context: str,
        owner_pin: dict[str, Any],
        registry_authority_provider: ProvenanceRegistryAuthorityProvider,
        provider_resolver: ProvenanceProviderResolver,
        trusted_clock: ProvenanceTrustedClock,
        revocation_head_source: ProvenanceRevocationHeadSource,
        durable_context: DurableProvenanceContext,
        verification_receipt_provider: ProvenanceVerificationReceiptProvider,
        test_only: bool = False,
    ) -> "ProvenanceDeploymentTrustContext":
        registry_binding = _extract_provider_binding(
            registry_authority_provider,
            allow_legacy_non_effect=True,
        )
        durable_binding = _extract_provider_binding(
            durable_context,
            allow_legacy_non_effect=True,
        )
        receipt_binding = _extract_provider_binding(
            verification_receipt_provider,
            allow_legacy_non_effect=True,
        )
        clock_binding = _extract_provider_binding(
            trusted_clock,
            allow_legacy_non_effect=True,
        )
        if (
            not _text(context_id)
            or not _text(registry_context)
            or type(owner_pin) is not dict
            or registry_binding is None
            or durable_binding is None
            or receipt_binding is None
            or clock_binding is None
        ):
            raise ValueError("PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID")
        return cls(
            context_id=context_id,
            registry_context=registry_context,
            _owner_pin_bytes=canonical_json_bytes(owner_pin),
            registry_authority_provider=registry_authority_provider,
            provider_resolver=provider_resolver,
            trusted_clock=trusted_clock,
            revocation_head_source=revocation_head_source,
            durable_context=durable_context,
            verification_receipt_provider=verification_receipt_provider,
            registry_authority_binding=registry_binding,
            durable_context_binding=durable_binding,
            verification_receipt_binding=receipt_binding,
            trusted_clock_binding=clock_binding,
            deployment_mode=TEST_ONLY_MODE if test_only else PRODUCTION_MODE,
        )


@dataclass(frozen=True, slots=True)
class ProvenanceCredentialAdmission:
    credential_id: str
    credential_digest: str
    credential_inclusion_digest: str
    signer_role: str
    status: str
    effective_from: int
    effective_until: int
    revocation_status: str
    revocation_sequence: int
    provider_public_key_fingerprint: str
    provider_binding: _PinnedEd25519Binding


@dataclass(frozen=True, slots=True)
class ProvenanceDecision:
    result: str
    reason: str
    provenance_digest: str | None
    lineage_authenticated: bool
    verification_trace: tuple[dict[str, Any], ...]
    verification_receipt: dict[str, Any]
    lineage_only: bool = True
    legal_truth_proven: bool = False
    semantic_correctness_proven: bool = False
    governance_allow_granted: bool = False
    licence_granted: bool = False
    execution_authority_granted: bool = False
    effect_authority_granted: bool = False
    pipeline_bypass_permitted: bool = False
    production_durable_storage_proven_by_module: bool = False

    @property
    def admitted(self) -> bool:
        return self.result == ADMIT and self.lineage_authenticated

    @property
    def verification_receipt_digest(self) -> str:
        return self.verification_receipt["digest"]


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError, OverflowError, RecursionError):
        return None
    except Exception:
        return None


def _safe_getattr(value: Any, name: str) -> Any:
    try:
        return getattr(value, name, None)
    except Exception:
        return None


def _public_key(provider: Any) -> Ed25519PublicKey | None:
    key = _safe_getattr(provider, "public_key")
    if callable(key):
        try:
            key = key()
        except Exception:
            return None
    return key if isinstance(key, Ed25519PublicKey) else None


def _public_key_bytes(provider: Any) -> bytes | None:
    key = _public_key(provider)
    if key is None:
        return None
    try:
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception:
        return None


def _extract_provider_binding(
    provider: Any,
    *,
    allow_legacy_non_effect: bool = False,
) -> _PinnedEd25519Binding | None:
    if is_hybrid_provider(provider):
        try:
            context = provider.hybrid_verification_context(
                allow_test_only=allow_legacy_non_effect
            )
            provider_id = _safe_getattr(provider, "provider_id")
            key_id = _safe_getattr(provider, "key_id")
            custody_class = _safe_getattr(provider, "custody_class")
            if (
                not isinstance(context, HybridVerificationContext)
                or context.provider_id != provider_id
                or context.ordered_key_set_digest != key_id
                or context.custody_class != custody_class
                or context.effect_authority is not False
                or _safe_getattr(provider, "effect_authority") is not False
            ):
                return None
            public_record_bytes = canonical_json_bytes(context.public_record())
            return _PinnedEd25519Binding(
                provider_id=context.provider_id,
                algorithm=HYBRID_SUITE_ID,
                key_id=context.ordered_key_set_digest,
                custody_class=context.custody_class,
                effect_authority=False,
                public_key_bytes=public_record_bytes,
                public_key_fingerprint=context.context_digest,
                hybrid_context=context,
                legacy_non_effect_only=False,
            )
        except (HybridSignatureError, TypeError, ValueError):
            return None
        except Exception:
            return None

    if not allow_legacy_non_effect:
        return None
    raw = _public_key_bytes(provider)
    fingerprint = sha512(raw).hexdigest() if raw is not None else None
    provider_id = _safe_getattr(provider, "provider_id")
    algorithm = _safe_getattr(provider, "algorithm")
    key_id = _safe_getattr(provider, "key_id")
    custody_class = _safe_getattr(provider, "custody_class")
    effect_authority = _safe_getattr(provider, "effect_authority")
    if (
        raw is None
        or not all(_text(value) for value in (
            provider_id, algorithm, key_id, fingerprint, custody_class,
        ))
        or algorithm != "Ed25519"
        or key_id != fingerprint
        or effect_authority is not False
    ):
        return None
    return _PinnedEd25519Binding(
        provider_id=provider_id,
        algorithm=algorithm,
        key_id=key_id,
        custody_class=custody_class,
        effect_authority=False,
        public_key_bytes=raw,
        public_key_fingerprint=fingerprint,
        hybrid_context=None,
        legacy_non_effect_only=True,
    )


def _independent_signature_valid(
    obj: Any, binding: _PinnedEd25519Binding | None
) -> bool:
    """Verify only with immutable public material measured once."""

    if type(obj) is not dict or obj.get("verified") is not False or binding is None:
        return False
    if binding.algorithm == HYBRID_SUITE_ID:
        if binding.hybrid_context is None or binding.legacy_non_effect_only:
            return False
        try:
            return verify_hybrid_signed_object(
                obj,
                trust_context=binding.hybrid_context,
                owner_pinned_context_digest=binding.public_key_fingerprint,
                expected_purpose=GENERIC_SIGNING_PURPOSE,
                require_effect_authority=False,
            )
        except (HybridSignatureError, TypeError, ValueError):
            return False
        except Exception:
            return False
    if binding.algorithm != "Ed25519" or binding.legacy_non_effect_only is not True:
        return False
    signature = obj.get("signature")
    if type(signature) is not dict or set(signature) != {
        "provider_id", "algorithm", "key_id", "custody_class",
        "effect_authority", "signature_b64",
    }:
        return False
    expected_metadata = {
        "provider_id": binding.provider_id,
        "algorithm": binding.algorithm,
        "key_id": binding.key_id,
        "custody_class": binding.custody_class,
        "effect_authority": binding.effect_authority,
    }
    if any(signature.get(field) != expected for field, expected in expected_metadata.items()):
        return False
    payload = {k: v for k, v in obj.items() if k not in _SIGNED_RESERVED_FIELDS}
    try:
        payload_bytes = canonical_json_bytes(payload)
        expected_digest = sha512(payload_bytes).hexdigest()
        encoded = signature.get("signature_b64")
        if (
            not is_sha512(obj.get("digest"))
            or not hmac.compare_digest(obj["digest"], expected_digest)
            or not _text(encoded)
        ):
            return False
        binding.public_key.verify(
            base64.b64decode(encoded, validate=True), payload_bytes
        )
    except (InvalidSignature, binascii.Error, TypeError, ValueError):
        return False
    except Exception:
        return False
    return True


def _append_trace(
    trace: list[dict[str, Any]], *, stage: str, result: str, evidence: dict[str, Any]
) -> None:
    evidence_digest = _safe_hash(evidence)
    if evidence_digest is None:
        evidence_digest = canonical_integrity_hash(
            {"indeterminate_evidence": True, "stage": stage}
        )
    entry = {
        "sequence": len(trace) + 1,
        "stage": stage,
        "result": result,
        "evidence_digest": evidence_digest,
        "prior_trace_digest": trace[-1]["trace_digest"] if trace else GENESIS_HASH,
    }
    entry["trace_digest"] = canonical_integrity_hash(entry)
    trace.append(entry)


def _receipt_context(graph: Any) -> dict[str, Any]:
    source = graph if type(graph) is dict else {}
    def scalar(name: str) -> Any:
        value = source.get(name)
        return value if type(value) in (str, int, bool) or value is None else None

    return {
        "request_fingerprint": scalar("request_fingerprint"),
        "graph_id": scalar("graph_id"),
        "graph_digest": scalar("digest"),
        "provenance_sequence": scalar("sequence"),
        "prior_provenance_digest": scalar("prior_provenance_digest"),
        "provenance_revocation_sequence": scalar("revocation_sequence"),
        "registry_snapshot_digest": scalar("registry_snapshot_digest"),
        "release_manifest_digest": scalar("release_manifest_digest"),
        "runtime_measurement_digest": scalar("runtime_measurement_digest"),
    }


def _finish(
    *,
    result: str,
    reason: str,
    graph: Any,
    trace: list[dict[str, Any]],
    evaluation_time: int | None,
    owner_pin_digest: str | None,
    registry_context: str | None,
    registry_snapshot: Any,
    clock_id: str | None,
    durable_context_id: str | None,
    durable_claim_result: str | None,
    durable_claim_digest: str | None,
    durable_transition_receipt_digest: str | None,
    durable_live_heads_digest: str | None,
    revocation_head_digest: str | None,
    clock_evidence_digest: str | None,
    trust_context: ProvenanceDeploymentTrustContext | None,
) -> ProvenanceDecision:
    authenticated = result == ADMIT
    _append_trace(
        trace,
        stage="terminal",
        result=result,
        evidence={
            "reason": reason,
            "lineage_authenticated": authenticated,
            **NO_AUTHORIZATION_EFFECT,
        },
    )
    snapshot = registry_snapshot if type(registry_snapshot) is dict else {}
    snapshot_sequence = snapshot.get("snapshot_sequence")
    registry_revocation_sequence = snapshot.get("revocation_sequence")
    if type(snapshot_sequence) is not int:
        snapshot_sequence = None
    if type(registry_revocation_sequence) is not int:
        registry_revocation_sequence = None
    receipt_payload = {
        "schema_id": VERIFICATION_RECEIPT_SCHEMA,
        "contract_id": DIGITAL_PROVENANCE_CONTRACT_ID,
        "schema_status": DIGITAL_PROVENANCE_SCHEMA_STATUS,
        "proof_scope": DIGITAL_PROVENANCE_PROOF_SCOPE,
        "result": result,
        "reason": reason,
        "evaluation_time": evaluation_time,
        **_receipt_context(graph),
        "owner_pin_digest": owner_pin_digest,
        "registry_context": registry_context,
        "registry_snapshot_sequence": snapshot_sequence,
        "registry_revocation_sequence": registry_revocation_sequence,
        "clock_id": clock_id,
        "durable_context_id": durable_context_id,
        "durable_claim_result": durable_claim_result,
        "durable_claim_digest": durable_claim_digest,
        "durable_transition_receipt_digest": durable_transition_receipt_digest,
        "durable_live_heads_digest": durable_live_heads_digest,
        "revocation_head_digest": revocation_head_digest,
        "clock_evidence_digest": clock_evidence_digest,
        "deployment_mode": (
            trust_context.deployment_mode
            if isinstance(trust_context, ProvenanceDeploymentTrustContext)
            and trust_context.deployment_mode in (PRODUCTION_MODE, TEST_ONLY_MODE)
            else None
        ),
        "deployment_trust_context_id": (
            trust_context.context_id
            if isinstance(trust_context, ProvenanceDeploymentTrustContext)
            and _text(trust_context.context_id)
            else None
        ),
        "production_durable_storage_proven_by_module": False,
        "trace_digest": _safe_hash(trace),
        "lineage_authenticated": authenticated,
        "lineage_only": True,
        **NO_AUTHORIZATION_EFFECT,
    }
    receipt: dict[str, Any]
    receipt_authenticated = False
    if isinstance(trust_context, ProvenanceDeploymentTrustContext):
        try:
            receipt = build_legacy_non_effect_signed_object(
                receipt_payload,
                provider=trust_context.verification_receipt_provider,
            )
            receipt_authenticated = _independent_signature_valid(
                receipt, trust_context.verification_receipt_binding
            )
        except Exception:
            receipt = {}
    else:
        receipt = {}
    if not receipt_authenticated:
        result = DENY
        reason = "PROVENANCE_VERIFICATION_RECEIPT_NOT_AUTHENTICATED"
        authenticated = False
        unsigned_payload = {
            **receipt_payload,
            "result": DENY,
            "reason": reason,
            "lineage_authenticated": False,
        }
        receipt = {
            **unsigned_payload,
            "digest": canonical_integrity_hash(unsigned_payload),
            "signature": None,
            "verified": False,
        }
    return ProvenanceDecision(
        result=result,
        reason=reason,
        provenance_digest=(graph.get("digest") if authenticated else None),
        lineage_authenticated=authenticated,
        verification_trace=tuple(deepcopy(trace)),
        verification_receipt=receipt,
    )


def verify_provenance_verification_receipt(
    receipt: Any,
    *,
    trust_context: ProvenanceDeploymentTrustContext,
) -> bool:
    """Independently verify a terminal receipt against the fixed receipt key."""

    try:
        return (
            isinstance(trust_context, ProvenanceDeploymentTrustContext)
            and type(receipt) is dict
            and set(receipt) == _VERIFICATION_RECEIPT_FIELDS
            and _deployment_context_error(trust_context) is None
            and receipt.get("schema_id") == VERIFICATION_RECEIPT_SCHEMA
            and receipt.get("contract_id") == DIGITAL_PROVENANCE_CONTRACT_ID
            and receipt.get("schema_status") == DIGITAL_PROVENANCE_SCHEMA_STATUS
            and receipt.get("proof_scope") == DIGITAL_PROVENANCE_PROOF_SCOPE
            and receipt.get("deployment_trust_context_id") == trust_context.context_id
            and receipt.get("deployment_mode") == trust_context.deployment_mode
            and receipt.get("owner_pin_digest")
            == _safe_hash(trust_context.owner_pin)
            and receipt.get("registry_context") == trust_context.registry_context
            and receipt.get("clock_id")
            == _safe_getattr(trust_context.trusted_clock, "clock_id")
            and receipt.get("durable_context_id")
            == _safe_getattr(trust_context.durable_context, "context_id")
            and receipt.get("lineage_authenticated")
            is (receipt.get("result") == ADMIT)
            and receipt.get("lineage_only") is True
            and receipt.get("production_durable_storage_proven_by_module") is False
            and all(
                receipt.get(field) is expected
                for field, expected in NO_AUTHORIZATION_EFFECT.items()
            )
            and _independent_signature_valid(
                receipt, trust_context.verification_receipt_binding
            )
        )
    except Exception:
        return False


def _owner_pin_error(
    pin: Any,
    *,
    expected_context: str,
    authority_provider: ProvenanceRegistryAuthorityProvider | None,
    authority_binding: _PinnedEd25519Binding | None,
) -> str | None:
    if type(pin) is not dict or set(pin) != _OWNER_PIN_FIELDS:
        return "PROVENANCE_OWNER_PIN_SHAPE_INVALID"
    required = (
        "pin_id", "registry_id", "registry_context", "authority_credential_id",
    )
    if (
        pin.get("schema_id") != OWNER_PIN_SCHEMA
        or not all(_text(pin.get(field)) for field in required)
        or pin.get("registry_context") != expected_context
        or pin.get("authority_role") != PROVENANCE_REGISTRY_AUTHORITY_ROLE
        or pin.get("effect_authority") is not False
    ):
        return "PROVENANCE_OWNER_PIN_INVALID"
    if authority_provider is None:
        return "PROVENANCE_REGISTRY_AUTHORITY_NOT_INJECTED"
    if (
        _safe_getattr(authority_provider, "provenance_registry_attestation_admitted")
        is not True
        or _safe_getattr(authority_provider, "effect_authority") is not False
    ):
        return "PROVENANCE_REGISTRY_AUTHORITY_NOT_ADMITTED"
    if authority_binding is None:
        return "PROVENANCE_OWNER_PIN_PROVIDER_MISMATCH"
    expected_binding = {
        "provider_id": authority_binding.provider_id,
        "algorithm": authority_binding.algorithm,
        "key_id": authority_binding.key_id,
        "public_key_fingerprint": authority_binding.public_key_fingerprint,
        "custody_class": authority_binding.custody_class,
        "effect_authority": authority_binding.effect_authority,
    }
    if any(pin.get(k) != v for k, v in expected_binding.items()):
        return "PROVENANCE_OWNER_PIN_PROVIDER_MISMATCH"
    return None


def _credential_digest(inclusion: dict[str, Any]) -> str | None:
    return _safe_hash(
        {
            field: inclusion[field]
            for field in (
                "credential_id", "signer_role", "status", "effective_from",
                "effective_until", "revocation_status", "revocation_sequence",
                "provider_id", "algorithm", "key_id", "public_key_fingerprint",
                "custody_class", "effect_authority",
            )
        }
    )


def _resolver_exact(resolver: Any, expected_context: str) -> bool:
    return (
        resolver is not None
        and _safe_getattr(resolver, "provider_resolution_admitted") is True
        and _text(_safe_getattr(resolver, "resolver_id"))
        and _safe_getattr(resolver, "registry_context") == expected_context
        and callable(_safe_getattr(resolver, "resolve_provider"))
    )


def _inclusion_admission(
    inclusion: Any,
    *,
    expected_role: str,
    expected_sequence: int,
    snapshot: dict[str, Any],
    evaluation_time: int,
    authority_binding: _PinnedEd25519Binding,
    resolver: ProvenanceProviderResolver,
) -> tuple[ProvenanceCredentialAdmission | None, str | None]:
    if type(inclusion) is not dict or set(inclusion) != _CREDENTIAL_INCLUSION_FIELDS:
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_SHAPE_INVALID"
    expected = {
        "schema_id": CREDENTIAL_INCLUSION_SCHEMA,
        "registry_id": snapshot["registry_id"],
        "registry_version": snapshot["registry_version"],
        "registry_context": snapshot["registry_context"],
        "snapshot_sequence": snapshot["snapshot_sequence"],
        "inclusion_sequence": expected_sequence,
        "signer_role": expected_role,
    }
    if any(inclusion.get(k) != v for k, v in expected.items()):
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_BINDING_INVALID"
    if (
        not _text(inclusion.get("credential_id"))
        or not all(
            _text(inclusion.get(field))
            for field in (
                "provider_id", "algorithm", "key_id", "custody_class",
            )
        )
        or inclusion.get("algorithm") != authority_binding.algorithm
        or inclusion.get("status") != ACTIVE
        or not _nonnegative_int(inclusion.get("effective_from"))
        or not _positive_int(inclusion.get("effective_until"))
        or not inclusion["effective_from"] <= evaluation_time < inclusion["effective_until"]
        or inclusion.get("revocation_status") != ACTIVE
        or not _nonnegative_int(inclusion.get("revocation_sequence"))
        or inclusion.get("effect_authority") is not False
        or inclusion.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or not is_sha512(inclusion.get("public_key_fingerprint"))
        or not is_sha512(inclusion.get("credential_digest"))
        or inclusion["credential_digest"] != _credential_digest(inclusion)
    ):
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_INACTIVE_OR_INVALID"
    if not _independent_signature_valid(inclusion, authority_binding):
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_SIGNATURE_INVALID"
    try:
        provider = resolver.resolve_provider(
            credential_id=inclusion["credential_id"], signer_role=expected_role
        )
    except Exception:
        return None, "PROVENANCE_PROVIDER_RESOLUTION_INDETERMINATE"
    if provider is None:
        return None, "PROVENANCE_PROVIDER_NOT_RESOLVED"
    if (
        _safe_getattr(provider, "provenance_attestation_admitted") is not True
        or _safe_getattr(provider, "effect_authority") is not False
    ):
        return None, "PROVENANCE_PROVIDER_NOT_ADMITTED"
    binding = _extract_provider_binding(
        provider,
        allow_legacy_non_effect=(
            authority_binding.algorithm == "Ed25519"
            and authority_binding.legacy_non_effect_only is True
        ),
    )
    expected_binding = None if binding is None else {
        "provider_id": binding.provider_id,
        "algorithm": binding.algorithm,
        "key_id": binding.key_id,
        "public_key_fingerprint": binding.public_key_fingerprint,
        "custody_class": binding.custody_class,
        "effect_authority": binding.effect_authority,
    }
    if expected_binding is None or any(
        inclusion.get(k) != value for k, value in expected_binding.items()
    ):
        return None, "PROVENANCE_PROVIDER_PUBLIC_KEY_MISMATCH"
    return ProvenanceCredentialAdmission(
        credential_id=inclusion["credential_id"],
        credential_digest=inclusion["credential_digest"],
        credential_inclusion_digest=inclusion["digest"],
        signer_role=expected_role,
        status=inclusion["status"],
        effective_from=inclusion["effective_from"],
        effective_until=inclusion["effective_until"],
        revocation_status=inclusion["revocation_status"],
        revocation_sequence=inclusion["revocation_sequence"],
        provider_public_key_fingerprint=inclusion["public_key_fingerprint"],
        provider_binding=binding,
    ), None


def _snapshot_admissions(
    snapshot: Any,
    *,
    pin: dict[str, Any],
    pin_digest: str,
    expected_context: str,
    evaluation_time: int,
    authority_binding: _PinnedEd25519Binding,
    resolver: ProvenanceProviderResolver,
) -> tuple[dict[str, ProvenanceCredentialAdmission] | None, str | None]:
    if type(snapshot) is not dict or set(snapshot) != _REGISTRY_SNAPSHOT_FIELDS:
        return None, "PROVENANCE_REGISTRY_SNAPSHOT_SHAPE_INVALID"
    if (
        snapshot.get("schema_id") != REGISTRY_SNAPSHOT_SCHEMA
        or snapshot.get("registry_id") != pin["registry_id"]
        or not _text(snapshot.get("registry_version"))
        or snapshot.get("registry_context") != expected_context
        or not _positive_int(snapshot.get("snapshot_sequence"))
        or not _nonnegative_int(snapshot.get("issued_at"))
        or not _nonnegative_int(snapshot.get("effective_from"))
        or not _positive_int(snapshot.get("effective_until"))
        or not snapshot["issued_at"] <= evaluation_time
        or not snapshot["effective_from"] <= evaluation_time < snapshot["effective_until"]
        or snapshot.get("status") != ACTIVE
        or not _nonnegative_int(snapshot.get("revocation_sequence"))
        or snapshot.get("owner_pin_digest") != pin_digest
        or snapshot.get("authority_role") != PROVENANCE_REGISTRY_AUTHORITY_ROLE
        or snapshot.get("authority_credential_id") != pin["authority_credential_id"]
        or snapshot.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
    ):
        return None, "PROVENANCE_REGISTRY_SNAPSHOT_INVALID"
    prior = snapshot.get("prior_snapshot_digest")
    if (
        (snapshot["snapshot_sequence"] == 1 and prior != GENESIS_HASH)
        or (snapshot["snapshot_sequence"] > 1 and not is_sha512(prior))
    ):
        return None, "PROVENANCE_REGISTRY_SNAPSHOT_PRIOR_INVALID"
    if not _independent_signature_valid(snapshot, authority_binding):
        return None, "PROVENANCE_REGISTRY_SNAPSHOT_SIGNATURE_INVALID"
    inclusions = snapshot.get("credential_inclusions")
    if type(inclusions) is not list or len(inclusions) != len(REQUIRED_SIGNER_ROLES):
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_SET_INVALID"
    inclusion_digests = [
        item.get("digest") if type(item) is dict else None for item in inclusions
    ]
    if snapshot.get("inclusion_set_digest") != _safe_hash(inclusion_digests):
        return None, "PROVENANCE_CREDENTIAL_INCLUSION_SET_DIGEST_INVALID"
    admissions: dict[str, ProvenanceCredentialAdmission] = {}
    ids: set[str] = set()
    digests: set[str] = set()
    for sequence, role in enumerate(REQUIRED_SIGNER_ROLES, start=1):
        admission, error = _inclusion_admission(
            inclusions[sequence - 1],
            expected_role=role,
            expected_sequence=sequence,
            snapshot=snapshot,
            evaluation_time=evaluation_time,
            authority_binding=authority_binding,
            resolver=resolver,
        )
        if error is not None or admission is None:
            return None, error or "PROVENANCE_CREDENTIAL_INCLUSION_INVALID"
        if admission.credential_id in ids or admission.credential_inclusion_digest in digests:
            return None, "PROVENANCE_CREDENTIAL_INCLUSION_DUPLICATE"
        ids.add(admission.credential_id)
        digests.add(admission.credential_inclusion_digest)
        admissions[role] = admission
    if snapshot["revocation_sequence"] < max(
        admission.revocation_sequence for admission in admissions.values()
    ):
        return None, "PROVENANCE_REGISTRY_REVOCATION_HEAD_INVALID"
    return admissions, None


def _attributes_error(node_type: str, attributes: Any) -> str | None:
    expected = _ATTRIBUTE_FIELDS[node_type]
    if type(attributes) is not dict or set(attributes) != expected:
        return "PROVENANCE_NODE_ATTRIBUTES_INVALID"
    if node_type == "authoritative_source":
        if not all(
            _text(attributes.get(field))
            for field in ("source_authority_id", "source_uri", "source_version")
        ) or not is_sha512(attributes.get("source_authority_credential_digest")):
            return "PROVENANCE_SOURCE_ATTRIBUTES_INVALID"
        return None
    if node_type == "extraction_transformation_toolchain":
        if not all(
            _text(attributes.get(field))
            for field in ("transformation_id", "tool_id", "tool_version")
        ):
            return "PROVENANCE_TRANSFORMATION_ATTRIBUTES_INVALID"
        digest_fields = (
            "tool_digest", "config_digest", "declared_input_digest", "declared_output_digest",
        )
        if any(not is_sha512(attributes.get(field)) for field in digest_fields):
            return "PROVENANCE_TRANSFORMATION_DIGEST_INVALID"
        dependencies = attributes.get("dependency_digests")
        if (
            type(dependencies) is not list
            or not dependencies
            or any(not is_sha512(item) for item in dependencies)
            or dependencies != sorted(set(dependencies))
        ):
            return "PROVENANCE_DEPENDENCY_DIGESTS_INVALID"
        return None
    if node_type == "generated_artifact":
        if (
            not _text(attributes.get("artifact_id"))
            or not _text(attributes.get("artifact_version"))
            or not is_sha512(attributes.get("derivation_digest"))
        ):
            return "PROVENANCE_ARTIFACT_ATTRIBUTES_INVALID"
        return None
    if node_type == "release_manifest":
        if (
            not _text(attributes.get("release_id"))
            or not _text(attributes.get("release_version"))
            or not is_sha512(attributes.get("release_manifest_digest"))
            or not is_sha512(attributes.get("artifact_content_digest"))
        ):
            return "PROVENANCE_RELEASE_ATTRIBUTES_INVALID"
        return None
    if (
        not _text(attributes.get("runtime_id"))
        or not is_sha512(attributes.get("runtime_environment_digest"))
        or not is_sha512(attributes.get("release_manifest_digest"))
        or not is_sha512(attributes.get("runtime_measurement_digest"))
    ):
        return "PROVENANCE_RUNTIME_ATTRIBUTES_INVALID"
    return None


def _node_error(
    node: Any,
    *,
    expected_type: str,
    expected_sequence: int,
    evaluation_time: int,
    admissions: dict[str, ProvenanceCredentialAdmission],
) -> str | None:
    if type(node) is not dict or set(node) != _NODE_FIELDS:
        return "PROVENANCE_NODE_SCHEMA_INVALID"
    role = PROVENANCE_NODE_SIGNER_ROLES[expected_type]
    admission = admissions.get(role)
    if admission is None:
        return "PROVENANCE_NODE_CREDENTIAL_NOT_INCLUDED"
    if (
        node.get("node_type") != expected_type
        or not _text(node.get("node_id"))
        or not is_sha512(node.get("content_digest"))
        or node.get("sequence") != expected_sequence
        or not _nonnegative_int(node.get("recorded_at"))
        or not _nonnegative_int(node.get("effective_from"))
        or not _positive_int(node.get("effective_until"))
        or not node["effective_from"] <= node["recorded_at"] <= evaluation_time
        or not node["effective_from"] <= evaluation_time < node["effective_until"]
        or node.get("effective_status") != ACTIVE
        or node.get("revocation_status") != ACTIVE
        or node.get("revocation_sequence") != admission.revocation_sequence
        or node.get("signer_role") != role
        or node.get("authority_credential_id") != admission.credential_id
        or node.get("authority_credential_digest") != admission.credential_digest
        or node.get("credential_inclusion_digest") != admission.credential_inclusion_digest
    ):
        return "PROVENANCE_NODE_STATE_INVALID"
    error = _attributes_error(expected_type, node.get("attributes"))
    if error is not None:
        return error
    if (
        expected_type == "authoritative_source"
        and node["attributes"]["source_authority_credential_digest"]
        != admission.credential_digest
    ):
        return "PROVENANCE_SOURCE_CREDENTIAL_MISMATCH"
    if not _independent_signature_valid(node, admission.provider_binding):
        return "PROVENANCE_NODE_SIGNATURE_INVALID"
    return None


def _edge_error(
    edge: Any,
    *,
    expected_sequence: int,
    expected_relation: str,
    source: dict[str, Any],
    target: dict[str, Any],
) -> str | None:
    if type(edge) is not dict or set(edge) != _EDGE_FIELDS:
        return "PROVENANCE_EDGE_SCHEMA_INVALID"
    if (
        not _text(edge.get("edge_id"))
        or edge.get("sequence") != expected_sequence
        or edge.get("relation") != expected_relation
        or edge.get("from_node_id") != source["node_id"]
        or edge.get("to_node_id") != target["node_id"]
        or edge.get("from_content_digest") != source["content_digest"]
        or edge.get("to_content_digest") != target["content_digest"]
    ):
        return "PROVENANCE_EDGE_BINDING_INVALID"
    return None


def _connected_acyclic(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> bool:
    identifiers = {node["node_id"] for node in nodes}
    adjacency = {identifier: [] for identifier in identifiers}
    indegree = {identifier: 0 for identifier in identifiers}
    for edge in edges:
        source = edge["from_node_id"]
        target = edge["to_node_id"]
        if source not in identifiers or target not in identifiers or source == target:
            return False
        adjacency[source].append(target)
        indegree[target] += 1
    roots = [identifier for identifier, degree in indegree.items() if degree == 0]
    if len(roots) != 1:
        return False
    queue = roots[:]
    visited: list[str] = []
    while queue:
        current = queue.pop(0)
        visited.append(current)
        for target in adjacency[current]:
            indegree[target] -= 1
            if indegree[target] == 0:
                queue.append(target)
    return len(visited) == len(nodes) and set(visited) == identifiers


def _lineage_error(graph: dict[str, Any], nodes: list[dict[str, Any]]) -> str | None:
    source, transformation, artifact, release, runtime = nodes
    tx = transformation["attributes"]
    artifact_attributes = artifact["attributes"]
    release_attributes = release["attributes"]
    runtime_attributes = runtime["attributes"]
    if graph.get("declared_transformation_ids") != [tx["transformation_id"]]:
        return "PROVENANCE_UNDECLARED_TRANSFORMATION"
    if (
        tx["declared_input_digest"] != source["content_digest"]
        or tx["declared_output_digest"] != artifact["content_digest"]
    ):
        return "PROVENANCE_TRANSFORMATION_BINDING_INVALID"
    derivation = _safe_hash(
        {
            "source_content_digest": source["content_digest"],
            "transformation_node_digest": transformation["digest"],
            "artifact_content_digest": artifact["content_digest"],
            "tool_digest": tx["tool_digest"],
            "config_digest": tx["config_digest"],
            "dependency_digests": tx["dependency_digests"],
        }
    )
    if artifact_attributes["derivation_digest"] != derivation:
        return "PROVENANCE_ARTIFACT_DERIVATION_INVALID"
    if (
        release["content_digest"] != release_attributes["release_manifest_digest"]
        or release_attributes["artifact_content_digest"] != artifact["content_digest"]
        or graph.get("release_manifest_digest") != release_attributes["release_manifest_digest"]
    ):
        return "PROVENANCE_RELEASE_BINDING_INVALID"
    if (
        runtime["content_digest"] != runtime_attributes["runtime_measurement_digest"]
        or runtime_attributes["release_manifest_digest"]
        != release_attributes["release_manifest_digest"]
        or graph.get("runtime_measurement_digest")
        != runtime_attributes["runtime_measurement_digest"]
    ):
        return "PROVENANCE_RUNTIME_BINDING_INVALID"
    return None


def _clock_exact(clock: Any) -> bool:
    return (
        clock is not None
        and _safe_getattr(clock, "trusted_clock_admitted") is True
        and _safe_getattr(clock, "trusted_clock_attestation_admitted") is True
        and _text(_safe_getattr(clock, "clock_id"))
        and callable(_safe_getattr(clock, "current_time_evidence"))
    )


def _clock_evidence_error(
    evidence: Any,
    *,
    context_id: str,
    clock_id: str,
    binding: _PinnedEd25519Binding,
) -> str | None:
    if type(evidence) is not dict or set(evidence) != _CLOCK_EVIDENCE_FIELDS:
        return "PROVENANCE_CLOCK_EVIDENCE_SHAPE_INVALID"
    if (
        evidence.get("schema_id") != CLOCK_EVIDENCE_SCHEMA
        or evidence.get("context_id") != context_id
        or evidence.get("clock_id") != clock_id
        or not _positive_int(evidence.get("clock_sequence"))
        or not _nonnegative_int(evidence.get("observed_at"))
        or evidence.get("status") != ACTIVE
        or evidence.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or not _independent_signature_valid(evidence, binding)
    ):
        return "PROVENANCE_CLOCK_EVIDENCE_INVALID"
    return None


def _current_clock_evidence(
    clock: Any,
    *,
    context_id: str,
    binding: _PinnedEd25519Binding,
) -> tuple[dict[str, Any] | None, str | None]:
    if not _clock_exact(clock):
        return None, "PROVENANCE_TRUSTED_CLOCK_REQUIRED"
    try:
        evidence = clock.current_time_evidence(context_id=context_id)
    except Exception:
        return None, "PROVENANCE_TRUSTED_CLOCK_INDETERMINATE"
    error = _clock_evidence_error(
        evidence,
        context_id=context_id,
        clock_id=_safe_getattr(clock, "clock_id"),
        binding=binding,
    )
    return (None, error) if error is not None else (evidence, None)


def _durable_context_exact(context: Any, *, test_only: bool) -> bool:
    common = (
        context is not None
        and _safe_getattr(context, "durable_atomic_claim_admitted") is True
        and _safe_getattr(context, "durable_transition_attestation_admitted") is True
        and _text(_safe_getattr(context, "durable_storage_class"))
        and _text(_safe_getattr(context, "context_id"))
        and callable(_safe_getattr(context, "claim_next"))
        and callable(_safe_getattr(context, "read_live_heads"))
        and callable(_safe_getattr(context, "is_claimed"))
    )
    if not common:
        return False
    storage_class = _safe_getattr(context, "durable_storage_class")
    if test_only:
        return (
            storage_class == "TEST_ONLY_IN_MEMORY_DURABLE_CONTRACT_MODEL"
            and _safe_getattr(
                context, "production_durable_storage_admitted"
            ) is False
        )
    return (
        storage_class in _PRODUCTION_DURABLE_STORAGE_CLASSES
        and not any(term in storage_class.upper() for term in _FORBIDDEN_PRODUCTION_STORAGE_TERMS)
        and _safe_getattr(
            context, "durable_storage_external_attestation_admitted"
        ) is True
        and _safe_getattr(context, "production_durable_storage_admitted") is True
    )


def _deployment_context_error(
    context: Any,
) -> str | None:
    if not isinstance(context, ProvenanceDeploymentTrustContext):
        return "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_REQUIRED"
    try:
        if (
            not _text(context.context_id)
            or not _text(context.registry_context)
            or context.private_composition_root_required is not True
            or context.production_durable_storage_required is not True
            or context.deployment_mode not in (PRODUCTION_MODE, TEST_ONLY_MODE)
            or not isinstance(context.registry_authority_binding, _PinnedEd25519Binding)
            or not isinstance(context.durable_context_binding, _PinnedEd25519Binding)
            or not isinstance(context.verification_receipt_binding, _PinnedEd25519Binding)
            or not isinstance(context.trusted_clock_binding, _PinnedEd25519Binding)
            or (
                context.deployment_mode == PRODUCTION_MODE
                and any(
                    binding.algorithm != HYBRID_SUITE_ID
                    or binding.hybrid_context is None
                    or binding.hybrid_context.signer_class != PRODUCTION_SIGNER
                    or binding.legacy_non_effect_only is True
                    for binding in (
                        context.registry_authority_binding,
                        context.durable_context_binding,
                        context.verification_receipt_binding,
                        context.trusted_clock_binding,
                    )
                )
            )
            or _safe_getattr(
                context.verification_receipt_provider,
                "provenance_verification_receipt_admitted",
            ) is not True
            or not _clock_exact(context.trusted_clock)
            or not _durable_context_exact(
                context.durable_context,
                test_only=context.deployment_mode == TEST_ONLY_MODE,
            )
        ):
            return "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"
    except Exception:
        return "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"
    return None


def _revocation_head_source_exact(source: Any, expected_context: str) -> bool:
    return (
        source is not None
        and _safe_getattr(source, "revocation_head_source_admitted") is True
        and _text(_safe_getattr(source, "source_id"))
        and _safe_getattr(source, "registry_context") == expected_context
        and callable(_safe_getattr(source, "current_revocation_head"))
    )


def _revocation_head_error(
    head: Any,
    *,
    snapshot: dict[str, Any],
    owner_pin: dict[str, Any],
    owner_pin_digest: str,
    expected_context: str,
    evaluation_time: int,
    authority_binding: _PinnedEd25519Binding,
) -> str | None:
    if type(head) is not dict or set(head) != _REVOCATION_HEAD_FIELDS:
        return "PROVENANCE_REVOCATION_HEAD_SHAPE_INVALID"
    if (
        head.get("schema_id") != REVOCATION_HEAD_SCHEMA
        or head.get("registry_id") != snapshot["registry_id"]
        or head.get("registry_context") != expected_context
        or head.get("snapshot_digest") != snapshot["digest"]
        or head.get("snapshot_sequence") != snapshot["snapshot_sequence"]
        or head.get("revocation_sequence") != snapshot["revocation_sequence"]
        or head.get("observed_at") != evaluation_time
        or head.get("owner_pin_digest") != owner_pin_digest
        or head.get("authority_role") != PROVENANCE_REGISTRY_AUTHORITY_ROLE
        or head.get("authority_credential_id")
        != owner_pin["authority_credential_id"]
        or head.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
    ):
        return "PROVENANCE_REVOCATION_HEAD_BINDING_INVALID"
    if not _independent_signature_valid(head, authority_binding):
        return "PROVENANCE_REVOCATION_HEAD_SIGNATURE_INVALID"
    return None


def _head_exact(value: Any, *, allow_none: bool) -> bool:
    return allow_none if value is None else (
        type(value) is dict
        and set(value) == _HEAD_FIELDS
        and _positive_int(value.get("sequence"))
        and is_sha512(value.get("digest"))
        and _nonnegative_int(value.get("revocation_sequence"))
    )


def _expected_stream_head(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": claim["provenance_sequence"],
        "digest": claim["graph_digest"],
        "revocation_sequence": claim["provenance_revocation_sequence"],
    }


def _expected_registry_head(claim: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": claim["registry_snapshot_sequence"],
        "digest": claim["registry_snapshot_digest"],
        "revocation_sequence": claim["registry_revocation_sequence"],
    }


def _durable_previous_heads_exact(
    receipt: dict[str, Any], claim: dict[str, Any]
) -> bool:
    previous_stream = receipt.get("previous_stream_head")
    previous_registry = receipt.get("previous_registry_head")
    previous_state = receipt.get("previous_state_digest")
    if previous_state == GENESIS_HASH:
        return (
            receipt.get("transition_sequence") == 1
            and claim["provenance_sequence"] == 1
            and claim["prior_provenance_digest"] == GENESIS_HASH
            and claim["registry_snapshot_sequence"] == 1
            and claim["prior_registry_snapshot_digest"] == GENESIS_HASH
            and previous_stream is None
            and previous_registry is None
        )
    if claim["provenance_sequence"] == 1:
        if previous_stream is not None:
            return False
    elif (
        type(previous_stream) is not dict
        or previous_stream.get("sequence") != claim["provenance_sequence"] - 1
        or previous_stream.get("digest") != claim["prior_provenance_digest"]
        or previous_stream.get("revocation_sequence")
        > claim["provenance_revocation_sequence"]
    ):
        return False
    current_registry = _expected_registry_head(claim)
    if previous_registry == current_registry:
        return True
    return (
        claim["registry_snapshot_sequence"] > 1
        and type(previous_registry) is dict
        and previous_registry.get("sequence")
        == claim["registry_snapshot_sequence"] - 1
        and previous_registry.get("digest")
        == claim["prior_registry_snapshot_digest"]
        and previous_registry.get("revocation_sequence")
        <= claim["registry_revocation_sequence"]
    )


def _durable_transition_error(
    receipt: Any,
    *,
    claim: dict[str, Any],
    claim_digest: str,
    context_id: str,
    revocation_head_digest: str,
    binding: _PinnedEd25519Binding,
) -> str | None:
    if type(receipt) is not dict or set(receipt) != _DURABLE_TRANSITION_FIELDS:
        return "PROVENANCE_DURABLE_TRANSITION_SHAPE_INVALID"
    if (
        receipt.get("schema_id") != DURABLE_TRANSITION_RECEIPT_SCHEMA
        or receipt.get("context_id") != context_id
        or receipt.get("claim_digest") != claim_digest
        or receipt.get("result") not in {
            DURABLE_CLAIMED, DURABLE_ALREADY_CLAIMED, DURABLE_ROLLBACK,
            DURABLE_CONFLICT,
        }
        or not _positive_int(receipt.get("transition_sequence"))
        or (
            receipt.get("previous_state_digest") != GENESIS_HASH
            and not is_sha512(receipt.get("previous_state_digest"))
        )
        or not is_sha512(receipt.get("state_digest"))
        or receipt.get("stream_id") != claim["stream_id"]
        or not _head_exact(receipt.get("previous_stream_head"), allow_none=True)
        or not _head_exact(receipt.get("current_stream_head"), allow_none=True)
        or not _head_exact(receipt.get("previous_registry_head"), allow_none=True)
        or not _head_exact(receipt.get("current_registry_head"), allow_none=True)
        or receipt.get("evaluation_time") != claim["evaluation_time"]
        or receipt.get("revocation_head_digest") != revocation_head_digest
        or receipt.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or not _independent_signature_valid(receipt, binding)
    ):
        return "PROVENANCE_DURABLE_TRANSITION_INVALID"
    if receipt["result"] == DURABLE_CLAIMED and (
        receipt.get("current_stream_head") != _expected_stream_head(claim)
        or receipt.get("current_registry_head") != _expected_registry_head(claim)
        or not _durable_previous_heads_exact(receipt, claim)
        or receipt.get("state_digest") == receipt.get("previous_state_digest")
    ):
        return "PROVENANCE_DURABLE_TRANSITION_HEAD_INVALID"
    return None


def _durable_live_heads_error(
    live: Any,
    *,
    transition: dict[str, Any],
    claim: dict[str, Any],
    claim_digest: str,
    context_id: str,
    revocation_head_digest: str,
    binding: _PinnedEd25519Binding,
) -> str | None:
    if type(live) is not dict or set(live) != _DURABLE_LIVE_HEADS_FIELDS:
        return "PROVENANCE_DURABLE_LIVE_HEADS_SHAPE_INVALID"
    if (
        live.get("schema_id") != DURABLE_LIVE_HEADS_SCHEMA
        or live.get("context_id") != context_id
        or live.get("transition_sequence") != transition["transition_sequence"]
        or live.get("state_digest") != transition["state_digest"]
        or live.get("stream_id") != claim["stream_id"]
        or live.get("stream_head") != transition["current_stream_head"]
        or live.get("registry_head") != transition["current_registry_head"]
        or live.get("last_evaluation_time") != claim["evaluation_time"]
        or live.get("revocation_head_digest") != revocation_head_digest
        or live.get("queried_claim_digest") != claim_digest
        or live.get("is_claimed") is not True
        or live.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or not _independent_signature_valid(live, binding)
    ):
        return "PROVENANCE_DURABLE_LIVE_HEADS_INVALID"
    return None


def _durable_claim(
    *,
    graph: dict[str, Any],
    snapshot: dict[str, Any],
    owner_pin_digest: str,
    expected_context: str,
    evaluation_time: int,
    revocation_head_digest: str,
    clock_evidence_digest: str,
) -> dict[str, Any]:
    stream_id = canonical_integrity_hash(
        {
            "owner_pin_digest": owner_pin_digest,
            "registry_context": expected_context,
            "graph_id": graph["graph_id"],
        }
    )
    return {
        "contract_id": DIGITAL_PROVENANCE_CONTRACT_ID,
        "stream_id": stream_id,
        "registry_context": expected_context,
        "owner_pin_digest": owner_pin_digest,
        "request_fingerprint": graph["request_fingerprint"],
        "graph_id": graph["graph_id"],
        "graph_digest": graph["digest"],
        "provenance_sequence": graph["sequence"],
        "prior_provenance_digest": graph["prior_provenance_digest"],
        "provenance_revocation_sequence": graph["revocation_sequence"],
        "registry_snapshot_digest": snapshot["digest"],
        "registry_snapshot_sequence": snapshot["snapshot_sequence"],
        "prior_registry_snapshot_digest": snapshot["prior_snapshot_digest"],
        "registry_revocation_sequence": snapshot["revocation_sequence"],
        "evaluation_time": evaluation_time,
        "release_manifest_digest": graph["release_manifest_digest"],
        "runtime_measurement_digest": graph["runtime_measurement_digest"],
        "current_revocation_head_digest": revocation_head_digest,
        "current_clock_evidence_digest": clock_evidence_digest,
    }


def _verify_digital_provenance(
    graph: Any,
    *,
    registry_snapshot: dict[str, Any] | None,
    trust_context: ProvenanceDeploymentTrustContext,
    expected_request_fingerprint: str,
    expected_release_manifest_digest: str,
    expected_runtime_measurement_digest: str,
) -> ProvenanceDecision:
    """Verify lineage using one deployment-fixed trust context."""

    trace: list[dict[str, Any]] = []
    evaluation_time: int | None = None
    claim_result: str | None = None
    claim_digest: str | None = None
    transition_digest: str | None = None
    live_heads_digest: str | None = None
    revocation_head_digest: str | None = None
    clock_evidence_digest: str | None = None
    expected_context: str | None = None
    owner_pin: dict[str, Any] | None = None
    pin_digest: str | None = None
    clock_id: str | None = None
    durable_context_id: str | None = None

    if isinstance(trust_context, ProvenanceDeploymentTrustContext):
        try:
            expected_context = trust_context.registry_context
            owner_pin = trust_context.owner_pin
            pin_digest = _safe_hash(owner_pin)
            clock_id = _safe_getattr(trust_context.trusted_clock, "clock_id")
            durable_context_id = _safe_getattr(
                trust_context.durable_context, "context_id"
            )
        except Exception:
            pass

    def finish(result: str, reason: str) -> ProvenanceDecision:
        return _finish(
            result=result,
            reason=reason,
            graph=graph,
            trace=trace,
            evaluation_time=evaluation_time,
            owner_pin_digest=pin_digest,
            registry_context=expected_context,
            registry_snapshot=registry_snapshot,
            clock_id=clock_id if _text(clock_id) else None,
            durable_context_id=(
                durable_context_id if _text(durable_context_id) else None
            ),
            durable_claim_result=claim_result,
            durable_claim_digest=claim_digest,
            durable_transition_receipt_digest=transition_digest,
            durable_live_heads_digest=live_heads_digest,
            revocation_head_digest=revocation_head_digest,
            clock_evidence_digest=clock_evidence_digest,
            trust_context=(
                trust_context
                if isinstance(trust_context, ProvenanceDeploymentTrustContext)
                else None
            ),
        )

    def deny(reason: str) -> ProvenanceDecision:
        return finish(DENY, reason)

    context_error = _deployment_context_error(trust_context)
    if context_error is not None:
        return deny(context_error)
    assert owner_pin is not None and expected_context is not None
    clock = trust_context.trusted_clock
    durable_context = trust_context.durable_context
    authority_binding = trust_context.registry_authority_binding

    clock_evidence, clock_error = _current_clock_evidence(
        clock,
        context_id=trust_context.context_id,
        binding=trust_context.trusted_clock_binding,
    )
    if clock_error is not None or clock_evidence is None:
        return deny(clock_error or "PROVENANCE_TRUSTED_CLOCK_INDETERMINATE")
    evaluation_time = clock_evidence["observed_at"]
    clock_evidence_digest = clock_evidence["digest"]
    _append_trace(
        trace,
        stage="trusted_clock",
        result="PASS",
        evidence={
            "clock_id": clock_id,
            "evaluation_time": evaluation_time,
            "clock_sequence": clock_evidence["clock_sequence"],
            "clock_evidence_digest": clock_evidence_digest,
        },
    )
    if (
        not is_sha512(expected_request_fingerprint)
        or not is_sha512(expected_release_manifest_digest)
        or not is_sha512(expected_runtime_measurement_digest)
    ):
        return deny("PROVENANCE_EXPECTATION_INVALID")
    pin_error = _owner_pin_error(
        owner_pin,
        expected_context=expected_context,
        authority_provider=trust_context.registry_authority_provider,
        authority_binding=authority_binding,
    )
    if pin_error is not None or pin_digest is None:
        return deny(pin_error or "PROVENANCE_OWNER_PIN_INVALID")
    _append_trace(
        trace,
        stage="owner_pin",
        result="PASS",
        evidence={
            "owner_pin_digest": pin_digest,
            "registry_context": expected_context,
            "authority_public_key_fingerprint": authority_binding.public_key_fingerprint,
        },
    )
    resolver = trust_context.provider_resolver
    if not _resolver_exact(resolver, expected_context):
        return deny("PROVENANCE_PROVIDER_RESOLVER_REQUIRED")
    admissions, snapshot_error = _snapshot_admissions(
        registry_snapshot,
        pin=owner_pin,
        pin_digest=pin_digest,
        expected_context=expected_context,
        evaluation_time=evaluation_time,
        authority_binding=authority_binding,
        resolver=resolver,
    )
    if snapshot_error is not None or admissions is None:
        return deny(snapshot_error or "PROVENANCE_REGISTRY_SNAPSHOT_INVALID")
    assert registry_snapshot is not None

    revocation_source = trust_context.revocation_head_source
    if not _revocation_head_source_exact(revocation_source, expected_context):
        return deny("PROVENANCE_REVOCATION_HEAD_SOURCE_REQUIRED")
    try:
        revocation_head = revocation_source.current_revocation_head(
            registry_id=registry_snapshot["registry_id"],
            registry_context=expected_context,
        )
    except Exception:
        return deny("PROVENANCE_REVOCATION_HEAD_INDETERMINATE")
    revocation_error = _revocation_head_error(
        revocation_head,
        snapshot=registry_snapshot,
        owner_pin=owner_pin,
        owner_pin_digest=pin_digest,
        expected_context=expected_context,
        evaluation_time=evaluation_time,
        authority_binding=authority_binding,
    )
    if revocation_error is not None:
        return deny(revocation_error)
    revocation_head_digest = revocation_head["digest"]
    _append_trace(
        trace,
        stage="registry_snapshot_and_live_revocation_head",
        result="PASS",
        evidence={
            "snapshot_digest": registry_snapshot["digest"],
            "snapshot_sequence": registry_snapshot["snapshot_sequence"],
            "revocation_sequence": registry_snapshot["revocation_sequence"],
            "revocation_head_digest": revocation_head_digest,
            "inclusion_set_digest": registry_snapshot["inclusion_set_digest"],
        },
    )
    for role in REQUIRED_SIGNER_ROLES:
        admission = admissions[role]
        _append_trace(
            trace,
            stage=f"credential_inclusion:{role}",
            result="PASS",
            evidence={
                "credential_id": admission.credential_id,
                "credential_digest": admission.credential_digest,
                "credential_inclusion_digest": admission.credential_inclusion_digest,
                "public_key_fingerprint": admission.provider_public_key_fingerprint,
                "revocation_sequence": admission.revocation_sequence,
            },
        )

    if type(graph) is not dict or set(graph) != _GRAPH_FIELDS:
        return deny("PROVENANCE_GRAPH_SCHEMA_INVALID")
    if (
        graph.get("contract_id") != DIGITAL_PROVENANCE_CONTRACT_ID
        or graph.get("schema_status") != DIGITAL_PROVENANCE_SCHEMA_STATUS
        or graph.get("proof_scope") != DIGITAL_PROVENANCE_PROOF_SCOPE
        or not _text(graph.get("graph_id"))
        or not _text(graph.get("graph_version"))
        or graph.get("request_fingerprint") != expected_request_fingerprint
        or graph.get("evaluation_time") != evaluation_time
        or not _positive_int(graph.get("sequence"))
        or (graph["sequence"] == 1 and graph.get("prior_provenance_digest") != GENESIS_HASH)
        or (graph["sequence"] > 1 and not is_sha512(graph.get("prior_provenance_digest")))
        or graph.get("revocation_status") != ACTIVE
        or graph.get("revocation_sequence") != revocation_head["revocation_sequence"]
        or graph.get("owner_pin_digest") != pin_digest
        or graph.get("registry_id") != registry_snapshot["registry_id"]
        or graph.get("registry_version") != registry_snapshot["registry_version"]
        or graph.get("registry_context") != expected_context
        or graph.get("registry_snapshot_digest") != registry_snapshot["digest"]
        or graph.get("release_manifest_digest") != expected_release_manifest_digest
        or graph.get("runtime_measurement_digest") != expected_runtime_measurement_digest
    ):
        return deny("PROVENANCE_GRAPH_BINDING_INVALID")
    if graph.get("lineage_only") is not True or any(
        graph.get(field) is not expected
        for field, expected in NO_AUTHORIZATION_EFFECT.items()
    ):
        return deny("PROVENANCE_SCOPE_OR_AUTHORITY_INVALID")
    graph_admission = admissions[PROVENANCE_GRAPH_SIGNER_ROLE]
    if (
        graph.get("signer_role") != PROVENANCE_GRAPH_SIGNER_ROLE
        or graph.get("authority_credential_id") != graph_admission.credential_id
        or graph.get("authority_credential_digest") != graph_admission.credential_digest
        or graph.get("credential_inclusion_digest")
        != graph_admission.credential_inclusion_digest
    ):
        return deny("PROVENANCE_GRAPH_CREDENTIAL_BINDING_INVALID")
    if not _independent_signature_valid(graph, graph_admission.provider_binding):
        return deny("PROVENANCE_GRAPH_SIGNATURE_INVALID")
    _append_trace(
        trace,
        stage="graph_signature",
        result="PASS",
        evidence={
            "graph_digest": graph["digest"],
            "credential_inclusion_digest": graph_admission.credential_inclusion_digest,
            "public_key_fingerprint": graph_admission.provider_public_key_fingerprint,
        },
    )

    nodes = graph.get("nodes")
    if type(nodes) is not list or len(nodes) != len(PROVENANCE_NODE_TYPES):
        return deny("PROVENANCE_NODE_SET_INVALID")
    node_ids: set[str] = set()
    node_digests: set[str] = set()
    prior_recorded_at = -1
    for sequence, (node, expected_type) in enumerate(
        zip(nodes, PROVENANCE_NODE_TYPES, strict=True), start=1
    ):
        error = _node_error(
            node,
            expected_type=expected_type,
            expected_sequence=sequence,
            evaluation_time=evaluation_time,
            admissions=admissions,
        )
        if error is not None:
            return deny(error)
        if node["node_id"] in node_ids or node["digest"] in node_digests:
            return deny("PROVENANCE_DUPLICATE_NODE")
        if node["recorded_at"] < prior_recorded_at:
            return deny("PROVENANCE_NODE_TIME_REORDERED")
        prior_recorded_at = node["recorded_at"]
        node_ids.add(node["node_id"])
        node_digests.add(node["digest"])

    edges = graph.get("edges")
    if type(edges) is not list or len(edges) != len(PROVENANCE_EDGE_RELATIONS):
        return deny("PROVENANCE_EDGE_SET_INVALID")
    edge_ids: set[str] = set()
    for sequence, relation in enumerate(PROVENANCE_EDGE_RELATIONS, start=1):
        edge = edges[sequence - 1]
        error = _edge_error(
            edge,
            expected_sequence=sequence,
            expected_relation=relation,
            source=nodes[sequence - 1],
            target=nodes[sequence],
        )
        if error is not None:
            return deny(error)
        if edge["edge_id"] in edge_ids:
            return deny("PROVENANCE_DUPLICATE_EDGE")
        edge_ids.add(edge["edge_id"])
    if not _connected_acyclic(nodes, edges):
        return deny("PROVENANCE_GRAPH_DISCONNECTED_OR_CYCLIC")
    error = _lineage_error(graph, nodes)
    if error is not None:
        return deny(error)
    _append_trace(
        trace,
        stage="lineage",
        result="PASS",
        evidence={
            "node_digests": [node["digest"] for node in nodes],
            "edges_digest": canonical_integrity_hash(edges),
            "release_manifest_digest": graph["release_manifest_digest"],
            "runtime_measurement_digest": graph["runtime_measurement_digest"],
        },
    )

    terminal_clock_evidence, terminal_clock_error = _current_clock_evidence(
        clock,
        context_id=trust_context.context_id,
        binding=trust_context.trusted_clock_binding,
    )
    if terminal_clock_error is not None or terminal_clock_evidence is None:
        return deny(
            terminal_clock_error or "PROVENANCE_TRUSTED_CLOCK_INDETERMINATE"
        )
    if terminal_clock_evidence != clock_evidence:
        return deny("PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED")
    try:
        terminal_revocation_head = revocation_source.current_revocation_head(
            registry_id=registry_snapshot["registry_id"],
            registry_context=expected_context,
        )
    except Exception:
        return deny("PROVENANCE_REVOCATION_HEAD_INDETERMINATE")
    terminal_revocation_error = _revocation_head_error(
        terminal_revocation_head,
        snapshot=registry_snapshot,
        owner_pin=owner_pin,
        owner_pin_digest=pin_digest,
        expected_context=expected_context,
        evaluation_time=evaluation_time,
        authority_binding=authority_binding,
    )
    if terminal_revocation_error is not None:
        return deny(terminal_revocation_error)
    if terminal_revocation_head != revocation_head:
        return deny("PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED")

    claim = _durable_claim(
        graph=graph,
        snapshot=registry_snapshot,
        owner_pin_digest=pin_digest,
        expected_context=expected_context,
        evaluation_time=evaluation_time,
        revocation_head_digest=revocation_head_digest,
        clock_evidence_digest=clock_evidence_digest,
    )
    if set(claim) != _DURABLE_CLAIM_FIELDS:
        return deny("PROVENANCE_DURABLE_CLAIM_INVALID")
    claim_digest = canonical_integrity_hash(claim)
    try:
        transition = durable_context.claim_next(
            claim=deepcopy(claim),
            revocation_head_digest=revocation_head_digest,
        )
    except Exception:
        return deny("PROVENANCE_DURABLE_CONTEXT_INDETERMINATE")
    transition_error = _durable_transition_error(
        transition,
        claim=claim,
        claim_digest=claim_digest,
        context_id=durable_context_id,
        revocation_head_digest=revocation_head_digest,
        binding=trust_context.durable_context_binding,
    )
    if transition_error is not None:
        return deny(transition_error)
    transition_digest = transition["digest"]
    claim_result = transition["result"]
    if claim_result != DURABLE_CLAIMED:
        return deny({
            DURABLE_ALREADY_CLAIMED: "PROVENANCE_DURABLE_CLAIM_REPLAY",
            DURABLE_ROLLBACK: "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_ROLLBACK",
            DURABLE_CONFLICT: "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_CONFLICT",
        }.get(claim_result, "PROVENANCE_DURABLE_CONTEXT_INDETERMINATE"))
    try:
        live_heads = durable_context.read_live_heads(
            stream_id=claim["stream_id"], claim_digest=claim_digest
        )
        persisted_claimed = durable_context.is_claimed(claim_digest=claim_digest)
    except Exception:
        return deny("PROVENANCE_DURABLE_PERSISTENCE_INDETERMINATE")
    live_error = _durable_live_heads_error(
        live_heads,
        transition=transition,
        claim=claim,
        claim_digest=claim_digest,
        context_id=durable_context_id,
        revocation_head_digest=revocation_head_digest,
        binding=trust_context.durable_context_binding,
    )
    if live_error is not None or persisted_claimed is not True:
        return deny(live_error or "PROVENANCE_DURABLE_CLAIM_NOT_PERSISTED")
    live_heads_digest = live_heads["digest"]
    final_clock_evidence, final_clock_error = _current_clock_evidence(
        clock,
        context_id=trust_context.context_id,
        binding=trust_context.trusted_clock_binding,
    )
    if final_clock_error is not None or final_clock_evidence is None:
        return deny(
            final_clock_error or "PROVENANCE_TRUSTED_CLOCK_INDETERMINATE"
        )
    if final_clock_evidence != clock_evidence:
        return deny("PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED")
    try:
        final_revocation_head = revocation_source.current_revocation_head(
            registry_id=registry_snapshot["registry_id"],
            registry_context=expected_context,
        )
    except Exception:
        return deny("PROVENANCE_REVOCATION_HEAD_INDETERMINATE")
    final_revocation_error = _revocation_head_error(
        final_revocation_head,
        snapshot=registry_snapshot,
        owner_pin=owner_pin,
        owner_pin_digest=pin_digest,
        expected_context=expected_context,
        evaluation_time=evaluation_time,
        authority_binding=authority_binding,
    )
    if final_revocation_error is not None:
        return deny(final_revocation_error)
    if final_revocation_head != revocation_head:
        return deny("PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED")
    _append_trace(
        trace,
        stage="durable_atomic_claim_and_persisted_heads",
        result="PASS",
        evidence={
            "context_id": durable_context_id,
            "claim_digest": claim_digest,
            "claim_result": claim_result,
            "transition_receipt_digest": transition_digest,
            "live_heads_digest": live_heads_digest,
            "revocation_head_digest": revocation_head_digest,
        },
    )
    return finish(ADMIT, "PROVENANCE_LINEAGE_AUTHENTICATED_ONLY")


def verify_digital_provenance(
    graph: Any,
    *,
    registry_snapshot: dict[str, Any] | None,
    trust_context: ProvenanceDeploymentTrustContext,
    expected_request_fingerprint: str,
    expected_release_manifest_digest: str,
    expected_runtime_measurement_digest: str,
) -> ProvenanceDecision:
    """Deterministically deny malformed or indeterminate external evidence."""

    try:
        return _verify_digital_provenance(
            graph,
            registry_snapshot=registry_snapshot,
            trust_context=trust_context,
            expected_request_fingerprint=expected_request_fingerprint,
            expected_release_manifest_digest=expected_release_manifest_digest,
            expected_runtime_measurement_digest=expected_runtime_measurement_digest,
        )
    except Exception:
        context = (
            trust_context
            if isinstance(trust_context, ProvenanceDeploymentTrustContext)
            else None
        )
        try:
            owner_pin = context.owner_pin if context is not None else None
        except Exception:
            owner_pin = None
        registry_context = (
            context.registry_context
            if context is not None and _text(context.registry_context)
            else None
        )
        observed_clock_id = (
            _safe_getattr(context.trusted_clock, "clock_id")
            if context else None
        )
        observed_durable_context_id = (
            _safe_getattr(context.durable_context, "context_id")
            if context else None
        )
        return _finish(
            result=DENY,
            reason="PROVENANCE_EVIDENCE_INDETERMINATE",
            graph=graph,
            trace=[],
            evaluation_time=None,
            owner_pin_digest=_safe_hash(owner_pin),
            registry_context=registry_context,
            registry_snapshot=registry_snapshot,
            clock_id=observed_clock_id if _text(observed_clock_id) else None,
            durable_context_id=(
                observed_durable_context_id
                if _text(observed_durable_context_id) else None
            ),
            durable_claim_result=None,
            durable_claim_digest=None,
            durable_transition_receipt_digest=None,
            durable_live_heads_digest=None,
            revocation_head_digest=None,
            clock_evidence_digest=None,
            trust_context=context,
        )
