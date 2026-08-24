from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from hashlib import sha512
from inspect import signature
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.provenance.digital_provenance import (
    ACTIVE,
    ADMIT,
    CREDENTIAL_INCLUSION_SCHEMA,
    CLOCK_EVIDENCE_SCHEMA,
    DIGITAL_PROVENANCE_CONTRACT_ID,
    DIGITAL_PROVENANCE_PROOF_SCOPE,
    DIGITAL_PROVENANCE_SCHEMA_STATUS,
    DURABLE_LIVE_HEADS_SCHEMA,
    DURABLE_TRANSITION_RECEIPT_SCHEMA,
    DURABLE_ALREADY_CLAIMED,
    DURABLE_CLAIMED,
    DURABLE_CONFLICT,
    DURABLE_ROLLBACK,
    NO_AUTHORIZATION_EFFECT,
    OWNER_PIN_SCHEMA,
    PROVENANCE_GRAPH_SIGNER_ROLE,
    PROVENANCE_NODE_SIGNER_ROLES,
    PROVENANCE_NODE_TYPES,
    PROVENANCE_REGISTRY_AUTHORITY_ROLE,
    ProvenanceDeploymentTrustContext,
    REGISTRY_SNAPSHOT_SCHEMA,
    REQUIRED_SIGNER_ROLES,
    REVOCATION_HEAD_SCHEMA,
    verify_digital_provenance,
    verify_provenance_verification_receipt,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    canonical_integrity_hash,
    is_sha512,
)
from sbp_lex.security.signature_provider import (
    build_legacy_non_effect_signed_object as build_signed_object,
)


class ProvenanceProvider:
    algorithm = "Ed25519"
    custody_class = "CONTROLLED_PROVENANCE_EVIDENCE_KEY"
    token_signing_admitted = True
    effect_authority = False

    def __init__(
        self,
        role: str,
        *,
        registry_authority: bool = False,
        receipt_authority: bool = False,
        durable_authority: bool = False,
    ) -> None:
        self._key = Ed25519PrivateKey.generate()
        raw = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = sha512(raw).hexdigest()
        self.provider_id = f"ed25519-provenance-{role.lower()}:{fingerprint}"
        self.key_id = fingerprint
        self.provenance_attestation_admitted = not registry_authority
        self.provenance_registry_attestation_admitted = registry_authority
        self.provenance_verification_receipt_admitted = receipt_authority
        self.durable_transition_attestation_admitted = durable_authority

    @property
    def public_key(self):
        return self._key.public_key()

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise ValueError("SIGNING_KEY_ID_MISMATCH")
        return self._key.sign(message)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        try:
            self.public_key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


class TimeVaryingKeyProvider:
    """TEST_ONLY attacker: pinned metadata, changing public key, rogue signer."""

    provenance_attestation_admitted = True
    effect_authority = False
    token_signing_admitted = True

    def __init__(
        self, pinned_provider: ProvenanceProvider, rogue_provider: ProvenanceProvider
    ) -> None:
        self.provider_id = pinned_provider.provider_id
        self.algorithm = pinned_provider.algorithm
        self.key_id = pinned_provider.key_id
        self.custody_class = pinned_provider.custody_class
        self._pinned_key = pinned_provider.public_key
        self._rogue = rogue_provider
        self._reads = 0

    @property
    def public_key(self):
        self._reads += 1
        return self._pinned_key if self._reads == 1 else self._rogue.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self._rogue.sign(message, key_id=self._rogue.key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self._rogue.verify(message, signature, key_id=self._rogue.key_id)


class ProviderResolver:
    provider_resolution_admitted = True
    resolver_id = "deployment-provenance-provider-resolver"

    def __init__(self, registry_context: str) -> None:
        self.registry_context = registry_context
        self.providers: dict[tuple[str, str], ProvenanceProvider] = {}
        self.raise_error = False

    def resolve_provider(self, *, credential_id: str, signer_role: str):
        if self.raise_error:
            raise RuntimeError("RESOLUTION_UNAVAILABLE")
        return self.providers.get((credential_id, signer_role))


class TrustedClock:
    trusted_clock_admitted = True
    trusted_clock_attestation_admitted = True
    clock_id = "deployment-provenance-clock"

    def __init__(self, value: int, provider: ProvenanceProvider) -> None:
        self.value = value
        self.clock_sequence = 1
        self.provider = provider
        self.provider_id = provider.provider_id
        self.algorithm = provider.algorithm
        self.key_id = provider.key_id
        self.custody_class = provider.custody_class
        self.token_signing_admitted = provider.token_signing_admitted
        self.effect_authority = False
        self.raise_error = False
        self.calls = 0
        self.advance_on_call: int | None = None

    @property
    def public_key(self):
        return self.provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self.provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self.provider.verify(message, signature, key_id=key_id)

    def current_time_evidence(self, *, context_id: str) -> dict:
        if self.raise_error:
            raise RuntimeError("CLOCK_UNAVAILABLE")
        self.calls += 1
        if self.advance_on_call == self.calls:
            self.value += 1
            self.clock_sequence += 1
        return build_signed_object(
            {
                "schema_id": CLOCK_EVIDENCE_SCHEMA,
                "context_id": context_id,
                "clock_id": self.clock_id,
                "clock_sequence": self.clock_sequence,
                "observed_at": self.value,
                "status": ACTIVE,
                "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
            },
            provider=self,
        )


class RevocationHeadSource:
    revocation_head_source_admitted = True
    source_id = "deployment-live-provenance-revocation-head"

    def __init__(self, registry_context: str, provider: ProvenanceProvider) -> None:
        self.registry_context = registry_context
        self.provider = provider
        self.snapshot: dict | None = None
        self.owner_pin: dict | None = None
        self.clock: TrustedClock | None = None
        self.raise_error = False
        self.calls = 0
        self.advance_on_call: int | None = None

    def current_revocation_head(
        self, *, registry_id: str, registry_context: str
    ) -> dict:
        if self.raise_error:
            raise RuntimeError("REVOCATION_HEAD_UNAVAILABLE")
        assert self.snapshot is not None and self.owner_pin is not None
        assert self.clock is not None
        self.calls += 1
        observed_revocation = self.snapshot["revocation_sequence"]
        if self.advance_on_call == self.calls:
            observed_revocation += 1
        payload = {
            "schema_id": REVOCATION_HEAD_SCHEMA,
            "registry_id": registry_id,
            "registry_context": registry_context,
            "snapshot_digest": self.snapshot["digest"],
            "snapshot_sequence": self.snapshot["snapshot_sequence"],
            "revocation_sequence": observed_revocation,
            "observed_at": self.clock.value,
            "owner_pin_digest": canonical_integrity_hash(self.owner_pin),
            "authority_role": PROVENANCE_REGISTRY_AUTHORITY_ROLE,
            "authority_credential_id": self.owner_pin["authority_credential_id"],
            "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        return build_signed_object(payload, provider=self.provider)


class DurableAtomicContext:
    """TEST_ONLY in-memory model of the deployment durable atomic contract."""

    durable_atomic_claim_admitted = True
    production_durable_storage_admitted = False
    durable_storage_class = "TEST_ONLY_IN_MEMORY_DURABLE_CONTRACT_MODEL"
    durable_storage_external_attestation_admitted = False
    durable_transition_attestation_admitted = True
    context_id = "durable-provenance-context"

    def __init__(self, provider: ProvenanceProvider) -> None:
        self.provider = provider
        self.provider_id = provider.provider_id
        self.algorithm = provider.algorithm
        self.key_id = provider.key_id
        self.custody_class = provider.custody_class
        self.token_signing_admitted = provider.token_signing_admitted
        self.effect_authority = False
        self.seen_claims: set[str] = set()
        self.seen_requests: set[str] = set()
        self.stream_heads: dict[str, dict] = {}
        self.registry_head: dict | None = None
        self.last_time: int | None = None
        self.transition_sequence = 0
        self.state_digest = GENESIS_HASH
        self.last_revocation_head_digest = GENESIS_HASH
        self.raise_error = False
        self.persist_claim = True
        self.fabricate_previous_stream = False
        self.fabricate_previous_registry = False

    @property
    def public_key(self):
        return self.provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self.provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self.provider.verify(message, signature, key_id=key_id)

    def claim_next(self, *, claim: dict, revocation_head_digest: str) -> dict:
        if self.raise_error:
            raise RuntimeError("DURABLE_CONTEXT_UNAVAILABLE")
        digest = canonical_integrity_hash(claim)
        previous_stream = deepcopy(self.stream_heads.get(claim["stream_id"]))
        previous_registry = deepcopy(self.registry_head)
        previous_state = self.state_digest
        result = DURABLE_CLAIMED
        if digest in self.seen_claims or claim["request_fingerprint"] in self.seen_requests:
            result = DURABLE_ALREADY_CLAIMED
        elif self.last_time is not None and claim["evaluation_time"] < self.last_time:
            result = DURABLE_ROLLBACK

        snapshot_sequence = claim["registry_snapshot_sequence"]
        snapshot_digest = claim["registry_snapshot_digest"]
        prior_snapshot = claim["prior_registry_snapshot_digest"]
        registry_revocation = claim["registry_revocation_sequence"]
        if result == DURABLE_CLAIMED and self.registry_head is None:
            if snapshot_sequence != 1 or prior_snapshot != GENESIS_HASH:
                result = DURABLE_ROLLBACK
        elif result == DURABLE_CLAIMED:
            head = self.registry_head
            if (
                snapshot_sequence < head["sequence"]
                or registry_revocation < head["revocation_sequence"]
            ):
                result = DURABLE_ROLLBACK
            elif snapshot_sequence == head["sequence"]:
                if snapshot_digest != head["digest"]:
                    result = DURABLE_CONFLICT
            elif (
                snapshot_sequence != head["sequence"] + 1
                or prior_snapshot != head["digest"]
            ):
                result = DURABLE_CONFLICT

        stream = claim["stream_id"]
        sequence = claim["provenance_sequence"]
        prior = claim["prior_provenance_digest"]
        revocation = claim["provenance_revocation_sequence"]
        stream_head = self.stream_heads.get(stream)
        if result == DURABLE_CLAIMED and stream_head is None:
            if sequence != 1 or prior != GENESIS_HASH:
                result = DURABLE_ROLLBACK
        elif result == DURABLE_CLAIMED:
            if (
                sequence <= stream_head["sequence"]
                or revocation < stream_head["revocation_sequence"]
            ):
                result = DURABLE_ROLLBACK
            elif sequence != stream_head["sequence"] + 1 or prior != stream_head["digest"]:
                result = DURABLE_CONFLICT

        if result == DURABLE_CLAIMED:
            current_stream = {
                "sequence": sequence,
                "digest": claim["graph_digest"],
                "revocation_sequence": revocation,
            }
            current_registry = {
                "sequence": snapshot_sequence,
                "digest": snapshot_digest,
                "revocation_sequence": registry_revocation,
            }
            if self.persist_claim:
                self.seen_claims.add(digest)
                self.seen_requests.add(claim["request_fingerprint"])
                self.stream_heads[stream] = deepcopy(current_stream)
                self.registry_head = deepcopy(current_registry)
                self.last_time = claim["evaluation_time"]
                self.last_revocation_head_digest = revocation_head_digest
                self.transition_sequence += 1
                self.state_digest = canonical_integrity_hash({
                    "transition_sequence": self.transition_sequence,
                    "previous_state_digest": previous_state,
                    "stream_id": stream,
                    "stream_head": current_stream,
                    "registry_head": current_registry,
                    "claim_digest": digest,
                    "revocation_head_digest": revocation_head_digest,
                })
        else:
            current_stream = previous_stream
            current_registry = previous_registry
            self.transition_sequence += 1
        payload = {
            "schema_id": DURABLE_TRANSITION_RECEIPT_SCHEMA,
            "context_id": self.context_id,
            "claim_digest": digest,
            "result": result,
            "transition_sequence": self.transition_sequence,
            "previous_state_digest": previous_state,
            "state_digest": self.state_digest,
            "stream_id": stream,
            "previous_stream_head": self._external_head(previous_stream),
            "current_stream_head": self._external_head(current_stream),
            "previous_registry_head": self._external_head(previous_registry),
            "current_registry_head": self._external_head(current_registry),
            "evaluation_time": claim["evaluation_time"],
            "revocation_head_digest": revocation_head_digest,
            "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        if self.fabricate_previous_stream:
            payload["previous_stream_head"] = {
                "sequence": max(1, sequence),
                "digest": canonical_integrity_hash({"fabricated": "stream"}),
                "revocation_sequence": revocation,
            }
        if self.fabricate_previous_registry:
            payload["previous_registry_head"] = {
                "sequence": max(1, snapshot_sequence),
                "digest": canonical_integrity_hash({"fabricated": "registry"}),
                "revocation_sequence": registry_revocation,
            }
        return build_signed_object(payload, provider=self)

    @staticmethod
    def _external_head(head: dict | None) -> dict | None:
        if head is None:
            return None
        return {
            "sequence": head["sequence"],
            "digest": head["digest"],
            "revocation_sequence": head.get(
                "revocation_sequence", head.get("revocation")
            ),
        }

    def read_live_heads(self, *, stream_id: str, claim_digest: str) -> dict:
        payload = {
            "schema_id": DURABLE_LIVE_HEADS_SCHEMA,
            "context_id": self.context_id,
            "transition_sequence": self.transition_sequence,
            "state_digest": self.state_digest,
            "stream_id": stream_id,
            "stream_head": self._external_head(self.stream_heads.get(stream_id)),
            "registry_head": self._external_head(self.registry_head),
            "last_evaluation_time": self.last_time,
            "revocation_head_digest": self.last_revocation_head_digest,
            "queried_claim_digest": claim_digest,
            "is_claimed": claim_digest in self.seen_claims,
            "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        return build_signed_object(payload, provider=self)

    def is_claimed(self, *, claim_digest: str) -> bool:
        return claim_digest in self.seen_claims


class DigitalProvenanceTests(unittest.TestCase):
    evaluation_time = 1_700_000_500
    registry_context = "SBP_LEX_V2_PRODUCTION_RELEASE_LINEAGE"

    def setUp(self) -> None:
        self.clock_provider = ProvenanceProvider("trusted-clock-authority")
        self.clock = TrustedClock(self.evaluation_time, self.clock_provider)
        self.owner_provider = ProvenanceProvider(
            "registry-authority",
            registry_authority=True,
        )
        self.durable_provider = ProvenanceProvider(
            "durable-transition-authority",
            durable_authority=True,
        )
        self.receipt_provider = ProvenanceProvider(
            "verification-receipt-authority",
            receipt_authority=True,
        )
        self.durable = DurableAtomicContext(self.durable_provider)
        self.resolver = ProviderResolver(self.registry_context)
        for role in REQUIRED_SIGNER_ROLES:
            provider = ProvenanceProvider(role)
            credential_id = f"credential-{role.lower()}"
            self.resolver.providers[(credential_id, role)] = provider
        self.owner_pin = self._owner_pin(self.owner_provider)
        self.request_fingerprint = canonical_integrity_hash(
            {"request_id": "provenance-request-1"}
        )
        self.release_manifest_digest = canonical_integrity_hash(
            {"release": "release-1", "manifest": 1}
        )
        self.runtime_measurement_digest = canonical_integrity_hash(
            {"runtime": "runtime-1", "measurement": 1}
        )
        self.snapshot = self._snapshot()
        self.revocation_source = RevocationHeadSource(
            self.registry_context, self.owner_provider
        )
        self.revocation_source.snapshot = self.snapshot
        self.revocation_source.owner_pin = self.owner_pin
        self.revocation_source.clock = self.clock
        self.trust_context = self._trust_context()

    def _trust_context(self, **overrides) -> ProvenanceDeploymentTrustContext:
        values = {
            "context_id": "deployment-provenance-trust-context",
            "registry_context": self.registry_context,
            "owner_pin": self.owner_pin,
            "registry_authority_provider": self.owner_provider,
            "provider_resolver": self.resolver,
            "trusted_clock": self.clock,
            "revocation_head_source": self.revocation_source,
            "durable_context": self.durable,
            "verification_receipt_provider": self.receipt_provider,
            "test_only": True,
        }
        values.update(overrides)
        return ProvenanceDeploymentTrustContext.create(**values)

    def _owner_pin(self, provider: ProvenanceProvider) -> dict:
        return {
            "schema_id": OWNER_PIN_SCHEMA,
            "pin_id": "owner-pin-provenance-registry-1",
            "registry_id": "owner-pinned-provenance-registry",
            "registry_context": self.registry_context,
            "authority_role": PROVENANCE_REGISTRY_AUTHORITY_ROLE,
            "authority_credential_id": "credential-registry-authority",
            "provider_id": provider.provider_id,
            "algorithm": provider.algorithm,
            "key_id": provider.key_id,
            "public_key_fingerprint": provider.key_id,
            "custody_class": provider.custody_class,
            "effect_authority": False,
        }

    def _credential_inclusion(
        self,
        *,
        role: str,
        sequence: int,
        snapshot_sequence: int,
        registry_version: str,
        revocation_sequence: int,
    ) -> dict:
        credential_id = f"credential-{role.lower()}"
        provider = self.resolver.providers[(credential_id, role)]
        payload = {
            "schema_id": CREDENTIAL_INCLUSION_SCHEMA,
            "registry_id": self.owner_pin["registry_id"],
            "registry_version": registry_version,
            "registry_context": self.registry_context,
            "snapshot_sequence": snapshot_sequence,
            "inclusion_sequence": sequence,
            "credential_id": credential_id,
            "credential_digest": "",
            "signer_role": role,
            "status": ACTIVE,
            "effective_from": self.evaluation_time - 10_000,
            "effective_until": self.evaluation_time + 10_000,
            "revocation_status": ACTIVE,
            "revocation_sequence": revocation_sequence,
            "provider_id": provider.provider_id,
            "algorithm": provider.algorithm,
            "key_id": provider.key_id,
            "public_key_fingerprint": provider.key_id,
            "custody_class": provider.custody_class,
            "effect_authority": False,
            "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        payload["credential_digest"] = canonical_integrity_hash(
            {
                field: payload[field]
                for field in (
                    "credential_id",
                    "signer_role",
                    "status",
                    "effective_from",
                    "effective_until",
                    "revocation_status",
                    "revocation_sequence",
                    "provider_id",
                    "algorithm",
                    "key_id",
                    "public_key_fingerprint",
                    "custody_class",
                    "effect_authority",
                )
            }
        )
        return build_signed_object(payload, provider=self.owner_provider)

    def _snapshot(
        self,
        *,
        sequence: int = 1,
        prior_digest: str = GENESIS_HASH,
        registry_version: str = "1",
        revocation_sequence: int = 1,
    ) -> dict:
        inclusions = [
            self._credential_inclusion(
                role=role,
                sequence=index,
                snapshot_sequence=sequence,
                registry_version=registry_version,
                revocation_sequence=revocation_sequence,
            )
            for index, role in enumerate(REQUIRED_SIGNER_ROLES, start=1)
        ]
        payload = {
            "schema_id": REGISTRY_SNAPSHOT_SCHEMA,
            "registry_id": self.owner_pin["registry_id"],
            "registry_version": registry_version,
            "registry_context": self.registry_context,
            "snapshot_sequence": sequence,
            "prior_snapshot_digest": prior_digest,
            "issued_at": self.clock.value - 100,
            "effective_from": self.clock.value - 1_000,
            "effective_until": self.clock.value + 10_000,
            "status": ACTIVE,
            "revocation_sequence": revocation_sequence,
            "owner_pin_digest": canonical_integrity_hash(self.owner_pin),
            "authority_role": PROVENANCE_REGISTRY_AUTHORITY_ROLE,
            "authority_credential_id": self.owner_pin["authority_credential_id"],
            "credential_inclusions": inclusions,
            "inclusion_set_digest": canonical_integrity_hash(
                [item["digest"] for item in inclusions]
            ),
            "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        return build_signed_object(payload, provider=self.owner_provider)

    @staticmethod
    def _inclusions(snapshot: dict) -> dict[str, dict]:
        return {
            inclusion["signer_role"]: inclusion
            for inclusion in snapshot["credential_inclusions"]
        }

    def _signed_node(
        self,
        *,
        snapshot: dict,
        node_id: str,
        node_type: str,
        content_digest: str,
        sequence: int,
        recorded_at: int,
        attributes: dict,
    ) -> dict:
        role = PROVENANCE_NODE_SIGNER_ROLES[node_type]
        inclusion = self._inclusions(snapshot)[role]
        provider = self.resolver.providers[(inclusion["credential_id"], role)]
        return build_signed_object(
            {
                "node_id": node_id,
                "node_type": node_type,
                "content_digest": content_digest,
                "recorded_at": recorded_at,
                "effective_from": self.clock.value - 1_000,
                "effective_until": self.clock.value + 1_000,
                "effective_status": ACTIVE,
                "sequence": sequence,
                "revocation_status": ACTIVE,
                "revocation_sequence": inclusion["revocation_sequence"],
                "signer_role": role,
                "authority_credential_id": inclusion["credential_id"],
                "authority_credential_digest": inclusion["credential_digest"],
                "credential_inclusion_digest": inclusion["digest"],
                "attributes": attributes,
            },
            provider=provider,
        )

    def graph(
        self,
        *,
        snapshot: dict | None = None,
        sequence: int = 1,
        prior_digest: str = GENESIS_HASH,
        revocation_sequence: int = 1,
        request_fingerprint: str | None = None,
    ) -> dict:
        snapshot = snapshot or self.snapshot
        inclusions = self._inclusions(snapshot)
        source_content = canonical_integrity_hash({"authoritative_source": "source-1"})
        artifact_content = canonical_integrity_hash({"generated_artifact": "artifact-1"})
        transformation_content = canonical_integrity_hash(
            {"transformation": "extract-and-generate-v1"}
        )
        source_inclusion = inclusions[
            PROVENANCE_NODE_SIGNER_ROLES["authoritative_source"]
        ]
        source = self._signed_node(
            snapshot=snapshot,
            node_id="source-node",
            node_type="authoritative_source",
            content_digest=source_content,
            sequence=1,
            recorded_at=self.clock.value - 50,
            attributes={
                "source_authority_id": "source-authority",
                "source_authority_credential_digest": source_inclusion[
                    "credential_digest"
                ],
                "source_uri": "authority://source/1",
                "source_version": "1",
            },
        )
        transformation = self._signed_node(
            snapshot=snapshot,
            node_id="transformation-node",
            node_type="extraction_transformation_toolchain",
            content_digest=transformation_content,
            sequence=2,
            recorded_at=self.clock.value - 40,
            attributes={
                "transformation_id": "declared-transformation-1",
                "tool_id": "deterministic-extractor",
                "tool_version": "1.0.0",
                "tool_digest": canonical_integrity_hash({"tool": "1.0.0"}),
                "config_digest": canonical_integrity_hash({"config": "locked"}),
                "dependency_digests": sorted(
                    [
                        canonical_integrity_hash({"dependency": "a"}),
                        canonical_integrity_hash({"dependency": "b"}),
                    ]
                ),
                "declared_input_digest": source_content,
                "declared_output_digest": artifact_content,
            },
        )
        derivation_digest = canonical_integrity_hash(
            {
                "source_content_digest": source_content,
                "transformation_node_digest": transformation["digest"],
                "artifact_content_digest": artifact_content,
                "tool_digest": transformation["attributes"]["tool_digest"],
                "config_digest": transformation["attributes"]["config_digest"],
                "dependency_digests": transformation["attributes"][
                    "dependency_digests"
                ],
            }
        )
        artifact = self._signed_node(
            snapshot=snapshot,
            node_id="artifact-node",
            node_type="generated_artifact",
            content_digest=artifact_content,
            sequence=3,
            recorded_at=self.clock.value - 30,
            attributes={
                "artifact_id": "artifact-1",
                "artifact_version": "1",
                "derivation_digest": derivation_digest,
            },
        )
        release = self._signed_node(
            snapshot=snapshot,
            node_id="release-node",
            node_type="release_manifest",
            content_digest=self.release_manifest_digest,
            sequence=4,
            recorded_at=self.clock.value - 20,
            attributes={
                "release_id": "release-1",
                "release_version": "1",
                "release_manifest_digest": self.release_manifest_digest,
                "artifact_content_digest": artifact_content,
            },
        )
        runtime = self._signed_node(
            snapshot=snapshot,
            node_id="runtime-node",
            node_type="runtime_measurement",
            content_digest=self.runtime_measurement_digest,
            sequence=5,
            recorded_at=self.clock.value - 10,
            attributes={
                "runtime_id": "runtime-1",
                "runtime_environment_digest": canonical_integrity_hash(
                    {"runtime_environment": "measured"}
                ),
                "release_manifest_digest": self.release_manifest_digest,
                "runtime_measurement_digest": self.runtime_measurement_digest,
            },
        )
        nodes = [source, transformation, artifact, release, runtime]
        relations = (
            "SOURCE_TRANSFORMED_BY",
            "TRANSFORMATION_GENERATED",
            "ARTIFACT_DECLARED_IN_RELEASE",
            "RELEASE_MEASURED_AT_RUNTIME",
        )
        edges = [
            {
                "edge_id": f"edge-{index}",
                "sequence": index,
                "from_node_id": nodes[index - 1]["node_id"],
                "to_node_id": nodes[index]["node_id"],
                "relation": relations[index - 1],
                "from_content_digest": nodes[index - 1]["content_digest"],
                "to_content_digest": nodes[index]["content_digest"],
            }
            for index in range(1, 5)
        ]
        graph_inclusion = inclusions[PROVENANCE_GRAPH_SIGNER_ROLE]
        provider = self.resolver.providers[
            (graph_inclusion["credential_id"], PROVENANCE_GRAPH_SIGNER_ROLE)
        ]
        payload = {
            "contract_id": DIGITAL_PROVENANCE_CONTRACT_ID,
            "schema_status": DIGITAL_PROVENANCE_SCHEMA_STATUS,
            "proof_scope": DIGITAL_PROVENANCE_PROOF_SCOPE,
            "graph_id": "provenance-graph-1",
            "graph_version": "1",
            "request_fingerprint": request_fingerprint or self.request_fingerprint,
            "evaluation_time": self.clock.value,
            "sequence": sequence,
            "revocation_status": ACTIVE,
            "revocation_sequence": revocation_sequence,
            "prior_provenance_digest": prior_digest,
            "owner_pin_digest": canonical_integrity_hash(self.owner_pin),
            "registry_id": snapshot["registry_id"],
            "registry_version": snapshot["registry_version"],
            "registry_context": self.registry_context,
            "registry_snapshot_digest": snapshot["digest"],
            "signer_role": PROVENANCE_GRAPH_SIGNER_ROLE,
            "authority_credential_id": graph_inclusion["credential_id"],
            "authority_credential_digest": graph_inclusion["credential_digest"],
            "credential_inclusion_digest": graph_inclusion["digest"],
            "declared_transformation_ids": ["declared-transformation-1"],
            "nodes": nodes,
            "edges": edges,
            "release_manifest_digest": self.release_manifest_digest,
            "runtime_measurement_digest": self.runtime_measurement_digest,
            "lineage_only": True,
            **deepcopy(NO_AUTHORIZATION_EFFECT),
        }
        return build_signed_object(payload, provider=provider)

    def _resign_graph(self, graph: dict) -> dict:
        payload = {k: deepcopy(v) for k, v in graph.items() if k not in {"digest", "signature", "verified"}}
        provider = self.resolver.providers[
            (payload["authority_credential_id"], PROVENANCE_GRAPH_SIGNER_ROLE)
        ]
        return build_signed_object(payload, provider=provider)

    def _resign_node(self, node: dict) -> dict:
        payload = {k: deepcopy(v) for k, v in node.items() if k not in {"digest", "signature", "verified"}}
        provider = self.resolver.providers[
            (payload["authority_credential_id"], payload["signer_role"])
        ]
        return build_signed_object(payload, provider=provider)

    def _resign_snapshot(self, snapshot: dict) -> dict:
        payload = {k: deepcopy(v) for k, v in snapshot.items() if k not in {"digest", "signature", "verified"}}
        return build_signed_object(payload, provider=self.owner_provider)

    def verify(self, graph: dict, **overrides):
        arguments = {
            "registry_snapshot": self.snapshot,
            "trust_context": self.trust_context,
            "expected_request_fingerprint": graph.get(
                "request_fingerprint", self.request_fingerprint
            ),
            "expected_release_manifest_digest": self.release_manifest_digest,
            "expected_runtime_measurement_digest": self.runtime_measurement_digest,
        }
        arguments.update(overrides)
        if "registry_snapshot" in overrides:
            self.revocation_source.snapshot = overrides["registry_snapshot"]
        return verify_digital_provenance(graph, **arguments)

    def test_exact_lineage_receipt_is_deterministic_and_non_authorizing(self) -> None:
        first = self.graph()
        second = self.graph()
        self.assertEqual(first, second)
        decision = self.verify(first)
        self.assertEqual(decision.result, ADMIT)
        self.assertTrue(decision.admitted)
        self.assertEqual(decision.provenance_digest, first["digest"])
        self.assertTrue(is_sha512(decision.verification_receipt_digest))
        payload = {
            key: value
            for key, value in decision.verification_receipt.items()
            if key not in {"digest", "signature", "verified"}
        }
        self.assertEqual(
            decision.verification_receipt_digest,
            canonical_integrity_hash(payload),
        )
        self.assertEqual(
            decision.verification_receipt["trace_digest"],
            canonical_integrity_hash(decision.verification_trace),
        )
        self.assertTrue(
            verify_provenance_verification_receipt(
                decision.verification_receipt,
                trust_context=self.trust_context,
            )
        )
        self.assertTrue(
            is_sha512(
                decision.verification_receipt[
                    "durable_transition_receipt_digest"
                ]
            )
        )
        self.assertTrue(
            is_sha512(decision.verification_receipt["durable_live_heads_digest"])
        )
        self.assertEqual(
            [entry["sequence"] for entry in decision.verification_trace],
            list(range(1, len(decision.verification_trace) + 1)),
        )
        self.assertTrue(decision.lineage_only)
        self.assertFalse(decision.production_durable_storage_proven_by_module)
        self.assertFalse(
            decision.verification_receipt[
                "production_durable_storage_proven_by_module"
            ]
        )
        for field in NO_AUTHORIZATION_EFFECT:
            self.assertFalse(getattr(decision, field))
            self.assertFalse(decision.verification_receipt[field])

    def test_time_and_all_lineage_heads_are_not_caller_parameters(self) -> None:
        parameters = signature(verify_digital_provenance).parameters
        for forbidden in (
            "evaluation_time",
            "expected_prior_provenance_digest",
            "prior_sequence",
            "prior_revocation_sequence",
            "expected_registry_snapshot_digest",
            "expected_owner_pin",
            "expected_registry_context",
            "registry_authority_provider",
            "provider_resolver",
            "trusted_clock",
            "durable_context",
        ):
            self.assertNotIn(forbidden, parameters)
        self.assertIn("trust_context", parameters)
        graph = self.graph()
        graph["evaluation_time"] += 1
        decision = self.verify(self._resign_graph(graph))
        self.assertEqual(decision.reason, "PROVENANCE_GRAPH_BINDING_INVALID")

    def test_missing_clock_context_resolver_or_owner_authority_fails_closed(self) -> None:
        graph = self.graph()
        cases = (
            (
                replace(self.trust_context, trusted_clock=None),
                "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID",
            ),
            (
                self._trust_context(provider_resolver=None),
                "PROVENANCE_PROVIDER_RESOLVER_REQUIRED",
            ),
            (
                self._trust_context(revocation_head_source=None),
                "PROVENANCE_REVOCATION_HEAD_SOURCE_REQUIRED",
            ),
        )
        for context, reason in cases:
            with self.subTest(reason=reason):
                decision = self.verify(graph, trust_context=context)
                self.assertFalse(decision.admitted)
                self.assertEqual(decision.reason, reason)

    def test_owner_pin_context_and_rogue_snapshot_authority_fail_closed(self) -> None:
        graph = self.graph()
        pin = deepcopy(self.owner_pin)
        pin["registry_context"] = "attacker-context"
        context = self._trust_context(owner_pin=pin)
        decision = self.verify(graph, trust_context=context)
        self.assertEqual(decision.reason, "PROVENANCE_OWNER_PIN_INVALID")

        rogue = ProvenanceProvider("rogue-registry-authority", registry_authority=True)
        rogue_snapshot = deepcopy(self.snapshot)
        rogue_snapshot = build_signed_object(
            {k: v for k, v in rogue_snapshot.items() if k not in {"digest", "signature", "verified"}},
            provider=rogue,
        )
        decision = self.verify(graph, registry_snapshot=rogue_snapshot)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_REGISTRY_SNAPSHOT_SIGNATURE_INVALID",
        )

    def test_fully_malicious_resolver_cannot_install_its_provider(self) -> None:
        graph = self.graph()
        inclusion = self._inclusions(self.snapshot)[PROVENANCE_GRAPH_SIGNER_ROLE]
        rogue = ProvenanceProvider(PROVENANCE_GRAPH_SIGNER_ROLE)
        self.resolver.providers[
            (inclusion["credential_id"], PROVENANCE_GRAPH_SIGNER_ROLE)
        ] = rogue
        decision = self.verify(graph)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reason, "PROVENANCE_PROVIDER_PUBLIC_KEY_MISMATCH")

    def test_whole_consistent_attacker_bundle_cannot_replace_fixed_context(self) -> None:
        original_owner = self.owner_provider
        original_resolver = self.resolver
        original_pin = self.owner_pin
        original_snapshot = self.snapshot
        attacker_owner = ProvenanceProvider(
            "attacker-registry-authority", registry_authority=True
        )
        attacker_resolver = ProviderResolver(self.registry_context)
        for role in REQUIRED_SIGNER_ROLES:
            attacker_resolver.providers[
                (f"credential-{role.lower()}", role)
            ] = ProvenanceProvider(f"attacker-{role}")
        self.owner_provider = attacker_owner
        self.resolver = attacker_resolver
        self.owner_pin = self._owner_pin(attacker_owner)
        attacker_snapshot = self._snapshot()
        attacker_graph = self.graph(snapshot=attacker_snapshot)
        self.owner_provider = original_owner
        self.resolver = original_resolver
        self.owner_pin = original_pin
        self.snapshot = original_snapshot

        decision = self.verify(
            attacker_graph, registry_snapshot=attacker_snapshot
        )
        self.assertFalse(decision.admitted)
        self.assertIn(
            decision.reason,
            {
                "PROVENANCE_REGISTRY_SNAPSHOT_INVALID",
                "PROVENANCE_REGISTRY_SNAPSHOT_SIGNATURE_INVALID",
            },
        )

    def test_time_varying_provider_key_cannot_substitute_after_admission(self) -> None:
        graph = self.graph()
        inclusion = self._inclusions(self.snapshot)[PROVENANCE_GRAPH_SIGNER_ROLE]
        key = (inclusion["credential_id"], PROVENANCE_GRAPH_SIGNER_ROLE)
        pinned = self.resolver.providers[key]
        varying = TimeVaryingKeyProvider(
            pinned, ProvenanceProvider("time-varying-rogue")
        )
        self.resolver.providers[key] = varying
        forged = build_signed_object(
            {
                field: deepcopy(value)
                for field, value in graph.items()
                if field not in {"digest", "signature", "verified"}
            },
            provider=varying,
        )
        decision = self.verify(forged)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reason, "PROVENANCE_GRAPH_SIGNATURE_INVALID")

    def test_initial_high_revocation_sequence_cannot_poison_durable_head(self) -> None:
        graph = self.graph(revocation_sequence=999_999)
        decision = self.verify(graph)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reason, "PROVENANCE_GRAPH_BINDING_INVALID")
        self.assertIsNone(self.durable.registry_head)

    def test_non_durable_in_memory_context_is_rejected(self) -> None:
        class NonDurableContext(DurableAtomicContext):
            production_durable_storage_admitted = False
            durable_storage_class = "IN_MEMORY"

        context = NonDurableContext(self.durable_provider)
        trust_context = self._trust_context(durable_context=context)
        decision = self.verify(self.graph(), trust_context=trust_context)
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"
        )

    def test_production_mode_rejects_test_only_self_attested_store(self) -> None:
        production_context = self._trust_context(test_only=False)
        decision = self.verify(
            self.graph(), trust_context=production_context
        )
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"
        )

    def test_mid_verification_clock_or_revocation_advance_fails_closed(self) -> None:
        self.clock.advance_on_call = 2
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED",
        )

        self.setUp()
        self.revocation_source.advance_on_call = 2
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertIn(
            decision.reason,
            {
                "PROVENANCE_REVOCATION_HEAD_BINDING_INVALID",
                "PROVENANCE_LIVE_CLOCK_OR_REVOCATION_HEAD_CHANGED",
            },
        )

    def test_fabricated_durable_previous_heads_fail_closed(self) -> None:
        self.durable.fabricate_previous_stream = True
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DURABLE_TRANSITION_HEAD_INVALID"
        )

        self.setUp()
        first = self.graph()
        self.assertTrue(self.verify(first).admitted)
        snapshot_two = self._snapshot(
            sequence=2,
            prior_digest=self.snapshot["digest"],
            registry_version="2",
            revocation_sequence=2,
        )
        self.clock.value += 1
        self.clock.clock_sequence += 1
        second = self.graph(
            snapshot=snapshot_two,
            sequence=2,
            prior_digest=first["digest"],
            revocation_sequence=2,
            request_fingerprint=canonical_integrity_hash(
                {"request": "fabricated-non-genesis-previous-head"}
            ),
        )
        self.durable.fabricate_previous_stream = True
        decision = self.verify(second, registry_snapshot=snapshot_two)
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DURABLE_TRANSITION_HEAD_INVALID"
        )

        self.setUp()
        self.durable.fabricate_previous_registry = True
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DURABLE_TRANSITION_HEAD_INVALID"
        )

    def test_malformed_unsupported_evidence_deterministically_denies(self) -> None:
        graph = self.graph()
        graph["request_fingerprint"] = object()
        decision = self.verify(graph)
        self.assertFalse(decision.admitted)
        self.assertEqual(decision.reason, "PROVENANCE_EXPECTATION_INVALID")
        self.assertTrue(
            verify_provenance_verification_receipt(
                decision.verification_receipt,
                trust_context=self.trust_context,
            )
        )

        class MaliciousPropertiesProvider:
            provenance_attestation_admitted = True
            effect_authority = False

            @property
            def provider_id(self):
                raise RuntimeError("MALICIOUS_PROPERTY")

            @property
            def public_key(self):
                raise RuntimeError("MALICIOUS_PROPERTY")

        role = PROVENANCE_NODE_SIGNER_ROLES["runtime_measurement"]
        inclusion = self._inclusions(self.snapshot)[role]
        valid_graph = self.graph()
        self.resolver.providers[
            (inclusion["credential_id"], role)
        ] = MaliciousPropertiesProvider()
        decision = self.verify(valid_graph)
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_PROVIDER_PUBLIC_KEY_MISMATCH"
        )

        self.setUp()
        unsupported_snapshot = deepcopy(self.snapshot)
        unsupported_snapshot["credential_inclusions"][0]["provider_id"] = object()
        decision = self.verify(
            self.graph(), registry_snapshot=unsupported_snapshot
        )
        self.assertFalse(decision.admitted)
        self.assertIn(
            decision.reason,
            {
                "PROVENANCE_REGISTRY_SNAPSHOT_SIGNATURE_INVALID",
                "PROVENANCE_CREDENTIAL_INCLUSION_INACTIVE_OR_INVALID",
            },
        )

    def test_signed_transition_without_persisted_claim_fails_closed(self) -> None:
        self.durable.is_claimed = lambda *, claim_digest: False
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_DURABLE_CLAIM_NOT_PERSISTED"
        )

    def test_live_revocation_head_tamper_fails_closed(self) -> None:
        original = self.revocation_source.current_revocation_head

        def tampered_head(*, registry_id: str, registry_context: str) -> dict:
            head = original(
                registry_id=registry_id,
                registry_context=registry_context,
            )
            head["revocation_sequence"] += 1
            return head

        self.revocation_source.current_revocation_head = tampered_head
        decision = self.verify(self.graph())
        self.assertFalse(decision.admitted)
        self.assertEqual(
            decision.reason, "PROVENANCE_REVOCATION_HEAD_BINDING_INVALID"
        )

    def test_signed_verification_receipt_forgery_is_rejected(self) -> None:
        decision = self.verify(self.graph())
        self.assertTrue(decision.admitted)
        tampered = deepcopy(decision.verification_receipt)
        tampered["reason"] = "FORGED_ALLOW"
        self.assertFalse(
            verify_provenance_verification_receipt(
                tampered, trust_context=self.trust_context
            )
        )
        rogue = ProvenanceProvider(
            "rogue-receipt-authority", receipt_authority=True
        )
        forged = build_signed_object(
            {
                field: deepcopy(value)
                for field, value in decision.verification_receipt.items()
                if field not in {"digest", "signature", "verified"}
            },
            provider=rogue,
        )
        self.assertFalse(
            verify_provenance_verification_receipt(
                forged, trust_context=self.trust_context
            )
        )

    def test_snapshot_tamper_and_signed_bundle_with_tampered_inclusion_fail(self) -> None:
        graph = self.graph()
        snapshot = deepcopy(self.snapshot)
        snapshot["revocation_sequence"] = 99
        decision = self.verify(graph, registry_snapshot=snapshot)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_REGISTRY_SNAPSHOT_SIGNATURE_INVALID",
        )

        snapshot = deepcopy(self.snapshot)
        encoded = snapshot["credential_inclusions"][0]["signature"]["signature_b64"]
        snapshot["credential_inclusions"][0]["signature"]["signature_b64"] = (
            ("A" if encoded[0] != "A" else "B") + encoded[1:]
        )
        snapshot["inclusion_set_digest"] = canonical_integrity_hash(
            [item["digest"] for item in snapshot["credential_inclusions"]]
        )
        snapshot = self._resign_snapshot(snapshot)
        decision = self.verify(graph, registry_snapshot=snapshot)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_CREDENTIAL_INCLUSION_SIGNATURE_INVALID",
        )

    def test_provider_actual_public_key_must_match_signed_inclusion(self) -> None:
        graph = self.graph()
        role = PROVENANCE_NODE_SIGNER_ROLES["runtime_measurement"]
        inclusion = self._inclusions(self.snapshot)[role]
        self.resolver.providers[(inclusion["credential_id"], role)] = ProvenanceProvider(role)
        decision = self.verify(graph)
        self.assertEqual(decision.reason, "PROVENANCE_PROVIDER_PUBLIC_KEY_MISMATCH")

    def test_historical_replay_fails_even_with_identical_signed_expectations(self) -> None:
        graph = self.graph()
        self.assertTrue(self.verify(graph).admitted)
        replay = self.verify(graph)
        self.assertFalse(replay.admitted)
        self.assertEqual(replay.reason, "PROVENANCE_DURABLE_CLAIM_REPLAY")
        self.assertEqual(
            replay.verification_receipt["durable_claim_result"],
            DURABLE_ALREADY_CLAIMED,
        )

    def test_provenance_sequence_and_revocation_rollback_fail_atomically(self) -> None:
        graph1 = self.graph()
        self.assertTrue(self.verify(graph1).admitted)
        snapshot2 = self._snapshot(
            sequence=2,
            prior_digest=self.snapshot["digest"],
            registry_version="2",
            revocation_sequence=2,
        )
        self.clock.value += 1
        graph2 = self.graph(
            snapshot=snapshot2,
            sequence=2,
            prior_digest=graph1["digest"],
            revocation_sequence=2,
            request_fingerprint=canonical_integrity_hash({"request": 2}),
        )
        self.assertTrue(
            self.verify(graph2, registry_snapshot=snapshot2).admitted
        )

        rolled_back = self.graph(
            snapshot=snapshot2,
            sequence=1,
            prior_digest=GENESIS_HASH,
            revocation_sequence=2,
            request_fingerprint=canonical_integrity_hash({"request": "rollback-seq"}),
        )
        decision = self.verify(rolled_back, registry_snapshot=snapshot2)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_ROLLBACK",
        )

        revocation_rollback = self.graph(
            snapshot=snapshot2,
            sequence=3,
            prior_digest=graph2["digest"],
            revocation_sequence=1,
            request_fingerprint=canonical_integrity_hash({"request": "rollback-rev"}),
        )
        decision = self.verify(revocation_rollback, registry_snapshot=snapshot2)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_GRAPH_BINDING_INVALID",
        )

    def test_registry_snapshot_rollback_and_prior_head_conflict_fail(self) -> None:
        graph1 = self.graph()
        self.assertTrue(self.verify(graph1).admitted)
        snapshot2 = self._snapshot(
            sequence=2,
            prior_digest=self.snapshot["digest"],
            registry_version="2",
            revocation_sequence=2,
        )
        self.clock.value += 1
        graph2 = self.graph(
            snapshot=snapshot2,
            sequence=2,
            prior_digest=graph1["digest"],
            revocation_sequence=2,
            request_fingerprint=canonical_integrity_hash({"request": 2}),
        )
        self.assertTrue(self.verify(graph2, registry_snapshot=snapshot2).admitted)

        historical = self.graph(
            snapshot=self.snapshot,
            sequence=3,
            prior_digest=graph2["digest"],
            revocation_sequence=1,
            request_fingerprint=canonical_integrity_hash({"request": "old-snapshot"}),
        )
        decision = self.verify(historical, registry_snapshot=self.snapshot)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_ROLLBACK",
        )

        bad_snapshot = self._snapshot(
            sequence=3,
            prior_digest=canonical_integrity_hash({"wrong": "snapshot-head"}),
            registry_version="3",
            revocation_sequence=3,
        )
        graph3 = self.graph(
            snapshot=bad_snapshot,
            sequence=3,
            prior_digest=graph2["digest"],
            revocation_sequence=3,
            request_fingerprint=canonical_integrity_hash({"request": 3}),
        )
        decision = self.verify(graph3, registry_snapshot=bad_snapshot)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_CONFLICT",
        )

    def test_trusted_clock_rollback_is_rejected_by_durable_context(self) -> None:
        graph1 = self.graph()
        self.assertTrue(self.verify(graph1).admitted)
        self.clock.value -= 1
        graph2 = self.graph(
            sequence=2,
            prior_digest=graph1["digest"],
            revocation_sequence=1,
            request_fingerprint=canonical_integrity_hash({"request": "clock-rollback"}),
        )
        decision = self.verify(graph2)
        self.assertEqual(
            decision.reason,
            "PROVENANCE_DURABLE_SEQUENCE_OR_HEAD_ROLLBACK",
        )

    def test_missing_duplicate_reordered_or_extra_nodes_fail_closed(self) -> None:
        base = self.graph()
        mutations = []
        missing = deepcopy(base)
        missing["nodes"].pop()
        mutations.append(missing)
        duplicate = deepcopy(base)
        duplicate["nodes"][-1] = deepcopy(duplicate["nodes"][0])
        mutations.append(duplicate)
        reordered = deepcopy(base)
        reordered["nodes"][0], reordered["nodes"][1] = (
            reordered["nodes"][1],
            reordered["nodes"][0],
        )
        mutations.append(reordered)
        extra = deepcopy(base)
        extra["nodes"].append(deepcopy(extra["nodes"][-1]))
        mutations.append(extra)
        for mutation in mutations:
            with self.subTest(nodes=len(mutation["nodes"])):
                self.assertFalse(self.verify(self._resign_graph(mutation)).admitted)

    def test_edge_reorder_or_orphan_and_undeclared_transformation_fail(self) -> None:
        graph = self.graph()
        graph["edges"].reverse()
        self.assertFalse(self.verify(self._resign_graph(graph)).admitted)

        graph = self.graph()
        graph["edges"][0]["to_node_id"] = "orphan-node"
        self.assertFalse(self.verify(self._resign_graph(graph)).admitted)

        graph = self.graph()
        graph["declared_transformation_ids"] = ["attacker-transformation"]
        decision = self.verify(self._resign_graph(graph))
        self.assertEqual(decision.reason, "PROVENANCE_UNDECLARED_TRANSFORMATION")

    def test_node_signature_tamper_and_graph_authority_claim_fail_closed(self) -> None:
        graph = self.graph()
        graph["nodes"][0]["content_digest"] = "0" * 128
        self.assertFalse(self.verify(graph).admitted)

        graph = self.graph()
        graph["governance_allow_granted"] = True
        decision = self.verify(self._resign_graph(graph))
        self.assertEqual(decision.reason, "PROVENANCE_SCOPE_OR_AUTHORITY_INVALID")

    def test_indeterminate_clock_resolver_or_durable_context_fails_closed(self) -> None:
        graph = self.graph()
        self.clock.raise_error = True
        self.assertEqual(
            self.verify(graph).reason,
            "PROVENANCE_TRUSTED_CLOCK_INDETERMINATE",
        )
        self.clock.raise_error = False
        self.resolver.raise_error = True
        self.assertEqual(
            self.verify(graph).reason,
            "PROVENANCE_PROVIDER_RESOLUTION_INDETERMINATE",
        )
        self.resolver.raise_error = False
        self.durable.raise_error = True
        self.assertEqual(
            self.verify(graph).reason,
            "PROVENANCE_DURABLE_CONTEXT_INDETERMINATE",
        )


if __name__ == "__main__":
    unittest.main()
