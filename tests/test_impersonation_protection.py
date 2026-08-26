from __future__ import annotations

from copy import deepcopy
from hashlib import sha512
import os
import unittest
from unittest.mock import patch

os.environ["SBP_LEX_IMPERSONATION_RUNTIME_MODE"] = "TEST_ONLY"

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.governance.three_p_doctrine import THREE_P_DOCTRINE_ID
import sbp_lex.identity.impersonation_protection as impersonation_module
from sbp_lex.identity.impersonation_protection import (
    AUTHORITY_BOUNDARY_COMPONENT,
    CLOCK_HEAD_SCHEMA,
    CLOCK_HEAD_TRANSITION_SCHEMA,
    CLOCK_RECORD_SCHEMA,
    DEPLOYMENT_DEPENDENCIES,
    IMPERSONATION_DENY,
    IMPERSONATION_PASS,
    IMPERSONATION_PROTECTION_CONTRACT_ID,
    IMPERSONATION_PROTECTION_SCHEMA_STATUS,
    IMPERSONATION_PROTECTION_SEMANTICS,
    ImpersonationTrustContext,
    LIVE_REGISTRY_SCHEMA,
    NO_AUTHORIZATION_EFFECT,
    POSSESSION_PROOF_SCHEMA,
    REPLAY_CLAIMED,
    REPLAY_HEAD_SCHEMA,
    REPLAY_PERSISTENCE_SCHEMA,
    SOVEREIGN_IDENTITY_COMPONENT,
    TRUST_ACTIVE,
    TRUST_CONTEXT_SCHEMA,
    TRUST_REVOKED,
    evaluate_impersonation_protection,
    impersonation_protection_hash_payload,
    impersonation_upstream_hash_payload,
    verify_impersonation_protection,
    _install_test_only_impersonation_deployment_pins,
    _register_test_only_impersonation_composition_boundary,
    _reset_test_only_impersonation_composition_boundaries,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import (
    build_legacy_non_effect_signed_object as build_signed_object,
    verify_legacy_non_effect_signed_object,
)


TEST_ONLY_FIXTURE_CLASS = "TEST_ONLY_NONPRODUCTION_FIXTURE"


class Ed25519FixtureProvider:
    fixture_class = TEST_ONLY_FIXTURE_CLASS
    algorithm = "Ed25519"
    custody_class = "NONPRODUCTION_EVIDENCE_ONLY"
    token_signing_admitted = True
    effect_authority = False

    def __init__(self, provider_id: str) -> None:
        self._key = Ed25519PrivateKey.generate()
        self.key_unavailable = False
        public = self._key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.provider_id = provider_id
        self.key_id = sha512(public).hexdigest()

    @property
    def public_key(self):
        if self.key_unavailable:
            raise RuntimeError("TEST_ONLY_PUBLIC_KEY_UNAVAILABLE")
        return self._key.public_key()

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        if key_id != self.key_id:
            raise ValueError("KEY_ID_MISMATCH")
        return self._key.sign(message)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        if key_id != self.key_id:
            return False
        try:
            self._key.public_key().verify(signature, message)
        except InvalidSignature:
            return False
        return True


def provider_binding(provider: Ed25519FixtureProvider) -> dict:
    return {
        "provider_id": provider.provider_id,
        "algorithm": provider.algorithm,
        "key_id": provider.key_id,
        "custody_class": provider.custody_class,
        "effect_authority": False,
        "ed25519_public_key_fingerprint": provider.key_id,
    }


class FixedClockFixture:
    fixture_class = TEST_ONLY_FIXTURE_CLASS
    clock_id = "university-evidence-clock"
    clock_version = "1"

    def __init__(
        self,
        now_ms: int,
        provider: Ed25519FixtureProvider,
    ) -> None:
        self.now = now_ms
        self.unavailable = False
        self.provider = provider
        self.provider_id = provider.provider_id
        self.algorithm = provider.algorithm
        self.key_id = provider.key_id
        self.custody_class = provider.custody_class
        self.token_signing_admitted = True
        self.effect_authority = False
        self.clock_sequence = 1
        self.prior_clock_record_digest = GENESIS_HASH
        self.record_mutation = None

    @property
    def public_key(self):
        return self.provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self.provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self.provider.verify(message, signature, key_id=key_id)

    def current_time_record(
        self,
        *,
        context_id: str,
        context_digest: str,
    ) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_CLOCK_UNAVAILABLE")
        payload = {
            "schema": CLOCK_RECORD_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": context_id,
            "context_digest": context_digest,
            "clock_id": self.clock_id,
            "clock_version": self.clock_version,
            "clock_sequence": self.clock_sequence,
            "prior_clock_record_digest": self.prior_clock_record_digest,
            "now_ms": self.now,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        if self.record_mutation is not None:
            self.record_mutation(payload)
        return build_signed_object(payload, provider=self)

    def advance(self, *, context_id: str, context_digest: str) -> None:
        current = self.current_time_record(
            context_id=context_id,
            context_digest=context_digest,
        )
        self.prior_clock_record_digest = canonical_integrity_hash(current)
        self.clock_sequence += 1
        self.now += 1


class DurableClockHeadFixture:
    fixture_class = TEST_ONLY_FIXTURE_CLASS
    head_id = "university-durable-clock-head"
    head_version = "1"

    def __init__(self, provider: Ed25519FixtureProvider) -> None:
        self.provider = provider
        self.provider_id = provider.provider_id
        self.algorithm = provider.algorithm
        self.key_id = provider.key_id
        self.custody_class = provider.custody_class
        self.token_signing_admitted = True
        self.effect_authority = False
        self.unavailable = False
        self.head_sequence = 0
        self.clock_sequence = 0
        self.clock_record_digest = GENESIS_HASH
        self.prior_clock_record_digest = GENESIS_HASH
        self.latest_transition_receipt_digest = GENESIS_HASH
        self.observed_at_ms = 0
        self.transition_mutation = None
        self.head_mutation = None
        self.head_mutation_on_read = None
        self.head_read_count = 0

    @property
    def public_key(self):
        return self.provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self.provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self.provider.verify(message, signature, key_id=key_id)

    def current_head(self, *, context_id: str, context_digest: str) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_CLOCK_HEAD_UNAVAILABLE")
        self.head_read_count += 1
        payload = {
            "schema": CLOCK_HEAD_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": context_id,
            "context_digest": context_digest,
            "head_id": self.head_id,
            "head_version": self.head_version,
            "head_sequence": self.head_sequence,
            "clock_sequence": self.clock_sequence,
            "clock_record_digest": self.clock_record_digest,
            "prior_clock_record_digest": self.prior_clock_record_digest,
            "latest_transition_receipt_digest": (
                self.latest_transition_receipt_digest
            ),
            "observed_at_ms": self.observed_at_ms,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        if self.head_mutation is not None and (
            self.head_mutation_on_read is None
            or self.head_read_count == self.head_mutation_on_read
        ):
            self.head_mutation(payload)
        return build_signed_object(payload, provider=self)

    def advance_once(self, *, transition: dict) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_CLOCK_HEAD_UNAVAILABLE")
        receipt_payload = deepcopy(transition)
        if self.transition_mutation is not None:
            self.transition_mutation(receipt_payload)
        receipt = build_signed_object(receipt_payload, provider=self)
        if receipt_payload == transition:
            self.head_sequence = transition["head_sequence"]
            self.clock_sequence = transition["clock_sequence"]
            self.clock_record_digest = transition["clock_record_digest"]
            self.prior_clock_record_digest = transition[
                "prior_clock_record_digest"
            ]
            self.latest_transition_receipt_digest = canonical_integrity_hash(
                receipt
            )
            self.observed_at_ms = transition["observed_at_ms"]
        return receipt


class AuthenticatedUpstreamVerifierFixture:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(
        self,
        component_id: str,
        provider: Ed25519FixtureProvider,
    ) -> None:
        self.component_id = component_id
        self.provider = provider
        self.verifier_id = f"university-evidence-{component_id}-verifier"
        self.verifier_version = "1"
        self.unavailable = False
        self.receipt_mutation = None
        self.return_boolean = False

    def verify_authenticated(
        self,
        *,
        state: dict,
        dependencies: object,
        expected_receipt: dict,
    ) -> dict | bool:
        if self.unavailable or dependencies is not self.provider:
            return False
        if self.component_id == SOVEREIGN_IDENTITY_COMPONENT:
            trace = state.get("sovereign_identity_trace")
            record = state.get("sovereign_identity_record")
            expected_result = "VERIFIED"
            expected_digest = canonical_integrity_hash(trace)
            actual_digest = state.get("sovereign_identity_digest")
            false_fields = (
                "biometric_proof_established",
                "access_granted",
                "authority_granted",
                "licence_granted",
                "execution_authority_granted",
                "effect_authority_granted",
            )
        else:
            trace = state.get("authority_boundary_trace")
            record = state.get("authority_boundary_record")
            expected_result = "BOUNDARY_PASS"
            expected_digest = canonical_integrity_hash(record)
            actual_digest = state.get("authority_boundary_digest")
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
            or set(record)
            != {
                "component_id",
                "result",
                "request_fingerprint",
                "evaluation_time",
                "signed_evidence",
                *false_fields,
            }
            or record["component_id"] != self.component_id
            or record["result"] != expected_result
            or record["request_fingerprint"] != state.get("request_fingerprint")
            or record["evaluation_time"] != state.get("evaluation_time")
            or any(record[field] is not False for field in false_fields)
            or actual_digest != expected_digest
        ):
            return False
        source = record["signed_evidence"]
        authenticated = (
            verify_legacy_non_effect_signed_object(
                source,
                provider=self.provider,
            )
            and source.get("component_id") == self.component_id
            and source.get("result") == expected_result
            and source.get("request_fingerprint")
            == state.get("request_fingerprint")
            and source.get("evaluation_time") == state.get("evaluation_time")
            and source.get("authorization_effect") == NO_AUTHORIZATION_EFFECT
        )
        if not authenticated or self.return_boolean:
            return authenticated
        receipt = deepcopy(expected_receipt)
        if self.receipt_mutation is not None:
            self.receipt_mutation(receipt)
        return build_signed_object(receipt, provider=self.provider)


class LiveRegistryFixture:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(self, context_record: dict, provider: Ed25519FixtureProvider) -> None:
        self.context_record = context_record
        self.provider = provider
        self.registry_sequence = 7
        self.authority_sequence = 11
        self.revocation_status = TRUST_ACTIVE
        self.revocation_sequence = 3
        self.valid_from_ms = 900
        self.valid_until_ms = 1_200
        self.unavailable = False
        self.mutation = None

    def lookup_identity(self, *, subject_id: str, participant_id: str) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_REGISTRY_UNAVAILABLE")
        payload = {
            "schema": LIVE_REGISTRY_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
            "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
            "context_id": self.context_record["context_id"],
            "context_digest": self.context_record["digest"],
            "registry_id": self.context_record["registry_id"],
            "registry_sequence": self.registry_sequence,
            "subject_id": subject_id,
            "participant_id": participant_id,
            "stakeholder_class": self.context_record["stakeholder_class"],
            "role_id": self.context_record["role_id"],
            "mandate_id": self.context_record["mandate_id"],
            "mandate_actions": deepcopy(self.context_record["mandate_actions"]),
            "mandate_jurisdictions": deepcopy(
                self.context_record["mandate_jurisdictions"]
            ),
            "jurisdiction": self.context_record["jurisdiction"],
            "subject_provider_binding": deepcopy(
                self.context_record["subject_provider_binding"]
            ),
            "authority_sequence": self.authority_sequence,
            "revocation_status": self.revocation_status,
            "revocation_sequence": self.revocation_sequence,
            "valid_from_ms": self.valid_from_ms,
            "valid_until_ms": self.valid_until_ms,
        }
        if self.mutation is not None:
            self.mutation(payload)
        return build_signed_object(payload, provider=self.provider)


class DurableReplayGuardFixture:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(
        self,
        context_record: dict,
        provider: Ed25519FixtureProvider,
    ) -> None:
        self.context_record = context_record
        self.provider = provider
        self.registry_sequence = 0
        self.authority_sequence = 0
        self.revocation_sequence = 0
        self.claim_sequence = 0
        self.latest_receipt_digest = GENESIS_HASH
        self.claims: dict[tuple[str, str], str] = {}
        self.receipts: dict[str, dict] = {}
        self.unavailable = False
        self.force_is_claimed_false = False
        self.head_mutation = None
        self.receipt_mutation = None
        self.persistence_mutation = None

    def current_head(
        self,
        *,
        namespace: str,
        subject_binding_digest: str,
        observed_at_ms: int,
    ) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_REPLAY_STORE_UNAVAILABLE")
        payload = {
            "schema": REPLAY_HEAD_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": self.context_record["context_id"],
            "context_digest": self.context_record["digest"],
            "namespace": namespace,
            "subject_binding_digest": subject_binding_digest,
            "registry_sequence": self.registry_sequence,
            "authority_sequence": self.authority_sequence,
            "revocation_sequence": self.revocation_sequence,
            "claim_sequence": self.claim_sequence,
            "latest_claim_receipt_digest": self.latest_receipt_digest,
            "observed_at_ms": observed_at_ms,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        if self.head_mutation is not None:
            self.head_mutation(payload)
        return build_signed_object(payload, provider=self.provider)

    def claim_once(self, *, claim: dict) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_REPLAY_STORE_UNAVAILABLE")
        key = (claim["namespace"], claim["replay_key"])
        if key in self.claims:
            return deepcopy(self.receipts[self.claims[key]])
        if (
            claim["claim_sequence"] != self.claim_sequence + 1
            or claim["prior_claim_receipt_digest"]
            != self.latest_receipt_digest
            or claim["registry_sequence"] < self.registry_sequence
            or claim["authority_sequence"] < self.authority_sequence
            or claim["revocation_sequence"] < self.revocation_sequence
        ):
            raise RuntimeError("TEST_ONLY_NONMONOTONIC_CLAIM")
        payload = deepcopy(claim)
        if self.receipt_mutation is not None:
            self.receipt_mutation(payload)
        receipt = build_signed_object(payload, provider=self.provider)
        digest = canonical_integrity_hash(receipt)
        self.registry_sequence = claim["registry_sequence"]
        self.authority_sequence = claim["authority_sequence"]
        self.revocation_sequence = claim["revocation_sequence"]
        self.claim_sequence = claim["claim_sequence"]
        self.latest_receipt_digest = digest
        self.claims[key] = digest
        self.receipts[digest] = deepcopy(receipt)
        return receipt

    def is_claimed(
        self,
        *,
        namespace: str,
        replay_key: str,
        receipt_digest: str,
        subject_binding_digest: str,
        observed_at_ms: int,
        current_head_digest: str,
    ) -> dict:
        if self.unavailable:
            raise RuntimeError("TEST_ONLY_REPLAY_STORE_UNAVAILABLE")
        persisted = (
            not self.force_is_claimed_false
            and self.claims.get((namespace, replay_key)) == receipt_digest
            and receipt_digest in self.receipts
        )
        receipt = self.receipts.get(receipt_digest, {})
        payload = {
            "schema": REPLAY_PERSISTENCE_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": self.context_record["context_id"],
            "context_digest": self.context_record["digest"],
            "namespace": namespace,
            "replay_key": replay_key,
            "claim_receipt_digest": receipt_digest,
            "subject_binding_digest": subject_binding_digest,
            "claim_sequence": receipt.get("claim_sequence", -1),
            "current_head_digest": current_head_digest,
            "registry_sequence": self.registry_sequence,
            "authority_sequence": self.authority_sequence,
            "revocation_sequence": self.revocation_sequence,
            "observed_at_ms": observed_at_ms,
            "persisted": persisted,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }
        if self.persistence_mutation is not None:
            self.persistence_mutation(payload)
        return build_signed_object(payload, provider=self.provider)


class ImpersonationProtectionTests(unittest.TestCase):
    now = 1_000

    def setUp(self) -> None:
        _reset_test_only_impersonation_composition_boundaries()
        self.owner_provider = Ed25519FixtureProvider("university-owner")
        self.registry_provider = Ed25519FixtureProvider("university-registry")
        self.subject_provider = Ed25519FixtureProvider("university-subject")
        self.replay_provider = Ed25519FixtureProvider("university-replay")
        self.sovereign_provider = Ed25519FixtureProvider(
            "university-sovereign-evidence"
        )
        self.boundary_provider = Ed25519FixtureProvider(
            "university-boundary-evidence"
        )
        self.clock_provider = Ed25519FixtureProvider("university-clock")
        self.clock = FixedClockFixture(self.now, self.clock_provider)
        self.clock_head_signer = Ed25519FixtureProvider(
            "university-durable-clock-head"
        )
        self.clock_head = DurableClockHeadFixture(self.clock_head_signer)
        self.pseudonym_key = b"university-test-only-pseudonym-key-0001"
        self.sovereign_verifier = AuthenticatedUpstreamVerifierFixture(
            SOVEREIGN_IDENTITY_COMPONENT,
            self.sovereign_provider,
        )
        self.boundary_verifier = AuthenticatedUpstreamVerifierFixture(
            AUTHORITY_BOUNDARY_COMPONENT,
            self.boundary_provider,
        )
        payload = self.context_payload()
        self.context_record = build_signed_object(
            payload,
            provider=self.owner_provider,
        )
        self.registry = LiveRegistryFixture(
            self.context_record,
            self.registry_provider,
        )
        self.replay = DurableReplayGuardFixture(
            self.context_record,
            self.replay_provider,
        )
        _install_test_only_impersonation_deployment_pins(
            context_id=self.context_record["context_id"],
            context_digest=self.context_record["digest"],
            owner_public_key_hex=self.owner_provider.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex(),
        )
        self.register_composition()
        self.context = self.make_context()

    def register_composition(self) -> None:
        _register_test_only_impersonation_composition_boundary(
            signed_context_record=self.context_record,
            owner_provider=self.owner_provider,
            registry_provider=self.registry_provider,
            subject_provider=self.subject_provider,
            replay_provider=self.replay_provider,
            registry=self.registry,
            replay_guard=self.replay,
            sovereign_identity_verifier=self.sovereign_verifier,
            sovereign_identity_dependencies=self.sovereign_provider,
            authority_boundary_verifier=self.boundary_verifier,
            authority_boundary_dependencies=self.boundary_provider,
            trusted_clock=self.clock,
            clock_head_provider=self.clock_head,
            pseudonym_key=self.pseudonym_key,
        )

    def register_attacker_composition(self) -> None:
        attacker_owner = Ed25519FixtureProvider("attacker-first-owner")
        payload = self.context_payload()
        payload["context_id"] = "attacker-first-context"
        payload["owner_id"] = "attacker-first-owner"
        payload["owner_provider_binding"] = provider_binding(attacker_owner)
        attacker_record = build_signed_object(payload, provider=attacker_owner)
        _register_test_only_impersonation_composition_boundary(
            signed_context_record=attacker_record,
            owner_provider=attacker_owner,
            registry_provider=self.registry_provider,
            subject_provider=self.subject_provider,
            replay_provider=self.replay_provider,
            registry=self.registry,
            replay_guard=self.replay,
            sovereign_identity_verifier=self.sovereign_verifier,
            sovereign_identity_dependencies=self.sovereign_provider,
            authority_boundary_verifier=self.boundary_verifier,
            authority_boundary_dependencies=self.boundary_provider,
            trusted_clock=self.clock,
            clock_head_provider=self.clock_head,
            pseudonym_key=b"attacker-first-pseudonym-key-material",
        )

    def context_payload(self) -> dict:
        return {
            "schema": TRUST_CONTEXT_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
            "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
            "three_p_doctrine_id": THREE_P_DOCTRINE_ID,
            "context_id": "deployment-impersonation-context-one",
            "context_version": "1",
            "context_sequence": 1,
            "prior_context_digest": GENESIS_HASH,
            "owner_id": "deployment-owner-one",
            "registry_id": "deployment-registry-one",
            "owner_provider_binding": provider_binding(self.owner_provider),
            "registry_provider_binding": provider_binding(self.registry_provider),
            "subject_provider_binding": provider_binding(self.subject_provider),
            "replay_provider_binding": provider_binding(self.replay_provider),
            "clock_provider_binding": provider_binding(self.clock),
            "clock_head_provider_binding": provider_binding(self.clock_head),
            "subject_id": "subject-one",
            "participant_id": "participant-one",
            "stakeholder_class": "regulators",
            "role_id": "reviewer",
            "mandate_id": "mandate-one",
            "mandate_actions": ["review"],
            "mandate_jurisdictions": ["AU"],
            "jurisdiction": "AU",
            "audience": "sbp-lex-v2",
            "maximum_proof_age_ms": 100,
            "minimum_registry_sequence": 5,
            "minimum_authority_sequence": 8,
            "minimum_revocation_sequence": 2,
            "replay_namespace": "sbp-lex-v2:impersonation",
            "pseudonym_key_id": sha512(self.pseudonym_key).hexdigest(),
            "sovereign_identity_verifier": {
                "verifier_id": self.sovereign_verifier.verifier_id,
                "verifier_version": self.sovereign_verifier.verifier_version,
                "hash_stage": "upstream:sovereign_identity",
                "receipt_provider_binding": provider_binding(
                    self.sovereign_provider
                ),
            },
            "authority_boundary_verifier": {
                "verifier_id": self.boundary_verifier.verifier_id,
                "verifier_version": self.boundary_verifier.verifier_version,
                "hash_stage": "upstream:authority_boundary",
                "receipt_provider_binding": provider_binding(
                    self.boundary_provider
                ),
            },
            "trusted_clock_id": self.clock.clock_id,
            "trusted_clock_version": self.clock.clock_version,
            "clock_head_id": self.clock_head.head_id,
            "clock_head_version": self.clock_head.head_version,
            "minimum_clock_sequence": 1,
            "valid_from_ms": 0,
            "valid_until_ms": 5_000,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            "deployment_dependencies": dict(DEPLOYMENT_DEPENDENCIES),
        }

    def make_context(self, **changes) -> ImpersonationTrustContext:
        arguments = {
            "pinned_context_id": self.context_record["context_id"],
            "pinned_context_digest": self.context_record["digest"],
            "pinned_owner_provider_binding": provider_binding(
                self.owner_provider
            ),
            "signed_context_record": self.context_record,
            "owner_provider": self.owner_provider,
            "registry_provider": self.registry_provider,
            "subject_provider": self.subject_provider,
            "replay_provider": self.replay_provider,
            "registry": self.registry,
            "replay_guard": self.replay,
            "sovereign_identity_verifier": self.sovereign_verifier,
            "sovereign_identity_dependencies": self.sovereign_provider,
            "authority_boundary_verifier": self.boundary_verifier,
            "authority_boundary_dependencies": self.boundary_provider,
            "trusted_clock": self.clock,
            "clock_head_provider": self.clock_head,
        }
        arguments.update(changes)
        return ImpersonationTrustContext(**arguments)

    def upstream_record(
        self,
        component_id: str,
        provider: Ed25519FixtureProvider,
        result: str,
        false_fields: tuple[str, ...],
        request_fingerprint: str,
    ) -> dict:
        source = build_signed_object(
            {
                "component_id": component_id,
                "result": result,
                "request_fingerprint": request_fingerprint,
                "evaluation_time": self.now,
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            },
            provider=provider,
        )
        return {
            "component_id": component_id,
            "result": result,
            "request_fingerprint": request_fingerprint,
            "evaluation_time": self.now,
            "signed_evidence": source,
            **{field: False for field in false_fields},
        }

    def state(self, *, advance_clock: bool = True) -> dict:
        if advance_clock and self.clock_head.clock_sequence >= self.clock.clock_sequence:
            self.clock.advance(
                context_id=self.context_record["context_id"],
                context_digest=self.context_record["digest"],
            )
            self.now = self.clock.now
        request = {
            "subject": "subject-one",
            "participant": "participant-one",
            "action": "review",
        }
        fingerprint = canonical_integrity_hash(request)
        sovereign = self.upstream_record(
            SOVEREIGN_IDENTITY_COMPONENT,
            self.sovereign_provider,
            "VERIFIED",
            (
                "biometric_proof_established",
                "access_granted",
                "authority_granted",
                "licence_granted",
                "execution_authority_granted",
                "effect_authority_granted",
            ),
            fingerprint,
        )
        boundary = self.upstream_record(
            AUTHORITY_BOUNDARY_COMPONENT,
            self.boundary_provider,
            "BOUNDARY_PASS",
            (
                "stakeholder_label_grants_rights",
                "authority_granted",
                "licence_granted",
                "execution_authority_granted",
                "effect_authority_granted",
                "pipeline_bypass_permitted",
            ),
            fingerprint,
        )
        state = {
            "identity": {"subject_id": self.context_record["subject_id"]},
            "participant_id": self.context_record["participant_id"],
            "stakeholder_class": self.context_record["stakeholder_class"],
            "participant_role": self.context_record["role_id"],
            "participant_mandate_id": self.context_record["mandate_id"],
            "action": "review",
            "requested_jurisdiction": "AU",
            "jurisdiction": "AU",
            "request_fingerprint": fingerprint,
            "evaluation_time": self.now,
            "impersonation_session_id": "session-one",
            "impersonation_audience": self.context_record["audience"],
            "impersonation_challenge": canonical_integrity_hash(
                {"challenge": "unique-one"}
            ),
            "sovereign_identity_trace": [sovereign],
            "sovereign_identity_record": deepcopy(sovereign),
            "sovereign_identity_digest": canonical_integrity_hash([sovereign]),
            "sovereign_identity_result": "VERIFIED",
            "authority_boundary_trace": [boundary],
            "authority_boundary_record": deepcopy(boundary),
            "authority_boundary_digest": canonical_integrity_hash(boundary),
            "authority_boundary_trace_digest": canonical_integrity_hash(
                [boundary]
            ),
            "authority_boundary_result": "BOUNDARY_PASS",
            "hash_chain": [],
            "state_hash": GENESIS_HASH,
        }
        self.bind_upstream(state)
        return state

    def bind_upstream(self, state: dict) -> None:
        state["hash_chain"] = []
        state["state_hash"] = GENESIS_HASH
        for component, stage in (
            (SOVEREIGN_IDENTITY_COMPONENT, "upstream:sovereign_identity"),
            (AUTHORITY_BOUNDARY_COMPONENT, "upstream:authority_boundary"),
        ):
            payload = impersonation_upstream_hash_payload(
                state,
                component_id=component,
                context_id=self.context_record["context_id"],
                context_digest=self.context_record["digest"],
            )
            entry = build_hash_chain_entry(
                previous_hash=state["state_hash"],
                stage=stage,
                payload=payload,
            )
            state["hash_chain"].append(entry)
            state["state_hash"] = entry["hash"]

    def registry_record(self) -> dict:
        return self.registry.lookup_identity(
            subject_id=self.context_record["subject_id"],
            participant_id=self.context_record["participant_id"],
        )

    def proof(self, state: dict, **changes) -> dict:
        registry = self.registry_record()
        payload = {
            "schema": POSSESSION_PROOF_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
            "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
            "context_id": self.context_record["context_id"],
            "context_digest": self.context_record["digest"],
            "registry_record_digest": canonical_integrity_hash(registry),
            "subject_id": self.context_record["subject_id"],
            "participant_id": self.context_record["participant_id"],
            "stakeholder_class": self.context_record["stakeholder_class"],
            "role_id": self.context_record["role_id"],
            "mandate_id": self.context_record["mandate_id"],
            "requested_action": state["action"],
            "jurisdiction": self.context_record["jurisdiction"],
            "subject_provider_binding": provider_binding(self.subject_provider),
            "challenge": state["impersonation_challenge"],
            "request_fingerprint": state["request_fingerprint"],
            "session_id": state["impersonation_session_id"],
            "audience": state["impersonation_audience"],
            "issued_at_ms": self.now - 50,
            "expires_at_ms": self.now + 50,
            "registry_sequence": registry["registry_sequence"],
            "authority_sequence": registry["authority_sequence"],
            "revocation_sequence": registry["revocation_sequence"],
            "sovereign_identity_digest": state["sovereign_identity_digest"],
            "authority_boundary_digest": state["authority_boundary_digest"],
            "prior_impersonation_digest": state.get(
                "impersonation_protection_digest"
            ),
        }
        payload.update(changes)
        return build_signed_object(payload, provider=self.subject_provider)

    def evaluate(self, state: object, proof: dict | None, **changes) -> dict:
        arguments = {"possession_proof": proof, "trust_context": self.context}
        arguments.update(changes)
        return evaluate_impersonation_protection(state, **arguments)

    def test_valid_proof_passes_with_receipt_and_grants_nothing(self) -> None:
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(
            result["impersonation_protection_result"],
            IMPERSONATION_PASS,
            result["impersonation_protection_reason"],
        )
        self.assertTrue(
            verify_impersonation_protection(result, trust_context=self.context)
        )
        record = result["impersonation_protection_record"]
        for field in (
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
        ):
            self.assertIs(record[field], False)
        self.assertEqual(
            record["replay_claim_receipt"]["result"],
            REPLAY_CLAIMED,
        )
        self.assertFalse(any(impersonation_protection_hash_payload(result)[field]
                             for field in NO_AUTHORIZATION_EFFECT))

    def test_context_is_immutable_and_owner_signed(self) -> None:
        with self.assertRaisesRegex(
            AttributeError,
            "IMPERSONATION_TRUST_CONTEXT_IMMUTABLE",
        ):
            self.context._registry = object()
        tampered = self.context.signed_context_record
        tampered["role_id"] = "attacker-role"
        context = self.make_context(signed_context_record=tampered)
        state = self.state()
        result = self.evaluate(state, self.proof(state), trust_context=context)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_fully_self_consistent_attacker_context_fails_deployment_pin(self) -> None:
        attacker_owner = Ed25519FixtureProvider("attacker-owner")
        attacker_registry_provider = Ed25519FixtureProvider("attacker-registry")
        attacker_subject = Ed25519FixtureProvider("attacker-subject")
        attacker_replay_provider = Ed25519FixtureProvider("attacker-replay")
        attacker_payload = self.context_payload()
        attacker_payload.update(
            {
                "owner_id": "attacker-owner",
                "role_id": "attacker-role",
                "owner_provider_binding": provider_binding(attacker_owner),
                "registry_provider_binding": provider_binding(
                    attacker_registry_provider
                ),
                "subject_provider_binding": provider_binding(attacker_subject),
                "replay_provider_binding": provider_binding(
                    attacker_replay_provider
                ),
            }
        )
        attacker_record = build_signed_object(
            attacker_payload,
            provider=attacker_owner,
        )
        attacker_registry = LiveRegistryFixture(
            attacker_record,
            attacker_registry_provider,
        )
        attacker_replay = DurableReplayGuardFixture(
            attacker_record,
            attacker_replay_provider,
        )
        attacker_context = ImpersonationTrustContext(
            pinned_context_id=attacker_record["context_id"],
            pinned_context_digest=attacker_record["digest"],
            pinned_owner_provider_binding=provider_binding(attacker_owner),
            signed_context_record=attacker_record,
            owner_provider=attacker_owner,
            registry_provider=attacker_registry_provider,
            subject_provider=attacker_subject,
            replay_provider=attacker_replay_provider,
            registry=attacker_registry,
            replay_guard=attacker_replay,
            sovereign_identity_verifier=self.sovereign_verifier,
            sovereign_identity_dependencies=self.sovereign_provider,
            authority_boundary_verifier=self.boundary_verifier,
            authority_boundary_dependencies=self.boundary_provider,
            trusted_clock=self.clock,
            clock_head_provider=self.clock_head,
        )
        state = self.state()
        result = self.evaluate(
            state,
            self.proof(state),
            trust_context=attacker_context,
        )
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)
        self.assertEqual(
            result["impersonation_protection_reason"],
            "IMPERSONATION_COMPOSITION_BOUNDARY_NOT_REGISTERED",
        )

    def test_attacker_first_registration_cannot_choose_external_pins(self) -> None:
        _reset_test_only_impersonation_composition_boundaries(clear_pins=False)
        with self.assertRaisesRegex(ValueError, "DEPLOYMENT_PIN_MISMATCH"):
            self.register_attacker_composition()
        self.register_composition()
        self.context = self.make_context()
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(IMPERSONATION_PASS, result["impersonation_protection_result"])

    def test_test_only_reset_cannot_replace_externally_fixed_root(self) -> None:
        _reset_test_only_impersonation_composition_boundaries(clear_pins=False)
        with self.assertRaisesRegex(ValueError, "DEPLOYMENT_PIN_MISMATCH"):
            self.register_attacker_composition()
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(IMPERSONATION_DENY, result["impersonation_protection_result"])
        self.register_composition()
        self.context = self.make_context()

    def test_minimal_forged_upstream_pass_records_are_rejected(self) -> None:
        for component in (
            SOVEREIGN_IDENTITY_COMPONENT,
            AUTHORITY_BOUNDARY_COMPONENT,
        ):
            with self.subTest(component=component):
                state = self.state()
                forged = {"result": "VERIFIED" if component == SOVEREIGN_IDENTITY_COMPONENT else "BOUNDARY_PASS"}
                if component == SOVEREIGN_IDENTITY_COMPONENT:
                    state["sovereign_identity_trace"] = [forged]
                    state["sovereign_identity_record"] = deepcopy(forged)
                    state["sovereign_identity_digest"] = canonical_integrity_hash([forged])
                else:
                    state["authority_boundary_trace"] = [forged]
                    state["authority_boundary_record"] = deepcopy(forged)
                    state["authority_boundary_digest"] = canonical_integrity_hash(forged)
                self.bind_upstream(state)
                result = self.evaluate(state, self.proof(state))
                self.assertEqual(
                    result["impersonation_protection_result"],
                    IMPERSONATION_DENY,
                )

    def test_upstream_callback_and_hash_binding_fail_closed(self) -> None:
        state = self.state()
        self.sovereign_verifier.unavailable = True
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)
        self.sovereign_verifier.unavailable = False

        state = self.state()
        state["hash_chain"][0]["payload_hash"] = "0" * 128
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_replay_receipt_must_exist_durably_at_verification(self) -> None:
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertTrue(
            verify_impersonation_protection(result, trust_context=self.context)
        )
        self.replay.force_is_claimed_false = True
        self.assertFalse(
            verify_impersonation_protection(result, trust_context=self.context)
        )

    def test_replayed_proof_is_denied(self) -> None:
        first_state = self.state()
        proof = self.proof(first_state)
        first = self.evaluate(first_state, proof)
        self.assertEqual(first["impersonation_protection_result"], IMPERSONATION_PASS)
        second_state = self.state()
        second = self.evaluate(second_state, proof)
        self.assertEqual(second["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_durable_sequence_rollback_and_live_advance_fail_closed(self) -> None:
        state = self.state()
        valid = self.evaluate(state, self.proof(state))
        self.assertEqual(valid["impersonation_protection_result"], IMPERSONATION_PASS)

        self.registry.registry_sequence = 6
        rolled_back = self.state()
        result = self.evaluate(rolled_back, self.proof(rolled_back))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)
        self.registry.registry_sequence = 8
        self.assertFalse(
            verify_impersonation_protection(valid, trust_context=self.context)
        )

    def test_revocation_provider_substitution_and_unavailability_fail_closed(self) -> None:
        self.registry.revocation_status = TRUST_REVOKED
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        self.registry.revocation_status = TRUST_ACTIVE
        alternate = Ed25519FixtureProvider("alternate-subject")
        context = self.make_context(subject_provider=alternate)
        state = self.state()
        result = self.evaluate(state, self.proof(state), trust_context=context)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        self.registry.unavailable = True
        state = self.state()
        result = self.evaluate(state, None)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_wrong_missing_extra_stale_and_future_proofs_fail_closed(self) -> None:
        cases = []
        state = self.state()
        valid = self.proof(state)
        missing = deepcopy(valid)
        del missing["audience"]
        cases.append(missing)
        extra = deepcopy(valid)
        extra["caller_root"] = "attacker"
        cases.append(extra)
        cases.append(self.proof(state, role_id="wrong-role"))
        cases.append(self.proof(state, issued_at_ms=1_001, expires_at_ms=1_050))
        cases.append(self.proof(state, issued_at_ms=899, expires_at_ms=1_050))
        for proof in cases:
            with self.subTest(fields=set(proof)):
                fresh = self.state()
                result = self.evaluate(fresh, proof)
                self.assertEqual(
                    result["impersonation_protection_result"],
                    IMPERSONATION_DENY,
                )

    def test_record_retains_only_pseudonymous_proof_bindings(self) -> None:
        state = self.state()
        raw_values = (
            self.context_record["subject_id"],
            self.context_record["participant_id"],
            self.context_record["role_id"],
            state["impersonation_session_id"],
            state["impersonation_challenge"],
        )
        result = self.evaluate(state, self.proof(state))
        record_text = repr(result["impersonation_protection_record"])
        for raw in raw_values:
            self.assertNotIn(raw, record_text)
        record = result["impersonation_protection_record"]
        self.assertNotIn("possession_proof", record)
        self.assertNotIn("registry_record", record)
        self.assertIn("possession_proof_digest", record)
        self.assertIn("registry_record_digest", record)

    def test_malformed_state_and_trace_return_structured_deny(self) -> None:
        non_dict = self.evaluate(None, None)
        self.assertEqual(non_dict["impersonation_protection_result"], IMPERSONATION_DENY)
        self.assertEqual(
            non_dict["impersonation_protection_reason"],
            "IMPERSONATION_STATE_NOT_DICT",
        )
        malformed = self.state()
        malformed["impersonation_protection_trace"] = "not-a-list"
        result = self.evaluate(malformed, None)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)
        self.assertEqual(
            result["impersonation_protection_reason"],
            "IMPERSONATION_TRACE_INVALID",
        )

    def test_trace_receipt_and_digest_tamper_fail_verification(self) -> None:
        state = self.state()
        valid = self.evaluate(state, self.proof(state))
        mutations = (
            lambda value: value["impersonation_protection_record"].update(
                {"authority_granted": True}
            ),
            lambda value: value["impersonation_protection_trace"][-1][
                "replay_claim_receipt"
            ].update({"registry_sequence": 999}),
            lambda value: value.update(
                {"impersonation_protection_digest": "0" * 128}
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                tampered = deepcopy(valid)
                mutation(tampered)
                self.assertFalse(
                    verify_impersonation_protection(
                        tampered,
                        trust_context=self.context,
                    )
                )

    def test_metadata_mimic_time_varying_keys_and_verifier_swap_fail_closed(
        self,
    ) -> None:
        mimic = Ed25519FixtureProvider(self.subject_provider.provider_id)
        mimic.key_id = self.subject_provider.key_id
        context = self.make_context(subject_provider=mimic)
        state = self.state()
        result = self.evaluate(
            state,
            self.proof(state),
            trust_context=context,
        )
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        state = self.state()
        proof = self.proof(state)
        original_subject_key = self.subject_provider._key
        self.subject_provider._key = Ed25519PrivateKey.generate()
        result = self.evaluate(state, proof)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)
        self.subject_provider._key = original_subject_key

        class MimicVerifier:
            fixture_class = TEST_ONLY_FIXTURE_CLASS
            verifier_id = self.sovereign_verifier.verifier_id
            verifier_version = self.sovereign_verifier.verifier_version

            def verify_authenticated(self, **kwargs):
                return True

        context = self.make_context(
            sovereign_identity_verifier=MimicVerifier()
        )
        state = self.state()
        result = self.evaluate(
            state,
            self.proof(state),
            trust_context=context,
        )
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_clock_and_dependency_swap_and_property_failure_are_denied(self) -> None:
        alternate_clock_provider = Ed25519FixtureProvider("university-clock")
        alternate_clock = FixedClockFixture(self.now, alternate_clock_provider)
        context = self.make_context(trusted_clock=alternate_clock)
        state = self.state()
        result = self.evaluate(
            state,
            self.proof(state),
            trust_context=context,
        )
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        alternate_registry = LiveRegistryFixture(
            self.context_record,
            self.registry_provider,
        )
        context = self.make_context(registry=alternate_registry)
        state = self.state()
        result = self.evaluate(
            state,
            self.proof(state),
            trust_context=context,
        )
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        self.registry_provider.key_unavailable = True
        state = self.state()
        result = self.evaluate(state, None)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_boolean_and_forged_upstream_callback_receipts_are_denied(self) -> None:
        self.sovereign_verifier.return_boolean = True
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        self.sovereign_verifier.return_boolean = False
        self.sovereign_verifier.receipt_mutation = lambda payload: payload.update(
            {"request_fingerprint": "0" * 128}
        )
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_signed_replay_transition_persistence_and_head_rollback(self) -> None:
        state = self.state()
        valid = self.evaluate(state, self.proof(state))
        self.assertEqual(valid["impersonation_protection_result"], IMPERSONATION_PASS)
        receipt = valid["impersonation_protection_record"][
            "replay_claim_receipt"
        ]
        self.assertEqual(receipt["pre_claim_head_digest"], canonical_integrity_hash(
            build_signed_object(
                {
                    "schema": REPLAY_HEAD_SCHEMA,
                    "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                    "context_id": self.context_record["context_id"],
                    "context_digest": self.context_record["digest"],
                    "namespace": self.context_record["replay_namespace"],
                    "subject_binding_digest": receipt["subject_binding_digest"],
                    "registry_sequence": 0,
                    "authority_sequence": 0,
                    "revocation_sequence": 0,
                    "claim_sequence": 0,
                    "latest_claim_receipt_digest": GENESIS_HASH,
                    "observed_at_ms": self.now,
                    "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
                },
                provider=self.replay_provider,
            )
        ))
        self.replay.claim_sequence = 0
        self.replay.latest_receipt_digest = GENESIS_HASH
        self.assertFalse(
            verify_impersonation_protection(valid, trust_context=self.context)
        )

    def test_forged_signed_persistence_receipt_is_denied(self) -> None:
        self.replay.persistence_mutation = lambda payload: payload.update(
            {"persisted": False}
        )
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_forged_signed_replay_transition_receipt_is_denied(self) -> None:
        self.replay.receipt_mutation = lambda payload: payload.update(
            {"pre_claim_head_digest": "0" * 128}
        )
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_signed_clock_rollback_and_time_varying_verifier_key_are_denied(
        self,
    ) -> None:
        state = self.state()
        self.clock.clock_sequence = 0
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

        self.clock.clock_sequence = 1
        self.clock.prior_clock_record_digest = GENESIS_HASH
        state = self.state()
        proof = self.proof(state)
        self.sovereign_provider._key = Ed25519PrivateKey.generate()
        result = self.evaluate(state, proof)
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_DENY)

    def test_fresh_state_historical_clock_freeze_and_predecessor_fork_are_denied(
        self,
    ) -> None:
        first_state = self.state()
        first = self.evaluate(first_state, self.proof(first_state))
        self.assertEqual(IMPERSONATION_PASS, first["impersonation_protection_result"])

        frozen_state = self.state(advance_clock=False)
        frozen = self.evaluate(frozen_state, self.proof(frozen_state))
        self.assertEqual(IMPERSONATION_DENY, frozen["impersonation_protection_result"])
        self.assertEqual(
            "IMPERSONATION_CLOCK_HISTORY_NOT_MONOTONIC",
            frozen["impersonation_protection_reason"],
        )

        self.clock.advance(
            context_id=self.context_record["context_id"],
            context_digest=self.context_record["digest"],
        )
        self.now = self.clock.now
        self.clock.prior_clock_record_digest = "f" * 128
        forked_state = self.state(advance_clock=False)
        forked = self.evaluate(forked_state, self.proof(forked_state))
        self.assertEqual(IMPERSONATION_DENY, forked["impersonation_protection_result"])
        self.assertEqual(
            "IMPERSONATION_CLOCK_HISTORY_NOT_MONOTONIC",
            forked["impersonation_protection_reason"],
        )

    def test_clock_head_terminal_change_and_same_metadata_substitution_are_denied(
        self,
    ) -> None:
        self.clock_head.head_mutation_on_read = 3
        self.clock_head.head_mutation = lambda payload: payload.update(
            {"head_sequence": payload["head_sequence"] + 1}
        )
        state = self.state()
        changed = self.evaluate(state, self.proof(state))
        self.assertEqual(IMPERSONATION_DENY, changed["impersonation_protection_result"])

        _reset_test_only_impersonation_composition_boundaries(clear_pins=False)
        self.register_composition()
        alternate_signer = Ed25519FixtureProvider(
            self.clock_head_signer.provider_id
        )
        alternate = DurableClockHeadFixture(alternate_signer)
        context = self.make_context(clock_head_provider=alternate)
        state = self.state(advance_clock=False)
        substituted = self.evaluate(
            state,
            self.proof(state),
            trust_context=context,
        )
        self.assertEqual(
            IMPERSONATION_DENY,
            substituted["impersonation_protection_result"],
        )

    def test_test_only_registration_and_reset_are_disabled_in_production_mode(
        self,
    ) -> None:
        with patch.object(
            impersonation_module,
            "_RUNTIME_MODE",
            impersonation_module._RUNTIME_MODE_PRODUCTION,
        ):
            with self.assertRaisesRegex(RuntimeError, "DISABLED_IN_PRODUCTION"):
                _reset_test_only_impersonation_composition_boundaries()
            with self.assertRaisesRegex(RuntimeError, "DISABLED_IN_PRODUCTION"):
                self.register_composition()

    def test_keyed_pseudonyms_resist_low_entropy_unsalted_linkability(self) -> None:
        state = self.state()
        result = self.evaluate(state, self.proof(state))
        self.assertEqual(result["impersonation_protection_result"], IMPERSONATION_PASS)
        snapshot = result["impersonation_protection_record"][
            "evaluation_snapshot"
        ]
        unsalted_subject = canonical_integrity_hash(
            {
                "subject_id": "subject-one",
                "participant_id": "participant-one",
                "stakeholder_class": "regulators",
                "role_id": "reviewer",
                "mandate_id": "mandate-one",
                "requested_action": "review",
                "jurisdiction": "AU",
            }
        )
        unsalted_session = canonical_integrity_hash(
            {"session_id": "session-one", "audience": "sbp-lex-v2"}
        )
        self.assertNotEqual(snapshot["subject_binding_digest"], unsalted_subject)
        self.assertNotEqual(snapshot["session_binding_digest"], unsalted_session)
        self.assertNotIn(self.pseudonym_key.hex(), repr(result))
        self.assertEqual(
            result["impersonation_protection_record"]["deployment_dependencies"],
            DEPLOYMENT_DEPENDENCIES,
        )


if __name__ == "__main__":
    unittest.main()
