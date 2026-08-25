from __future__ import annotations

import base64
import hmac
import unittest
from copy import deepcopy
from hashlib import sha512
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.compliance.australian_minor_access import (
    ACTION_CREATE_OR_MAINTAIN_ACCOUNT,
    AGE_ASSURANCE_USE_SCOPE,
    AGE_AT_LEAST_16,
    AGE_UNDER_16,
    AUSTRALIAN_MINOR_ACCESS_CLOCK_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_DURABLE_PROVIDER_ADMISSION_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_LANE_PURPOSE_PREFIX,
    AUSTRALIAN_MINOR_ACCESS_OWNER_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_REGISTRY_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_REPLAY_HEAD_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_REPLAY_RECEIPT_PURPOSE,
    AUSTRALIAN_MINOR_ACCESS_REVOCATION_PURPOSE,
    DISCLOSURE_SCOPE,
    LANES,
    RESIDENCE_AUSTRALIA,
    RESULT_DENY,
    RESULT_ESCALATE,
    RESULT_NOT_APPLICABLE,
    RESULT_PASS,
    SCHEMA,
    SERVICE_IN_SCOPE,
    SERVICE_OUT_OF_SCOPE,
    AustralianMinorAccessError,
    _clear_australian_minor_access_deployment_for_tests,
    _install_australian_minor_access_deployment_for_tests,
    bind_australian_minor_access_hash,
    evaluate_australian_minor_access,
    install_australian_minor_access_production,
    verify_australian_minor_access,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    PRODUCTION_DUAL_CUSTODY_CLASS,
    PRODUCTION_SIGNER,
    DualSignatureLaneCustody,
    HybridVerificationContext,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import build_signed_object


class Signer:
    def __init__(self, provider_id: str, credential_id: str, custody: str) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.provider_id = provider_id
        self.credential_id = credential_id
        self.custody = custody

    @property
    def public_raw(self) -> bytes:
        return self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    @property
    def fingerprint(self) -> str:
        return sha512(self.public_raw).hexdigest()

    def binding(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "credential_id": self.credential_id,
            "algorithm": "Ed25519",
            "public_key_hex": self.public_raw.hex(),
            "key_fingerprint": self.fingerprint,
            "custody_class": self.custody,
            "effect_authority": False,
        }

    def sign(self, payload: dict, *, signature_binding: dict | None = None) -> dict:
        binding = signature_binding or self.binding()
        return {
            "payload": deepcopy(payload),
            "payload_digest": canonical_integrity_hash(payload),
            "signature": {
                "provider_id": binding["provider_id"],
                "credential_id": binding["credential_id"],
                "algorithm": binding["algorithm"],
                "key_fingerprint": binding["key_fingerprint"],
                "custody_class": binding["custody_class"],
                "effect_authority": False,
                "signature_b64": base64.b64encode(
                    self.private.sign(canonical_json_bytes(payload))
                ).decode("ascii"),
            },
        }


class ProductionHybridSigner:
    algorithm = HYBRID_SUITE_ID
    custody_class = PRODUCTION_DUAL_CUSTODY_CLASS
    signer_class = PRODUCTION_SIGNER
    effect_authority = False
    token_signing_admitted = True

    def __init__(self, provider_id: str, credential_id: str, custody: str) -> None:
        del custody
        self.provider_id = provider_id
        self.credential_id = credential_id
        self._mldsa87_private_key = MLDSA87PrivateKey.generate()
        self._ed448_private_key = Ed448PrivateKey.generate()
        self.key_epoch = 1
        self.key_version = "production-1"
        self._context = HybridVerificationContext(
            provider_id=provider_id,
            key_epoch=self.key_epoch,
            key_version=self.key_version,
            custody_class=self.custody_class,
            signer_class=self.signer_class,
            mldsa87_public_key=self._mldsa87_private_key.public_key(),
            ed448_public_key=self._ed448_private_key.public_key(),
            effect_authority=False,
            external_custody_admitted=True,
            external_custody_admission_sha512=sha512(
                f"{provider_id}:coordinator".encode()
            ).hexdigest(),
            mldsa87_custody=self._lane_custody(
                "ML-DSA-87", f"{provider_id}:mldsa87"
            ),
            ed448_custody=self._lane_custody(
                "Ed448", f"{provider_id}:ed448"
            ),
        )

    def _lane_custody(
        self, algorithm: str, identity: str
    ) -> DualSignatureLaneCustody:
        return DualSignatureLaneCustody(
            algorithm=algorithm,
            provider_id=identity,
            key_version=self.key_version,
            key_epoch=self.key_epoch,
            rotation_epoch=self.key_epoch,
            custody_class=f"EXTERNAL_NON_EXPORTABLE_{algorithm}",
            custody_reference=f"external://{identity}",
            signer_class=PRODUCTION_SIGNER,
            external_custody_admitted=True,
            custody_admission_sha512=sha512(
                f"{identity}:admission".encode()
            ).hexdigest(),
            non_exportable=True,
        )

    @property
    def fingerprint(self) -> str:
        return self._context.context_digest

    @property
    def key_id(self) -> str:
        return self._context.ordered_key_set_digest

    def hybrid_verification_context(
        self, *, allow_test_only: bool = False
    ) -> HybridVerificationContext:
        del allow_test_only
        return self._context

    def sign_hybrid_preimage(
        self,
        preimage: bytes,
        *,
        purpose: str,
        context_digest: str,
    ) -> tuple[bytes, bytes]:
        if context_digest != self._context.context_digest or not purpose:
            raise ValueError("HYBRID_SIGNING_CONTEXT_MISMATCH")
        return (
            self._mldsa87_private_key.sign(preimage),
            self._ed448_private_key.sign(preimage),
        )

    def binding(self) -> dict:
        return {
            "provider_id": self.provider_id,
            "credential_id": self.credential_id,
            "algorithm": HYBRID_SUITE_ID,
            "public_key_hex": (
                self._context.mldsa87_public_key_bytes
                + self._context.ed448_public_key_bytes
            ).hex(),
            "key_fingerprint": self._context.context_digest,
            "custody_class": self._context.custody_class,
            "effect_authority": False,
        }

    @staticmethod
    def _purpose(payload: dict) -> str:
        if "production_durable_storage_admitted" in payload:
            return AUSTRALIAN_MINOR_ACCESS_DURABLE_PROVIDER_ADMISSION_PURPOSE
        if "deployment_mode" in payload:
            return AUSTRALIAN_MINOR_ACCESS_OWNER_PURPOSE
        if "lane" in payload:
            return f"{AUSTRALIAN_MINOR_ACCESS_LANE_PURPOSE_PREFIX}{payload['lane']}"
        if "revoked_evidence_digests" in payload:
            return AUSTRALIAN_MINOR_ACCESS_REVOCATION_PURPOSE
        if "time_sequence" in payload:
            return AUSTRALIAN_MINOR_ACCESS_CLOCK_PURPOSE
        if "replay_key" in payload:
            return AUSTRALIAN_MINOR_ACCESS_REPLAY_RECEIPT_PURPOSE
        if "namespace" in payload and "head_digest" in payload:
            return AUSTRALIAN_MINOR_ACCESS_REPLAY_HEAD_PURPOSE
        if "registry_id" in payload:
            return AUSTRALIAN_MINOR_ACCESS_REGISTRY_PURPOSE
        raise ValueError("UNKNOWN_TEST_SIGNATURE_PURPOSE")

    def sign(self, payload: dict, *, signature_binding: dict | None = None) -> dict:
        if signature_binding not in (None, self.binding()):
            raise ValueError("SIGNATURE_BINDING_OVERRIDE_REJECTED")
        return build_signed_object(
            deepcopy(payload),
            provider=self,
            purpose=self._purpose(payload),
        )

class Pseudonymizer:
    pseudonymizer_id = "pseudo-service"
    version = "1"
    key_id = "pseudo-key-1"

    def __init__(self, secret: bytes) -> None:
        self._secret = sha512(secret).digest()
        self.key_fingerprint = sha512(self._secret).hexdigest()

    def pseudonymize(self, label: str, payload: dict) -> str:
        return hmac.new(
            self._secret,
            label.encode("utf-8") + b"\x00" + canonical_json_bytes(payload),
            sha512,
        ).hexdigest()


class Clock:
    id = "clock-service"
    version = "1"

    def __init__(self, signer: Signer, context_id: str, now: int) -> None:
        self.signer = signer
        self.context_id = context_id
        self.now = now
        self.chain: list[dict] = []
        self.append(now)

    def append(self, observed_at: int) -> dict:
        envelope = self.signer.sign(
            {
                "schema": SCHEMA,
                "context_id": self.context_id,
                "source_id": self.id,
                "source_version": self.version,
                "time_sequence": len(self.chain) + 1,
                "prior_evidence_digest": (
                    GENESIS_HASH
                    if not self.chain
                    else canonical_integrity_hash(self.chain[-1])
                ),
                "observed_at": observed_at,
                "status": "ACTIVE",
                "effect_authority": False,
            }
        )
        self.chain.append(envelope)
        self.now = observed_at
        return envelope

    def current_time_chain(self, context_id: str) -> list[dict]:
        return deepcopy(self.chain)

    def is_current(self, context_id: str, digest: str, sequence: int) -> bool:
        return (
            digest == canonical_integrity_hash(self.chain[-1])
            and sequence == len(self.chain)
        )


class RevocationStore:
    id = "revocation-store"
    version = "1"

    def __init__(self, signer: Signer, payload: dict) -> None:
        self.signer = signer
        self.payload = payload
        self.chain = [self.signer.sign(deepcopy(payload))]

    def append(self, payload: dict) -> dict:
        envelope = self.signer.sign(deepcopy(payload))
        self.payload = deepcopy(payload)
        self.chain.append(envelope)
        return envelope

    def current_head_chain(self, context_id: str) -> list[dict]:
        return deepcopy(self.chain)

    def is_current(self, context_id: str, digest: str, sequence: int) -> bool:
        current = self.chain[-1]
        payload = current.get("payload", current)
        return (
            digest == canonical_integrity_hash(current)
            and sequence == payload["head_sequence"]
        )


class ReplayStore:
    id = "replay-store"
    version = "1"

    def __init__(self, signer: Signer, context_id: str) -> None:
        self.signer = signer
        self.context_id = context_id
        self.heads: dict[tuple[str, str], tuple[int, str, int]] = {}
        self.claims: dict[tuple[str, str], str] = {}
        self.receipts: dict[tuple[str, str], dict] = {}
        self.throw = False

    def _head(self, namespace: str, subject_binding: str, observed_at: int) -> dict:
        sequence, digest, head_time = self.heads.get(
            (namespace, subject_binding),
            (0, "0" * 128, observed_at),
        )
        return self.signer.sign(
            {
                "schema": SCHEMA,
                "context_id": self.context_id,
                "store_id": self.id,
                "store_version": self.version,
                "namespace": namespace,
                "subject_session_binding_digest": subject_binding,
                "sequence": sequence,
                "head_digest": digest,
                "observed_at": head_time,
                "status": "ACTIVE",
                "effect_authority": False,
            }
        )

    def current_head(self, namespace: str, subject_binding: str, observed_at: int) -> dict:
        if self.throw:
            raise RuntimeError("unavailable")
        return self._head(namespace, subject_binding, observed_at)

    def claim_once(self, claim: dict) -> dict:
        if self.throw:
            raise RuntimeError("unavailable")
        key = (claim["namespace"], claim["replay_key"])
        if key in self.claims:
            raise RuntimeError("replay")
        receipt = self.signer.sign(deepcopy(claim))
        receipt_digest = canonical_integrity_hash(receipt)
        expected_head = canonical_integrity_hash(
            {
                "prior_head_digest": claim["prior_head_digest"],
                "receipt_digest": receipt_digest,
                "sequence": claim["sequence"],
            }
        )
        self.heads[(claim["namespace"], claim["subject_session_binding_digest"])] = (
            claim["sequence"],
            expected_head,
            claim["claimed_at"],
        )
        self.claims[key] = receipt_digest
        self.receipts[key] = deepcopy(receipt)
        return receipt

    def is_claimed(self, namespace: str, replay_key: str, receipt_digest: str) -> bool:
        if self.throw:
            raise RuntimeError("unavailable")
        return self.claims.get((namespace, replay_key)) == receipt_digest

    def persisted_receipt(self, namespace: str, replay_key: str) -> dict | None:
        if self.throw:
            raise RuntimeError("unavailable")
        return deepcopy(self.receipts.get((namespace, replay_key)))


class Resolver:
    def __init__(self, lane: str, signer: Signer, result: str, details: dict) -> None:
        self.lane = lane
        self.signer = signer
        self.result = result
        self.details = details
        self.registry_digest = ""
        self.revocation_digest = ""
        self.now = 1_000
        self.signature_binding_override: dict | None = None

    def resolve(self, snapshot: dict) -> dict:
        binding = self.signature_binding_override or self.signer.binding()
        payload = {
            "schema": SCHEMA,
            "context_id": "au-minor-context",
            "lane": self.lane,
            "provider_id": binding["provider_id"],
            "credential_id": binding["credential_id"],
            "key_fingerprint": binding["key_fingerprint"],
            "evidence_sequence": 1,
            "registry_digest": self.registry_digest,
            "revocation_head_digest": self.revocation_digest,
            "request_fingerprint": snapshot["request_fingerprint"],
            "minor_access_request_binding_digest": snapshot[
                "minor_access_request_binding_digest"
            ],
            "subject_session_binding_digest": snapshot["subject_session_binding_digest"],
            "stage": snapshot["stage"],
            "issued_at": self.now - 10,
            "expires_at": self.now + 10,
            "status": "ACTIVE",
            "result": self.result,
            "details": deepcopy(self.details),
            "effect_authority": False,
        }
        return self.signer.sign(payload, signature_binding=binding)


class Fixture:
    def __init__(
        self,
        *,
        age_result: str = AGE_AT_LEAST_16,
        pseudonym_secret: bytes = b"deployment-pseudonym-key-A",
        government_id_used: bool = False,
        alternative: bool = True,
        destruction: bool = True,
        production: bool = False,
    ) -> None:
        self.context_id = "au-minor-context"
        self.now = 1_000
        self.production = production
        signer_type = ProductionHybridSigner if production else Signer
        self.owner = signer_type(
            "DEPLOYMENT_OWNER", "owner:pending", "DEPLOYMENT_OWNER_ROOT"
        )
        self.owner.credential_id = f"owner:{self.owner.fingerprint}"
        self.registry_signer = signer_type("registry-provider", "registry-credential", "HSM")
        self.revocation_signer = signer_type("revocation-provider", "revocation-credential", "HSM")
        self.replay_signer = signer_type("replay-provider", "replay-credential", "HSM")
        self.clock_signer = signer_type("clock-provider", "clock-credential", "HSM")
        self.lane_signers = {
            lane: signer_type(f"{lane.lower()}-provider", f"{lane.lower()}-credential", "HSM")
            for lane in LANES
        }
        self.pseudonymizer = Pseudonymizer(pseudonym_secret)
        policy = {
            "method_class": "NON_ID_ATTRIBUTE_ASSURANCE",
            "government_id_used": government_id_used,
            "digital_id_used": False,
            "reasonable_non_government_id_alternative_available": alternative,
            "government_id_required": False,
            "digital_id_required": False,
            "privacy_preserving": True,
            "raw_date_of_birth_retained": False,
            "use_scope": AGE_ASSURANCE_USE_SCOPE,
            "disclosure_scope": DISCLOSURE_SCOPE,
            "retain_only_until_destruction": True,
            "youth_penalty_applied": False,
        }
        destruction_details = {
            "destroyed": destruction,
            "retained": not destruction,
            "destruction_scope": AGE_ASSURANCE_USE_SCOPE,
            "destroyed_at": self.now,
            "destruction_receipt_id": "destruction-receipt-1",
        }
        lane_results = {
            "SERVICE_SCOPE": SERVICE_IN_SCOPE,
            "ORDINARY_RESIDENCE": RESIDENCE_AUSTRALIA,
            "ACCOUNT_ACTION": ACTION_CREATE_OR_MAINTAIN_ACCOUNT,
            "AGE_ASSURANCE": age_result,
            "METHOD_PRIVACY_POLICY": "COMPLIANT",
            "PRIVACY_DESTRUCTION": "DESTROYED",
        }
        lane_details = {
            "SERVICE_SCOPE": {"service_scope_code": SERVICE_IN_SCOPE},
            "ORDINARY_RESIDENCE": {
                "ordinary_residence_code": RESIDENCE_AUSTRALIA
            },
            "ACCOUNT_ACTION": {
                "account_action_code": ACTION_CREATE_OR_MAINTAIN_ACCOUNT
            },
            "AGE_ASSURANCE": {"threshold": 16, "raw_date_of_birth_present": False},
            "METHOD_PRIVACY_POLICY": policy,
            "PRIVACY_DESTRUCTION": destruction_details,
        }
        self.resolvers = {
            lane: Resolver(lane, self.lane_signers[lane], lane_results[lane], lane_details[lane])
            for lane in LANES
        }
        self.clock = Clock(self.clock_signer, self.context_id, self.now)
        self.replay_store = ReplayStore(self.replay_signer, self.context_id)
        lane_bindings = {lane: self.lane_signers[lane].binding() for lane in LANES}
        self.registry_payload = {
            "schema": SCHEMA,
            "context_id": self.context_id,
            "registry_id": "registry-store",
            "registry_version": "1",
            "registry_sequence": 7,
            "decision_sequence_head": 11,
            "decision_digest_head": "1" * 128,
            "revocation_sequence": 3,
            "status": "ACTIVE",
            "valid_from": 1,
            "valid_until": 10_000,
            "lane_binding_digests": {
                lane: canonical_integrity_hash(lane_bindings[lane]) for lane in LANES
            },
            "effect_authority": False,
        }
        self.registry = self.registry_signer.sign(self.registry_payload)
        self.registry_digest = canonical_integrity_hash(self.registry)
        self.revocation_payload = {
            "schema": SCHEMA,
            "context_id": self.context_id,
            "registry_digest": self.registry_digest,
            "head_sequence": 1,
            "revocation_sequence": 3,
            "registry_sequence": 7,
            "prior_head_digest": GENESIS_HASH,
            "revoked_evidence_digests": [],
            "issued_at": self.now - 20,
            "expires_at": self.now + 20,
            "status": "ACTIVE",
            "effect_authority": False,
        }
        self.revocation_store = RevocationStore(self.revocation_signer, self.revocation_payload)
        self.revocation_head = deepcopy(self.revocation_store.chain[0])
        self.revocation_digest = canonical_integrity_hash(self.revocation_head)
        for resolver in self.resolvers.values():
            resolver.registry_digest = self.registry_digest
            resolver.revocation_digest = self.revocation_digest
        self.owner_payload = {
            "schema": SCHEMA,
            "context_id": self.context_id,
            "status": "ACTIVE",
            "valid_from": 1,
            "valid_until": 10_000,
            "composition_sequence": 4,
            "revocation_sequence": 3,
            "registry_digest": self.registry_digest,
            "revocation_head_digest": self.revocation_digest,
            "registry_binding": self.registry_signer.binding(),
            "revocation_binding": self.revocation_signer.binding(),
            "replay_binding": self.replay_signer.binding(),
            "clock_binding": self.clock_signer.binding(),
            "lane_bindings": lane_bindings,
            "registry_store_id": "registry-store",
            "registry_store_version": "1",
            "revocation_store_id": self.revocation_store.id,
            "revocation_store_version": self.revocation_store.version,
            "replay_store_id": self.replay_store.id,
            "replay_store_version": self.replay_store.version,
            "clock_source_id": self.clock.id,
            "clock_source_version": self.clock.version,
            "clock_head_digest": canonical_integrity_hash(self.clock.chain[0]),
            "clock_sequence": 1,
            "pseudonymizer_binding": {
                "pseudonymizer_id": self.pseudonymizer.pseudonymizer_id,
                "version": self.pseudonymizer.version,
                "key_id": self.pseudonymizer.key_id,
                "key_fingerprint": self.pseudonymizer.key_fingerprint,
            },
            "deployment_mode": "PRODUCTION" if production else "TEST_ONLY",
            "effect_authority": False,
        }
        self.resign_owner()

    def resign_owner(self) -> None:
        self.owner_record = self.owner.sign(self.owner_payload)
        self.context_digest = canonical_integrity_hash(self.owner_record)

    @property
    def composition(self) -> dict:
        return {
            "owner_record": self.owner_record,
            "registry": self.registry,
            "revocation_store": self.revocation_store,
            "replay_store": self.replay_store,
            "clock": self.clock,
            "pseudonymization_key": self.pseudonymizer._secret,
            "resolvers": self.resolvers,
        }

    def production_contexts(self) -> dict[str, HybridVerificationContext]:
        if not self.production:
            raise ValueError("PRODUCTION_FIXTURE_REQUIRED")
        return {
            "registry": self.registry_signer._context,
            "revocation": self.revocation_signer._context,
            "replay": self.replay_signer._context,
            "clock": self.clock_signer._context,
            **{
                lane: signer._context
                for lane, signer in self.lane_signers.items()
            },
        }

    def durable_provider_admissions(
        self,
        signer: ProductionHybridSigner,
        *,
        invalid_evidence_kind: str | None = None,
        sequence_offset: int = 0,
    ) -> dict[str, dict]:
        providers = {
            "clock": self.clock,
            "revocation": self.revocation_store,
            "replay": self.replay_store,
        }
        admissions = {}
        for sequence, (kind, provider) in enumerate(providers.items(), 1):
            evidence_digest = sha512(
                f"external-durability-evidence:{kind}".encode()
            ).hexdigest()
            if kind == invalid_evidence_kind:
                evidence_digest = "self-declared"
            admissions[kind] = signer.sign(
                {
                    "schema": (
                        "SBP-LEX-AU-MINOR-DURABLE-PROVIDER-ADMISSION-V1"
                    ),
                    "context_id": self.context_id,
                    "provider_kind": kind,
                    "provider_id": provider.id,
                    "provider_version": provider.version,
                    "storage_class": "EXTERNALLY_ATTESTED_DURABLE_SERVICE",
                    "durability_evidence_sha512": evidence_digest,
                    "admission_sequence": sequence + sequence_offset,
                    "status": "ACTIVE",
                    "restart_durable": True,
                    "transactional": True,
                    "corruption_fail_closed": True,
                    "rollback_protected": True,
                    "production_durable_storage_admitted": True,
                    "effect_authority": False,
                }
            )
        return admissions

    @staticmethod
    def durable_provider_admission_pins(
        admissions: dict[str, dict],
    ) -> dict[str, str]:
        return {
            kind: canonical_integrity_hash(admission)
            for kind, admission in admissions.items()
        }

    def install(self, *, test_only: bool = True) -> None:
        if self.production:
            contexts = self.production_contexts()
            install_australian_minor_access_production(
                self.composition,
                fixed_context_id=self.context_id,
                fixed_context_digest=self.context_digest,
                owner_trust_context=self.owner._context,
                owner_pinned_context_digest=self.owner._context.context_digest,
                signer_trust_contexts=contexts,
                signer_owner_pinned_context_digests={
                    name: context.context_digest
                    for name, context in contexts.items()
                },
            )
            return
        _install_australian_minor_access_deployment_for_tests(
            self.composition,
            fixed_context_id=self.context_id,
            fixed_context_digest=self.context_digest,
            owner_public_key_hex=self.owner.public_raw.hex(),
            test_only=test_only,
        )

    def state(self, **updates: object) -> dict:
        request_fingerprint = canonical_integrity_hash(
            {
                "schema_id": "SBP_LEX_V2_CANONICAL_PIPELINE_REQUEST_V1",
                "request_id": "pipeline-request-1",
                "request_nonce": "1",
            }
        )
        ingress = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="canonical_pipeline_ingress",
            payload={"request_fingerprint": request_fingerprint},
        )
        state = {
            "subject_id": "1",
            "session_id": "1",
            "service_id": "1",
            "request_nonce": "1",
            "request_fingerprint": request_fingerprint,
            "hash_chain": [ingress],
            "state_hash": ingress["hash"],
            "australian_minor_access_hash_binding_index": None,
            "australian_minor_access_hash_binding_hash": None,
        }
        state.update(updates)
        return state


class AustralianMinorAccessTests(unittest.TestCase):
    def tearDown(self) -> None:
        _clear_australian_minor_access_deployment_for_tests(test_only=True)

    def test_production_rejects_in_memory_stores_without_external_admission(self) -> None:
        fixture = Fixture(production=True)
        fixture.clock.production_durable_storage_admitted = True
        fixture.revocation_store.production_durable_storage_admitted = "true"
        fixture.replay_store.durability_evidence_sha512 = "0" * 128
        with patch(
            "sbp_lex.compliance.australian_minor_access._ACTIVE_COMPOSITION",
            None,
        ):
            with self.assertRaisesRegex(
                AustralianMinorAccessError,
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_REQUIRED",
            ):
                fixture.install()

    def test_production_rejects_unpinned_or_invalid_durability_evidence(self) -> None:
        fixture = Fixture(production=True)
        contexts = fixture.production_contexts()
        admission_signer = ProductionHybridSigner(
            "external-durability-admission-authority",
            "external-durability-admission-credential",
            "EXTERNAL_DURABILITY_ADMISSION_ROOT",
        )
        common = {
            "fixed_context_id": fixture.context_id,
            "fixed_context_digest": fixture.context_digest,
            "owner_trust_context": fixture.owner._context,
            "owner_pinned_context_digest": fixture.owner._context.context_digest,
            "signer_trust_contexts": contexts,
            "signer_owner_pinned_context_digests": {
                name: context.context_digest
                for name, context in contexts.items()
            },
            "durable_provider_trust_context": admission_signer._context,
        }
        with patch(
            "sbp_lex.compliance.australian_minor_access._ACTIVE_COMPOSITION",
            None,
        ):
            with self.assertRaisesRegex(
                AustralianMinorAccessError,
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_PIN_INVALID",
            ):
                install_australian_minor_access_production(
                    fixture.composition,
                    **common,
                    durable_provider_admissions=(
                        fixture.durable_provider_admissions(admission_signer)
                    ),
                    durable_provider_owner_pinned_context_digest="0" * 128,
                )
            invalid_admissions = fixture.durable_provider_admissions(
                admission_signer,
                invalid_evidence_kind="replay",
            )
            with self.assertRaisesRegex(
                AustralianMinorAccessError,
                "PRODUCTION_DURABLE_PROVIDER_ADMISSION_CLAIMS_INVALID",
            ):
                install_australian_minor_access_production(
                    fixture.composition,
                    **common,
                    durable_provider_admissions=invalid_admissions,
                    durable_provider_owner_pinned_admission_digests=(
                        fixture.durable_provider_admission_pins(
                            invalid_admissions
                        )
                    ),
                    durable_provider_owner_pinned_context_digest=(
                        admission_signer._context.context_digest
                    ),
                )

    def test_production_rejects_stale_signed_admission_documents(self) -> None:
        fixture = Fixture(production=True)
        contexts = fixture.production_contexts()
        admission_signer = ProductionHybridSigner(
            "external-durability-admission-authority",
            "external-durability-admission-credential",
            "EXTERNAL_DURABILITY_ADMISSION_ROOT",
        )
        stale = fixture.durable_provider_admissions(admission_signer)
        current = fixture.durable_provider_admissions(
            admission_signer,
            sequence_offset=10,
        )
        with patch(
            "sbp_lex.compliance.australian_minor_access._ACTIVE_COMPOSITION",
            None,
        ):
            with self.assertRaisesRegex(
                AustralianMinorAccessError,
                "PRODUCTION_DURABLE_PROVIDER_DOCUMENT_PIN_MISMATCH",
            ):
                install_australian_minor_access_production(
                    fixture.composition,
                    fixed_context_id=fixture.context_id,
                    fixed_context_digest=fixture.context_digest,
                    owner_trust_context=fixture.owner._context,
                    owner_pinned_context_digest=(
                        fixture.owner._context.context_digest
                    ),
                    signer_trust_contexts=contexts,
                    signer_owner_pinned_context_digests={
                        name: context.context_digest
                        for name, context in contexts.items()
                    },
                    durable_provider_admissions=stale,
                    durable_provider_owner_pinned_admission_digests=(
                        fixture.durable_provider_admission_pins(current)
                    ),
                    durable_provider_trust_context=admission_signer._context,
                    durable_provider_owner_pinned_context_digest=(
                        admission_signer._context.context_digest
                    ),
                )

    def test_production_rejects_pin_tamper_and_legacy_owner_without_fallback(self) -> None:
        fixture = Fixture(production=True)
        contexts = fixture.production_contexts()
        admission_signer = ProductionHybridSigner(
            "external-durability-admission-authority",
            "external-durability-admission-credential",
            "EXTERNAL_DURABILITY_ADMISSION_ROOT",
        )
        admissions = fixture.durable_provider_admissions(admission_signer)
        admission_pins = fixture.durable_provider_admission_pins(admissions)
        pins = {
            name: context.context_digest for name, context in contexts.items()
        }
        pins["AGE_ASSURANCE"] = "0" * 128
        with patch(
            "sbp_lex.compliance.australian_minor_access._ACTIVE_COMPOSITION",
            None,
        ):
            with self.assertRaises(AustralianMinorAccessError):
                install_australian_minor_access_production(
                    fixture.composition,
                    fixed_context_id=fixture.context_id,
                    fixed_context_digest=fixture.context_digest,
                    owner_trust_context=fixture.owner._context,
                    owner_pinned_context_digest=(
                        fixture.owner._context.context_digest
                    ),
                    signer_trust_contexts=contexts,
                    signer_owner_pinned_context_digests=pins,
                    durable_provider_admissions=admissions,
                    durable_provider_owner_pinned_admission_digests=(
                        admission_pins
                    ),
                    durable_provider_trust_context=admission_signer._context,
                    durable_provider_owner_pinned_context_digest=(
                        admission_signer._context.context_digest
                    ),
                )

        legacy_owner = Signer(
            "DEPLOYMENT_OWNER", "owner:legacy", "DEPLOYMENT_OWNER_ROOT"
        )
        composition = fixture.composition
        composition["owner_record"] = legacy_owner.sign(fixture.owner_payload)
        with patch(
            "sbp_lex.compliance.australian_minor_access._ACTIVE_COMPOSITION",
            None,
        ):
            with self.assertRaises(AustralianMinorAccessError):
                install_australian_minor_access_production(
                    composition,
                    fixed_context_id=fixture.context_id,
                    fixed_context_digest=canonical_integrity_hash(
                        composition["owner_record"]
                    ),
                    owner_trust_context=fixture.owner._context,
                    owner_pinned_context_digest=(
                        fixture.owner._context.context_digest
                    ),
                    signer_trust_contexts=contexts,
                    signer_owner_pinned_context_digests={
                        name: context.context_digest
                        for name, context in contexts.items()
                    },
                    durable_provider_admissions=admissions,
                    durable_provider_owner_pinned_admission_digests=(
                        admission_pins
                    ),
                    durable_provider_trust_context=admission_signer._context,
                    durable_provider_owner_pinned_context_digest=(
                        admission_signer._context.context_digest
                    ),
                )

    def test_exact_age_threshold_and_no_independent_authority(self) -> None:
        under = Fixture(age_result=AGE_UNDER_16)
        under.install()
        under_state = under.state()
        under_record = evaluate_australian_minor_access(under_state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_DENY, under_record["result"])
        self.assertFalse(under_record["access_granted"])
        self.assertFalse(under_record["authority_granted"])
        bind_australian_minor_access_hash(under_state)
        self.assertTrue(verify_australian_minor_access(under_state))

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        sixteen = Fixture(age_result=AGE_AT_LEAST_16)
        sixteen.install()
        sixteen_state = sixteen.state()
        sixteen_record = evaluate_australian_minor_access(sixteen_state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_PASS, sixteen_record["result"])
        self.assertFalse(sixteen_record["access_granted"])
        self.assertFalse(sixteen_record["execution_authority_granted"])
        bind_australian_minor_access_hash(sixteen_state)
        self.assertTrue(verify_australian_minor_access(sixteen_state))

    def test_caller_cannot_choose_not_applicable_and_canonical_hash_binding_is_exact(self) -> None:
        fixture = Fixture(age_result=AGE_UNDER_16)
        fixture.install()
        state = fixture.state(applicable=False, residence="OUTSIDE_AUSTRALIA")
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_DENY, record["result"])
        entry = bind_australian_minor_access_hash(state)
        self.assertEqual("australian_minor_access", entry["stage"])
        self.assertEqual(1, state["australian_minor_access_hash_binding_index"])
        self.assertEqual(entry["hash"], state["state_hash"])
        self.assertTrue(verify_australian_minor_access(state))
        state["hash_chain"][1]["payload_hash"] = "0" * 128
        self.assertFalse(verify_australian_minor_access(state))

    def test_full_consistent_attacker_context_cannot_replace_registered_root(self) -> None:
        legitimate = Fixture()
        legitimate.install()
        attacker = Fixture(pseudonym_secret=b"attacker-owned-pseudonym-key")
        with self.assertRaisesRegex(AustralianMinorAccessError, "ALREADY_REGISTERED"):
            attacker.install()
        state = legitimate.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(legitimate.context_digest, record["context_digest"])

    def test_metadata_mimic_and_time_varying_lane_key_fail_closed(self) -> None:
        fixture = Fixture()
        pinned = deepcopy(fixture.owner_payload["lane_bindings"]["SERVICE_SCOPE"])
        fixture.install()
        attacker = Signer("mimic", "mimic", "SOFTWARE")
        resolver = fixture.resolvers["SERVICE_SCOPE"]
        resolver.signer = attacker
        resolver.signature_binding_override = pinned
        state = fixture.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_ESCALATE, record["result"])
        self.assertFalse(verify_australian_minor_access(state))

    def test_same_sequence_registry_substitution_is_rejected_by_exact_digest(self) -> None:
        fixture = Fixture()
        substituted = deepcopy(fixture.registry_payload)
        substituted["decision_digest_head"] = "2" * 128
        fixture.registry = fixture.registry_signer.sign(substituted)
        with self.assertRaisesRegex(AustralianMinorAccessError, "REGISTRY_DIGEST_MISMATCH"):
            fixture.install()

    def test_live_revocation_head_substitution_fails_closed(self) -> None:
        fixture = Fixture()
        fixture.install()
        substituted = deepcopy(fixture.revocation_store.chain[-1]["payload"])
        substituted["revoked_evidence_digests"] = ["a" * 128]
        fixture.revocation_store.chain[-1] = fixture.revocation_signer.sign(
            substituted
        )
        state = fixture.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_ESCALATE, record["result"])

    def test_clock_and_replay_provider_swaps_fail_closed(self) -> None:
        for target in ("clock", "replay"):
            with self.subTest(target=target):
                fixture = Fixture()
                fixture.install()
                attacker = Signer(f"attacker-{target}", f"attacker-{target}", "SOFTWARE")
                if target == "clock":
                    payload = deepcopy(fixture.clock.chain[-1]["payload"])
                    fixture.clock.chain[-1] = attacker.sign(payload)
                else:
                    fixture.replay_store.signer = attacker
                state = fixture.state()
                record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
                self.assertEqual(RESULT_ESCALATE, record["result"])
                _clear_australian_minor_access_deployment_for_tests(test_only=True)

    def test_six_lanes_reject_provider_key_and_credential_reuse_individually(self) -> None:
        for field, expected in (
            ("provider_id", "LANE_PROVIDER_REUSE"),
            ("key", "LANE_KEY_REUSE"),
            ("credential_id", "LANE_CREDENTIAL_REUSE"),
        ):
            with self.subTest(field=field):
                fixture = Fixture()
                first = deepcopy(fixture.owner_payload["lane_bindings"][LANES[0]])
                second = fixture.owner_payload["lane_bindings"][LANES[1]]
                if field == "key":
                    second["public_key_hex"] = first["public_key_hex"]
                    second["key_fingerprint"] = first["key_fingerprint"]
                else:
                    second[field] = first[field]
                fixture.resign_owner()
                with self.assertRaisesRegex(AustralianMinorAccessError, expected):
                    fixture.install()
                _clear_australian_minor_access_deployment_for_tests(test_only=True)

    def test_low_entropy_identifiers_are_deployment_keyed_and_unlinkable(self) -> None:
        first = Fixture(pseudonym_secret=b"first-secret-key-material")
        first.install()
        first_state = first.state()
        first_record = evaluate_australian_minor_access(first_state, stage="ACCOUNT_ADMISSION")
        first_request = first_record["snapshot"]["request_fingerprint"]
        first_minor_binding = first_record["snapshot"][
            "minor_access_request_binding_digest"
        ]
        first_subject = first_record["snapshot"]["subject_session_binding_digest"]
        _clear_australian_minor_access_deployment_for_tests(test_only=True)

        second = Fixture(pseudonym_secret=b"second-secret-key-material")
        second.install()
        second_state = second.state()
        second_record = evaluate_australian_minor_access(second_state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(first_request, second_record["snapshot"]["request_fingerprint"])
        self.assertNotEqual(
            first_minor_binding,
            second_record["snapshot"]["minor_access_request_binding_digest"],
        )
        self.assertNotEqual(first_subject, second_record["snapshot"]["subject_session_binding_digest"])
        self.assertNotEqual(first_request, first_minor_binding)

    def test_government_id_without_reasonable_alternative_and_destruction_failure_escalate(self) -> None:
        for fixture in (
            Fixture(government_id_used=True, alternative=False),
            Fixture(destruction=False),
        ):
            with self.subTest():
                fixture.install()
                state = fixture.state()
                record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
                self.assertEqual(RESULT_ESCALATE, record["result"])
                self.assertFalse(record["access_granted"])
                _clear_australian_minor_access_deployment_for_tests(test_only=True)

    def test_durable_replay_receipt_and_live_persistence_are_required(self) -> None:
        fixture = Fixture()
        fixture.install()
        state = fixture.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_PASS, record["result"])
        bind_australian_minor_access_hash(state)
        self.assertTrue(verify_australian_minor_access(state))
        fixture.replay_store.claims.clear()
        self.assertFalse(verify_australian_minor_access(state))

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        throwing = Fixture()
        throwing.install()
        throwing.replay_store.throw = True
        failed_state = throwing.state()
        self.assertEqual(
            RESULT_ESCALATE,
            evaluate_australian_minor_access(failed_state, stage="ACCOUNT_ADMISSION")["result"],
        )

    def test_tamper_and_raw_identity_nonretention(self) -> None:
        fixture = Fixture()
        fixture.install()
        state = fixture.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        serialized = canonical_json_bytes(record)
        self.assertNotIn(b'"subject_id"', serialized)
        self.assertNotIn(b'"session_id"', serialized)
        bind_australian_minor_access_hash(state)
        state["australian_minor_access"]["result"] = RESULT_DENY
        self.assertFalse(verify_australian_minor_access(state))

    def test_canonical_chain_reorder_legacy_shape_and_caller_index_are_rejected(self) -> None:
        fixture = Fixture()
        fixture.install()
        state = fixture.state()
        evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        bind_australian_minor_access_hash(state)
        downstream = build_hash_chain_entry(
            previous_hash=state["state_hash"],
            stage="canonical_pipeline_downstream",
            payload={"result": "CONTINUE"},
        )
        state["hash_chain"].append(downstream)
        state["state_hash"] = downstream["hash"]
        self.assertTrue(verify_australian_minor_access(state))
        state["hash_chain"][1], state["hash_chain"][2] = (
            state["hash_chain"][2],
            state["hash_chain"][1],
        )
        self.assertFalse(verify_australian_minor_access(state))

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        legacy = Fixture()
        legacy.install()
        legacy_state = legacy.state()
        evaluate_australian_minor_access(legacy_state, stage="ACCOUNT_ADMISSION")
        legacy_state["hash_chain"] = [
            {
                "index": 0,
                "label": "AUSTRALIAN_MINOR_ACCESS",
                "record_digest": legacy_state["australian_minor_access"]["record_digest"],
                "prior_digest": "0" * 128,
                "entry_digest": "1" * 128,
            }
        ]
        legacy_state["state_hash"] = "1" * 128
        with self.assertRaisesRegex(AustralianMinorAccessError, "HASH_CHAIN_INVALID"):
            bind_australian_minor_access_hash(legacy_state)

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        canonical = Fixture()
        canonical.install()
        canonical_state = canonical.state()
        evaluate_australian_minor_access(canonical_state, stage="ACCOUNT_ADMISSION")
        canonical_state["expected_hash_binding_index"] = 1
        with self.assertRaisesRegex(
            AustralianMinorAccessError,
            "CALLER_SUPPLIED_HASH_INDEX_REJECTED",
        ):
            bind_australian_minor_access_hash(canonical_state)

    def test_test_only_root_rejects_production_install_and_reset(self) -> None:
        attacker = Fixture(pseudonym_secret=b"attacker-first-root")
        with self.assertRaisesRegex(
            AustralianMinorAccessError,
            "TEST_ONLY_INSTALL_REQUIRED",
        ):
            attacker.install(test_only=False)
        legitimate = Fixture()
        legitimate.install()
        with self.assertRaisesRegex(
            AustralianMinorAccessError,
            "TEST_ONLY_RESET_REQUIRED",
        ):
            _clear_australian_minor_access_deployment_for_tests(test_only=False)

    def test_pseudonymizer_mimic_cannot_replace_owner_pinned_hmac_key(self) -> None:
        fixture = Fixture()
        composition = fixture.composition
        composition["pseudonymization_key"] = b"x" * 64
        with self.assertRaisesRegex(
            AustralianMinorAccessError,
            "PSEUDONYMIZATION_KEY_PIN_MISMATCH",
        ):
            _install_australian_minor_access_deployment_for_tests(
                composition,
                fixed_context_id=fixture.context_id,
                fixed_context_digest=fixture.context_digest,
                owner_public_key_hex=fixture.owner.public_raw.hex(),
                test_only=True,
            )

    def test_clock_and_revocation_heads_advance_but_freeze_and_rollback_fail(self) -> None:
        fixture = Fixture()
        fixture.install()
        fixture.clock.append(1_001)
        next_revocation = deepcopy(fixture.revocation_store.chain[-1]["payload"])
        next_revocation.update(
            {
                "head_sequence": 2,
                "revocation_sequence": 4,
                "prior_head_digest": canonical_integrity_hash(
                    fixture.revocation_store.chain[-1]
                ),
                "issued_at": 1_001,
                "expires_at": 1_020,
            }
        )
        next_envelope = fixture.revocation_store.append(next_revocation)
        next_digest = canonical_integrity_hash(next_envelope)
        for resolver in fixture.resolvers.values():
            resolver.revocation_digest = next_digest
        state = fixture.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_PASS, record["result"])
        bind_australian_minor_access_hash(state)
        self.assertTrue(verify_australian_minor_access(state))
        fixture.clock.append(1_002)
        self.assertTrue(verify_australian_minor_access(state))

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        frozen = Fixture()
        frozen.install()
        frozen.clock.append(1_001)
        frozen.clock.current_time_chain = (
            lambda context_id: deepcopy(frozen.clock.chain[:-1])
        )
        self.assertEqual(
            RESULT_ESCALATE,
            evaluate_australian_minor_access(
                frozen.state(), stage="ACCOUNT_ADMISSION"
            )["result"],
        )

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        rollback = Fixture()
        rollback.install()
        rollback.clock.append(999)
        self.assertEqual(
            RESULT_ESCALATE,
            evaluate_australian_minor_access(
                rollback.state(), stage="ACCOUNT_ADMISSION"
            )["result"],
        )

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        revoked_freeze = Fixture()
        revoked_freeze.install()
        advanced = deepcopy(revoked_freeze.revocation_store.chain[-1]["payload"])
        advanced.update(
            {
                "head_sequence": 2,
                "revocation_sequence": 4,
                "prior_head_digest": canonical_integrity_hash(
                    revoked_freeze.revocation_store.chain[-1]
                ),
            }
        )
        revoked_freeze.revocation_store.append(advanced)
        revoked_freeze.revocation_store.current_head_chain = (
            lambda context_id: deepcopy(revoked_freeze.revocation_store.chain[:-1])
        )
        self.assertEqual(
            RESULT_ESCALATE,
            evaluate_australian_minor_access(
                revoked_freeze.state(), stage="ACCOUNT_ADMISSION"
            )["result"],
        )

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        revoked_rollback = Fixture()
        revoked_rollback.install()
        rolled_back = deepcopy(revoked_rollback.revocation_store.chain[-1]["payload"])
        rolled_back.update(
            {
                "head_sequence": 2,
                "revocation_sequence": 2,
                "prior_head_digest": canonical_integrity_hash(
                    revoked_rollback.revocation_store.chain[-1]
                ),
            }
        )
        revoked_rollback.revocation_store.append(rolled_back)
        self.assertEqual(
            RESULT_ESCALATE,
            evaluate_australian_minor_access(
                revoked_rollback.state(), stage="ACCOUNT_ADMISSION"
            )["result"],
        )

    def test_replay_boolean_lie_without_exact_persisted_receipt_fails_closed(self) -> None:
        fixture = Fixture()
        fixture.install()
        fixture.replay_store.persisted_receipt = (
            lambda namespace, replay_key: None
        )
        record = evaluate_australian_minor_access(
            fixture.state(), stage="ACCOUNT_ADMISSION"
        )
        self.assertEqual(RESULT_ESCALATE, record["result"])

    def test_extra_and_previously_ignored_record_fields_fail_after_rebinding(self) -> None:
        fixture = Fixture()
        fixture.install()
        state = fixture.state()
        evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        bind_australian_minor_access_hash(state)

        def attacker_rebind(candidate: dict) -> None:
            record = candidate["australian_minor_access"]
            record["record_digest"] = canonical_integrity_hash(
                {key: value for key, value in record.items() if key != "record_digest"}
            )
            payload = {
                "record_digest": record["record_digest"],
                "result": record["result"],
                "access_granted": False,
                "authority_granted": False,
                "licence_granted": False,
                "execution_authority_granted": False,
                "effect_authority": False,
            }
            entry = build_hash_chain_entry(
                previous_hash=candidate["hash_chain"][0]["hash"],
                stage="australian_minor_access",
                payload=payload,
            )
            candidate["hash_chain"][1] = entry
            candidate["state_hash"] = entry["hash"]
            candidate["australian_minor_access_hash_binding_hash"] = entry["hash"]

        extra = deepcopy(state)
        extra["australian_minor_access"]["ignored"] = "attacker"
        attacker_rebind(extra)
        self.assertFalse(verify_australian_minor_access(extra))

        ignored = deepcopy(state)
        ignored["australian_minor_access"]["reason"] = "ATTACKER_REASON"
        attacker_rebind(ignored)
        self.assertFalse(verify_australian_minor_access(ignored))

    def test_scope_details_reject_personal_data_and_out_of_scope_skips_age(self) -> None:
        injected = Fixture()
        injected.resolvers["SERVICE_SCOPE"].details["raw_person_name"] = "person"
        injected.install()
        record = evaluate_australian_minor_access(
            injected.state(), stage="ACCOUNT_ADMISSION"
        )
        self.assertEqual(RESULT_ESCALATE, record["result"])

        _clear_australian_minor_access_deployment_for_tests(test_only=True)
        outside = Fixture()
        service = outside.resolvers["SERVICE_SCOPE"]
        service.result = SERVICE_OUT_OF_SCOPE
        service.details = {"service_scope_code": SERVICE_OUT_OF_SCOPE}
        age_calls: list[bool] = []

        def prohibited_age_collection(snapshot: dict) -> dict:
            age_calls.append(True)
            raise AssertionError("age resolver must not be called")

        outside.resolvers["AGE_ASSURANCE"].resolve = prohibited_age_collection
        outside.install()
        state = outside.state()
        record = evaluate_australian_minor_access(state, stage="ACCOUNT_ADMISSION")
        self.assertEqual(RESULT_NOT_APPLICABLE, record["result"])
        self.assertEqual([], age_calls)
        self.assertEqual(set(LANES[:3]), set(record["evidence"]))
        bind_australian_minor_access_hash(state)
        self.assertTrue(verify_australian_minor_access(state))

    def test_malformed_top_level_state_and_stage_return_structured_fail_records(self) -> None:
        malformed_state = evaluate_australian_minor_access(
            None, stage="ACCOUNT_ADMISSION"  # type: ignore[arg-type]
        )
        self.assertEqual(RESULT_ESCALATE, malformed_state["result"])
        self.assertFalse(malformed_state["authority_granted"])
        state: dict = {}
        malformed_stage = evaluate_australian_minor_access(
            state, stage=""  # type: ignore[arg-type]
        )
        self.assertEqual(RESULT_ESCALATE, malformed_stage["result"])
        self.assertEqual(malformed_stage, state["australian_minor_access"])


if __name__ == "__main__":
    unittest.main()
