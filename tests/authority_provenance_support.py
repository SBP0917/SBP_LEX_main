from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from sbp_lex.governance.authority_provenance import (
    AUTHORITY_PROVENANCE_CONTRACT_ID,
    AUTHORITY_PROVENANCE_EVIDENCE_CLASSES,
    AUTHORITY_PROVENANCE_SCHEMA_STATUS,
)
from sbp_lex.security.authority_trust import (
    AUTHORITY_CLOCK_RECEIPT_SCHEMA_ID,
    AUTHORITY_REGISTRY_HEAD_SCHEMA_ID,
    AUTHORITY_TRUST_REQUIRED_ROLES,
    TEST_ONLY_FIXTURE_CLASS,
    AuthorityProvenanceDependencies,
    _install_test_only_authority_trust_pins,
    _register_test_only_authority_trust_context,
    _reset_test_only_authority_trust,
    authority_trust_context_payload,
    role_pin_from_provider,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object as build_signed_object,
)


def _provider() -> Ed25519SoftwareProvider:
    return Ed25519SoftwareProvider.from_private_key(
        Ed25519PrivateKey.generate(),
        skg_attestation_admitted=True,
    )


_TEST_ONLY_HEAD_GENESIS = canonical_integrity_hash(
    {"authority_provenance_head": "TEST_ONLY_GENESIS"}
)


class StableClock:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(self, provider, *, observed_at: int = 100, sequence: int = 1):
        self.provider = provider
        self.observed_at = observed_at
        self.sequence = sequence
        self.change_on_second_call = False
        self.calls = 0

    def current_time_receipt(self, *, context_id, request_fingerprint):
        self.calls += 1
        observed_at = self.observed_at
        if self.change_on_second_call and self.calls > 1:
            observed_at += 1
        return build_signed_object(
            {
                "schema_id": AUTHORITY_CLOCK_RECEIPT_SCHEMA_ID,
                "context_id": context_id,
                "request_fingerprint": request_fingerprint,
                "sequence": self.sequence,
                "previous_digest": _TEST_ONLY_HEAD_GENESIS,
                "observed_at": observed_at,
            },
            provider=self.provider,
        )


class StableRegistry:
    fixture_class = TEST_ONLY_FIXTURE_CLASS

    def __init__(self, provider, *, observed_at: int = 100, sequence: int = 1):
        self.provider = provider
        self.observed_at = observed_at
        self.sequence = sequence
        self.head_digest = canonical_integrity_hash({"head": "authority"})
        self.change_on_second_call = False
        self.calls = 0

    def current_registry_head(self, *, context_id, request_fingerprint):
        self.calls += 1
        head_digest = self.head_digest
        if self.change_on_second_call and self.calls > 1:
            head_digest = canonical_integrity_hash({"head": "changed"})
        return build_signed_object(
            {
                "schema_id": AUTHORITY_REGISTRY_HEAD_SCHEMA_ID,
                "context_id": context_id,
                "request_fingerprint": request_fingerprint,
                "sequence": self.sequence,
                "previous_digest": _TEST_ONLY_HEAD_GENESIS,
                "head_digest": head_digest,
                "observed_at": self.observed_at,
            },
            provider=self.provider,
        )


class PassingAuthorityProvenanceEvaluator:
    fixture_class = TEST_ONLY_FIXTURE_CLASS
    evaluator_id = "TEST_ONLY_AUTHORITY_PROVENANCE_EVALUATOR"
    evaluator_version = "1"
    authority_credential_id = "TEST_ONLY_AUTHORITY_PROVENANCE_CREDENTIAL"

    def __init__(
        self,
        provider,
        *,
        resolved_authority: str = "external-authority",
        class_id: str = "EXTERNAL_CLASS",
        subclass_id: str = "EXTERNAL_SUBCLASS",
    ):
        self.provider = provider
        self.force_authority = False
        self.resolved_authority = resolved_authority
        self.class_id = class_id
        self.subclass_id = subclass_id

    def evaluate_authority_provenance(self, *, stage, snapshot):
        policy_artifact = snapshot["submitted_claims"]["policy_artifact"]
        authority_digest = canonical_integrity_hash(
            {"authority": self.resolved_authority}
        )
        jurisdiction_digest = canonical_integrity_hash(
            {"jurisdiction": snapshot["submitted_claims"]["requested_jurisdiction"]}
        )
        classification_digest = canonical_integrity_hash(
            {"rules": "external-ap-acf"}
        )
        policy_digest = canonical_integrity_hash(policy_artifact)
        false_value = self.force_authority
        determination = {
            "result": "PASS",
            "participant_id": snapshot["participant_id"],
            "mandate_id": snapshot["mandate_id"],
            "requested_action": snapshot["requested_action"],
            "resolved_authority": {
                "authority_id": self.resolved_authority,
                "evidence_digest": authority_digest,
            },
            "resolved_jurisdiction": {
                "jurisdiction_id": snapshot["submitted_claims"][
                    "requested_jurisdiction"
                ],
                "evidence_digest": jurisdiction_digest,
            },
            "classification": {
                "taxonomy_id": "externally-supplied-taxonomy",
                "rule_set_id": "externally-supplied-rules",
                "rule_set_version": "1",
                "rule_set_digest": classification_digest,
                "class_id": self.class_id,
                "subclass_id": self.subclass_id,
            },
            "policy": {
                "policy_id": policy_artifact["policy_id"],
                "policy_version": policy_artifact["policy_version"],
                "policy_digest": policy_digest,
                "status": policy_artifact["status"],
                "effective_from": policy_artifact["effective_from"],
                "effective_until": policy_artifact["effective_until"],
                "permitted_actions": list(policy_artifact["permitted_actions"]),
                "restricted_actions": list(policy_artifact["restricted_actions"]),
            },
            "evidence_references": [
                {
                    "evidence_class": evidence_class,
                    "evidence_id": f"TEST_ONLY:{evidence_class}",
                    "source": (
                        f"TEST_ONLY_EXTERNAL_SEMANTICS:{evidence_class}"
                    ),
                    "digest": digest,
                }
                for evidence_class, digest in zip(
                    AUTHORITY_PROVENANCE_EVIDENCE_CLASSES,
                    (
                        authority_digest,
                        jurisdiction_digest,
                        classification_digest,
                        policy_digest,
                    ),
                    strict=True,
                )
            ],
            "authority_granted": false_value,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
            "pipeline_bypass_permitted": False,
            "downstream_override_permitted": False,
        }
        return build_signed_object(
            {
                "contract_id": AUTHORITY_PROVENANCE_CONTRACT_ID,
                "schema_status": AUTHORITY_PROVENANCE_SCHEMA_STATUS,
                "evaluator_id": self.evaluator_id,
                "evaluator_version": self.evaluator_version,
                "authority_credential": {
                    "credential_id": self.authority_credential_id,
                    "authority_role": "AUTHORITY_PROVENANCE_EVALUATOR",
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot[
                    "pre_evaluation_state_hash"
                ],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_provenance_digest": snapshot[
                    "prior_provenance_digest"
                ],
                "trust_context_digest": snapshot["trust_context_digest"],
                "clock_receipt_digest": snapshot["clock_receipt_digest"],
                "registry_head_digest": snapshot["registry_head_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
        )


@dataclass
class AuthorityProvenanceFixture:
    dependencies: AuthorityProvenanceDependencies
    evaluator: PassingAuthorityProvenanceEvaluator
    clock: StableClock
    registry: StableRegistry
    providers: dict[str, Ed25519SoftwareProvider]
    context_digest: str

    @classmethod
    def create(
        cls,
        *,
        identity_provider=None,
        identity_evaluator=None,
        boundary_provider=None,
        boundary_evaluator=None,
        skg_provider=None,
        skg_evaluator=None,
        observed_at: int = 100,
        resolved_authority: str = "external-authority",
        class_id: str = "EXTERNAL_CLASS",
        subclass_id: str = "EXTERNAL_SUBCLASS",
    ) -> "AuthorityProvenanceFixture":
        _reset_test_only_authority_trust()
        providers = {
            role: _provider()
            for role in ("owner", *AUTHORITY_TRUST_REQUIRED_ROLES)
        }
        if identity_provider is not None:
            providers["sovereign_identity"] = identity_provider
        if boundary_provider is not None:
            providers["authority_boundary"] = boundary_provider
        if skg_provider is not None:
            providers["skg_authority"] = skg_provider
        evaluator = PassingAuthorityProvenanceEvaluator(
            providers["authority_provenance"],
            resolved_authority=resolved_authority,
            class_id=class_id,
            subclass_id=subclass_id,
        )
        clock = StableClock(
            providers["trusted_clock"], observed_at=observed_at
        )
        registry = StableRegistry(
            providers["authority_registry"], observed_at=observed_at
        )
        metadata = {
            "sovereign_identity": (
                getattr(
                    identity_evaluator,
                    "identity_evaluator_id",
                    "TEST_ONLY_IDENTITY_EVALUATOR",
                ),
                getattr(
                    identity_evaluator,
                    "identity_evaluator_version",
                    "1",
                ),
                getattr(
                    identity_evaluator,
                    "identity_issuer_credential_id",
                    "TEST_ONLY_IDENTITY_CREDENTIAL",
                ),
            ),
            "authority_boundary": (
                getattr(
                    boundary_evaluator,
                    "evaluator_id",
                    "TEST_ONLY_BOUNDARY_EVALUATOR",
                ),
                getattr(boundary_evaluator, "evaluator_version", "1"),
                getattr(
                    boundary_evaluator,
                    "authority_credential_id",
                    "TEST_ONLY_BOUNDARY_CREDENTIAL",
                ),
            ),
            "skg_authority": (
                getattr(
                    skg_evaluator,
                    "evaluator_id",
                    "TEST_ONLY_SKG_EVALUATOR",
                ),
                getattr(skg_evaluator, "evaluator_version", "1"),
                getattr(
                    skg_evaluator,
                    "authority_credential_id",
                    "TEST_ONLY_SKG_CREDENTIAL",
                ),
            ),
            "authority_provenance": (
                evaluator.evaluator_id,
                evaluator.evaluator_version,
                evaluator.authority_credential_id,
            ),
            "trusted_clock": ("TEST_ONLY_CLOCK", "1", "TEST_ONLY_CLOCK_KEY"),
            "authority_registry": (
                "TEST_ONLY_REGISTRY",
                "1",
                "TEST_ONLY_REGISTRY_KEY",
            ),
        }
        role_pins = tuple(
            role_pin_from_provider(
                role=role,
                provider=providers[role],
                evaluator_id=metadata[role][0],
                evaluator_version=metadata[role][1],
                authority_credential_id=metadata[role][2],
            )
            for role in AUTHORITY_TRUST_REQUIRED_ROLES
        )
        payload = authority_trust_context_payload(
            context_id="TEST_ONLY_AUTHORITY_CONTEXT",
            context_version="1",
            role_pins=role_pins,
            minimum_clock_sequence=1,
            minimum_registry_sequence=1,
            minimum_registry_head_digest=registry.head_digest,
        )
        signed_context = build_signed_object(
            payload, provider=providers["owner"]
        )
        _install_test_only_authority_trust_pins(
            context_id=payload["context_id"],
            context_digest=signed_context["digest"],
            owner_public_key_hex=providers["owner"].public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex(),
        )
        _register_test_only_authority_trust_context(
            signed_context_record=signed_context,
            owner_provider=providers["owner"],
            role_pins=role_pins,
            evaluator=evaluator,
            trusted_clock=clock,
            registry_head_provider=registry,
        )
        return cls(
            dependencies=AuthorityProvenanceDependencies(
                fixed_context_id=payload["context_id"],
                owner_pinned_context_digest=signed_context["digest"],
            ),
            evaluator=evaluator,
            clock=clock,
            registry=registry,
            providers=providers,
            context_digest=signed_context["digest"],
        )

    def state(self) -> dict:
        request_fingerprint = canonical_integrity_hash({"request": "p0"})
        previous = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="foundational_baseline",
            payload={"result": "PASS"},
        )
        identity_source = build_signed_object(
            {
                "evaluator_id": "TEST_ONLY_IDENTITY_EVALUATOR",
                "evaluator_version": "1",
                "issuer_credential": {
                    "credential_id": "TEST_ONLY_IDENTITY_CREDENTIAL",
                    "authority_role": "V2_SOVEREIGN_IDENTITY_EVIDENCE_ISSUER",
                },
                "determination": {"result": "VERIFIED"},
            },
            provider=self.providers["sovereign_identity"],
        )
        identity_record = {
            "evaluation_time": 100,
            "evaluation_source": identity_source,
            "result": "VERIFIED",
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
        }
        identity_trace = [identity_record]
        boundary_source = build_signed_object(
            {
                "evaluator_id": "TEST_ONLY_BOUNDARY_EVALUATOR",
                "evaluator_version": "1",
                "authority_credential": {
                    "credential_id": "TEST_ONLY_BOUNDARY_CREDENTIAL",
                    "authority_role": "AUTHORITY_BOUNDED_PARTICIPANT_EVALUATOR",
                },
                "determination": {"result": "BOUNDARY_PASS"},
            },
            provider=self.providers["authority_boundary"],
        )
        boundary_record = {
            "evaluation_snapshot": {"evaluation_time": 100},
            "evaluation_source": boundary_source,
            "result": "BOUNDARY_PASS",
            "authority_granted": False,
            "licence_granted": False,
            "execution_authority_granted": False,
            "effect_authority_granted": False,
            "pipeline_bypass_permitted": False,
        }
        boundary_trace = [boundary_record]
        policy = {
            "policy_id": "TEST_ONLY_POLICY",
            "policy_version": "1",
            "status": "ACTIVE",
            "effective_from": 0,
            "effective_until": 1000,
            "permitted_actions": ["inspect"],
            "restricted_actions": [],
        }
        return {
            "request_fingerprint": request_fingerprint,
            "hash_chain": [previous],
            "state_hash": previous["hash"],
            "evaluation_time": 100,
            "foundational_baseline_digest": canonical_integrity_hash(
                {"foundational": "PASS"}
            ),
            "sovereign_identity_record": identity_record,
            "sovereign_identity_trace": identity_trace,
            "sovereign_identity_digest": canonical_integrity_hash(identity_trace),
            "sovereign_identity_result": "VERIFIED",
            "authority_boundary_record": boundary_record,
            "authority_boundary_trace": boundary_trace,
            "authority_boundary_digest": canonical_integrity_hash(
                boundary_record
            ),
            "authority_boundary_trace_digest": canonical_integrity_hash(
                boundary_trace
            ),
            "authority_boundary_result": "BOUNDARY_PASS",
            "participant_id": "participant",
            "participant_mandate_id": "mandate",
            "action": "inspect",
            "submitted_authority_claim": "caller-claim",
            "requested_jurisdiction": "AU",
            "submitted_ap_acf_class": "CALLER_CLASS",
            "submitted_ap_acf_subclass": "CALLER_SUBCLASS",
            "submitted_policy_artifact": policy,
            "resolved_authority": "",
            "jurisdiction": "",
            "ap_acf_class": None,
            "ap_acf_subclass": None,
            "governance_policy_record": {},
            "governance_policy_digest": None,
            "authority_provenance_trace": [],
            "authority_provenance_record": {},
            "authority_provenance_digest": None,
            "authority_provenance_trace_digest": None,
        }


def append_authority_provenance_binding(state: dict) -> None:
    from sbp_lex.governance.authority_provenance import (
        AUTHORITY_PROVENANCE_STAGE,
        authority_provenance_hash_payload,
    )

    entry = build_hash_chain_entry(
        previous_hash=state["state_hash"],
        stage=AUTHORITY_PROVENANCE_STAGE,
        payload=authority_provenance_hash_payload(state),
    )
    state["hash_chain"].append(entry)
    state["state_hash"] = entry["hash"]
