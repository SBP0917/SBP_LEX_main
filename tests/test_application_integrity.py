from __future__ import annotations

import os
import tempfile
import unittest
from copy import deepcopy
from hashlib import sha512
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from sbp_lex.security.application_integrity import (
    ACTIVE,
    ADMISSION_AUTHORITY_ROLE,
    ASSURANCE_LIMITS,
    ApplicationIntegrityRejected,
    GENESIS,
    HEAD_EVIDENCE_SCHEMA,
    HEAD_SNAPSHOT_SCHEMA,
    MANIFEST_SCHEMA,
    NO_AUTHORIZATION_EFFECT,
    RELEASE_AUTHORITY_ROLE,
    TRUST_CONTEXT_SCHEMA,
    TRUSTED_ADMISSION_SCHEMA,
    TIME_EVIDENCE_SCHEMA,
    compute_application_integrity_anti_rollback_digest,
    compute_application_integrity_trust_context_digest,
    compute_runtime_measurement_digest,
    verify_application_integrity,
    verify_application_integrity_result,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object as build_signed_object,
)


class ReleaseProviderFixture:
    release_integrity_attestation_admitted = True
    release_integrity_signer_class = "TEST_ONLY"

    def __init__(self) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )
        self.provider_id = self._provider.provider_id
        self.algorithm = self._provider.algorithm
        self.key_id = self._provider.key_id
        self.custody_class = self._provider.custody_class
        self.token_signing_admitted = self._provider.token_signing_admitted
        self.three_p_attestation_admitted = False
        self.framework_attestation_admitted = False
        self.licence_attestation_admitted = False
        self.skg_attestation_admitted = False
        self.lifecycle_attestation_admitted = False
        self.effect_authority = False
        self.public_key_failure: Exception | None = None

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self._provider.sign(message, key_id=key_id)

    @property
    def public_key(self):
        if self.public_key_failure is not None:
            raise self.public_key_failure
        return self._provider.public_key

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str,
    ) -> bool:
        return self._provider.verify(message, signature, key_id=key_id)


class AdmissionProviderFixture:
    release_admission_attestation_admitted = True
    release_admission_signer_class = "TEST_ONLY"
    release_admission_credential_id = "owner-admission-credential"

    def __init__(self, release_provider: ReleaseProviderFixture | None = None) -> None:
        self._provider = (
            release_provider._provider
            if release_provider is not None
            else Ed25519SoftwareProvider.from_private_key(
                Ed25519PrivateKey.generate()
            )
        )
        self.provider_id = self._provider.provider_id
        self.algorithm = self._provider.algorithm
        self.key_id = self._provider.key_id
        self.custody_class = self._provider.custody_class
        self.token_signing_admitted = self._provider.token_signing_admitted
        self.three_p_attestation_admitted = False
        self.framework_attestation_admitted = False
        self.licence_attestation_admitted = False
        self.skg_attestation_admitted = False
        self.lifecycle_attestation_admitted = False
        self.effect_authority = False
        self.public_key_failure: Exception | None = None

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self._provider.sign(message, key_id=key_id)

    @property
    def public_key(self):
        if self.public_key_failure is not None:
            raise self.public_key_failure
        return self._provider.public_key

    def verify(
        self,
        message: bytes,
        signature: bytes,
        *,
        key_id: str,
    ) -> bool:
        return self._provider.verify(message, signature, key_id=key_id)


class TimeProviderFixture:
    application_integrity_time_provider_id = "deployment-trusted-clock"
    application_integrity_time_provider_version = "1"
    application_integrity_time_source_class = "TEST_ONLY_MONOTONIC_CLOCK"
    application_integrity_time_owner_bound = True

    def __init__(self, now_ms: int) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )
        self.provider_id = self._provider.provider_id
        self.algorithm = self._provider.algorithm
        self.key_id = self._provider.key_id
        self.custody_class = self._provider.custody_class
        self.effect_authority = False
        self.token_signing_admitted = True
        self.now_ms = now_ms
        self.evidence_sequence = 1
        self.failure: Exception | None = None

    @property
    def public_key(self):
        return self._provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self._provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self._provider.verify(message, signature, key_id=key_id)

    def current_application_integrity_time_evidence(self, context_id: str) -> dict:
        if self.failure is not None:
            raise self.failure
        return build_signed_object(
            {
                "schema_id": TIME_EVIDENCE_SCHEMA,
                "context_id": context_id,
                "provider_id": self.application_integrity_time_provider_id,
                "provider_version": self.application_integrity_time_provider_version,
                "source_class": self.application_integrity_time_source_class,
                "evidence_sequence": self.evidence_sequence,
                "observed_at_ms": self.now_ms,
                "status": ACTIVE,
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            },
            provider=self,
        )


class HeadProviderFixture:
    application_integrity_head_provider_id = "deployment-durable-head-store"
    application_integrity_head_provider_version = "1"
    application_integrity_head_storage_class = "TEST_ONLY_DURABLE_ATOMIC_STORE"
    application_integrity_heads_owner_bound = True
    application_integrity_heads_durable = True
    application_integrity_heads_atomic = True

    def __init__(self, snapshot: dict, *, observed_at_ms: int = 1_000_000) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )
        self.provider_id = self._provider.provider_id
        self.algorithm = self._provider.algorithm
        self.key_id = self._provider.key_id
        self.custody_class = self._provider.custody_class
        self.effect_authority = False
        self.token_signing_admitted = True
        self.snapshot = deepcopy(snapshot)
        self.observed_at_ms = observed_at_ms
        self.evidence_sequence = 1
        self.failure: Exception | None = None

    @property
    def public_key(self):
        return self._provider.public_key

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        return self._provider.sign(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        return self._provider.verify(message, signature, key_id=key_id)

    def current_application_integrity_head_evidence(self, context_id: str) -> dict:
        if self.failure is not None:
            raise self.failure
        return build_signed_object(
            {
                "schema_id": HEAD_EVIDENCE_SCHEMA,
                "context_id": context_id,
                "provider_id": self.application_integrity_head_provider_id,
                "provider_version": self.application_integrity_head_provider_version,
                "storage_class": self.application_integrity_head_storage_class,
                "evidence_sequence": self.evidence_sequence,
                "observed_at_ms": self.observed_at_ms,
                "status": ACTIVE,
                "head_snapshot": deepcopy(self.snapshot),
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            },
            provider=self,
        )


def _public_key_fingerprint(provider) -> str:
    encoded = provider.public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha512(encoded).hexdigest()


def _head_snapshot(
    *,
    context_id: str,
    manifest: dict,
    admission: dict,
    head_state_sequence: int = 1,
) -> dict:
    anti_rollback = compute_application_integrity_anti_rollback_digest(
        context_id=context_id,
        head_state_sequence=head_state_sequence,
        release_sequence_head=manifest["release_sequence"],
        prior_release_digest_head=manifest["prior_release_digest"],
        manifest_digest_head=manifest["digest"],
        admission_sequence_head=admission["admission_sequence"],
        prior_admission_digest_head=admission["prior_admission_digest"],
        admission_digest_head=admission["digest"],
        revocation_sequence_head=admission["revocation_sequence"],
    )
    payload = {
        "schema_id": HEAD_SNAPSHOT_SCHEMA,
        "context_id": context_id,
        "head_state_sequence": head_state_sequence,
        "release_sequence_head": manifest["release_sequence"],
        "prior_release_digest_head": manifest["prior_release_digest"],
        "manifest_digest_head": manifest["digest"],
        "admission_sequence_head": admission["admission_sequence"],
        "prior_admission_digest_head": admission["prior_admission_digest"],
        "admission_digest_head": admission["digest"],
        "revocation_sequence_head": admission["revocation_sequence"],
        "anti_rollback_state_digest": anti_rollback,
    }
    return {
        **payload,
        "head_snapshot_digest": canonical_integrity_hash(payload),
    }


class TrustContextFixture:
    def __init__(
        self,
        *,
        manifest: dict,
        admission: dict,
        owner_admission_authority_pin: dict,
        release_signer: ReleaseProviderFixture,
        admission_signer: AdmissionProviderFixture,
        context_id: str = "deployment-owner-application-integrity",
        context_version: str = "1",
        trusted_now_ms: int = 1_000_000,
        head_state_sequence: int = 1,
        release_sequence_head: int | None = None,
        prior_release_digest_head: str | None = None,
        manifest_digest_head: str | None = None,
        admission_sequence_head: int | None = None,
        prior_admission_digest_head: str | None = None,
        admission_digest_head: str | None = None,
        revocation_sequence_head: int | None = None,
        time_provider: TimeProviderFixture | None = None,
        head_provider: HeadProviderFixture | None = None,
        release_public_key_fingerprint: str | None = None,
        admission_public_key_fingerprint: str | None = None,
        allow_test_only_release_signer: bool = True,
        allow_test_only_admission_signer: bool = True,
    ) -> None:
        release_sequence = (
            manifest["release_sequence"]
            if release_sequence_head is None
            else release_sequence_head
        )
        prior_release = (
            manifest["prior_release_digest"]
            if prior_release_digest_head is None
            else prior_release_digest_head
        )
        manifest_digest = (
            manifest["digest"]
            if manifest_digest_head is None
            else manifest_digest_head
        )
        admission_sequence = (
            admission["admission_sequence"]
            if admission_sequence_head is None
            else admission_sequence_head
        )
        prior_admission = (
            admission["prior_admission_digest"]
            if prior_admission_digest_head is None
            else prior_admission_digest_head
        )
        admission_digest = (
            admission["digest"]
            if admission_digest_head is None
            else admission_digest_head
        )
        revocation_sequence = (
            admission["revocation_sequence"]
            if revocation_sequence_head is None
            else revocation_sequence_head
        )
        anti_rollback = compute_application_integrity_anti_rollback_digest(
            context_id=context_id,
            head_state_sequence=head_state_sequence,
            release_sequence_head=release_sequence,
            prior_release_digest_head=prior_release,
            manifest_digest_head=manifest_digest,
            admission_sequence_head=admission_sequence,
            prior_admission_digest_head=prior_admission,
            admission_digest_head=admission_digest,
            revocation_sequence_head=revocation_sequence,
        )
        head_payload = {
            "schema_id": HEAD_SNAPSHOT_SCHEMA,
            "context_id": context_id,
            "head_state_sequence": head_state_sequence,
            "release_sequence_head": release_sequence,
            "prior_release_digest_head": prior_release,
            "manifest_digest_head": manifest_digest,
            "admission_sequence_head": admission_sequence,
            "prior_admission_digest_head": prior_admission,
            "admission_digest_head": admission_digest,
            "revocation_sequence_head": revocation_sequence,
            "anti_rollback_state_digest": anti_rollback,
        }
        self.time_provider = time_provider or TimeProviderFixture(
            trusted_now_ms
        )
        self.head_provider = head_provider or HeadProviderFixture(
            {
                **head_payload,
                "head_snapshot_digest": canonical_integrity_hash(
                    head_payload
                ),
            },
            observed_at_ms=trusted_now_ms,
        )
        time_key = self.time_provider.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        head_key = self.head_provider.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        time_evidence = self.time_provider.current_application_integrity_time_evidence(
            context_id
        )
        head_evidence = self.head_provider.current_application_integrity_head_evidence(
            context_id
        )
        resolution = {
            "schema_id": TRUST_CONTEXT_SCHEMA,
            "context_id": context_id,
            "context_version": context_version,
            "status": ACTIVE,
            "owner_admission_authority_pin": deepcopy(
                owner_admission_authority_pin
            ),
            "release_signer": release_signer,
            "admission_signer": admission_signer,
            "release_public_key_fingerprint": (
                release_public_key_fingerprint
                or _public_key_fingerprint(release_signer)
            ),
            "admission_public_key_fingerprint": (
                admission_public_key_fingerprint
                or _public_key_fingerprint(admission_signer)
            ),
            "trusted_time_provider": self.time_provider,
            "anti_rollback_head_provider": self.head_provider,
            "trusted_time_public_key_hex": time_key.hex(),
            "trusted_time_public_key_fingerprint": sha512(time_key).hexdigest(),
            "trusted_time_evidence_digest_head": time_evidence["digest"],
            "anti_rollback_head_public_key_hex": head_key.hex(),
            "anti_rollback_head_public_key_fingerprint": sha512(head_key).hexdigest(),
            "anti_rollback_head_evidence_digest_head": head_evidence["digest"],
            "allow_test_only_release_signer": allow_test_only_release_signer,
            "allow_test_only_admission_signer": (
                allow_test_only_admission_signer
            ),
        }
        resolution["context_digest"] = (
            compute_application_integrity_trust_context_digest(resolution)
        )
        self._resolution = resolution

    @property
    def context_id(self) -> str:
        return self._resolution["context_id"]

    @property
    def context_digest(self) -> str:
        return self._resolution["context_digest"]

    def resolve_application_integrity_trust(
        self,
        context_id: str,
    ) -> dict:
        if context_id != self.context_id:
            raise LookupError("UNKNOWN_CONTEXT")
        return {
            key: (
                value
                if key
                in {
                    "release_signer",
                    "admission_signer",
                    "trusted_time_provider",
                    "anti_rollback_head_provider",
                }
                else deepcopy(value)
            )
            for key, value in self._resolution.items()
        }


class ApplicationIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.provider = ReleaseProviderFixture()
        self.admission_provider = AdmissionProviderFixture()
        self.trusted_now_ms = 1_000_000
        self.contents = {
            "config/app.toml": b"mode = 'prototype'\n",
            "formal/spec.tla": b"---- MODULE Spec ----\n====\n",
            "main.py": b"print('entrypoint')\n",
            "requirements.lock": b"dependency==1.0 --hash=sha512:fixture\n",
            "sbp_lex/runtime.py": b"VALUE = 1\n",
            "security_core/Cargo.lock": b"version = 4\n",
            "security_core/Cargo.toml": b"[package]\nname='core'\n",
            "security_core/src/lib.rs": b"#![forbid(unsafe_code)]\n",
        }
        for relative, content in self.contents.items():
            path = self.root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.manifest, self.admission = self._release_objects()
        self.context = self._trust_context()

    def _issuer(self, provider: ReleaseProviderFixture | None = None) -> dict:
        provider = provider or self.provider
        return {
            "issuer_id": "release-issuer",
            "issuer_version": "1",
            "authority_role": RELEASE_AUTHORITY_ROLE,
            "credential_id": "release-credential",
            "provider_id": provider.provider_id,
            "algorithm": provider.algorithm,
            "key_id": provider.key_id,
            "custody_class": provider.custody_class,
            "effect_authority": provider.effect_authority,
            "signer_class": provider.release_integrity_signer_class,
        }

    def _admission_authority(
        self,
        provider: AdmissionProviderFixture | None = None,
    ) -> dict:
        provider = provider or self.admission_provider
        return {
            "issuer_id": "release-admission-owner",
            "issuer_version": "1",
            "authority_role": ADMISSION_AUTHORITY_ROLE,
            "credential_id": provider.release_admission_credential_id,
            "provider_id": provider.provider_id,
            "algorithm": provider.algorithm,
            "key_id": provider.key_id,
            "custody_class": provider.custody_class,
            "effect_authority": provider.effect_authority,
            "signer_class": provider.release_admission_signer_class,
        }

    def _files(self) -> list[dict]:
        return [
            {
                "path": relative,
                "size": len(content),
                "sha512": sha512(content).hexdigest(),
            }
            for relative, content in sorted(self.contents.items())
        ]

    def _payload(
        self,
        provider: ReleaseProviderFixture | None = None,
    ) -> dict:
        files = self._files()
        bindings = {
            "dependency_locks": [
                "requirements.lock",
                "security_core/Cargo.lock",
            ],
            "configuration": ["config/app.toml"],
            "rust_core": [
                "security_core/Cargo.lock",
                "security_core/Cargo.toml",
                "security_core/src/lib.rs",
            ],
            "formal_spec": ["formal/spec.tla"],
        }
        protected_roots = ["config", "formal", "sbp_lex", "security_core"]
        measurement = compute_runtime_measurement_digest(
            release_id="release-2026-08-28",
            release_version="2.0.0-prototype",
            release_sequence=1,
            entrypoint="main.py",
            protected_roots=protected_roots,
            files=files,
            bindings=bindings,
        )
        return {
            "schema_id": MANIFEST_SCHEMA,
            "release_id": "release-2026-08-28",
            "release_version": "2.0.0-prototype",
            "release_sequence": 1,
            "prior_release_digest": GENESIS,
            "status": ACTIVE,
            "revocation_sequence": 7,
            "entrypoint": "main.py",
            "protected_roots": protected_roots,
            "files": files,
            "bindings": bindings,
            "runtime_measurement_digest": measurement,
            "issuer": self._issuer(provider),
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            "assurance_limits": dict(ASSURANCE_LIMITS),
        }

    def _release_objects(
        self,
        payload: dict | None = None,
        *,
        provider: ReleaseProviderFixture | None = None,
        admission_provider: AdmissionProviderFixture | None = None,
    ) -> tuple[dict, dict]:
        provider = provider or self.provider
        admission_provider = admission_provider or self.admission_provider
        payload = deepcopy(payload or self._payload(provider))
        manifest = build_signed_object(payload, provider=provider)
        admission_payload = {
            "schema_id": TRUSTED_ADMISSION_SCHEMA,
            "admission_id": "owner-admission-2026-08-28",
            "admission_sequence": 1,
            "prior_admission_digest": GENESIS,
            "issued_at_ms": 900_000,
            "not_before_ms": 950_000,
            "expires_at_ms": 1_100_000,
            "release_id": manifest["release_id"],
            "release_version": manifest["release_version"],
            "release_sequence": manifest["release_sequence"],
            "prior_release_digest": manifest["prior_release_digest"],
            "status": manifest["status"],
            "revocation_sequence": manifest["revocation_sequence"],
            "manifest_digest": manifest["digest"],
            "entrypoint": manifest["entrypoint"],
            "issuer": deepcopy(manifest["issuer"]),
            "admission_authority": self._admission_authority(
                admission_provider
            ),
            "revoked_release_digests": [],
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            "assurance_limits": dict(ASSURANCE_LIMITS),
        }
        admission = build_signed_object(
            admission_payload,
            provider=admission_provider,
        )
        return manifest, admission

    def _resign_admission(
        self,
        admission: dict,
        *,
        provider: AdmissionProviderFixture | None = None,
    ) -> dict:
        payload = {
            key: deepcopy(value)
            for key, value in admission.items()
            if key not in {"digest", "signature", "verified"}
        }
        return build_signed_object(
            payload,
            provider=provider or self.admission_provider,
        )

    def _trust_context(
        self,
        manifest: dict | None = None,
        admission: dict | None = None,
        *,
        release_signer: ReleaseProviderFixture | None = None,
        admission_signer: AdmissionProviderFixture | None = None,
        **overrides,
    ) -> TrustContextFixture:
        manifest = manifest or self.manifest
        admission = admission or self.admission
        admission_signer = admission_signer or self.admission_provider
        return TrustContextFixture(
            manifest=manifest,
            admission=admission,
            owner_admission_authority_pin=self._admission_authority(
                admission_signer
            ),
            release_signer=release_signer or self.provider,
            admission_signer=admission_signer,
            **overrides,
        )

    def _verify(
        self,
        manifest: dict | None = None,
        admission: dict | None = None,
        **overrides,
    ):
        arguments = {
            "release_root": self.root,
            "trusted_admission": admission or self.admission,
            "trust_context": self.context,
            "fixed_context_id": self.context.context_id,
            "owner_pinned_context_digest": self.context.context_digest,
        }
        selected_context = overrides.get("trust_context")
        if selected_context is not None and hasattr(
            selected_context,
            "context_id",
        ):
            arguments["fixed_context_id"] = selected_context.context_id
            arguments["owner_pinned_context_digest"] = (
                selected_context.context_digest
            )
        arguments.update(overrides)
        return verify_application_integrity(
            manifest or self.manifest,
            **arguments,
        )

    def _verify_result(self, result: dict, **overrides) -> bool:
        arguments = {
            "manifest": self.manifest,
            "trusted_admission": self.admission,
            "release_root": self.root,
            "trust_context": self.context,
            "fixed_context_id": self.context.context_id,
            "owner_pinned_context_digest": self.context.context_digest,
        }
        arguments.update(overrides)
        return verify_application_integrity_result(result, **arguments)

    def test_exact_release_passes_with_deterministic_trace_and_no_authority(self) -> None:
        first = self._verify()
        second = self._verify()

        self.assertEqual(first, second)
        self.assertEqual(first["result"], "PASS")
        self.assertEqual(
            first["runtime_measurement_digest"],
            self.manifest["runtime_measurement_digest"],
        )
        self.assertTrue(first["trace"])
        self.assertEqual(first["trace"][-1]["stage"], "terminal")
        self.assertEqual(first["authorization_effect"], NO_AUTHORIZATION_EFFECT)
        self.assertFalse(any(first["authorization_effect"].values()))
        self.assertEqual(first["assurance_limits"], ASSURANCE_LIMITS)
        self.assertTrue(self._verify_result(first))

    def test_test_only_signer_requires_explicit_test_admission(self) -> None:
        release_denied = self._trust_context(
            allow_test_only_release_signer=False,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TEST_ONLY_RELEASE_SIGNER_REJECTED",
        ):
            self._verify(trust_context=release_denied)

        class UnavailableContext:
            pass

        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TRUST_CONTEXT_UNAVAILABLE",
        ):
            self._verify(
                trust_context=UnavailableContext(),
                fixed_context_id=self.context.context_id,
                owner_pinned_context_digest=self.context.context_digest,
            )
        admission_denied = self._trust_context(
            allow_test_only_admission_signer=False,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TEST_ONLY_RELEASE_ADMISSION_SIGNER_REJECTED",
        ):
            self._verify(trust_context=admission_denied)

    def test_file_tamper_removal_and_undeclared_module_fail_closed(self) -> None:
        runtime = self.root / "sbp_lex" / "runtime.py"
        runtime.write_bytes(b"VALUE = 2\n")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_FILE_MEASUREMENT_MISMATCH",
        ):
            self._verify()

        runtime.write_bytes(self.contents["sbp_lex/runtime.py"])
        (self.root / "formal" / "spec.tla").unlink()
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE",
        ):
            self._verify()

        (self.root / "formal" / "spec.tla").write_bytes(
            self.contents["formal/spec.tla"]
        )
        (self.root / "sbp_lex" / "injected.py").write_bytes(b"ALLOW = True\n")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "UNDECLARED_PROTECTED_ROOT_FILE",
        ):
            self._verify()

    def test_manifest_shape_binding_and_runtime_digest_tamper_fail_closed(self) -> None:
        extra = deepcopy(self.manifest)
        extra["unexpected"] = True
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_MANIFEST_SHAPE_INVALID",
        ):
            self._verify(extra)

        payload = self._payload()
        payload["bindings"]["rust_core"] = ["not-declared.rs"]
        manifest, admission = self._release_objects(payload)
        context = self._trust_context(manifest, admission)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_BINDING_REFERENCES_UNDECLARED_FILE",
        ):
            self._verify(manifest, admission, trust_context=context)

        payload = self._payload()
        payload["runtime_measurement_digest"] = "0" * 128
        manifest, admission = self._release_objects(payload)
        context = self._trust_context(manifest, admission)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_RUNTIME_MEASUREMENT_MISMATCH",
        ):
            self._verify(manifest, admission, trust_context=context)

    def test_path_escape_symlink_and_untrusted_signer_fail_closed(self) -> None:
        payload = self._payload()
        payload["entrypoint"] = "../main.py"
        manifest, admission = self._release_objects(payload)
        context = self._trust_context(manifest, admission)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TRUSTED_RELEASE_ENTRYPOINT_INVALID",
        ):
            self._verify(manifest, admission, trust_context=context)

        link = self.root / "sbp_lex" / "linked.py"
        try:
            os.symlink(self.root / "main.py", link)
        except OSError:
            pass
        else:
            with self.assertRaisesRegex(
                ApplicationIntegrityRejected,
                "RELEASE_PATH_SYMLINK_OR_REPARSE_REJECTED",
            ):
                self._verify()
            link.unlink()

        other = ReleaseProviderFixture()
        other_context = self._trust_context(release_signer=other)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_SIGNER_IDENTITY_MISMATCH",
        ):
            self._verify(trust_context=other_context)

    def test_replay_rollback_and_revocation_evidence_fail_closed(self) -> None:
        replay = deepcopy(self.admission)
        replay["manifest_digest"] = "a" * 128
        replay = self._resign_admission(replay)
        replay_context = self._trust_context(admission=replay)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_TRUSTED_ADMISSION_MISMATCH",
        ):
            self._verify(admission=replay, trust_context=replay_context)

        rollback = deepcopy(self.admission)
        rollback["release_sequence"] = 2
        rollback = self._resign_admission(rollback)
        rollback_context = self._trust_context(admission=rollback)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_TRUSTED_ADMISSION_MISMATCH",
        ):
            self._verify(admission=rollback, trust_context=rollback_context)

        revoked = deepcopy(self.admission)
        revoked["revoked_release_digests"] = [self.manifest["digest"]]
        revoked = self._resign_admission(revoked)
        revoked_context = self._trust_context(admission=revoked)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_MANIFEST_REVOKED",
        ):
            self._verify(admission=revoked, trust_context=revoked_context)

    def test_unsigned_wrong_self_admitted_and_tampered_admissions_fail_closed(
        self,
    ) -> None:
        unsigned = {
            key: deepcopy(value)
            for key, value in self.admission.items()
            if key not in {"digest", "signature", "verified"}
        }
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TRUSTED_RELEASE_ADMISSION_SHAPE_INVALID",
        ):
            self._verify(admission=unsigned)

        same_key_provider = AdmissionProviderFixture(self.provider)
        manifest, self_admission = self._release_objects(
            admission_provider=same_key_provider,
        )
        self_admission_context = self._trust_context(
            manifest,
            self_admission,
            admission_signer=same_key_provider,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TRUST_CONTEXT_INVALID",
        ):
            self._verify(
                manifest,
                self_admission,
                trust_context=self_admission_context,
            )

        wrong_admission_signer = AdmissionProviderFixture()
        wrong_context = TrustContextFixture(
            manifest=self.manifest,
            admission=self.admission,
            owner_admission_authority_pin=self._admission_authority(),
            release_signer=self.provider,
            admission_signer=wrong_admission_signer,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_ADMISSION_SIGNER_IDENTITY_MISMATCH",
        ):
            self._verify(trust_context=wrong_context)

        tampered = deepcopy(self.admission)
        tampered["signature"]["signature_b64"] = "AA=="
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TRUSTED_RELEASE_ADMISSION_SIGNATURE_INVALID",
        ):
            self._verify(admission=tampered)

    def test_admission_rollback_expiry_and_revocation_fail_closed(self) -> None:
        rollback_context = self._trust_context(
            admission_sequence_head=2,
            prior_admission_digest_head="b" * 128,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TRUSTED_ADMISSION_SEQUENCE_ROLLBACK_OR_MISMATCH",
        ):
            self._verify(trust_context=rollback_context)

        expired_context = self._trust_context(
            trusted_now_ms=self.admission["expires_at_ms"],
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "TRUSTED_RELEASE_ADMISSION_EXPIRED",
        ):
            self._verify(trust_context=expired_context)

        revoked = deepcopy(self.admission)
        revoked["revoked_release_digests"] = [self.manifest["digest"]]
        revoked = self._resign_admission(revoked)
        revoked_context = self._trust_context(admission=revoked)
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_MANIFEST_REVOKED",
        ):
            self._verify(admission=revoked, trust_context=revoked_context)

    def test_hard_link_and_post_pass_mutation_fail_closed(self) -> None:
        hard_link = self.root / "runtime-hard-link.py"
        try:
            os.link(self.root / "sbp_lex" / "runtime.py", hard_link)
        except OSError as exc:
            self.skipTest(f"hard links unavailable: {exc}")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_HARD_LINK_REJECTED",
        ):
            self._verify()
        hard_link.unlink()

        result = self._verify()
        (self.root / "sbp_lex" / "runtime.py").write_bytes(b"VALUE = 9\n")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "RELEASE_FILE_MEASUREMENT_MISMATCH",
        ):
            self._verify_result(result)

    def test_result_and_signed_receipt_tamper_fail_closed(self) -> None:
        result = self._verify()
        tampered_result = deepcopy(result)
        tampered_result["release_version"] = "attacker-version"
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_RESULT_DIGEST_INVALID",
        ):
            self._verify_result(tampered_result)

        tampered_receipt = deepcopy(result)
        tampered_receipt["receipt"]["signature"]["signature_b64"] = "AA=="
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_RECEIPT_INVALID",
        ):
            self._verify_result(tampered_receipt)

    def test_self_consistent_attacker_context_is_not_owner_pinned(self) -> None:
        attacker_release = ReleaseProviderFixture()
        attacker_admission = AdmissionProviderFixture()
        attacker_manifest, attacker_admission_object = self._release_objects(
            provider=attacker_release,
            admission_provider=attacker_admission,
        )
        attacker_context = self._trust_context(
            attacker_manifest,
            attacker_admission_object,
            release_signer=attacker_release,
            admission_signer=attacker_admission,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TRUST_CONTEXT_NOT_OWNER_PINNED",
        ):
            self._verify(
                attacker_manifest,
                attacker_admission_object,
                trust_context=attacker_context,
                fixed_context_id=self.context.context_id,
                owner_pinned_context_digest=self.context.context_digest,
            )

    def test_key_swap_and_owner_bound_provider_substitution_fail_closed(
        self,
    ) -> None:
        replacement = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )
        self.provider._provider = replacement
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_PIN_MISMATCH",
        ):
            self._verify()

        context = self._trust_context()
        context.time_provider.application_integrity_time_provider_id = (
            "attacker-clock"
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TRUST_CONTEXT_NOT_OWNER_PINNED",
        ):
            self._verify(trust_context=context)

    def test_historical_result_replay_and_head_rollback_fail_closed(self) -> None:
        result = self._verify()
        self.context.head_provider.snapshot = _head_snapshot(
            context_id=self.context.context_id,
            manifest=self.manifest,
            admission=self.admission,
            head_state_sequence=2,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_HEAD_EVIDENCE_NOT_CURRENT",
        ):
            self._verify_result(result)

        head_two_context = self._trust_context(head_state_sequence=2)
        head_two_result = self._verify(trust_context=head_two_context)
        head_two_context.head_provider.snapshot = _head_snapshot(
            context_id=head_two_context.context_id,
            manifest=self.manifest,
            admission=self.admission,
            head_state_sequence=1,
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_(HEAD_EVIDENCE_NOT_CURRENT|TRUST_CONTEXT_NOT_OWNER_PINNED)",
        ):
            self._verify_result(
                head_two_result,
                trust_context=head_two_context,
            )

    def test_heads_cannot_change_between_admission_and_terminal_check(self) -> None:
        first = _head_snapshot(
            context_id=self.context.context_id,
            manifest=self.manifest,
            admission=self.admission,
            head_state_sequence=2,
        )
        rolled_back = _head_snapshot(
            context_id=self.context.context_id,
            manifest=self.manifest,
            admission=self.admission,
            head_state_sequence=1,
        )

        class RollingBackHeadProvider(HeadProviderFixture):
            def __init__(self) -> None:
                super().__init__(first)
                self._responses = [first, first, rolled_back]

            def current_application_integrity_head_evidence(
                self,
                context_id: str,
            ) -> dict:
                self.snapshot = deepcopy(self._responses.pop(0))
                return super().current_application_integrity_head_evidence(context_id)

        context = self._trust_context(
            head_state_sequence=2,
            head_provider=RollingBackHeadProvider(),
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_HEAD_EVIDENCE_NOT_CURRENT",
        ):
            self._verify(trust_context=context)

    def test_cloned_clock_and_head_metadata_cannot_substitute_pinned_keys(self) -> None:
        for dependency in ("clock", "head"):
            with self.subTest(dependency=dependency):
                context = self._trust_context()
                provider = (
                    context.time_provider
                    if dependency == "clock"
                    else context.head_provider
                )
                replacement = Ed25519SoftwareProvider.from_private_key(
                    Ed25519PrivateKey.generate()
                )
                provider._provider = replacement
                with self.assertRaisesRegex(
                    ApplicationIntegrityRejected,
                    "APPLICATION_INTEGRITY_EVIDENCE_PUBLIC_KEY_PIN_MISMATCH",
                ):
                    self._verify(trust_context=context)

    def test_historical_signed_clock_and_head_evidence_are_rejected(self) -> None:
        historical_clock = TimeProviderFixture(900_000)
        old_clock_evidence = (
            historical_clock.current_application_integrity_time_evidence(
                self.context.context_id
            )
        )
        historical_clock.now_ms = 1_000_000
        historical_clock.evidence_sequence = 2
        clock_context = self._trust_context(time_provider=historical_clock)
        historical_clock.current_application_integrity_time_evidence = (
            lambda context_id: deepcopy(old_clock_evidence)
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TIME_EVIDENCE_NOT_CURRENT",
        ):
            self._verify(trust_context=clock_context)

        historical_head = HeadProviderFixture(
            _head_snapshot(
                context_id=self.context.context_id,
                manifest=self.manifest,
                admission=self.admission,
                head_state_sequence=1,
            )
        )
        old_head_evidence = (
            historical_head.current_application_integrity_head_evidence(
                self.context.context_id
            )
        )
        historical_head.snapshot = _head_snapshot(
            context_id=self.context.context_id,
            manifest=self.manifest,
            admission=self.admission,
            head_state_sequence=2,
        )
        historical_head.evidence_sequence = 2
        head_context = self._trust_context(
            head_state_sequence=2,
            head_provider=historical_head,
        )
        historical_head.current_application_integrity_head_evidence = (
            lambda context_id: deepcopy(old_head_evidence)
        )
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_(HEAD_EVIDENCE_NOT_CURRENT|TRUST_CONTEXT_NOT_OWNER_PINNED)",
        ):
            self._verify(trust_context=head_context)

    def test_signed_time_change_at_terminal_revalidation_fails_closed(self) -> None:
        class ChangingTimeProvider(TimeProviderFixture):
            def __init__(self) -> None:
                super().__init__(1_000_000)
                self._reads = 0

            def current_application_integrity_time_evidence(
                self,
                context_id: str,
            ) -> dict:
                self._reads += 1
                if self._reads >= 3:
                    self.now_ms = 1_000_001
                    self.evidence_sequence = 2
                return super().current_application_integrity_time_evidence(
                    context_id
                )

        context = self._trust_context(time_provider=ChangingTimeProvider())
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TIME_EVIDENCE_NOT_CURRENT",
        ):
            self._verify(trust_context=context)

    def test_unsupported_nested_result_and_receipt_values_are_structured(self) -> None:
        result = self._verify()
        malformed_result = deepcopy(result)
        malformed_result["issuer"]["issuer_version"] = object()
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_RESULT_MALFORMED_NESTED_VALUE",
        ):
            self._verify_result(malformed_result)

        malformed_receipt = deepcopy(result)
        malformed_receipt["receipt"]["signature"]["signature_b64"] = object()
        with self.assertRaises(ApplicationIntegrityRejected):
            self._verify_result(malformed_receipt)

    def test_all_regular_protected_files_are_measured_and_paths_redacted(
        self,
    ) -> None:
        unmeasured = self.root / "sbp_lex" / "policy-notes.txt"
        unmeasured.write_bytes(b"unmeasured policy data")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "UNDECLARED_PROTECTED_ROOT_FILE",
        ):
            self._verify()
        unmeasured.unlink()

        result = self._verify()
        rendered = repr(result)
        for relative_path in self.contents:
            self.assertNotIn(relative_path, rendered)
        path_stages = {
            "manifest_contract",
            "file_measurement",
            "protected_root_inventory",
        }
        self.assertTrue(
            all(
                entry["subject"].startswith("path-sha512:")
                for entry in result["trace"]
                if entry["stage"] in path_stages
            )
        )
        for required_limit in (
            "private_composition_root_isolation",
            "same_verified_file_handle_execution",
            "tpm_measurement",
            "platform_code_signing",
            "os_immutable_release_root",
        ):
            self.assertEqual(result["assurance_limits"][required_limit], "NOT_PROVEN")

    def test_dependency_and_property_failures_are_structured_denials(self) -> None:
        time_failure = self._trust_context()
        time_failure.time_provider.failure = RuntimeError("clock offline")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
        ):
            self._verify(trust_context=time_failure)

        head_failure = self._trust_context()
        head_failure.head_provider.failure = RuntimeError("head store offline")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
        ):
            self._verify(trust_context=head_failure)

        key_failure = self._trust_context()
        self.provider.public_key_failure = RuntimeError("public key offline")
        with self.assertRaisesRegex(
            ApplicationIntegrityRejected,
            "APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_UNAVAILABLE",
        ):
            self._verify(trust_context=key_failure)


if __name__ == "__main__":
    unittest.main()
