"""Out-of-band deployment identity and owner-pinned trust roots.

Nothing in a package may construct or select this object.  A verifier receives
it from deployment configuration and compares package digests against it.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .constants import (
    ARTIFACT_SIGNING_PURPOSE,
    CLOCK_SIGNING_PURPOSE,
    HISTORY_SIGNING_PURPOSE,
    PRODUCTION,
    REPOSITORY_IDENTITY_SCHEMA,
    TEST_ONLY,
)
from .digests import digest, digest_equal, is_sha512
from .paths import resolve_safe_path, validated_root
from .signing import HybridVerificationContext


class DeploymentTrustError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class RepositoryIdentity:
    """Deployment-fixed identity for one exact local repository directory."""

    repository_id: str
    canonical_root: str
    root_device: int
    root_inode: int
    git_metadata_device: int
    git_metadata_inode: int

    @classmethod
    def measure(cls, repository_root: str | Path, *, repository_id: str) -> "RepositoryIdentity":
        if type(repository_id) is not str or not repository_id:
            raise DeploymentTrustError("repository_id_invalid")
        root = validated_root(repository_root)
        git_metadata = resolve_safe_path(root, ".git")
        try:
            root_stat = root.lstat()
            git_stat = git_metadata.lstat()
        except OSError as exc:
            raise DeploymentTrustError("repository_identity_unavailable") from exc
        if not stat.S_ISDIR(git_stat.st_mode) or stat.S_ISLNK(git_stat.st_mode):
            raise DeploymentTrustError("repository_git_metadata_not_fixed_directory")
        canonical_root = os.path.normcase(str(root)) if os.name == "nt" else str(root)
        return cls(
            repository_id=repository_id,
            canonical_root=canonical_root,
            root_device=int(root_stat.st_dev),
            root_inode=int(root_stat.st_ino),
            git_metadata_device=int(git_stat.st_dev),
            git_metadata_inode=int(git_stat.st_ino),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_id": REPOSITORY_IDENTITY_SCHEMA,
            "repository_id": self.repository_id,
            "canonical_root": self.canonical_root,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
            "git_metadata_device": self.git_metadata_device,
            "git_metadata_inode": self.git_metadata_inode,
        }

    @property
    def identity_digest(self) -> str:
        return digest(self.as_dict())

    def matches(self, repository_root: str | Path) -> bool:
        try:
            observed = RepositoryIdentity.measure(
                repository_root, repository_id=self.repository_id
            )
        except DeploymentTrustError:
            return False
        return observed == self


@dataclass(frozen=True, slots=True)
class ExternalProviderAdmission:
    """Deployment-owned evidence; this package never manufactures it."""

    trust_custody_attestation_sha512: str
    trusted_clock_attestation_sha512: str
    durable_history_attestation_sha512: str
    admission_record_sha512: str

    def __post_init__(self) -> None:
        if not all(
            is_sha512(value)
            for value in (
                self.trust_custody_attestation_sha512,
                self.trusted_clock_attestation_sha512,
                self.durable_history_attestation_sha512,
                self.admission_record_sha512,
            )
        ):
            raise DeploymentTrustError("external_provider_admission_invalid")


@dataclass(frozen=True, slots=True)
class DeploymentTrust:
    """Three independent trust roots plus fixed repo and durable live-head pins."""

    composition_class: str
    repository_identity: RepositoryIdentity
    artifact_context: HybridVerificationContext
    clock_context: HybridVerificationContext
    history_context: HybridVerificationContext
    owner_pinned_artifact_context_digest: str
    owner_pinned_clock_context_digest: str
    owner_pinned_history_context_digest: str
    expected_accepted_history_digest: str
    minimum_accepted_history_sequence: int
    external_provider_admission: ExternalProviderAdmission | None = None

    def __post_init__(self) -> None:
        if self.composition_class not in {PRODUCTION, TEST_ONLY}:
            raise DeploymentTrustError("composition_class_invalid")
        contexts = (self.artifact_context, self.clock_context, self.history_context)
        purposes = (
            ARTIFACT_SIGNING_PURPOSE,
            CLOCK_SIGNING_PURPOSE,
            HISTORY_SIGNING_PURPOSE,
        )
        pins = (
            self.owner_pinned_artifact_context_digest,
            self.owner_pinned_clock_context_digest,
            self.owner_pinned_history_context_digest,
        )
        for context, purpose, pin in zip(contexts, purposes, pins):
            if context.purpose != purpose or not digest_equal(context.context_digest, pin):
                raise DeploymentTrustError("owner_pinned_context_invalid")
        if len({context.context_digest for context in contexts}) != 3:
            raise DeploymentTrustError("trust_roles_not_distinct")
        raw_keys = [
            key
            for context in contexts
            for key in (context.mldsa87_public_key_bytes, context.ed448_public_key_bytes)
        ]
        if len(raw_keys) != len(set(raw_keys)):
            raise DeploymentTrustError("owner_pinned_raw_public_keys_not_distinct")
        if not is_sha512(self.expected_accepted_history_digest):
            raise DeploymentTrustError("accepted_history_pin_invalid")
        if (
            type(self.minimum_accepted_history_sequence) is not int
            or self.minimum_accepted_history_sequence < 0
        ):
            raise DeploymentTrustError("accepted_history_minimum_sequence_invalid")
        if self.composition_class == TEST_ONLY:
            if any(
                context.signer_class != TEST_ONLY or not context.allow_test_only
                for context in contexts
            ):
                raise DeploymentTrustError("test_only_composition_not_explicit")
            if self.external_provider_admission is not None:
                raise DeploymentTrustError("test_only_external_provider_claim_rejected")
        else:
            if any(
                context.signer_class != PRODUCTION or context.allow_test_only
                for context in contexts
            ):
                raise DeploymentTrustError("production_context_not_admitted")
            if self.external_provider_admission is None:
                raise DeploymentTrustError("production_external_providers_required")
            raise DeploymentTrustError("production_provider_integration_not_implemented")

    def validate_repository(self, repository_root: str | Path) -> None:
        if not self.repository_identity.matches(repository_root):
            raise DeploymentTrustError("deployment_repository_identity_mismatch")


__all__ = [
    "DeploymentTrust",
    "DeploymentTrustError",
    "ExternalProviderAdmission",
    "RepositoryIdentity",
]
