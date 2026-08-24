from __future__ import annotations

import base64
import binascii
import json
import os
import stat
import unicodedata
from hashlib import sha512
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.integrity import (
    canonical_integrity_hash,
    is_sha512,
)
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    build_legacy_non_effect_signed_object,
    build_signed_object,
    verify_signed_object,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    PRODUCTION_SIGNER,
    TEST_ONLY_SIGNER,
    HybridSignatureError,
    HybridVerificationContext,
    is_hybrid_provider,
)


MANIFEST_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_RELEASE_MANIFEST_V1"
TRUSTED_ADMISSION_SCHEMA = "SBP_LEX_V2_TRUSTED_RELEASE_ADMISSION_V2"
RUNTIME_MEASUREMENT_SCHEMA = "SBP_LEX_V2_RUNTIME_MEASUREMENT_V1"
RESULT_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_RESULT_V2"
RECEIPT_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_RECEIPT_V1"
TRACE_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_TRACE_V1"
TRUST_CONTEXT_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_TRUST_CONTEXT_V1"
ANTI_ROLLBACK_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_ANTI_ROLLBACK_V1"
HEAD_SNAPSHOT_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_HEAD_SNAPSHOT_V1"
TIME_EVIDENCE_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_TIME_EVIDENCE_V1"
HEAD_EVIDENCE_SCHEMA = "SBP_LEX_V2_APPLICATION_INTEGRITY_HEAD_EVIDENCE_V1"
RELEASE_AUTHORITY_ROLE = "SBP_LEX_RELEASE_INTEGRITY_ISSUER"
ADMISSION_AUTHORITY_ROLE = "SBP_LEX_RELEASE_ADMISSION_AUTHORITY"
ACTIVE = "ACTIVE"
GENESIS = "GENESIS"

NO_AUTHORIZATION_EFFECT = {
    "authority_granted": False,
    "governance_authority_granted": False,
    "licence_granted": False,
    "execution_authority_granted": False,
    "effect_authority_granted": False,
    "bypass_granted": False,
}

ASSURANCE_LIMITS = {
    "os_secure_boot": "NOT_PROVEN",
    "platform_code_signing": "NOT_PROVEN",
    "tpm_measurement": "NOT_PROVEN",
    "measured_startup": "NOT_PROVEN",
    "external_anti_rollback": "NOT_PROVEN",
    "os_immutable_release_root": "NOT_PROVEN",
    "final_execute_time_remeasurement": "NOT_PROVEN",
    "same_verified_file_handle_execution": "NOT_PROVEN",
    "private_composition_root_isolation": "NOT_PROVEN",
}

_MANIFEST_PAYLOAD_FIELDS = {
    "schema_id",
    "release_id",
    "release_version",
    "release_sequence",
    "prior_release_digest",
    "status",
    "revocation_sequence",
    "entrypoint",
    "protected_roots",
    "files",
    "bindings",
    "runtime_measurement_digest",
    "issuer",
    "authorization_effect",
    "assurance_limits",
}
_SIGNED_OBJECT_FIELDS = _MANIFEST_PAYLOAD_FIELDS | {
    "digest",
    "signature",
    "verified",
}
_FILE_FIELDS = {"path", "size", "sha512"}
_BINDING_FIELDS = {
    "dependency_locks",
    "configuration",
    "rust_core",
    "formal_spec",
}
_ISSUER_FIELDS = {
    "issuer_id",
    "issuer_version",
    "authority_role",
    "credential_id",
    "provider_id",
    "algorithm",
    "key_id",
    "custody_class",
    "effect_authority",
    "signer_class",
}
_TRUSTED_ADMISSION_PAYLOAD_FIELDS = {
    "schema_id",
    "admission_id",
    "admission_sequence",
    "prior_admission_digest",
    "issued_at_ms",
    "not_before_ms",
    "expires_at_ms",
    "release_id",
    "release_version",
    "release_sequence",
    "prior_release_digest",
    "status",
    "revocation_sequence",
    "manifest_digest",
    "entrypoint",
    "issuer",
    "admission_authority",
    "revoked_release_digests",
    "authorization_effect",
    "assurance_limits",
}
_TRUSTED_ADMISSION_FIELDS = _TRUSTED_ADMISSION_PAYLOAD_FIELDS | {
    "digest",
    "signature",
    "verified",
}
_TRUST_CONTEXT_PAYLOAD_FIELDS = {
    "schema_id",
    "context_id",
    "context_version",
    "status",
    "owner_admission_authority_pin",
    "release_signer",
    "admission_signer",
    "release_public_key_fingerprint",
    "admission_public_key_fingerprint",
    "trusted_time_provider",
    "anti_rollback_head_provider",
    "trusted_time_public_key_hex",
    "trusted_time_public_key_fingerprint",
    "trusted_time_evidence_digest_head",
    "anti_rollback_head_public_key_hex",
    "anti_rollback_head_public_key_fingerprint",
    "anti_rollback_head_evidence_digest_head",
    "allow_test_only_release_signer",
    "allow_test_only_admission_signer",
}
_TRUST_CONTEXT_FIELDS = _TRUST_CONTEXT_PAYLOAD_FIELDS | {"context_digest"}
_HEAD_SNAPSHOT_PAYLOAD_FIELDS = {
    "schema_id",
    "context_id",
    "head_state_sequence",
    "release_sequence_head",
    "prior_release_digest_head",
    "manifest_digest_head",
    "admission_sequence_head",
    "prior_admission_digest_head",
    "admission_digest_head",
    "revocation_sequence_head",
    "anti_rollback_state_digest",
}
_HEAD_SNAPSHOT_FIELDS = _HEAD_SNAPSHOT_PAYLOAD_FIELDS | {"head_snapshot_digest"}
_TIME_EVIDENCE_PAYLOAD_FIELDS = {
    "schema_id",
    "context_id",
    "provider_id",
    "provider_version",
    "source_class",
    "evidence_sequence",
    "observed_at_ms",
    "status",
    "authorization_effect",
}
_TIME_EVIDENCE_FIELDS = _TIME_EVIDENCE_PAYLOAD_FIELDS | {
    "digest",
    "signature",
    "verified",
}
_HEAD_EVIDENCE_PAYLOAD_FIELDS = {
    "schema_id",
    "context_id",
    "provider_id",
    "provider_version",
    "storage_class",
    "evidence_sequence",
    "observed_at_ms",
    "status",
    "head_snapshot",
    "authorization_effect",
}
_HEAD_EVIDENCE_FIELDS = _HEAD_EVIDENCE_PAYLOAD_FIELDS | {
    "digest",
    "signature",
    "verified",
}
_RESULT_PAYLOAD_FIELDS = {
    "schema_id",
    "result",
    "release_id",
    "release_version",
    "release_sequence",
    "manifest_digest",
    "admission_sequence",
    "admission_digest",
    "runtime_measurement_digest",
    "issuer",
    "admission_authority",
    "trust_context_id",
    "trust_context_digest",
    "head_state_sequence",
    "head_snapshot_digest",
    "trusted_time_evidence_digest",
    "head_snapshot_evidence_digest",
    "anti_rollback_state_digest",
    "release_public_key_fingerprint",
    "admission_public_key_fingerprint",
    "trace",
    "trace_digest",
    "authorization_effect",
    "assurance_limits",
}
_RESULT_FIELDS = _RESULT_PAYLOAD_FIELDS | {"result_digest", "receipt"}
_RECEIPT_PAYLOAD_FIELDS = {
    "schema_id",
    "receipt_id",
    "issued_at_ms",
    "trust_context_id",
    "trust_context_digest",
    "head_state_sequence",
    "head_snapshot_digest",
    "trusted_time_evidence_digest",
    "head_snapshot_evidence_digest",
    "anti_rollback_state_digest",
    "release_public_key_fingerprint",
    "admission_public_key_fingerprint",
    "result_digest",
    "manifest_digest",
    "admission_digest",
    "runtime_measurement_digest",
    "trace_digest",
    "authorization_effect",
    "assurance_limits",
}
_RECEIPT_FIELDS = _RECEIPT_PAYLOAD_FIELDS | {
    "digest",
    "signature",
    "verified",
}

class ApplicationIntegrityRejected(ValueError):
    """The release cannot cross the application-integrity boundary."""


class ApplicationIntegrityProvider(SignatureProvider, Protocol):
    release_integrity_attestation_admitted: bool
    release_integrity_signer_class: str


class ApplicationIntegrityAdmissionProvider(SignatureProvider, Protocol):
    release_admission_attestation_admitted: bool
    release_admission_signer_class: str
    release_admission_credential_id: str


class ApplicationIntegrityTrustContext(Protocol):
    """Deployment-owned resolver for one fixed application-integrity context."""

    def resolve_application_integrity_trust(
        self,
        context_id: str,
    ) -> dict[str, Any]: ...


class ApplicationIntegrityTimeProvider(Protocol):
    application_integrity_time_provider_id: str
    application_integrity_time_provider_version: str
    application_integrity_time_source_class: str
    application_integrity_time_owner_bound: bool

    @property
    def public_key(self) -> Any: ...

    def current_application_integrity_time_evidence(
        self,
        context_id: str,
    ) -> dict[str, Any]: ...


class ApplicationIntegrityHeadProvider(Protocol):
    application_integrity_head_provider_id: str
    application_integrity_head_provider_version: str
    application_integrity_head_storage_class: str
    application_integrity_heads_owner_bound: bool
    application_integrity_heads_durable: bool
    application_integrity_heads_atomic: bool

    @property
    def public_key(self) -> Any: ...

    def current_application_integrity_head_evidence(
        self,
        context_id: str,
    ) -> dict[str, Any]: ...


def _reject(code: str) -> ApplicationIntegrityRejected:
    return ApplicationIntegrityRejected(code)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _positive_int(value: Any) -> bool:
    return type(value) is int and value > 0


def _reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _canonical_relative_path(value: Any, *, code: str) -> str:
    if not _text(value):
        raise _reject(code)
    if unicodedata.normalize("NFC", value) != value:
        raise _reject(code)
    if "\\" in value or "\x00" in value:
        raise _reject(code)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or value in {".", ".."}
        or any(part in {"", ".", ".."} or ":" in part for part in path.parts)
    ):
        raise _reject(code)
    return value


def _canonical_path_list(value: Any, *, code: str) -> list[str]:
    if type(value) is not list or not value:
        raise _reject(code)
    paths = [_canonical_relative_path(item, code=code) for item in value]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise _reject(code)
    if len({path.casefold() for path in paths}) != len(paths):
        raise _reject(code)
    return paths


def _inside_release_root(release_root: Path, relative_path: str) -> Path:
    candidate = release_root.joinpath(*PurePosixPath(relative_path).parts)
    current = release_root
    for part in PurePosixPath(relative_path).parts:
        current = current / part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
        if stat.S_ISLNK(metadata.st_mode) or _reparse_point(current):
            raise _reject("RELEASE_PATH_SYMLINK_OR_REPARSE_REJECTED")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(release_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise _reject("RELEASE_PATH_ESCAPE_REJECTED") from exc
    return resolved


def _validated_release_root(value: str | Path) -> Path:
    try:
        root = Path(value)
    except (TypeError, ValueError, OSError) as exc:
        raise _reject("RELEASE_ROOT_INVALID") from exc
    if not root.is_absolute():
        raise _reject("RELEASE_ROOT_MUST_BE_ABSOLUTE")
    try:
        metadata = root.lstat()
    except OSError as exc:
        raise _reject("RELEASE_ROOT_UNAVAILABLE") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _reparse_point(root)
    ):
        raise _reject("RELEASE_ROOT_INVALID")
    try:
        return root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _reject("RELEASE_ROOT_UNAVAILABLE") from exc


def _file_identity(metadata: os.stat_result) -> tuple[Any, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
    )


def _read_only_no_follow_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _raw_file_measurement(path: Path, *, relative_path: str) -> dict[str, Any]:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or _reparse_point(path):
            raise _reject("RELEASE_PATH_SYMLINK_OR_REPARSE_REJECTED")
        if not stat.S_ISREG(before.st_mode):
            raise _reject("RELEASE_DECLARED_PATH_NOT_REGULAR_FILE")
        if before.st_nlink != 1:
            raise _reject("RELEASE_HARD_LINK_REJECTED")
        digest = sha512()
        size = 0
        descriptor = os.open(path, _read_only_no_follow_flags())
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened_before = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened_before.st_mode)
                or opened_before.st_nlink != 1
                or _file_identity(before) != _file_identity(opened_before)
            ):
                raise _reject("RELEASE_FILE_IDENTITY_CHANGED")
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
            opened_after = os.fstat(handle.fileno())
        after = path.lstat()
    except ApplicationIntegrityRejected:
        raise
    except OSError as exc:
        raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
    identities = {
        _file_identity(before),
        _file_identity(opened_before),
        _file_identity(opened_after),
        _file_identity(after),
    }
    if len(identities) != 1 or size != opened_after.st_size:
        raise _reject("RELEASE_FILE_CHANGED_DURING_MEASUREMENT")
    return {
        "path": relative_path,
        "size": size,
        "sha512": digest.hexdigest(),
    }


def _protected_root_inventory(
    release_root: Path,
    relative_root: str,
) -> list[dict[str, Any]]:
    root = _inside_release_root(release_root, relative_root)
    try:
        if not root.is_dir():
            raise _reject("RELEASE_PROTECTED_ROOT_NOT_DIRECTORY")
    except OSError as exc:
        raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
    protected_files: list[dict[str, Any]] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
        for child in children:
            try:
                metadata = child.lstat()
            except OSError as exc:
                raise _reject("RELEASE_FILESYSTEM_EVIDENCE_UNAVAILABLE") from exc
            if stat.S_ISLNK(metadata.st_mode) or _reparse_point(child):
                raise _reject("RELEASE_PATH_SYMLINK_OR_REPARSE_REJECTED")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise _reject("RELEASE_SPECIAL_FILE_REJECTED")
            if metadata.st_nlink != 1:
                raise _reject("RELEASE_HARD_LINK_REJECTED")
            try:
                relative = child.resolve(strict=True).relative_to(release_root)
            except (OSError, RuntimeError, ValueError) as exc:
                raise _reject("RELEASE_PATH_ESCAPE_REJECTED") from exc
            relative_path = PurePosixPath(*relative.parts).as_posix()
            protected_files.append(
                _raw_file_measurement(child, relative_path=relative_path)
            )
    return sorted(protected_files, key=lambda item: item["path"])


def _manifest_files(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or not value:
        raise _reject("RELEASE_FILE_MANIFEST_INVALID")
    files: list[dict[str, Any]] = []
    for item in value:
        if type(item) is not dict or set(item) != _FILE_FIELDS:
            raise _reject("RELEASE_FILE_MANIFEST_INVALID")
        path = _canonical_relative_path(
            item.get("path"),
            code="RELEASE_FILE_PATH_INVALID",
        )
        if not _nonnegative_int(item.get("size")) or not is_sha512(
            item.get("sha512")
        ):
            raise _reject("RELEASE_FILE_MEASUREMENT_INVALID")
        files.append(
            {
                "path": path,
                "size": item["size"],
                "sha512": item["sha512"],
            }
        )
    paths = [item["path"] for item in files]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise _reject("RELEASE_FILE_MANIFEST_ORDER_INVALID")
    if len({path.casefold() for path in paths}) != len(paths):
        raise _reject("RELEASE_FILE_PATH_COLLISION")
    return files


def _bindings(value: Any, *, declared_paths: set[str]) -> dict[str, list[str]]:
    if type(value) is not dict or set(value) != _BINDING_FIELDS:
        raise _reject("RELEASE_REQUIRED_BINDINGS_INVALID")
    result: dict[str, list[str]] = {}
    for role in sorted(_BINDING_FIELDS):
        paths = _canonical_path_list(
            value.get(role),
            code="RELEASE_REQUIRED_BINDINGS_INVALID",
        )
        if any(path not in declared_paths for path in paths):
            raise _reject("RELEASE_BINDING_REFERENCES_UNDECLARED_FILE")
        result[role] = paths
    return result


def _issuer(
    value: Any,
    *,
    provider: ApplicationIntegrityProvider | None,
    allow_test_only_signer: bool,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _ISSUER_FIELDS:
        raise _reject("RELEASE_ISSUER_INVALID")
    if not all(
        _text(value.get(field))
        for field in (
            "issuer_id",
            "issuer_version",
            "authority_role",
            "credential_id",
            "provider_id",
            "algorithm",
            "key_id",
            "custody_class",
            "signer_class",
        )
    ) or type(value.get("effect_authority")) is not bool:
        raise _reject("RELEASE_ISSUER_INVALID")
    if value["authority_role"] != RELEASE_AUTHORITY_ROLE:
        raise _reject("RELEASE_ISSUER_ROLE_INVALID")
    if provider is None:
        raise _reject("RELEASE_SIGNER_NOT_INJECTED")
    identity = _trust_provider_identity(provider, admission=False)
    if identity["attestation_admitted"] is not True:
        raise _reject("RELEASE_SIGNER_NOT_ADMITTED")
    signer_class = identity["signer_class"]
    if signer_class not in {"PRODUCTION_RELEASE", "TEST_ONLY"}:
        raise _reject("RELEASE_SIGNER_CLASS_INVALID")
    if signer_class == "TEST_ONLY" and not allow_test_only_signer:
        raise _reject("TEST_ONLY_RELEASE_SIGNER_REJECTED")
    expected_provider = {
        "provider_id": identity["provider_id"],
        "algorithm": identity["algorithm"],
        "key_id": identity["key_id"],
        "custody_class": identity["custody_class"],
        "effect_authority": identity["effect_authority"],
        "signer_class": signer_class,
    }
    if any(value[field] != expected for field, expected in expected_provider.items()):
        raise _reject("RELEASE_SIGNER_IDENTITY_MISMATCH")
    return dict(value)


def _admission_authority(
    value: Any,
    *,
    provider: ApplicationIntegrityAdmissionProvider | None,
    owner_pin: Any,
    allow_test_only_signer: bool,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _ISSUER_FIELDS:
        raise _reject("RELEASE_ADMISSION_AUTHORITY_INVALID")
    if type(owner_pin) is not dict or set(owner_pin) != _ISSUER_FIELDS:
        raise _reject("OWNER_ADMISSION_AUTHORITY_PIN_INVALID")
    if not all(
        _text(value.get(field))
        for field in (
            "issuer_id",
            "issuer_version",
            "authority_role",
            "credential_id",
            "provider_id",
            "algorithm",
            "key_id",
            "custody_class",
            "signer_class",
        )
    ) or type(value.get("effect_authority")) is not bool:
        raise _reject("RELEASE_ADMISSION_AUTHORITY_INVALID")
    if value["authority_role"] != ADMISSION_AUTHORITY_ROLE:
        raise _reject("RELEASE_ADMISSION_AUTHORITY_ROLE_INVALID")
    if value != owner_pin:
        raise _reject("OWNER_ADMISSION_AUTHORITY_PIN_MISMATCH")
    if provider is None:
        raise _reject("RELEASE_ADMISSION_SIGNER_NOT_INJECTED")
    identity = _trust_provider_identity(provider, admission=True)
    if identity["attestation_admitted"] is not True:
        raise _reject("RELEASE_ADMISSION_SIGNER_NOT_ADMITTED")
    signer_class = identity["signer_class"]
    if signer_class not in {"PRODUCTION_ADMISSION", "TEST_ONLY"}:
        raise _reject("RELEASE_ADMISSION_SIGNER_CLASS_INVALID")
    if signer_class == "TEST_ONLY" and not allow_test_only_signer:
        raise _reject("TEST_ONLY_RELEASE_ADMISSION_SIGNER_REJECTED")
    expected_provider = {
        "credential_id": identity["credential_id"],
        "provider_id": identity["provider_id"],
        "algorithm": identity["algorithm"],
        "key_id": identity["key_id"],
        "custody_class": identity["custody_class"],
        "effect_authority": identity["effect_authority"],
        "signer_class": signer_class,
    }
    if any(value[field] != expected for field, expected in expected_provider.items()):
        raise _reject("RELEASE_ADMISSION_SIGNER_IDENTITY_MISMATCH")
    return dict(value)


def _trusted_admission(value: Any) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _TRUSTED_ADMISSION_FIELDS:
        raise _reject("TRUSTED_RELEASE_ADMISSION_SHAPE_INVALID")
    if (
        value.get("schema_id") != TRUSTED_ADMISSION_SCHEMA
        or not _text(value.get("admission_id"))
        or not _positive_int(value.get("admission_sequence"))
        or not _nonnegative_int(value.get("issued_at_ms"))
        or not _nonnegative_int(value.get("not_before_ms"))
        or not _positive_int(value.get("expires_at_ms"))
        or not _text(value.get("release_id"))
        or not _text(value.get("release_version"))
        or not _positive_int(value.get("release_sequence"))
        or value.get("status") != ACTIVE
        or not _nonnegative_int(value.get("revocation_sequence"))
        or not is_sha512(value.get("manifest_digest"))
        or type(value.get("issuer")) is not dict
        or type(value.get("admission_authority")) is not dict
        or not is_sha512(value.get("digest"))
        or value.get("verified") is not False
        or value.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or value.get("assurance_limits") != ASSURANCE_LIMITS
    ):
        raise _reject("TRUSTED_RELEASE_ADMISSION_INVALID")
    if not (
        value["issued_at_ms"] <= value["not_before_ms"]
        < value["expires_at_ms"]
    ):
        raise _reject("TRUSTED_RELEASE_ADMISSION_VALIDITY_INVALID")
    _canonical_relative_path(
        value.get("entrypoint"),
        code="TRUSTED_RELEASE_ENTRYPOINT_INVALID",
    )
    prior_admission = value.get("prior_admission_digest")
    if prior_admission != GENESIS and not is_sha512(prior_admission):
        raise _reject("TRUSTED_PRIOR_ADMISSION_DIGEST_INVALID")
    if value["admission_sequence"] == 1 and prior_admission != GENESIS:
        raise _reject("TRUSTED_ADMISSION_GENESIS_SEQUENCE_INVALID")
    if value["admission_sequence"] > 1 and prior_admission == GENESIS:
        raise _reject("TRUSTED_PRIOR_ADMISSION_DIGEST_REQUIRED")
    prior = value.get("prior_release_digest")
    if prior != GENESIS and not is_sha512(prior):
        raise _reject("TRUSTED_PRIOR_RELEASE_DIGEST_INVALID")
    revoked = value.get("revoked_release_digests")
    if (
        type(revoked) is not list
        or revoked != sorted(revoked)
        or len(revoked) != len(set(revoked))
        or any(not is_sha512(item) for item in revoked)
    ):
        raise _reject("TRUSTED_RELEASE_REVOCATION_SET_INVALID")
    return dict(value)


def compute_application_integrity_anti_rollback_digest(
    *,
    context_id: str,
    head_state_sequence: int = 1,
    release_sequence_head: int,
    prior_release_digest_head: str,
    manifest_digest_head: str,
    admission_sequence_head: int,
    prior_admission_digest_head: str,
    admission_digest_head: str,
    revocation_sequence_head: int,
) -> str:
    return canonical_integrity_hash(
        {
            "schema_id": ANTI_ROLLBACK_SCHEMA,
            "context_id": context_id,
            "head_state_sequence": head_state_sequence,
            "release_sequence_head": release_sequence_head,
            "prior_release_digest_head": prior_release_digest_head,
            "manifest_digest_head": manifest_digest_head,
            "admission_sequence_head": admission_sequence_head,
            "prior_admission_digest_head": prior_admission_digest_head,
            "admission_digest_head": admission_digest_head,
            "revocation_sequence_head": revocation_sequence_head,
        }
    )


def _dependency_property(value: Any, name: str, *, code: str) -> Any:
    try:
        return getattr(value, name)
    except Exception as exc:
        raise _reject(code) from exc


def _ed25519_public_key(
    provider: Any,
) -> tuple[Ed25519PublicKey, str]:
    key = _dependency_property(
        provider,
        "public_key",
        code="APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_UNAVAILABLE",
    )
    if callable(key):
        try:
            key = key()
        except Exception as exc:
            raise _reject(
                "APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_UNAVAILABLE"
            ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise _reject("APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_INVALID")
    try:
        encoded = key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except Exception as exc:
        raise _reject(
            "APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_UNAVAILABLE"
        ) from exc
    return key, sha512(encoded).hexdigest()


def _provider_public_material(
    provider: Any,
) -> tuple[bytes, str, HybridVerificationContext | None]:
    """Return immutable public material and its pin for v2 or legacy TEST_ONLY."""

    if is_hybrid_provider(provider):
        try:
            context = provider.hybrid_verification_context(allow_test_only=True)
        except (HybridSignatureError, TypeError, ValueError) as exc:
            raise _reject("APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_INVALID") from exc
        if not isinstance(context, HybridVerificationContext):
            raise _reject("APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_INVALID")
        encoded = canonical_json_bytes(context.public_record())
        return encoded, context.context_digest, context
    public_key, fingerprint = _ed25519_public_key(provider)
    encoded = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return encoded, fingerprint, None


def _trust_provider_identity(
    provider: Any,
    *,
    admission: bool,
) -> dict[str, Any]:
    _, public_key_fingerprint, hybrid_context = _provider_public_material(provider)
    identity = {
        "provider_id": _dependency_property(
            provider,
            "provider_id",
            code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
        ),
        "algorithm": _dependency_property(
            provider,
            "algorithm",
            code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
        ),
        "key_id": _dependency_property(
            provider,
            "key_id",
            code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
        ),
        "custody_class": _dependency_property(
            provider,
            "custody_class",
            code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
        ),
        "effect_authority": _dependency_property(
            provider,
            "effect_authority",
            code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
        )
        is True,
        "ed25519_public_key_fingerprint": public_key_fingerprint,
    }
    if not all(
        _text(identity[field])
        for field in ("provider_id", "algorithm", "key_id", "custody_class")
    ):
        raise _reject("APPLICATION_INTEGRITY_TRUST_PROVIDER_INVALID")
    if identity["algorithm"] not in {"Ed25519", HYBRID_SUITE_ID}:
        raise _reject("APPLICATION_INTEGRITY_SIGNER_ALGORITHM_INVALID")
    if identity["algorithm"] == HYBRID_SUITE_ID and hybrid_context is None:
        raise _reject("APPLICATION_INTEGRITY_SIGNER_ALGORITHM_INVALID")
    if admission:
        identity.update(
            {
                "credential_id": _dependency_property(
                    provider,
                    "release_admission_credential_id",
                    code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
                ),
                "attestation_admitted": _dependency_property(
                    provider,
                    "release_admission_attestation_admitted",
                    code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
                )
                is True,
                "signer_class": _dependency_property(
                    provider,
                    "release_admission_signer_class",
                    code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
                ),
            }
        )
        if not _text(identity["credential_id"]) or not _text(
            identity["signer_class"]
        ):
            raise _reject("APPLICATION_INTEGRITY_TRUST_PROVIDER_INVALID")
    else:
        identity.update(
            {
                "attestation_admitted": _dependency_property(
                    provider,
                    "release_integrity_attestation_admitted",
                    code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
                )
                is True,
                "signer_class": _dependency_property(
                    provider,
                    "release_integrity_signer_class",
                    code="APPLICATION_INTEGRITY_TRUST_PROVIDER_UNAVAILABLE",
                ),
            }
        )
        if not _text(identity["signer_class"]):
            raise _reject("APPLICATION_INTEGRITY_TRUST_PROVIDER_INVALID")
    if (
        identity["algorithm"] == "Ed25519"
        and identity["signer_class"] != TEST_ONLY_SIGNER
    ):
        raise _reject("APPLICATION_INTEGRITY_LEGACY_SIGNER_NOT_TEST_ONLY")
    if (
        hybrid_context is not None
        and (
            (
                identity["signer_class"] == TEST_ONLY_SIGNER
                and hybrid_context.signer_class != TEST_ONLY_SIGNER
            )
            or (
                identity["signer_class"] != TEST_ONLY_SIGNER
                and hybrid_context.signer_class != PRODUCTION_SIGNER
            )
        )
    ):
        raise _reject("APPLICATION_INTEGRITY_SIGNER_CLASS_MISMATCH")
    return identity


def _time_provider_identity(provider: Any) -> dict[str, Any]:
    fields = (
        "application_integrity_time_provider_id",
        "application_integrity_time_provider_version",
        "application_integrity_time_source_class",
    )
    try:
        public_material, public_key_fingerprint, hybrid_context = (
            _provider_public_material(provider)
        )
        public_key_hex = public_material.hex()
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_TIME_PUBLIC_KEY_UNAVAILABLE") from exc
    identity = {
        field: _dependency_property(
            provider,
            field,
            code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
        )
        for field in fields
    }
    identity["application_integrity_time_owner_bound"] = (
        _dependency_property(
            provider,
            "application_integrity_time_owner_bound",
            code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
        )
        is True
    )
    for field in ("provider_id", "algorithm", "key_id", "custody_class"):
        identity[field] = _dependency_property(
            provider,
            field,
            code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
        )
    identity["effect_authority"] = _dependency_property(
        provider,
        "effect_authority",
        code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
    )
    identity["ed25519_public_key_hex"] = public_key_hex
    identity["ed25519_public_key_fingerprint"] = public_key_fingerprint
    method = _dependency_property(
        provider,
        "current_application_integrity_time_evidence",
        code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
    )
    if (
        not all(_text(identity[field]) for field in fields)
        or not all(
            _text(identity[field])
            for field in ("provider_id", "algorithm", "key_id", "custody_class")
        )
        or identity["algorithm"] not in {"Ed25519", HYBRID_SUITE_ID}
        or (
            identity["algorithm"] == HYBRID_SUITE_ID
            and hybrid_context is None
        )
        or identity["effect_authority"] is not False
        or identity["application_integrity_time_owner_bound"] is not True
        or not callable(method)
    ):
        raise _reject("APPLICATION_INTEGRITY_TIME_PROVIDER_INVALID")
    return identity


def _head_provider_identity(provider: Any) -> dict[str, Any]:
    text_fields = (
        "application_integrity_head_provider_id",
        "application_integrity_head_provider_version",
        "application_integrity_head_storage_class",
    )
    true_fields = (
        "application_integrity_heads_owner_bound",
        "application_integrity_heads_durable",
        "application_integrity_heads_atomic",
    )
    try:
        public_material, public_key_fingerprint, hybrid_context = (
            _provider_public_material(provider)
        )
        public_key_hex = public_material.hex()
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_HEAD_PUBLIC_KEY_UNAVAILABLE") from exc
    identity = {
        field: _dependency_property(
            provider,
            field,
            code="APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
        )
        for field in (*text_fields, *true_fields)
    }
    for field in ("provider_id", "algorithm", "key_id", "custody_class"):
        identity[field] = _dependency_property(
            provider,
            field,
            code="APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
        )
    identity["effect_authority"] = _dependency_property(
        provider,
        "effect_authority",
        code="APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
    )
    identity["ed25519_public_key_hex"] = public_key_hex
    identity["ed25519_public_key_fingerprint"] = public_key_fingerprint
    method = _dependency_property(
        provider,
        "current_application_integrity_head_evidence",
        code="APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
    )
    if (
        not all(_text(identity[field]) for field in text_fields)
        or not all(
            _text(identity[field])
            for field in ("provider_id", "algorithm", "key_id", "custody_class")
        )
        or identity["algorithm"] not in {"Ed25519", HYBRID_SUITE_ID}
        or (
            identity["algorithm"] == HYBRID_SUITE_ID
            and hybrid_context is None
        )
        or identity["effect_authority"] is not False
        or not all(identity[field] is True for field in true_fields)
        or not callable(method)
    ):
        raise _reject("APPLICATION_INTEGRITY_HEAD_PROVIDER_INVALID")
    return identity


def _verify_signed_object_with_pinned_ed25519_key(
    value: dict[str, Any],
    *,
    provider: Any,
    expected_fingerprint: str,
) -> bool:
    try:
        before_identity = _trust_provider_identity(
            provider,
            admission=(
                "admission_id" in value or value.get("schema_id") == RECEIPT_SCHEMA
            ),
        )
        _, fingerprint, hybrid_context = _provider_public_material(provider)
        if fingerprint != expected_fingerprint:
            return False
        if not verify_signed_object(
            value,
            provider=provider,
            trust_context=hybrid_context,
            owner_pinned_context_digest=(
                fingerprint if hybrid_context is not None else None
            ),
            allow_legacy_non_effect=hybrid_context is None,
        ):
            return False
        if hybrid_context is not None:
            return before_identity == _trust_provider_identity(
                provider,
                admission=(
                    "admission_id" in value
                    or value.get("schema_id") == RECEIPT_SCHEMA
                ),
            )
        signature = value.get("signature")
        if type(signature) is not dict:
            return False
        encoded = signature.get("signature_b64")
        if type(encoded) is not str or not encoded:
            return False
        signature_bytes = base64.b64decode(encoded, validate=True)
        payload = {
            key: item
            for key, item in value.items()
            if key not in {"digest", "signature", "verified"}
        }
        public_key, _ = _ed25519_public_key(provider)
        public_key.verify(signature_bytes, canonical_json_bytes(payload))
        return before_identity == _trust_provider_identity(
            provider,
            admission=(
                "admission_id" in value or value.get("schema_id") == RECEIPT_SCHEMA
            ),
        )
    except (
        ApplicationIntegrityRejected,
        InvalidSignature,
        binascii.Error,
        TypeError,
        ValueError,
    ):
        return False
    except Exception:
        return False


def compute_application_integrity_trust_context_digest(
    resolution: dict[str, Any],
) -> str:
    if type(resolution) is not dict or frozenset(resolution) not in {
        frozenset(_TRUST_CONTEXT_PAYLOAD_FIELDS),
        frozenset(_TRUST_CONTEXT_FIELDS),
    }:
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_SHAPE_INVALID")
    try:
        payload = {
            key: value
            for key, value in resolution.items()
            if key
            not in {
                "context_digest",
                "release_signer",
                "admission_signer",
                "trusted_time_provider",
                "anti_rollback_head_provider",
            }
        }
        release_identity = _trust_provider_identity(
            resolution.get("release_signer"),
            admission=False,
        )
        admission_identity = _trust_provider_identity(
            resolution.get("admission_signer"),
            admission=True,
        )
        if (
            resolution.get("release_public_key_fingerprint")
            != release_identity["ed25519_public_key_fingerprint"]
            or resolution.get("admission_public_key_fingerprint")
            != admission_identity["ed25519_public_key_fingerprint"]
        ):
            raise _reject(
                "APPLICATION_INTEGRITY_SIGNER_PUBLIC_KEY_PIN_MISMATCH"
            )
        payload["release_signer_identity"] = release_identity
        payload["admission_signer_identity"] = admission_identity
        payload["trusted_time_provider_identity"] = _time_provider_identity(
            resolution.get("trusted_time_provider")
        )
        payload["anti_rollback_head_provider_identity"] = (
            _head_provider_identity(
                resolution.get("anti_rollback_head_provider")
            )
        )
        if (
            resolution.get("trusted_time_public_key_hex")
            != payload["trusted_time_provider_identity"]["ed25519_public_key_hex"]
            or resolution.get("trusted_time_public_key_fingerprint")
            != payload["trusted_time_provider_identity"][
                "ed25519_public_key_fingerprint"
            ]
            or resolution.get("anti_rollback_head_public_key_hex")
            != payload["anti_rollback_head_provider_identity"][
                "ed25519_public_key_hex"
            ]
            or resolution.get("anti_rollback_head_public_key_fingerprint")
            != payload["anti_rollback_head_provider_identity"][
                "ed25519_public_key_fingerprint"
            ]
        ):
            raise _reject("APPLICATION_INTEGRITY_EVIDENCE_PUBLIC_KEY_PIN_MISMATCH")
        if not is_sha512(resolution.get("trusted_time_evidence_digest_head")) or not is_sha512(
            resolution.get("anti_rollback_head_evidence_digest_head")
        ):
            raise _reject("APPLICATION_INTEGRITY_EVIDENCE_DIGEST_PIN_INVALID")
        return canonical_integrity_hash(payload)
    except ApplicationIntegrityRejected:
        raise
    except Exception as exc:
        raise _reject(
            "APPLICATION_INTEGRITY_TRUST_CONTEXT_DIGEST_FAILED"
        ) from exc


def _verify_signed_provider_evidence(
    value: Any,
    *,
    provider: Any,
    expected_identity: dict[str, Any],
    expected_public_key_hex: str,
    expected_public_key_fingerprint: str,
    payload_fields: set[str],
    all_fields: set[str],
    code: str,
) -> dict[str, Any]:
    try:
        if type(value) is not dict or set(value) != all_fields:
            raise _reject(f"{code}_SHAPE_INVALID")
        payload = {key: value[key] for key in payload_fields}
        if (
            value.get("verified") is not False
            or not is_sha512(value.get("digest"))
            or value["digest"] != canonical_integrity_hash(payload)
        ):
            raise _reject(f"{code}_DIGEST_INVALID")
        public_material, fingerprint, hybrid_context = _provider_public_material(
            provider
        )
        if (
            public_material.hex() != expected_public_key_hex
            or fingerprint != expected_public_key_fingerprint
            or expected_identity["ed25519_public_key_hex"]
            != expected_public_key_hex
            or expected_identity["ed25519_public_key_fingerprint"]
            != expected_public_key_fingerprint
        ):
            raise _reject(f"{code}_PUBLIC_KEY_PIN_MISMATCH")
        if hybrid_context is not None:
            if not verify_signed_object(
                value,
                provider=provider,
                trust_context=hybrid_context,
                owner_pinned_context_digest=fingerprint,
                allow_legacy_non_effect=False,
            ):
                raise _reject(f"{code}_SIGNATURE_INVALID")
            return payload
        signature = value.get("signature")
        signature_fields = {
            "provider_id",
            "algorithm",
            "key_id",
            "custody_class",
            "effect_authority",
            "signature_b64",
        }
        if type(signature) is not dict or set(signature) != signature_fields:
            raise _reject(f"{code}_SIGNATURE_SHAPE_INVALID")
        for field in (
            "provider_id",
            "algorithm",
            "key_id",
            "custody_class",
            "effect_authority",
        ):
            if signature.get(field) != expected_identity[field]:
                raise _reject(f"{code}_SIGNER_IDENTITY_MISMATCH")
        public_key, fingerprint = _ed25519_public_key(provider)
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if (
            raw.hex() != expected_public_key_hex
            or fingerprint != expected_public_key_fingerprint
        ):
            raise _reject(f"{code}_PUBLIC_KEY_PIN_MISMATCH")
        encoded = signature.get("signature_b64")
        if type(encoded) is not str or not encoded:
            raise _reject(f"{code}_SIGNATURE_INVALID")
        signature_bytes = base64.b64decode(encoded, validate=True)
        public_key.verify(signature_bytes, canonical_json_bytes(payload))
        return payload
    except ApplicationIntegrityRejected:
        raise
    except (InvalidSignature, binascii.Error, TypeError, ValueError) as exc:
        raise _reject(f"{code}_SIGNATURE_INVALID") from exc
    except Exception as exc:
        raise _reject(f"{code}_MALFORMED") from exc


def _current_trusted_time(
    provider: Any,
    *,
    context_id: str,
    expected_identity: dict[str, Any],
    expected_public_key_hex: str,
    expected_public_key_fingerprint: str,
    expected_evidence_digest: str,
) -> dict[str, Any]:
    if _time_provider_identity(provider) != expected_identity:
        raise _reject("APPLICATION_INTEGRITY_TIME_PROVIDER_SUBSTITUTED")
    method = _dependency_property(
        provider,
        "current_application_integrity_time_evidence",
        code="APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE",
    )
    try:
        evidence = method(context_id)
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_TIME_PROVIDER_UNAVAILABLE") from exc
    payload = _verify_signed_provider_evidence(
        evidence,
        provider=provider,
        expected_identity=expected_identity,
        expected_public_key_hex=expected_public_key_hex,
        expected_public_key_fingerprint=expected_public_key_fingerprint,
        payload_fields=_TIME_EVIDENCE_PAYLOAD_FIELDS,
        all_fields=_TIME_EVIDENCE_FIELDS,
        code="APPLICATION_INTEGRITY_TIME_EVIDENCE",
    )
    if (
        payload.get("schema_id") != TIME_EVIDENCE_SCHEMA
        or payload.get("context_id") != context_id
        or payload.get("provider_id")
        != expected_identity["application_integrity_time_provider_id"]
        or payload.get("provider_version")
        != expected_identity["application_integrity_time_provider_version"]
        or payload.get("source_class")
        != expected_identity["application_integrity_time_source_class"]
        or not _positive_int(payload.get("evidence_sequence"))
        or not _nonnegative_int(payload.get("observed_at_ms"))
        or payload.get("status") != ACTIVE
        or payload.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or evidence.get("digest") != expected_evidence_digest
    ):
        raise _reject("APPLICATION_INTEGRITY_TIME_EVIDENCE_NOT_CURRENT")
    if _time_provider_identity(provider) != expected_identity:
        raise _reject("APPLICATION_INTEGRITY_TIME_PROVIDER_SUBSTITUTED")
    return {
        "trusted_now_ms": payload["observed_at_ms"],
        "trusted_time_evidence_sequence": payload["evidence_sequence"],
        "trusted_time_evidence_digest": evidence["digest"],
        "trusted_time_evidence": dict(evidence),
    }


def _head_snapshot(value: Any, *, context_id: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != _HEAD_SNAPSHOT_FIELDS:
        raise _reject("APPLICATION_INTEGRITY_HEAD_SNAPSHOT_SHAPE_INVALID")
    if (
        value.get("schema_id") != HEAD_SNAPSHOT_SCHEMA
        or value.get("context_id") != context_id
        or not _positive_int(value.get("head_state_sequence"))
        or not _positive_int(value.get("release_sequence_head"))
        or not _positive_int(value.get("admission_sequence_head"))
        or not _nonnegative_int(value.get("revocation_sequence_head"))
        or not is_sha512(value.get("manifest_digest_head"))
        or not is_sha512(value.get("admission_digest_head"))
        or not is_sha512(value.get("anti_rollback_state_digest"))
        or not is_sha512(value.get("head_snapshot_digest"))
    ):
        raise _reject("APPLICATION_INTEGRITY_HEAD_SNAPSHOT_INVALID")
    for sequence_field, prior_field in (
        ("release_sequence_head", "prior_release_digest_head"),
        ("admission_sequence_head", "prior_admission_digest_head"),
    ):
        sequence = value[sequence_field]
        prior = value.get(prior_field)
        if prior != GENESIS and not is_sha512(prior):
            raise _reject("APPLICATION_INTEGRITY_HEAD_SNAPSHOT_INVALID")
        if (sequence == 1 and prior != GENESIS) or (
            sequence > 1 and prior == GENESIS
        ):
            raise _reject("APPLICATION_INTEGRITY_HEAD_SNAPSHOT_INVALID")
    expected_anti_rollback = compute_application_integrity_anti_rollback_digest(
        context_id=context_id,
        head_state_sequence=value["head_state_sequence"],
        release_sequence_head=value["release_sequence_head"],
        prior_release_digest_head=value["prior_release_digest_head"],
        manifest_digest_head=value["manifest_digest_head"],
        admission_sequence_head=value["admission_sequence_head"],
        prior_admission_digest_head=value["prior_admission_digest_head"],
        admission_digest_head=value["admission_digest_head"],
        revocation_sequence_head=value["revocation_sequence_head"],
    )
    payload = {key: value[key] for key in _HEAD_SNAPSHOT_PAYLOAD_FIELDS}
    if (
        value["anti_rollback_state_digest"] != expected_anti_rollback
        or value["head_snapshot_digest"] != canonical_integrity_hash(payload)
    ):
        raise _reject("APPLICATION_INTEGRITY_HEAD_SNAPSHOT_DIGEST_INVALID")
    return dict(value)


def _current_heads(
    provider: Any,
    *,
    context_id: str,
    expected_identity: dict[str, Any],
    expected_public_key_hex: str,
    expected_public_key_fingerprint: str,
    expected_evidence_digest: str,
) -> dict[str, Any]:
    if _head_provider_identity(provider) != expected_identity:
        raise _reject("APPLICATION_INTEGRITY_HEAD_PROVIDER_SUBSTITUTED")
    method = _dependency_property(
        provider,
        "current_application_integrity_head_evidence",
        code="APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE",
    )
    try:
        evidence = method(context_id)
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_HEAD_PROVIDER_UNAVAILABLE") from exc
    payload = _verify_signed_provider_evidence(
        evidence,
        provider=provider,
        expected_identity=expected_identity,
        expected_public_key_hex=expected_public_key_hex,
        expected_public_key_fingerprint=expected_public_key_fingerprint,
        payload_fields=_HEAD_EVIDENCE_PAYLOAD_FIELDS,
        all_fields=_HEAD_EVIDENCE_FIELDS,
        code="APPLICATION_INTEGRITY_HEAD_EVIDENCE",
    )
    if (
        payload.get("schema_id") != HEAD_EVIDENCE_SCHEMA
        or payload.get("context_id") != context_id
        or payload.get("provider_id")
        != expected_identity["application_integrity_head_provider_id"]
        or payload.get("provider_version")
        != expected_identity["application_integrity_head_provider_version"]
        or payload.get("storage_class")
        != expected_identity["application_integrity_head_storage_class"]
        or not _positive_int(payload.get("evidence_sequence"))
        or not _nonnegative_int(payload.get("observed_at_ms"))
        or payload.get("status") != ACTIVE
        or payload.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or evidence.get("digest") != expected_evidence_digest
    ):
        raise _reject("APPLICATION_INTEGRITY_HEAD_EVIDENCE_NOT_CURRENT")
    snapshot = _head_snapshot(payload.get("head_snapshot"), context_id=context_id)
    if _head_provider_identity(provider) != expected_identity:
        raise _reject("APPLICATION_INTEGRITY_HEAD_PROVIDER_SUBSTITUTED")
    return {
        **snapshot,
        "head_evidence_sequence": payload["evidence_sequence"],
        "head_snapshot_evidence_digest": evidence["digest"],
        "head_snapshot_evidence": dict(evidence),
    }


def _resolve_trust_context(
    context: ApplicationIntegrityTrustContext | None,
    *,
    fixed_context_id: str,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    if not _text(fixed_context_id) or not is_sha512(
        owner_pinned_context_digest
    ):
        raise _reject("OWNER_TRUST_CONTEXT_PIN_INVALID")
    try:
        resolver = getattr(context, "resolve_application_integrity_trust", None)
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_UNAVAILABLE") from exc
    if not callable(resolver):
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_UNAVAILABLE")
    try:
        resolution = resolver(fixed_context_id)
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_UNAVAILABLE") from exc
    if type(resolution) is not dict or set(resolution) != _TRUST_CONTEXT_FIELDS:
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_SHAPE_INVALID")
    if (
        resolution.get("schema_id") != TRUST_CONTEXT_SCHEMA
        or resolution.get("context_id") != fixed_context_id
        or not _text(resolution.get("context_version"))
        or resolution.get("status") != ACTIVE
        or not is_sha512(resolution.get("release_public_key_fingerprint"))
        or not is_sha512(resolution.get("admission_public_key_fingerprint"))
        or not _text(resolution.get("trusted_time_public_key_hex"))
        or not is_sha512(resolution.get("trusted_time_public_key_fingerprint"))
        or not is_sha512(resolution.get("trusted_time_evidence_digest_head"))
        or not _text(resolution.get("anti_rollback_head_public_key_hex"))
        or not is_sha512(
            resolution.get("anti_rollback_head_public_key_fingerprint")
        )
        or not is_sha512(
            resolution.get("anti_rollback_head_evidence_digest_head")
        )
        or resolution.get("release_public_key_fingerprint")
        == resolution.get("admission_public_key_fingerprint")
        or type(resolution.get("owner_admission_authority_pin")) is not dict
        or type(resolution.get("allow_test_only_release_signer")) is not bool
        or type(resolution.get("allow_test_only_admission_signer")) is not bool
    ):
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_INVALID")
    observed_context_digest = compute_application_integrity_trust_context_digest(
        resolution
    )
    if (
        resolution.get("context_digest") != observed_context_digest
        or observed_context_digest != owner_pinned_context_digest
    ):
        raise _reject("APPLICATION_INTEGRITY_TRUST_CONTEXT_NOT_OWNER_PINNED")
    release_identity = _trust_provider_identity(
        resolution["release_signer"],
        admission=False,
    )
    admission_identity = _trust_provider_identity(
        resolution["admission_signer"],
        admission=True,
    )
    time_identity = _time_provider_identity(resolution["trusted_time_provider"])
    head_identity = _head_provider_identity(
        resolution["anti_rollback_head_provider"]
    )
    production_signers_required = (
        resolution["allow_test_only_release_signer"] is False
        and resolution["allow_test_only_admission_signer"] is False
    )
    if production_signers_required and any(
        identity["algorithm"] != HYBRID_SUITE_ID
        for identity in (
            release_identity,
            admission_identity,
            time_identity,
            head_identity,
        )
    ):
        raise _reject("APPLICATION_INTEGRITY_PRODUCTION_HYBRID_REQUIRED")
    trusted_time = _current_trusted_time(
        resolution["trusted_time_provider"],
        context_id=fixed_context_id,
        expected_identity=time_identity,
        expected_public_key_hex=resolution["trusted_time_public_key_hex"],
        expected_public_key_fingerprint=resolution[
            "trusted_time_public_key_fingerprint"
        ],
        expected_evidence_digest=resolution["trusted_time_evidence_digest_head"],
    )
    heads = _current_heads(
        resolution["anti_rollback_head_provider"],
        context_id=fixed_context_id,
        expected_identity=head_identity,
        expected_public_key_hex=resolution[
            "anti_rollback_head_public_key_hex"
        ],
        expected_public_key_fingerprint=resolution[
            "anti_rollback_head_public_key_fingerprint"
        ],
        expected_evidence_digest=resolution[
            "anti_rollback_head_evidence_digest_head"
        ],
    )
    return {
        **resolution,
        **heads,
        **trusted_time,
        "release_signer_identity": release_identity,
        "admission_signer_identity": admission_identity,
        "trusted_time_provider_identity": time_identity,
        "anti_rollback_head_provider_identity": head_identity,
    }


def compute_runtime_measurement_digest(
    *,
    release_id: str,
    release_version: str,
    release_sequence: int,
    entrypoint: str,
    protected_roots: list[str],
    files: list[dict[str, Any]],
    bindings: dict[str, list[str]],
) -> str:
    """Return the canonical digest used by a signed release manifest."""

    return canonical_integrity_hash(
        {
            "schema_id": RUNTIME_MEASUREMENT_SCHEMA,
            "release_id": release_id,
            "release_version": release_version,
            "release_sequence": release_sequence,
            "entrypoint": entrypoint,
            "protected_roots": protected_roots,
            "files": files,
            "bindings": bindings,
        }
    )


def _append_trace(
    trace: list[dict[str, Any]],
    *,
    stage: str,
    subject: str,
    evidence: Any,
) -> None:
    entry = {
        "schema_id": TRACE_SCHEMA,
        "sequence": len(trace) + 1,
        "stage": stage,
        "subject": subject,
        "result": "PASS",
        "evidence_digest": canonical_integrity_hash(evidence),
        "previous_trace_digest": trace[-1]["trace_digest"] if trace else GENESIS,
    }
    entry["trace_digest"] = canonical_integrity_hash(entry)
    trace.append(entry)


def _redacted_path_subject(relative_path: str) -> str:
    return "path-sha512:" + sha512(relative_path.encode("utf-8")).hexdigest()


def _assert_trust_dependencies_unchanged(trust: dict[str, Any]) -> None:
    if (
        _trust_provider_identity(trust["release_signer"], admission=False)
        != trust["release_signer_identity"]
        or _trust_provider_identity(trust["admission_signer"], admission=True)
        != trust["admission_signer_identity"]
        or _time_provider_identity(trust["trusted_time_provider"])
        != trust["trusted_time_provider_identity"]
        or _head_provider_identity(trust["anti_rollback_head_provider"])
        != trust["anti_rollback_head_provider_identity"]
    ):
        raise _reject("APPLICATION_INTEGRITY_DEPENDENCY_SUBSTITUTED")


def _verify_application_integrity_impl(
    manifest: dict[str, Any],
    *,
    release_root: str | Path,
    trusted_admission: dict[str, Any],
    trust_context: ApplicationIntegrityTrustContext,
    fixed_context_id: str,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    """Verify one exact signed release against live filesystem evidence.

    All signers, owner authority pins, trusted time and anti-rollback heads are
    resolved from one deployment-owned context selected only by its fixed ID.
    """

    trace: list[dict[str, Any]] = []
    trust = _resolve_trust_context(
        trust_context,
        fixed_context_id=fixed_context_id,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    signer = trust["release_signer"]
    admission_signer = trust["admission_signer"]
    trusted_now_ms = trust["trusted_now_ms"]
    _append_trace(
        trace,
        stage="deployment_trust_context",
        subject=trust["context_id"],
        evidence={
            "context_digest": trust["context_digest"],
            "trusted_time_provider_identity": trust[
                "trusted_time_provider_identity"
            ],
            "anti_rollback_head_provider_identity": trust[
                "anti_rollback_head_provider_identity"
            ],
            "head_state_sequence": trust["head_state_sequence"],
            "head_snapshot_digest": trust["head_snapshot_digest"],
            "trusted_time_evidence_digest": trust[
                "trusted_time_evidence_digest"
            ],
            "head_snapshot_evidence_digest": trust[
                "head_snapshot_evidence_digest"
            ],
            "anti_rollback_state_digest": trust[
                "anti_rollback_state_digest"
            ],
        },
    )
    if type(manifest) is not dict or set(manifest) != _SIGNED_OBJECT_FIELDS:
        raise _reject("RELEASE_MANIFEST_SHAPE_INVALID")
    if manifest.get("schema_id") != MANIFEST_SCHEMA:
        raise _reject("RELEASE_MANIFEST_SCHEMA_INVALID")
    if manifest.get("verified") is not False:
        raise _reject("RELEASE_MANIFEST_VERIFIED_FLAG_INVALID")
    if manifest.get("status") != ACTIVE:
        raise _reject("RELEASE_NOT_ACTIVE")
    if (
        not _text(manifest.get("release_id"))
        or not _text(manifest.get("release_version"))
        or not _positive_int(manifest.get("release_sequence"))
        or not _nonnegative_int(manifest.get("revocation_sequence"))
        or not is_sha512(manifest.get("runtime_measurement_digest"))
        or not is_sha512(manifest.get("digest"))
        or manifest.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or manifest.get("assurance_limits") != ASSURANCE_LIMITS
    ):
        raise _reject("RELEASE_MANIFEST_CONTENT_INVALID")
    prior = manifest.get("prior_release_digest")
    if prior != GENESIS and not is_sha512(prior):
        raise _reject("RELEASE_PRIOR_DIGEST_INVALID")
    if manifest["release_sequence"] == 1 and prior != GENESIS:
        raise _reject("RELEASE_GENESIS_SEQUENCE_INVALID")
    if manifest["release_sequence"] > 1 and prior == GENESIS:
        raise _reject("RELEASE_PRIOR_DIGEST_REQUIRED")
    if (
        manifest["release_sequence"] != trust["release_sequence_head"]
        or manifest["prior_release_digest"]
        != trust["prior_release_digest_head"]
        or manifest["digest"] != trust["manifest_digest_head"]
        or manifest["revocation_sequence"]
        != trust["revocation_sequence_head"]
    ):
        raise _reject("RELEASE_ANTI_ROLLBACK_HEAD_MISMATCH")

    issuer = _issuer(
        manifest.get("issuer"),
        provider=signer,
        allow_test_only_signer=trust["allow_test_only_release_signer"],
    )
    if not _verify_signed_object_with_pinned_ed25519_key(
        manifest,
        provider=signer,
        expected_fingerprint=trust["release_public_key_fingerprint"],
    ):
        raise _reject("RELEASE_MANIFEST_SIGNATURE_INVALID")
    _append_trace(
        trace,
        stage="signed_manifest",
        subject=manifest["release_id"],
        evidence={"manifest_digest": manifest["digest"], "issuer": issuer},
    )

    admission = _trusted_admission(trusted_admission)
    admission_authority = _admission_authority(
        admission.get("admission_authority"),
        provider=admission_signer,
        owner_pin=trust["owner_admission_authority_pin"],
        allow_test_only_signer=trust[
            "allow_test_only_admission_signer"
        ],
    )
    if not _verify_signed_object_with_pinned_ed25519_key(
        admission,
        provider=admission_signer,
        expected_fingerprint=trust["admission_public_key_fingerprint"],
    ):
        raise _reject("TRUSTED_RELEASE_ADMISSION_SIGNATURE_INVALID")
    if any(
        admission_authority[field] == issuer[field]
        for field in ("credential_id", "provider_id", "key_id")
    ):
        raise _reject("RELEASE_ADMISSION_AUTHORITY_NOT_DISTINCT")
    if admission["admission_sequence"] != trust["admission_sequence_head"]:
        raise _reject("TRUSTED_ADMISSION_SEQUENCE_ROLLBACK_OR_MISMATCH")
    if (
        admission["prior_admission_digest"]
        != trust["prior_admission_digest_head"]
    ):
        raise _reject("TRUSTED_PRIOR_ADMISSION_DIGEST_MISMATCH")
    if admission["digest"] != trust["admission_digest_head"]:
        raise _reject("TRUSTED_ADMISSION_DIGEST_ROLLBACK_OR_MISMATCH")
    if admission["revocation_sequence"] != trust["revocation_sequence_head"]:
        raise _reject("TRUSTED_REVOCATION_SEQUENCE_ROLLBACK_OR_MISMATCH")
    if trusted_now_ms < admission["not_before_ms"]:
        raise _reject("TRUSTED_RELEASE_ADMISSION_NOT_YET_ACTIVE")
    if trusted_now_ms >= admission["expires_at_ms"]:
        raise _reject("TRUSTED_RELEASE_ADMISSION_EXPIRED")
    exact_admission_bindings = {
        "release_id": manifest["release_id"],
        "release_version": manifest["release_version"],
        "release_sequence": manifest["release_sequence"],
        "prior_release_digest": manifest["prior_release_digest"],
        "status": manifest["status"],
        "revocation_sequence": manifest["revocation_sequence"],
        "manifest_digest": manifest["digest"],
        "entrypoint": manifest["entrypoint"],
        "issuer": issuer,
    }
    if any(admission.get(field) != expected for field, expected in exact_admission_bindings.items()):
        raise _reject("RELEASE_TRUSTED_ADMISSION_MISMATCH")
    if manifest["digest"] in admission["revoked_release_digests"]:
        raise _reject("RELEASE_MANIFEST_REVOKED")
    _append_trace(
        trace,
        stage="trusted_admission",
        subject=manifest["release_id"],
        evidence={
            "admission_digest": admission["digest"],
            "admission_sequence": admission["admission_sequence"],
            "prior_admission_digest": admission["prior_admission_digest"],
            "revocation_sequence": admission["revocation_sequence"],
            "admission_authority": admission_authority,
        },
    )

    root = _validated_release_root(release_root)
    entrypoint = _canonical_relative_path(
        manifest.get("entrypoint"),
        code="RELEASE_ENTRYPOINT_INVALID",
    )
    protected_roots = _canonical_path_list(
        manifest.get("protected_roots"),
        code="RELEASE_PROTECTED_ROOTS_INVALID",
    )
    for index, left in enumerate(protected_roots):
        left_path = PurePosixPath(left)
        for right in protected_roots[index + 1 :]:
            right_path = PurePosixPath(right)
            if left_path in right_path.parents or right_path in left_path.parents:
                raise _reject("RELEASE_PROTECTED_ROOTS_OVERLAP")

    declared_files = _manifest_files(manifest.get("files"))
    declared_paths = {item["path"] for item in declared_files}
    if entrypoint not in declared_paths:
        raise _reject("RELEASE_ENTRYPOINT_NOT_DECLARED")
    bindings = _bindings(
        manifest.get("bindings"),
        declared_paths=declared_paths,
    )
    _append_trace(
        trace,
        stage="manifest_contract",
        subject=_redacted_path_subject(entrypoint),
        evidence={
            "entrypoint": entrypoint,
            "protected_roots": protected_roots,
            "bindings": bindings,
        },
    )

    observed_files: list[dict[str, Any]] = []
    for expected in declared_files:
        path = _inside_release_root(root, expected["path"])
        observed = _raw_file_measurement(
            path,
            relative_path=expected["path"],
        )
        if observed != expected:
            raise _reject("RELEASE_FILE_MEASUREMENT_MISMATCH")
        observed_files.append(observed)
        _append_trace(
            trace,
            stage="file_measurement",
            subject=_redacted_path_subject(expected["path"]),
            evidence=observed,
        )

    declared_by_path = {item["path"]: item for item in declared_files}
    for relative_root in protected_roots:
        protected_inventory = _protected_root_inventory(root, relative_root)
        undeclared = [
            item["path"]
            for item in protected_inventory
            if item["path"] not in declared_paths
        ]
        if undeclared:
            raise _reject("UNDECLARED_PROTECTED_ROOT_FILE")
        if any(
            item != declared_by_path[item["path"]]
            for item in protected_inventory
        ):
            raise _reject("PROTECTED_ROOT_FILE_MEASUREMENT_MISMATCH")
        _append_trace(
            trace,
            stage="protected_root_inventory",
            subject=_redacted_path_subject(relative_root),
            evidence={
                "protected_root": relative_root,
                "regular_files": protected_inventory,
            },
        )

    observed_runtime_digest = compute_runtime_measurement_digest(
        release_id=manifest["release_id"],
        release_version=manifest["release_version"],
        release_sequence=manifest["release_sequence"],
        entrypoint=entrypoint,
        protected_roots=protected_roots,
        files=observed_files,
        bindings=bindings,
    )
    if observed_runtime_digest != manifest["runtime_measurement_digest"]:
        raise _reject("RELEASE_RUNTIME_MEASUREMENT_MISMATCH")
    _assert_trust_dependencies_unchanged(trust)
    terminal_time = _current_trusted_time(
        trust["trusted_time_provider"],
        context_id=trust["context_id"],
        expected_identity=trust["trusted_time_provider_identity"],
        expected_public_key_hex=trust["trusted_time_public_key_hex"],
        expected_public_key_fingerprint=trust[
            "trusted_time_public_key_fingerprint"
        ],
        expected_evidence_digest=trust["trusted_time_evidence_digest_head"],
    )
    terminal_now_ms = terminal_time["trusted_now_ms"]
    if (
        terminal_now_ms != trusted_now_ms
        or terminal_time["trusted_time_evidence_digest"]
        != trust["trusted_time_evidence_digest"]
    ):
        raise _reject("APPLICATION_INTEGRITY_TIME_CHANGED_DURING_VERIFICATION")
    if terminal_now_ms >= admission["expires_at_ms"]:
        raise _reject("TRUSTED_RELEASE_ADMISSION_EXPIRED")
    terminal_heads = _current_heads(
        trust["anti_rollback_head_provider"],
        context_id=trust["context_id"],
        expected_identity=trust["anti_rollback_head_provider_identity"],
        expected_public_key_hex=trust[
            "anti_rollback_head_public_key_hex"
        ],
        expected_public_key_fingerprint=trust[
            "anti_rollback_head_public_key_fingerprint"
        ],
        expected_evidence_digest=trust[
            "anti_rollback_head_evidence_digest_head"
        ],
    )
    if any(
        terminal_heads[field] != trust[field]
        for field in _HEAD_SNAPSHOT_FIELDS
    ) or terminal_heads["head_snapshot_evidence_digest"] != trust[
        "head_snapshot_evidence_digest"
    ]:
        raise _reject("APPLICATION_INTEGRITY_HEADS_CHANGED_DURING_VERIFICATION")
    _assert_trust_dependencies_unchanged(trust)
    _append_trace(
        trace,
        stage="runtime_measurement",
        subject=manifest["release_id"],
        evidence={
            "runtime_measurement_digest": observed_runtime_digest,
            "manifest_digest": manifest["digest"],
        },
    )
    _append_trace(
        trace,
        stage="terminal",
        subject=manifest["release_id"],
        evidence={
            "result": "PASS",
            "authorization_effect": NO_AUTHORIZATION_EFFECT,
            "assurance_limits": ASSURANCE_LIMITS,
        },
    )
    trace_digest = canonical_integrity_hash(trace)
    result_payload = {
        "schema_id": RESULT_SCHEMA,
        "result": "PASS",
        "release_id": manifest["release_id"],
        "release_version": manifest["release_version"],
        "release_sequence": manifest["release_sequence"],
        "manifest_digest": manifest["digest"],
        "admission_sequence": admission["admission_sequence"],
        "admission_digest": admission["digest"],
        "runtime_measurement_digest": observed_runtime_digest,
        "issuer": issuer,
        "admission_authority": admission_authority,
        "trust_context_id": trust["context_id"],
        "trust_context_digest": trust["context_digest"],
        "head_state_sequence": trust["head_state_sequence"],
        "head_snapshot_digest": trust["head_snapshot_digest"],
        "trusted_time_evidence_digest": trust[
            "trusted_time_evidence_digest"
        ],
        "head_snapshot_evidence_digest": trust[
            "head_snapshot_evidence_digest"
        ],
        "anti_rollback_state_digest": trust[
            "anti_rollback_state_digest"
        ],
        "release_public_key_fingerprint": trust[
            "release_public_key_fingerprint"
        ],
        "admission_public_key_fingerprint": trust[
            "admission_public_key_fingerprint"
        ],
        "trace": trace,
        "trace_digest": trace_digest,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        "assurance_limits": dict(ASSURANCE_LIMITS),
    }
    result_digest = canonical_integrity_hash(result_payload)
    receipt_payload = {
        "schema_id": RECEIPT_SCHEMA,
        "receipt_id": canonical_integrity_hash(
            {
                "schema_id": RECEIPT_SCHEMA,
                "result_digest": result_digest,
                "trust_context_id": trust["context_id"],
                "anti_rollback_state_digest": trust[
                    "anti_rollback_state_digest"
                ],
            }
        ),
        "issued_at_ms": terminal_now_ms,
        "trust_context_id": trust["context_id"],
        "trust_context_digest": trust["context_digest"],
        "head_state_sequence": trust["head_state_sequence"],
        "head_snapshot_digest": trust["head_snapshot_digest"],
        "trusted_time_evidence_digest": trust[
            "trusted_time_evidence_digest"
        ],
        "head_snapshot_evidence_digest": trust[
            "head_snapshot_evidence_digest"
        ],
        "anti_rollback_state_digest": trust[
            "anti_rollback_state_digest"
        ],
        "release_public_key_fingerprint": trust[
            "release_public_key_fingerprint"
        ],
        "admission_public_key_fingerprint": trust[
            "admission_public_key_fingerprint"
        ],
        "result_digest": result_digest,
        "manifest_digest": manifest["digest"],
        "admission_digest": admission["digest"],
        "runtime_measurement_digest": observed_runtime_digest,
        "trace_digest": trace_digest,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        "assurance_limits": dict(ASSURANCE_LIMITS),
    }
    try:
        receipt_builder = (
            build_signed_object
            if is_hybrid_provider(admission_signer)
            else build_legacy_non_effect_signed_object
        )
        receipt = receipt_builder(receipt_payload, provider=admission_signer)
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_RECEIPT_SIGNING_FAILED") from exc
    if not _verify_signed_object_with_pinned_ed25519_key(
        receipt,
        provider=admission_signer,
        expected_fingerprint=trust["admission_public_key_fingerprint"],
    ):
        raise _reject("APPLICATION_INTEGRITY_RECEIPT_SIGNATURE_INVALID")
    _assert_trust_dependencies_unchanged(trust)
    final_time = _current_trusted_time(
        trust["trusted_time_provider"],
        context_id=trust["context_id"],
        expected_identity=trust["trusted_time_provider_identity"],
        expected_public_key_hex=trust["trusted_time_public_key_hex"],
        expected_public_key_fingerprint=trust[
            "trusted_time_public_key_fingerprint"
        ],
        expected_evidence_digest=trust["trusted_time_evidence_digest_head"],
    )
    final_now_ms = final_time["trusted_now_ms"]
    if (
        final_now_ms != terminal_now_ms
        or final_time["trusted_time_evidence_digest"]
        != terminal_time["trusted_time_evidence_digest"]
    ):
        raise _reject("APPLICATION_INTEGRITY_TIME_CHANGED_DURING_VERIFICATION")
    if final_now_ms >= admission["expires_at_ms"]:
        raise _reject("TRUSTED_RELEASE_ADMISSION_EXPIRED")
    final_heads = _current_heads(
        trust["anti_rollback_head_provider"],
        context_id=trust["context_id"],
        expected_identity=trust["anti_rollback_head_provider_identity"],
        expected_public_key_hex=trust[
            "anti_rollback_head_public_key_hex"
        ],
        expected_public_key_fingerprint=trust[
            "anti_rollback_head_public_key_fingerprint"
        ],
        expected_evidence_digest=trust[
            "anti_rollback_head_evidence_digest_head"
        ],
    )
    if any(
        final_heads[field] != terminal_heads[field]
        for field in _HEAD_SNAPSHOT_FIELDS
    ) or final_heads["head_snapshot_evidence_digest"] != terminal_heads[
        "head_snapshot_evidence_digest"
    ]:
        raise _reject("APPLICATION_INTEGRITY_HEADS_CHANGED_DURING_VERIFICATION")
    return {
        **result_payload,
        "result_digest": result_digest,
        "receipt": receipt,
    }


def _verify_integrity_trace(trace: Any, trace_digest: Any) -> bool:
    if type(trace) is not list or not trace or not is_sha512(trace_digest):
        return False
    previous = GENESIS
    fields = {
        "schema_id",
        "sequence",
        "stage",
        "subject",
        "result",
        "evidence_digest",
        "previous_trace_digest",
        "trace_digest",
    }
    for index, entry in enumerate(trace, start=1):
        if (
            type(entry) is not dict
            or set(entry) != fields
            or entry.get("schema_id") != TRACE_SCHEMA
            or entry.get("sequence") != index
            or not _text(entry.get("stage"))
            or not _text(entry.get("subject"))
            or entry.get("result") != "PASS"
            or not is_sha512(entry.get("evidence_digest"))
            or entry.get("previous_trace_digest") != previous
            or not is_sha512(entry.get("trace_digest"))
        ):
            return False
        payload = {
            key: value for key, value in entry.items() if key != "trace_digest"
        }
        if entry["trace_digest"] != canonical_integrity_hash(payload):
            return False
        previous = entry["trace_digest"]
    return canonical_integrity_hash(trace) == trace_digest


def _verify_application_integrity_result_impl(
    result: dict[str, Any],
    *,
    manifest: dict[str, Any],
    trusted_admission: dict[str, Any],
    release_root: str | Path,
    trust_context: ApplicationIntegrityTrustContext,
    fixed_context_id: str,
    owner_pinned_context_digest: str,
) -> bool:
    """Verify the signed receipt, result binding and current live files."""

    if type(trusted_admission) is not dict:
        raise _reject("TRUSTED_RELEASE_ADMISSION_SHAPE_INVALID")
    trust = _resolve_trust_context(
        trust_context,
        fixed_context_id=fixed_context_id,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if type(result) is not dict or set(result) != _RESULT_FIELDS:
        raise _reject("APPLICATION_INTEGRITY_RESULT_SHAPE_INVALID")
    if (
        result.get("schema_id") != RESULT_SCHEMA
        or result.get("result") != "PASS"
        or not is_sha512(result.get("result_digest"))
        or result.get("trust_context_id") != trust["context_id"]
        or result.get("trust_context_digest") != trust["context_digest"]
        or result.get("head_state_sequence")
        != trust["head_state_sequence"]
        or result.get("head_snapshot_digest")
        != trust["head_snapshot_digest"]
        or result.get("trusted_time_evidence_digest")
        != trust["trusted_time_evidence_digest"]
        or result.get("head_snapshot_evidence_digest")
        != trust["head_snapshot_evidence_digest"]
        or result.get("anti_rollback_state_digest")
        != trust["anti_rollback_state_digest"]
        or result.get("release_public_key_fingerprint")
        != trust["release_public_key_fingerprint"]
        or result.get("admission_public_key_fingerprint")
        != trust["admission_public_key_fingerprint"]
        or result.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
        or result.get("assurance_limits") != ASSURANCE_LIMITS
        or not _verify_integrity_trace(
            result.get("trace"),
            result.get("trace_digest"),
        )
    ):
        raise _reject("APPLICATION_INTEGRITY_RESULT_INVALID")
    result_payload = {
        key: result[key] for key in _RESULT_PAYLOAD_FIELDS
    }
    if canonical_integrity_hash(result_payload) != result["result_digest"]:
        raise _reject("APPLICATION_INTEGRITY_RESULT_DIGEST_INVALID")
    receipt = result.get("receipt")
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise _reject("APPLICATION_INTEGRITY_RECEIPT_SHAPE_INVALID")
    expected_receipt_bindings = {
        "schema_id": RECEIPT_SCHEMA,
        "receipt_id": canonical_integrity_hash(
            {
                "schema_id": RECEIPT_SCHEMA,
                "result_digest": result["result_digest"],
                "trust_context_id": trust["context_id"],
                "anti_rollback_state_digest": trust[
                    "anti_rollback_state_digest"
                ],
            }
        ),
        "trust_context_id": trust["context_id"],
        "trust_context_digest": trust["context_digest"],
        "head_state_sequence": trust["head_state_sequence"],
        "head_snapshot_digest": trust["head_snapshot_digest"],
        "trusted_time_evidence_digest": trust[
            "trusted_time_evidence_digest"
        ],
        "head_snapshot_evidence_digest": trust[
            "head_snapshot_evidence_digest"
        ],
        "anti_rollback_state_digest": trust[
            "anti_rollback_state_digest"
        ],
        "release_public_key_fingerprint": trust[
            "release_public_key_fingerprint"
        ],
        "admission_public_key_fingerprint": trust[
            "admission_public_key_fingerprint"
        ],
        "result_digest": result["result_digest"],
        "manifest_digest": result["manifest_digest"],
        "admission_digest": result["admission_digest"],
        "runtime_measurement_digest": result[
            "runtime_measurement_digest"
        ],
        "trace_digest": result["trace_digest"],
        "authorization_effect": NO_AUTHORIZATION_EFFECT,
        "assurance_limits": ASSURANCE_LIMITS,
    }
    if (
        receipt.get("verified") is not False
        or not is_sha512(receipt.get("digest"))
        or not _nonnegative_int(receipt.get("issued_at_ms"))
        or receipt.get("issued_at_ms") > trust["trusted_now_ms"]
        or receipt.get("issued_at_ms")
        < trusted_admission.get("not_before_ms", -1)
        or any(
            receipt.get(field) != expected
            for field, expected in expected_receipt_bindings.items()
        )
        or not _verify_signed_object_with_pinned_ed25519_key(
            receipt,
            provider=trust["admission_signer"],
            expected_fingerprint=trust[
                "admission_public_key_fingerprint"
            ],
        )
    ):
        raise _reject("APPLICATION_INTEGRITY_RECEIPT_INVALID")
    remeasured = verify_application_integrity(
        manifest,
        release_root=release_root,
        trusted_admission=trusted_admission,
        trust_context=trust_context,
        fixed_context_id=fixed_context_id,
        owner_pinned_context_digest=owner_pinned_context_digest,
    )
    if remeasured["result_digest"] != result["result_digest"]:
        raise _reject("APPLICATION_INTEGRITY_RESULT_REMEASUREMENT_MISMATCH")
    return True


def verify_application_integrity(
    manifest: dict[str, Any],
    *,
    release_root: str | Path,
    trusted_admission: dict[str, Any],
    trust_context: ApplicationIntegrityTrustContext,
    fixed_context_id: str,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    """Structured fail-closed wrapper for application admission."""

    try:
        return _verify_application_integrity_impl(
            manifest,
            release_root=release_root,
            trusted_admission=trusted_admission,
            trust_context=trust_context,
            fixed_context_id=fixed_context_id,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
    except ApplicationIntegrityRejected:
        raise
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_MALFORMED_NESTED_VALUE") from exc


def verify_application_integrity_result(
    result: dict[str, Any],
    *,
    manifest: dict[str, Any],
    trusted_admission: dict[str, Any],
    release_root: str | Path,
    trust_context: ApplicationIntegrityTrustContext,
    fixed_context_id: str,
    owner_pinned_context_digest: str,
) -> bool:
    """Structured fail-closed wrapper for result and receipt verification."""

    try:
        return _verify_application_integrity_result_impl(
            result,
            manifest=manifest,
            trusted_admission=trusted_admission,
            release_root=release_root,
            trust_context=trust_context,
            fixed_context_id=fixed_context_id,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
    except ApplicationIntegrityRejected:
        raise
    except Exception as exc:
        raise _reject("APPLICATION_INTEGRITY_RESULT_MALFORMED_NESTED_VALUE") from exc


__all__ = [
    "ACTIVE",
    "ADMISSION_AUTHORITY_ROLE",
    "ANTI_ROLLBACK_SCHEMA",
    "ASSURANCE_LIMITS",
    "ApplicationIntegrityAdmissionProvider",
    "ApplicationIntegrityProvider",
    "ApplicationIntegrityRejected",
    "ApplicationIntegrityHeadProvider",
    "ApplicationIntegrityTimeProvider",
    "ApplicationIntegrityTrustContext",
    "GENESIS",
    "HEAD_SNAPSHOT_SCHEMA",
    "HEAD_EVIDENCE_SCHEMA",
    "MANIFEST_SCHEMA",
    "NO_AUTHORIZATION_EFFECT",
    "RELEASE_AUTHORITY_ROLE",
    "RECEIPT_SCHEMA",
    "RESULT_SCHEMA",
    "RUNTIME_MEASUREMENT_SCHEMA",
    "TRACE_SCHEMA",
    "TIME_EVIDENCE_SCHEMA",
    "TRUST_CONTEXT_SCHEMA",
    "TRUSTED_ADMISSION_SCHEMA",
    "compute_application_integrity_anti_rollback_digest",
    "compute_application_integrity_trust_context_digest",
    "compute_runtime_measurement_digest",
    "verify_application_integrity",
    "verify_application_integrity_result",
]
