"""Python/Rust/SPARK dependency and toolchain guard (stage 6)."""

from __future__ import annotations

import importlib.metadata
import hashlib
import platform
import re
import sys
import sysconfig
from pathlib import Path
from typing import Any, Mapping

from .artifact import build_signed_artifact, validate_signed_artifact
from .constants import DEPENDENCY_LOCK_PATHS, FAIL, PASS
from .digests import digest
from .paths import LocalTrustPathError, measure_file, resolve_safe_path, strict_load_json, validated_root
from .signing import HybridSigningContext, HybridVerificationContext


PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_TOOLCHAIN_GUARD_PAYLOAD_V1"
PYTHON_LOCK_PATH = "python-dependencies.lock.json"
PYTHON_LOCK_SCHEMA = "sbp.lex.v2.python-dependency-lock/1"
PYTHON_LOCK_INVALID = "COMMITTED_LOCK_INVALID"
PYTHON_LOCK_MISSING = "COMMITTED_LOCK_MISSING"
PYTHON_LOCK_VALID = "COMMITTED_LOCK_VALID"
_PYTHON_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?)$"
)
_PYTHON_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PYTHON_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)
_PYTHON_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")


def _stable_file_bytes(root: Path, relative: str) -> bytes:
    before = measure_file(root, relative)
    try:
        content = resolve_safe_path(root, relative).read_bytes()
    except OSError as exc:
        raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
    after = measure_file(root, relative)
    if (
        before != after
        or len(content) != before["size_bytes"]
        or hashlib.sha512(content).hexdigest() != before["sha512"]
    ):
        raise LocalTrustPathError("evidence_changed_during_read")
    return content


def _expected_python_environment() -> dict[str, str]:
    abi_tag = sys.implementation.cache_tag
    platform_tag = sysconfig.get_platform()
    if type(abi_tag) is not str or not abi_tag or type(platform_tag) is not str or not platform_tag:
        raise LocalTrustPathError("python_environment_binding_unavailable")
    return {
        "implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "abi_tag": abi_tag,
        "platform_tag": platform_tag,
    }


def _python_identity(value: Any) -> str | None:
    if type(value) is not str or _PYTHON_NAME.fullmatch(value) is None:
        return None
    return re.sub(r"[-_.]+", "-", value).casefold()


def _local_python_dependency_evidence(
    requirements_content: bytes,
    lock: Any | None,
    installed_packages: list[dict[str, str]],
) -> dict[str, Any]:
    failures: list[str] = []
    requirements: list[dict[str, str]] = []
    seen: set[str] = set()
    try:
        lines = requirements_content.decode("utf-8", errors="strict").splitlines()
    except UnicodeError:
        lines = []
        failures.append("PYTHON_REQUIREMENTS_ENCODING_INVALID")
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        matched = _PYTHON_REQUIREMENT.fullmatch(line)
        identity = _python_identity(matched.group("name")) if matched else None
        if matched is None or identity is None:
            failures.append("PYTHON_REQUIREMENT_UNPINNED_OR_INVALID")
            continue
        if identity in seen:
            failures.append("PYTHON_REQUIREMENT_DUPLICATE_OR_CASE_VARIANT")
            continue
        seen.add(identity)
        requirements.append({
            "identity": identity,
            "version": matched.group("version"),
            "source_requirement": line,
        })
    requirements.sort(key=lambda item: item["identity"])
    requirement_failures = list(failures)
    if not requirements:
        failures.append("PYTHON_REQUIREMENTS_EMPTY")
        requirement_failures.append("PYTHON_REQUIREMENTS_EMPTY")
    if lock is None:
        failures.append("PYTHON_LOCK_MISSING")
        lock_status = PYTHON_LOCK_MISSING
    else:
        lock_status = PYTHON_LOCK_INVALID
        try:
            if type(lock) is not dict or set(lock) != {
                "schema_id", "lock_sequence", "prior_lock_sha512", "requirements_sha512",
                "target_environment", "rollback_guard", "packages",
            }:
                raise ValueError("PYTHON_LOCK_FIELDS_INVALID")
            sequence = lock["lock_sequence"]
            prior = lock["prior_lock_sha512"]
            if lock["schema_id"] != PYTHON_LOCK_SCHEMA or type(sequence) is not int or sequence <= 0:
                raise ValueError("PYTHON_LOCK_SCHEMA_OR_SEQUENCE_INVALID")
            if (sequence == 1 and prior != "GENESIS") or (
                sequence > 1 and (type(prior) is not str or re.fullmatch(r"[0-9a-f]{128}", prior) is None)
            ):
                raise ValueError("PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID")
            if lock["requirements_sha512"] != digest(requirements):
                raise ValueError("PYTHON_LOCK_REQUIREMENTS_MISMATCH")
            if lock["target_environment"] != _expected_python_environment():
                raise ValueError("PYTHON_LOCK_ENVIRONMENT_MISMATCH")
            rollback = lock["rollback_guard"]
            if type(rollback) is not dict or set(rollback) != {
                "accepted_attempt_history_sequence", "accepted_attempt_history_sha512",
            }:
                raise ValueError("PYTHON_LOCK_ROLLBACK_GUARD_INVALID")
            history_sequence = rollback["accepted_attempt_history_sequence"]
            history_digest = rollback["accepted_attempt_history_sha512"]
            if (
                type(history_sequence) is not int
                or history_sequence < 0
                or sequence != history_sequence + 1
                or type(history_digest) is not str
                or re.fullmatch(r"[0-9a-f]{128}", history_digest) is None
            ):
                raise ValueError("PYTHON_LOCK_ROLLBACK_GUARD_INVALID")
            packages = lock["packages"]
            if type(packages) is not list or not packages:
                raise ValueError("PYTHON_LOCK_PACKAGES_INVALID")
            identities: list[str] = []
            by_identity: dict[str, dict[str, Any]] = {}
            for package in packages:
                if type(package) is not dict or set(package) != {
                    "name", "version", "hashes", "scopes", "direct", "dependencies",
                }:
                    raise ValueError("PYTHON_LOCK_PACKAGE_FIELDS_INVALID")
                identity = _python_identity(package["name"])
                if identity is None or package["name"] != identity:
                    raise ValueError("PYTHON_LOCK_PACKAGE_CASE_VARIANT")
                hashes = package["hashes"]
                scopes = package["scopes"]
                dependencies = package["dependencies"]
                if type(package["version"]) is not str or _PYTHON_VERSION.fullmatch(package["version"]) is None:
                    raise ValueError("PYTHON_LOCK_PACKAGE_UNPINNED")
                if (
                    type(hashes) is not list or not hashes
                    or hashes != sorted(hashes) or len(hashes) != len(set(hashes))
                    or any(type(item) is not str or _PYTHON_HASH.fullmatch(item) is None for item in hashes)
                ):
                    raise ValueError("PYTHON_LOCK_PACKAGE_UNHASHED_OR_DUPLICATE")
                if (
                    type(scopes) is not list or not scopes
                    or scopes != sorted(scopes) or len(scopes) != len(set(scopes))
                    or any(scope not in {"development", "production"} for scope in scopes)
                ):
                    raise ValueError("PYTHON_LOCK_PACKAGE_SCOPE_INVALID")
                if type(package["direct"]) is not bool or type(dependencies) is not list:
                    raise ValueError("PYTHON_LOCK_PACKAGE_RELATION_INVALID")
                normalized_dependencies = [_python_identity(item) for item in dependencies]
                if (
                    any(item is None for item in normalized_dependencies)
                    or dependencies != normalized_dependencies
                    or dependencies != sorted(dependencies)
                    or len(dependencies) != len(set(dependencies))
                    or identity in dependencies
                ):
                    raise ValueError("PYTHON_LOCK_DEPENDENCY_INVALID")
                identities.append(identity)
                by_identity[identity] = package
            if identities != sorted(identities) or len(identities) != len(set(identities)):
                raise ValueError("PYTHON_LOCK_PACKAGE_DUPLICATE_OR_CASE_VARIANT")
            if any(
                dependency not in by_identity
                for package in packages for dependency in package["dependencies"]
            ):
                raise ValueError("PYTHON_LOCK_DEPENDENCY_MISSING")
            expected_direct = {item["identity"]: item["version"] for item in requirements}
            actual_direct = {
                item["name"]: item["version"] for item in packages if item["direct"]
            }
            if expected_direct != actual_direct or any(
                "production" not in item["scopes"] for item in packages if item["direct"]
            ):
                raise ValueError("PYTHON_LOCK_DIRECT_REQUIREMENTS_MISMATCH")
            reachable = set(actual_direct)
            pending = list(actual_direct)
            while pending:
                for dependency in by_identity[pending.pop()]["dependencies"]:
                    if dependency not in reachable:
                        reachable.add(dependency)
                        pending.append(dependency)
            if reachable != set(by_identity):
                raise ValueError("PYTHON_LOCK_EXTRA_PACKAGE")
            installed_by_identity: dict[str, str] = {}
            for installed in installed_packages:
                if type(installed) is not dict or set(installed) != {"name", "version"}:
                    raise ValueError("PYTHON_INSTALLED_PACKAGE_INVALID")
                installed_identity = _python_identity(installed["name"])
                installed_version = installed["version"]
                if (
                    installed_identity is None
                    or type(installed_version) is not str
                    or _PYTHON_VERSION.fullmatch(installed_version) is None
                    or installed_identity in installed_by_identity
                ):
                    raise ValueError("PYTHON_INSTALLED_PACKAGE_DUPLICATE_OR_CASE_VARIANT")
                installed_by_identity[installed_identity] = installed_version
            locked_versions = {
                item["name"]: item["version"] for item in packages
            }
            if installed_by_identity != locked_versions:
                raise ValueError("PYTHON_INSTALLED_PACKAGES_LOCK_MISMATCH_OR_EXTRA")
            if requirement_failures:
                raise ValueError(requirement_failures[0])
            lock_status = PYTHON_LOCK_VALID
        except (KeyError, TypeError, ValueError) as error:
            failures.append(str(error) or type(error).__name__)
    return {
        "requirements": requirements,
        "requirements_sha512": digest(requirements),
        "requirements_status": "EXACTLY_PINNED" if not requirement_failures else "INVALID_OR_UNPINNED",
        "lock_path": PYTHON_LOCK_PATH,
        "lock_status": lock_status,
        "lock_failures": sorted(set(failures)),
        "dependency_evidence_status": "COMPLETE" if lock_status == PYTHON_LOCK_VALID else "INCOMPLETE",
        "runtime_attachment": "NONE",
        "authority_granted": False,
    }


def _collect_python_dependency_evidence(
    root: Path,
    installed_packages: list[dict[str, str]],
) -> dict[str, Any]:
    try:
        requirements = _stable_file_bytes(root, "requirements.txt")
        requirements_record = measure_file(root, "requirements.txt")
    except LocalTrustPathError as error:
        return {
            "dependency_evidence_status": "INCOMPLETE",
            "requirements_status": "MISSING_OR_INVALID",
            "lock_status": PYTHON_LOCK_INVALID,
            "lock_failures": [str(error)],
            "requirements_record": None,
            "lock_path": PYTHON_LOCK_PATH,
            "runtime_attachment": "NONE",
            "authority_granted": False,
        }
    lock_document: dict[str, Any] | None = None
    lock_failure: str | None = None
    try:
        lock_document = strict_load_json(resolve_safe_path(root, PYTHON_LOCK_PATH))
    except LocalTrustPathError as error:
        try:
            resolve_safe_path(root, PYTHON_LOCK_PATH)
        except LocalTrustPathError:
            pass
        else:
            lock_failure = str(error)
    evidence = _local_python_dependency_evidence(
        requirements, lock_document, installed_packages
    )
    evidence["requirements_record"] = requirements_record
    if lock_failure is not None:
        evidence["lock_status"] = PYTHON_LOCK_INVALID
        evidence["dependency_evidence_status"] = "INCOMPLETE"
        evidence["lock_failures"] = sorted(set([*evidence["lock_failures"], lock_failure]))
    return evidence


def collect_isolated_assurance_evidence(
    manifest: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
) -> list[dict[str, Any]]:
    manifest_files = manifest.get("payload", {}).get("evidence_inventory", {}).get("files", [])
    command_results = execution_envelope.get("payload", {}).get("command_results", [])
    specifications = {
        "RUST_SECURITY_CORE": {
            "source_prefixes": ("security_core/src/",),
            "source_paths": ("security_core/Cargo.toml", "security_core/Cargo.lock"),
            "command_id": "rust_security_core",
            "status_paths": ("docs/security/RUST_TCB_AND_TLA_VALIDATION.md",),
        },
        "TLA_FORMAL_MODEL": {
            "source_prefixes": ("formal/tla/",),
            "source_paths": (),
            "command_id": "formal_tla_native",
            "status_paths": (
                "docs/security/RUST_TCB_AND_TLA_VALIDATION.md",
                "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
            ),
        },
        "SPARK_SAFETY_MONITOR": {
            "source_prefixes": ("spark_safety_monitor/src/",),
            "source_paths": ("spark_safety_monitor/spark_safety_monitor.gpr",),
            "command_id": "spark_gnatprove_native",
            "status_paths": (
                "evidence/v2/spark-proof-evidence.json",
                "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
            ),
        },
    }
    proofs: list[dict[str, Any]] = []
    for component, spec in specifications.items():
        sources = [
            item for item in manifest_files
            if type(item) is dict and (
                item.get("path") in spec["source_paths"]
                or any(str(item.get("path", "")).startswith(prefix) for prefix in spec["source_prefixes"])
            )
        ]
        logs = [
            item for item in command_results
            if type(item) is dict and item.get("command_id") == spec["command_id"]
        ]
        statuses = [
            item for item in manifest_files
            if type(item) is dict and item.get("path") in spec["status_paths"]
        ]
        proof = {
            "component": component,
            "classification": "PRESENT_TESTED_BUT_INACTIVE",
            "source_evidence": sources,
            "native_command_transcript_evidence": logs,
            "status_evidence": statuses,
            "runtime_attachment": "NONE",
            "authority_granted": False,
        }
        proof["proof_digest"] = digest(proof)
        proofs.append(proof)
    return proofs


def collect_toolchain_inventory(repository_root: str | Path) -> dict[str, Any]:
    root = validated_root(repository_root)
    packages = sorted(
        [
            {"name": distribution.metadata.get("Name", ""), "version": distribution.version}
            for distribution in importlib.metadata.distributions()
            if distribution.metadata.get("Name") and distribution.version
        ],
        key=lambda item: (item["name"].casefold(), item["version"]),
    )
    python_dependency_evidence = _collect_python_dependency_evidence(root, packages)
    locks: list[dict[str, Any]] = []
    missing: list[str] = []
    for relative in DEPENDENCY_LOCK_PATHS:
        try:
            locks.append(measure_file(root, relative))
        except LocalTrustPathError:
            missing.append(relative)
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "dependency_locks": locks,
        "missing_dependency_locks": missing,
        "python_dependency_evidence": python_dependency_evidence,
        "installed_packages": packages,
        "environment_values_retained": False,
    }


def build_toolchain_guard(
    repository_root: str | Path,
    *,
    constitutional_gates: Mapping[str, Any],
    manifest: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
    signer: HybridSigningContext,
    time_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    inventory = collect_toolchain_inventory(repository_root)
    assurance_evidence = collect_isolated_assurance_evidence(manifest, execution_envelope)
    python_evidence_complete = (
        inventory["python_dependency_evidence"]["dependency_evidence_status"] == "COMPLETE"
    )
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": PASS if not inventory["missing_dependency_locks"] and python_evidence_complete else FAIL,
        "bound_constitutional_gates_digest": constitutional_gates.get("artifact_digest"),
        "bound_manifest_digest": manifest.get("artifact_digest"),
        "bound_execution_envelope_digest": execution_envelope.get("artifact_digest"),
        "toolchain_inventory": inventory,
        "python_dependency_assurance_classification": (
            "PRESENT_TESTED" if python_evidence_complete else "MISSING_OR_INVALID"
        ),
        "isolated_assurance_classification": "PRESENT_TESTED_BUT_INACTIVE",
        "isolated_assurance_evidence": assurance_evidence,
        "runtime_attachment": "NONE",
    }
    return build_signed_artifact(
        stage="toolchain_guard",
        payload=payload,
        signer=signer,
        prior_artifact_digest=str(constitutional_gates.get("artifact_digest")),
        time_evidence=time_evidence,
    )


def validate_toolchain_guard(
    guard: Any,
    repository_root: str | Path,
    *,
    expected_gates_digest: str,
    expected_manifest_digest: str,
    expected_envelope_digest: str,
    expected_assurance_evidence: list[dict[str, Any]],
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        guard,
        expected_stage="toolchain_guard",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=expected_gates_digest,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = guard["payload"]
        if (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("status") != PASS
            or payload.get("bound_constitutional_gates_digest") != expected_gates_digest
            or payload.get("bound_manifest_digest") != expected_manifest_digest
            or payload.get("bound_execution_envelope_digest") != expected_envelope_digest
            or payload.get("toolchain_inventory") != collect_toolchain_inventory(repository_root)
            or payload.get("python_dependency_assurance_classification") != "PRESENT_TESTED"
            or payload.get("isolated_assurance_classification") != "PRESENT_TESTED_BUT_INACTIVE"
            or payload.get("isolated_assurance_evidence") != expected_assurance_evidence
            or len(expected_assurance_evidence) != 3
            or any(
                not item.get("source_evidence")
                or not item.get("native_command_transcript_evidence")
                or not item.get("status_evidence")
                or item.get("classification") != "PRESENT_TESTED_BUT_INACTIVE"
                or item.get("runtime_attachment") != "NONE"
                or item.get("authority_granted") is not False
                for item in expected_assurance_evidence
            )
            or payload.get("runtime_attachment") != "NONE"
        ):
            failures.append("toolchain_guard_not_current_or_admissible")
    except (KeyError, TypeError, ValueError):
        failures.append("toolchain_guard_malformed")
    return {**base, "status": PASS if not failures else FAIL, "validation_failures": sorted(set(failures))}


__all__ = [
    "build_toolchain_guard", "collect_isolated_assurance_evidence",
    "collect_toolchain_inventory", "validate_toolchain_guard",
]
