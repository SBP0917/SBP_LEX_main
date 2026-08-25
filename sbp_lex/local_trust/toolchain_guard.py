"""Python/Rust/SPARK dependency and toolchain guard (stage 6)."""

from __future__ import annotations

import hashlib
import hmac
import importlib.metadata
import platform
import re
import shutil
import stat
import sys
import sysconfig
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifact import build_signed_artifact, validate_signed_artifact
from .command_evidence import validate_full_byte_transcript
from .constants import COMMAND_POLICY, DEPENDENCY_LOCK_PATHS, FAIL, PASS
from .digests import digest, is_sha512
from .paths import (
    LocalTrustPathError,
    measure_file,
    resolve_safe_path,
    strict_load_json,
    validated_root,
)
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_TOOLCHAIN_GUARD_PAYLOAD_V1"
PYTHON_LOCK_PATH = "python-dependencies.lock.json"
PYTHON_LOCK_SCHEMA = "sbp.lex.v2.python-dependency-lock/2"
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
_HASH_LOCK_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^ ]+) "
    r"--hash=(?P<hash>sha256:[0-9a-f]{64})$"
)
_ASSURANCE_DIRECT_REQUIREMENTS = frozenset({"pytest"})
_PYTHON_BOOTSTRAP_PACKAGES = frozenset({"pip", "setuptools", "wheel"})
_TOOL_VERSION_COMMANDS = {
    "python": "tool_python_version",
    "cargo": "tool_cargo_version",
    "java": "tool_java_version",
    "alr": "tool_alr_version",
    "git": "tool_git_version",
}


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


def _measure_executable(path: Path, *, tool_id: str) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        before = resolved.stat()
        if not stat.S_ISREG(before.st_mode):
            raise LocalTrustPathError("tool_executable_not_safe")
        hasher = hashlib.sha512()
        size = 0
        with resolved.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                size += len(chunk)
                hasher.update(chunk)
        after = resolved.stat()
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or size != before.st_size
        ):
            raise LocalTrustPathError("tool_executable_changed_during_measurement")
        return {
            "tool_id": tool_id,
            "resolved_path": str(resolved),
            "size_bytes": size,
            "hardlink_count": before.st_nlink,
            "sha512": hasher.hexdigest(),
            "version_command_id": _TOOL_VERSION_COMMANDS[tool_id],
        }
    except (OSError, RuntimeError) as exc:
        raise LocalTrustPathError("tool_executable_measurement_failed") from exc


def _collect_tool_executables() -> tuple[list[dict[str, Any]], list[str]]:
    measurements: list[dict[str, Any]] = []
    missing: list[str] = []
    for tool_id in _TOOL_VERSION_COMMANDS:
        selected = sys.executable if tool_id == "python" else shutil.which(tool_id)
        if type(selected) is not str or not selected:
            missing.append(tool_id)
            continue
        try:
            measurements.append(
                _measure_executable(Path(selected), tool_id=tool_id)
            )
        except LocalTrustPathError:
            missing.append(tool_id)
    return measurements, missing


def _executable_pin_evidence(
    measurements: list[dict[str, Any]],
    missing: list[str],
    expected_pins: Mapping[str, str] | None,
) -> dict[str, Any]:
    supplied = dict(expected_pins) if isinstance(expected_pins, Mapping) else {}
    measured = {
        item["tool_id"]: item["sha512"]
        for item in measurements
        if type(item) is dict
        and type(item.get("tool_id")) is str
        and is_sha512(item.get("sha512"))
    }
    pin_set_valid = (
        set(supplied) == set(_TOOL_VERSION_COMMANDS)
        and all(is_sha512(value) for value in supplied.values())
    )
    matches = (
        pin_set_valid
        and not missing
        and set(measured) == set(_TOOL_VERSION_COMMANDS)
        and all(
            hmac.compare_digest(measured[tool_id], supplied[tool_id])
            for tool_id in _TOOL_VERSION_COMMANDS
        )
    )
    failures: list[str] = []
    if not supplied:
        failures.append("EXTERNAL_EXECUTABLE_PINS_ABSENT")
    elif not pin_set_valid:
        failures.append("EXTERNAL_EXECUTABLE_PIN_SET_INVALID")
    elif not matches:
        failures.append("EXTERNAL_EXECUTABLE_PIN_MISMATCH")
    return {
        "external_executable_sha512_pins": supplied,
        "external_executable_pins_present": matches,
        "executable_pin_failures": failures,
        "executable_assurance_classification": (
            "EXTERNALLY_PINNED" if matches
            else "MEASURED_LOCALLY_EXTERNAL_PINS_ABSENT_OR_INVALID"
        ),
    }


def _tool_version_evidence(
    execution_envelope: Mapping[str, Any],
) -> list[dict[str, Any]]:
    command_results = execution_envelope.get("payload", {}).get(
        "command_results", []
    )
    if type(command_results) is not list:
        return []
    return [
        item
        for item in command_results
        if type(item) is dict
        and item.get("command_id") in set(_TOOL_VERSION_COMMANDS.values())
    ]


def _tool_versions_complete(evidence: list[dict[str, Any]]) -> bool:
    return (
        len(evidence) == len(_TOOL_VERSION_COMMANDS)
        and {item.get("command_id") for item in evidence}
        == set(_TOOL_VERSION_COMMANDS.values())
        and all(
            item.get("status") == "COMMAND_PASS"
            and item.get("exit_code") == 0
            and validate_full_byte_transcript(item)
            for item in evidence
        )
    )


def _commands_use_measured_executables(
    execution_envelope: Mapping[str, Any],
    measurements: list[dict[str, Any]],
) -> bool:
    measured_paths = {
        item.get("tool_id"): item.get("resolved_path")
        for item in measurements
        if type(item) is dict
    }
    results = execution_envelope.get("payload", {}).get("command_results", [])
    if type(results) is not list:
        return False
    by_id: dict[str, list[dict[str, Any]]] = {}
    for item in results:
        if type(item) is dict and type(item.get("command_id")) is str:
            by_id.setdefault(item["command_id"], []).append(item)
    for policy in COMMAND_POLICY:
        command_id = policy[0]
        raw_executable = policy[1][0]
        tool_id = "python" if raw_executable == "{python}" else raw_executable
        matches = by_id.get(command_id, [])
        if len(matches) != 1:
            return False
        arguments = matches[0].get("arguments")
        if (
            tool_id not in measured_paths
            or type(arguments) is not list
            or not arguments
            or type(arguments[0]) is not str
            or arguments[0].casefold()
            != str(measured_paths[tool_id]).casefold()
        ):
            return False
    return True


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


def _parse_hash_lock(content: bytes, *, label: str) -> dict[str, dict[str, Any]]:
    try:
        lines = content.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise ValueError(f"PYTHON_{label}_HASH_LOCK_ENCODING_INVALID") from exc
    directives: list[str] = []
    packages: dict[str, dict[str, Any]] = {}
    ordered: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--"):
            directives.append(line)
            continue
        matched = _HASH_LOCK_LINE.fullmatch(line)
        identity = _python_identity(matched.group("name")) if matched else None
        if (
            matched is None
            or identity is None
            or matched.group("name") != identity
            or identity in packages
            or _PYTHON_VERSION.fullmatch(matched.group("version")) is None
        ):
            raise ValueError(f"PYTHON_{label}_HASH_LOCK_ENTRY_INVALID")
        ordered.append(identity)
        packages[identity] = {
            "version": matched.group("version"),
            "hashes": [matched.group("hash")],
        }
    if (
        directives != ["--only-binary=:all:", "--require-hashes"]
        or ordered != sorted(ordered)
        or not packages
    ):
        raise ValueError(f"PYTHON_{label}_HASH_LOCK_POLICY_INVALID")
    return packages


def _local_python_dependency_evidence(
    requirements_content: bytes,
    production_hash_lock_content: bytes,
    assurance_hash_lock_content: bytes,
    lock: Any | None,
    installed_packages: list[dict[str, str]],
    *,
    expected_accepted_history_sequence: int | None,
    expected_accepted_history_digest: str | None,
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
    try:
        production_hash_lock = _parse_hash_lock(
            production_hash_lock_content,
            label="PRODUCTION",
        )
        assurance_hash_lock = _parse_hash_lock(
            assurance_hash_lock_content,
            label="ASSURANCE",
        )
    except ValueError as error:
        production_hash_lock = {}
        assurance_hash_lock = {}
        failures.append(str(error))
        requirement_failures.append(str(error))
    if lock is None:
        failures.append("PYTHON_LOCK_MISSING")
        lock_status = PYTHON_LOCK_MISSING
    else:
        lock_status = PYTHON_LOCK_INVALID
        try:
            if type(lock) is not dict or set(lock) != {
                "schema_id", "lock_sequence", "prior_lock_sha512", "requirements_sha512",
                "production_hash_lock_sha512", "assurance_hash_lock_sha512",
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
            if (
                lock["production_hash_lock_sha512"]
                != hashlib.sha512(production_hash_lock_content).hexdigest()
                or lock["assurance_hash_lock_sha512"]
                != hashlib.sha512(assurance_hash_lock_content).hexdigest()
            ):
                raise ValueError("PYTHON_HASH_LOCK_BINDING_MISMATCH")
            if lock["target_environment"] != {
                **_expected_python_environment(),
                "installed_scope": "assurance",
            }:
                raise ValueError("PYTHON_LOCK_ENVIRONMENT_MISMATCH")
            rollback = lock["rollback_guard"]
            if type(rollback) is not dict or set(rollback) != {
                "accepted_attempt_history_sequence", "accepted_attempt_history_sha512",
            }:
                raise ValueError("PYTHON_LOCK_ROLLBACK_GUARD_INVALID")
            history_sequence = rollback["accepted_attempt_history_sequence"]
            history_digest = rollback["accepted_attempt_history_sha512"]
            if (
                type(expected_accepted_history_sequence) is not int
                or expected_accepted_history_sequence < 0
                or not is_sha512(expected_accepted_history_digest)
                or type(history_sequence) is not int
                or history_sequence < 0
                or sequence != history_sequence + 1
                or history_sequence != expected_accepted_history_sequence
                or history_digest != expected_accepted_history_digest
            ):
                raise ValueError("PYTHON_LOCK_ROLLBACK_GUARD_INVALID")
            packages = lock["packages"]
            if type(packages) is not list or not packages:
                raise ValueError("PYTHON_LOCK_PACKAGES_INVALID")
            identities: list[str] = []
            by_identity: dict[str, dict[str, Any]] = {}
            for package in packages:
                if type(package) is not dict or set(package) != {
                    "name", "version", "hashes", "scopes", "direct_scopes", "dependencies",
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
                    or any(scope not in {"assurance", "production"} for scope in scopes)
                ):
                    raise ValueError("PYTHON_LOCK_PACKAGE_SCOPE_INVALID")
                direct_scopes = package["direct_scopes"]
                if (
                    type(direct_scopes) is not list
                    or direct_scopes != sorted(direct_scopes)
                    or len(direct_scopes) != len(set(direct_scopes))
                    or any(scope not in scopes for scope in direct_scopes)
                    or type(dependencies) is not list
                ):
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
            expected_production_direct = {
                item["identity"]: item["version"] for item in requirements
            }
            expected_assurance_direct = {
                **expected_production_direct,
                **{
                    name: assurance_hash_lock[name]["version"]
                    for name in _ASSURANCE_DIRECT_REQUIREMENTS
                    if name in assurance_hash_lock
                },
            }
            actual_direct_by_scope = {
                scope: {
                    item["name"]: item["version"]
                    for item in packages
                    if scope in item["direct_scopes"]
                }
                for scope in ("production", "assurance")
            }
            if (
                not _ASSURANCE_DIRECT_REQUIREMENTS.issubset(assurance_hash_lock)
                or expected_production_direct
                != actual_direct_by_scope["production"]
                or expected_assurance_direct
                != actual_direct_by_scope["assurance"]
            ):
                raise ValueError("PYTHON_LOCK_DIRECT_REQUIREMENTS_MISMATCH")
            for scope, expected_lock in (
                ("production", production_hash_lock),
                ("assurance", assurance_hash_lock),
            ):
                scoped = {
                    item["name"]: item for item in packages if scope in item["scopes"]
                }
                if set(scoped) != set(expected_lock):
                    raise ValueError("PYTHON_LOCK_SCOPE_CLOSURE_MISMATCH")
                for name, item in scoped.items():
                    if (
                        item["version"] != expected_lock[name]["version"]
                        or item["hashes"] != expected_lock[name]["hashes"]
                        or any(dependency not in scoped for dependency in item["dependencies"])
                    ):
                        raise ValueError("PYTHON_LOCK_SCOPE_PACKAGE_MISMATCH")
                reachable = set(actual_direct_by_scope[scope])
                pending = list(reachable)
                while pending:
                    for dependency in scoped[pending.pop()]["dependencies"]:
                        if dependency not in reachable:
                            reachable.add(dependency)
                            pending.append(dependency)
                if reachable != set(scoped):
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
                name: item["version"] for name, item in assurance_hash_lock.items()
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
        "production_hash_lock_sha512": hashlib.sha512(
            production_hash_lock_content
        ).hexdigest(),
        "assurance_hash_lock_sha512": hashlib.sha512(
            assurance_hash_lock_content
        ).hexdigest(),
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
    *,
    expected_accepted_history_sequence: int | None,
    expected_accepted_history_digest: str | None,
) -> dict[str, Any]:
    try:
        requirements = _stable_file_bytes(root, "requirements.txt")
        production_hash_lock = _stable_file_bytes(
            root, "requirements-production.lock.txt"
        )
        assurance_hash_lock = _stable_file_bytes(
            root, "requirements-test.lock.txt"
        )
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
        requirements,
        production_hash_lock,
        assurance_hash_lock,
        lock_document,
        installed_packages,
        expected_accepted_history_sequence=expected_accepted_history_sequence,
        expected_accepted_history_digest=expected_accepted_history_digest,
    )
    evidence["requirements_record"] = requirements_record
    if lock_failure is not None:
        evidence["lock_status"] = PYTHON_LOCK_INVALID
        evidence["dependency_evidence_status"] = "INCOMPLETE"
        evidence["lock_failures"] = sorted(
            {*evidence["lock_failures"], lock_failure}
        )
    return evidence


def collect_isolated_assurance_evidence(
    manifest: Mapping[str, Any],
    execution_envelope: Mapping[str, Any],
) -> list[dict[str, Any]]:
    manifest_files = manifest.get("payload", {}).get("evidence_inventory", {}).get("files", [])
    command_results = execution_envelope.get("payload", {}).get("command_results", [])
    rust_command_ids = tuple(
        command[0] for command in COMMAND_POLICY if command[0].startswith("rust_")
    )
    specifications = {
        "RUST_ALL_CRATES": {
            "source_prefixes": (
                "hybrid_signature_rust/",
                "independent_verifier_rust/",
                "polyglot/rust/v2_assurance_kernel/",
                "rust_authority_service/",
                "security_core/",
                "trusted_core_rust/",
                "wire_protocol/rust/",
                "wire_protocol/v2/rust/",
            ),
            "source_paths": (),
            "command_ids": rust_command_ids,
            "status_paths": ("docs/security/RUST_TCB_AND_TLA_VALIDATION.md",),
        },
        "TLA_ALL_FORMAL_MODELS": {
            "source_prefixes": ("formal/tla/",),
            "source_paths": (
                "formal/SBPLexAuthority.cfg",
                "formal/SBPLexAuthority.tla",
            ),
            "command_ids": (
                "formal_tla_v2_tpm_disabled",
                "formal_tla_v2_tpm_admitted",
                "formal_tla_authority",
            ),
            "status_paths": (
                "docs/security/RUST_TCB_AND_TLA_VALIDATION.md",
                "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
            ),
        },
        "PYTHON_FORMAL_EXPLORER": {
            "source_prefixes": (),
            "source_paths": ("formal/check_model.py",),
            "command_ids": ("formal_python_explorer",),
            "status_paths": (
                "formal/README.md",
                "docs/validation/V2_CANONICAL_STATUS.md",
            ),
        },
        "SPARK_SAFETY_MONITOR": {
            "source_prefixes": ("spark_safety_monitor/src/",),
            "source_paths": (
                "spark_safety_monitor/spark_safety_monitor.gpr",
                "spark_safety_monitor/tools/run_harness.py",
            ),
            "command_ids": (
                "spark_gnatprove_native",
                "spark_build_native",
                "spark_assertion_harness",
            ),
            "status_paths": (
                "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
                "docs/validation/V2_CANONICAL_STATUS.md",
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
            if type(item) is dict and item.get("command_id") in spec["command_ids"]
        ]
        statuses = [
            item for item in manifest_files
            if type(item) is dict and item.get("path") in spec["status_paths"]
        ]
        proof = {
            "component": component,
            "classification": "PRESENT_TESTED_BUT_INACTIVE",
            "source_evidence": sources,
            "required_source_prefixes": list(spec["source_prefixes"]),
            "required_source_paths": list(spec["source_paths"]),
            "native_command_transcript_evidence": logs,
            "required_command_ids": list(spec["command_ids"]),
            "status_evidence": statuses,
            "runtime_attachment": "NONE",
            "authority_granted": False,
        }
        proof["proof_digest"] = digest(proof)
        proofs.append(proof)
    return proofs


def _isolated_assurance_complete(proofs: list[dict[str, Any]]) -> bool:
    expected_components = {
        "RUST_ALL_CRATES",
        "TLA_ALL_FORMAL_MODELS",
        "PYTHON_FORMAL_EXPLORER",
        "SPARK_SAFETY_MONITOR",
    }
    if (
        len(proofs) != len(expected_components)
        or {item.get("component") for item in proofs} != expected_components
    ):
        return False
    for item in proofs:
        commands = item.get("native_command_transcript_evidence")
        required_command_ids = item.get("required_command_ids")
        source_evidence = item.get("source_evidence")
        required_source_prefixes = item.get("required_source_prefixes")
        required_source_paths = item.get("required_source_paths")
        if (
            type(source_evidence) is not list
            or not source_evidence
            or type(required_source_prefixes) is not list
            or type(required_source_paths) is not list
            or any(
                not any(
                    str(source.get("path", "")).startswith(prefix)
                    for source in source_evidence
                    if type(source) is dict
                )
                for prefix in required_source_prefixes
            )
            or any(
                not any(
                    source.get("path") == path
                    for source in source_evidence
                    if type(source) is dict
                )
                for path in required_source_paths
            )
            or not item.get("status_evidence")
            or type(commands) is not list
            or type(required_command_ids) is not list
            or len(commands) != len(required_command_ids)
            or {command.get("command_id") for command in commands}
            != set(required_command_ids)
            or len(required_command_ids) != len(set(required_command_ids))
            or item.get("classification") != "PRESENT_TESTED_BUT_INACTIVE"
            or item.get("runtime_attachment") != "NONE"
            or item.get("authority_granted") is not False
        ):
            return False
        if any(
            type(command) is not dict
            or command.get("status") != "COMMAND_PASS"
            or command.get("exit_code") != 0
            or not validate_full_byte_transcript(command)
            for command in commands
        ):
            return False
    return True


def collect_toolchain_inventory(
    repository_root: str | Path,
    *,
    expected_accepted_history_sequence: int | None = None,
    expected_accepted_history_digest: str | None = None,
    expected_executable_sha512_pins: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = validated_root(repository_root)
    discovered_packages = [
        {"name": distribution.metadata.get("Name", ""), "version": distribution.version}
        for distribution in importlib.metadata.distributions()
        if distribution.metadata.get("Name") and distribution.version
    ]
    packages = sorted(
        [
            item
            for item in discovered_packages
            if _python_identity(item["name"]) not in _PYTHON_BOOTSTRAP_PACKAGES
        ],
        key=lambda item: (item["name"].casefold(), item["version"]),
    )
    bootstrap_packages = sorted(
        [
            item
            for item in discovered_packages
            if _python_identity(item["name"]) in _PYTHON_BOOTSTRAP_PACKAGES
        ],
        key=lambda item: (item["name"].casefold(), item["version"]),
    )
    python_dependency_evidence = _collect_python_dependency_evidence(
        root,
        packages,
        expected_accepted_history_sequence=expected_accepted_history_sequence,
        expected_accepted_history_digest=expected_accepted_history_digest,
    )
    locks: list[dict[str, Any]] = []
    missing: list[str] = []
    executable_measurements, missing_executables = _collect_tool_executables()
    executable_pin_evidence = _executable_pin_evidence(
        executable_measurements,
        missing_executables,
        expected_executable_sha512_pins,
    )
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
        "executable_measurements": executable_measurements,
        "missing_executable_measurements": missing_executables,
        **executable_pin_evidence,
        "dependency_locks": locks,
        "missing_dependency_locks": missing,
        "python_dependency_evidence": python_dependency_evidence,
        "installed_packages": packages,
        "bootstrap_python_tooling": bootstrap_packages,
        "bootstrap_python_tooling_classification": "NON_RUNTIME_INSTALL_TOOLING",
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
    expected_executable_sha512_pins: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    manifest_payload = manifest.get("payload")
    accepted_history_sequence = (
        manifest_payload.get("accepted_history_sequence")
        if isinstance(manifest_payload, Mapping)
        else None
    )
    accepted_history_digest = (
        manifest_payload.get("accepted_history_digest")
        if isinstance(manifest_payload, Mapping)
        else None
    )
    inventory = collect_toolchain_inventory(
        repository_root,
        expected_accepted_history_sequence=accepted_history_sequence,
        expected_accepted_history_digest=accepted_history_digest,
        expected_executable_sha512_pins=expected_executable_sha512_pins,
    )
    assurance_evidence = collect_isolated_assurance_evidence(manifest, execution_envelope)
    tool_version_evidence = _tool_version_evidence(execution_envelope)
    python_evidence_complete = (
        inventory["python_dependency_evidence"]["dependency_evidence_status"] == "COMPLETE"
    )
    isolated_evidence_complete = _isolated_assurance_complete(assurance_evidence)
    tool_versions_complete = _tool_versions_complete(tool_version_evidence)
    executable_inventory_complete = (
        not inventory["missing_executable_measurements"]
        and len(inventory["executable_measurements"]) == len(_TOOL_VERSION_COMMANDS)
    )
    command_executable_bindings_complete = _commands_use_measured_executables(
        execution_envelope,
        inventory["executable_measurements"],
    )
    external_executable_pins_present = inventory[
        "external_executable_pins_present"
    ] is True
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": (
            PASS
            if not inventory["missing_dependency_locks"]
            and python_evidence_complete
            and isolated_evidence_complete
            and tool_versions_complete
            and executable_inventory_complete
            and command_executable_bindings_complete
            and external_executable_pins_present
            else FAIL
        ),
        "bound_constitutional_gates_digest": constitutional_gates.get("artifact_digest"),
        "bound_manifest_digest": manifest.get("artifact_digest"),
        "bound_execution_envelope_digest": execution_envelope.get("artifact_digest"),
        "toolchain_inventory": inventory,
        "tool_version_evidence": tool_version_evidence,
        "command_executable_bindings_complete": (
            command_executable_bindings_complete
        ),
        "python_dependency_assurance_classification": (
            "PRESENT_TESTED" if python_evidence_complete else "MISSING_OR_INVALID"
        ),
        "executable_pin_assurance_classification": (
            "EXTERNALLY_PINNED"
            if external_executable_pins_present
            else "MEASURED_LOCALLY_EXTERNAL_PINS_ABSENT"
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
    expected_accepted_history_sequence: int,
    expected_accepted_history_digest: str,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
    expected_executable_sha512_pins: Mapping[str, str] | None = None,
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
            or payload.get("toolchain_inventory")
            != collect_toolchain_inventory(
                repository_root,
                expected_accepted_history_sequence=expected_accepted_history_sequence,
                expected_accepted_history_digest=expected_accepted_history_digest,
                expected_executable_sha512_pins=(
                    expected_executable_sha512_pins
                ),
            )
            or payload.get("python_dependency_assurance_classification") != "PRESENT_TESTED"
            or payload.get("executable_pin_assurance_classification")
            != "EXTERNALLY_PINNED"
            or type(payload.get("tool_version_evidence")) is not list
            or not _tool_versions_complete(payload["tool_version_evidence"])
            or payload.get("command_executable_bindings_complete") is not True
            or payload.get("isolated_assurance_classification") != "PRESENT_TESTED_BUT_INACTIVE"
            or payload.get("isolated_assurance_evidence") != expected_assurance_evidence
            or not _isolated_assurance_complete(expected_assurance_evidence)
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
