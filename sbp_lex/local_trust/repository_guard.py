"""Fail-closed repository and known-good Python verification guard."""

from __future__ import annotations

import importlib.metadata
import os
import re
import subprocess
import sys
import threading
from hashlib import sha512
from pathlib import Path
from time import monotonic
from types import MappingProxyType
from typing import Any, cast

from .command_evidence import (
    _terminate,
    _windows_creation_flags,
    _WindowsCommandJob,
)
from .constants import (
    DEPENDENCY_LOCK_PATHS,
    MAX_COMMAND_OUTPUT_BYTES,
)
from .digests import digest
from .paths import (
    LocalTrustPathError,
    measure_file,
    resolve_safe_path,
    strict_load_json,
    validated_root,
)
from .secure_git import PinnedGit, SecureGitError
from .toolchain_guard import _local_python_dependency_evidence

GUARD_SCHEMA = "SBP_LEX_V2_REPOSITORY_GUARD_V1"
EXPECTED_RUNTIME_RECORD = "python-3.12.13"
EXPECTED_IMPLEMENTATION = "CPython"
EXPECTED_PYTHON_VERSION = "3.12.13"
MAX_TRACKED_PATHS = 100_000
MAX_TRACKED_INVENTORY_BYTES = 1_073_741_824
BOOTSTRAP_PACKAGES = frozenset({"pip", "setuptools", "wheel"})
DIRECT_REQUIREMENTS = MappingProxyType({"cryptography": "50.0.0"})
PRODUCTION_PACKAGES = MappingProxyType({
    "cffi": "2.1.1",
    "cryptography": "50.0.0",
    "pycparser": "3.0",
})
TEST_PACKAGES = MappingProxyType({
    **PRODUCTION_PACKAGES,
    "colorama": "0.4.6",
    "iniconfig": "2.3.0",
    "packaging": "26.3",
    "pluggy": "1.6.0",
    "pygments": "2.21.0",
    "pytest": "9.1.1",
})
REQUIRED_CRITICAL_FILES = frozenset(
    {
        "main.py",
        "pytest.ini",
        "requirements-production.lock.txt",
        "requirements-test.lock.txt",
        "requirements.txt",
        "runtime.txt",
    }
)
_CHANGE_CLASSES = MappingProxyType({
    "runtime_logic": MappingProxyType({
        "required_checks": ("focused_regression", "full_regression", "static_analysis"),
        "rollback_plan_required": True,
    }),
    "trust_boundary": MappingProxyType({
        "required_checks": ("full_regression", "static_analysis", "trust_boundary_review"),
        "rollback_plan_required": True,
    }),
    "schema_or_config": MappingProxyType({
        "required_checks": ("focused_regression", "full_regression", "rollback_plan"),
        "rollback_plan_required": True,
    }),
    "dependency_or_toolchain": MappingProxyType({
        "required_checks": ("clean_rebuild", "dependency_lock", "full_regression"),
        "rollback_plan_required": True,
    }),
    "documentation_or_report": MappingProxyType({
        "required_checks": ("provenance_inventory",),
        "rollback_plan_required": True,
    }),
    "release_or_archive": MappingProxyType({
        "required_checks": ("clean_rebuild", "full_regression", "provenance_inventory"),
        "rollback_plan_required": True,
    }),
    "emergency_fix": MappingProxyType({
        "required_checks": ("focused_regression", "rollback_plan", "trust_boundary_review"),
        "rollback_plan_required": True,
    }),
})
_CANONICAL_CHANGE_CONTROL_POLICY = MappingProxyType({
    "schema_id": "SBP_LEX_V2_LIFECYCLE_CHANGE_CONTROL_V1",
    "authority_granted": False,
    "baseline_comparison_required": True,
    "reversibility_required": True,
    "release_requires_clean_tree": True,
    "change_classes": _CHANGE_CLASSES,
    "prohibited": (
        "authority_claim_from_repository_guard",
        "dirty_tree_release",
        "lock_hash_bypass",
        "rollback_plan_omission",
        "self_admitted_external_trust",
    ),
})
CHANGE_CONTROL_POLICY = _CANONICAL_CHANGE_CONTROL_POLICY
NO_AUTHORITY = MappingProxyType({
    "authority_granted": False,
    "decision_granted": False,
    "deployment_admitted": False,
    "effect_authority_granted": False,
    "execution_authority_granted": False,
    "publication_authority_granted": False,
    "release_admitted": False,
})

_LOCK_LINE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*)==(?P<version>[0-9]+(?:\.[0-9]+)+) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})$"
)


class RepositoryGuardError(RuntimeError):
    pass


def _normalise_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def _stable_bytes(root: Path, relative: str) -> bytes:
    before = measure_file(root, relative)
    try:
        content = resolve_safe_path(root, relative).read_bytes()
    except OSError as exc:
        raise RepositoryGuardError("critical_file_read_failed") from exc
    after = measure_file(root, relative)
    if (
        before != after
        or len(content) != before["size_bytes"]
        or sha512(content).hexdigest() != before["sha512"]
    ):
        raise RepositoryGuardError("critical_file_changed_during_read")
    return content


def _read_bounded_stream(
    stream: Any,
    target: bytearray,
    peer: bytearray,
    lock: threading.Lock,
    overflow: threading.Event,
    *,
    max_output_bytes: int,
) -> None:
    try:
        while not overflow.is_set():
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            with lock:
                if len(target) + len(peer) + len(chunk) > max_output_bytes:
                    overflow.set()
                    return
                target.extend(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _run_bounded(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
) -> tuple[int, bytes, bytes]:
    stdout = bytearray()
    stderr = bytearray()
    output_lock = threading.Lock()
    overflow = threading.Event()
    process: subprocess.Popen[bytes] | None = None
    windows_job: _WindowsCommandJob | None = None
    timed_out = False
    try:
        process = subprocess.Popen(
            arguments,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=env,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=_windows_creation_flags(),
        )
        try:
            windows_job = _WindowsCommandJob(process)
        except BaseException:
            process.kill()
            process.wait(timeout=5)
            raise
        if process.stdout is None or process.stderr is None:
            raise RepositoryGuardError("command_capture_stream_unavailable")
        readers = (
            threading.Thread(
                target=_read_bounded_stream,
                args=(process.stdout, stdout, stderr, output_lock, overflow),
                kwargs={"max_output_bytes": max_output_bytes},
                daemon=True,
            ),
            threading.Thread(
                target=_read_bounded_stream,
                args=(process.stderr, stderr, stdout, output_lock, overflow),
                kwargs={"max_output_bytes": max_output_bytes},
                daemon=True,
            ),
        )
        for reader in readers:
            reader.start()
        deadline = monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set() or monotonic() >= deadline:
                timed_out = not overflow.is_set()
                _terminate(process, windows_job)
                break
            overflow.wait(0.05)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(process, windows_job)
            process.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise RepositoryGuardError("command_capture_thread_not_closed")
        if overflow.is_set():
            raise RepositoryGuardError("command_output_limit")
        if monotonic() >= deadline:
            timed_out = True
        if timed_out:
            raise RepositoryGuardError("command_timeout")
        return process.returncode, bytes(stdout), bytes(stderr)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RepositoryGuardError("command_execution_failed") from exc
    finally:
        if process is not None and process.poll() is None:
            _terminate(process, windows_job)
        if windows_job is not None:
            windows_job.close()


def _git(runner: PinnedGit, root: Path, *arguments: str) -> bytes:
    try:
        return runner.run(root, *arguments, timeout_seconds=30)
    except SecureGitError as exc:
        raise RepositoryGuardError("git_command_failed") from exc


def _parse_lock(root: Path, relative: str) -> dict[str, tuple[str, str]]:
    try:
        text = _stable_bytes(root, relative).decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RepositoryGuardError("dependency_lock_encoding_invalid") from exc
    directives: list[str] = []
    packages: dict[str, tuple[str, str]] = {}
    ordered: list[str] = []
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        if raw.startswith("--"):
            directives.append(raw)
            continue
        matched = _LOCK_LINE.fullmatch(raw)
        if matched is None:
            raise RepositoryGuardError("dependency_lock_entry_invalid")
        name = matched.group("name")
        artifact_digest = matched.group("digest")
        if name in packages or len(set(artifact_digest)) < 8:
            raise RepositoryGuardError("dependency_lock_hash_or_duplicate_invalid")
        ordered.append(name)
        packages[name] = (matched.group("version"), artifact_digest)
    if directives != ["--only-binary=:all:", "--require-hashes"]:
        raise RepositoryGuardError("dependency_lock_directives_invalid")
    if ordered != sorted(ordered):
        raise RepositoryGuardError("dependency_lock_order_invalid")
    return packages


def _direct_requirements(root: Path) -> dict[str, str]:
    try:
        text = _stable_bytes(root, "requirements.txt").decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RepositoryGuardError("requirements_encoding_invalid") from exc
    result: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw or raw.startswith("#"):
            continue
        if raw.count("==") != 1:
            raise RepositoryGuardError("requirements_not_exactly_pinned")
        name, version = raw.split("==", maxsplit=1)
        identity = _normalise_name(name)
        if name != identity or identity in result or not version:
            raise RepositoryGuardError("requirements_invalid")
        result[identity] = version
    return result


def _python_dependency_lock_bound(
    root: Path,
    *,
    expected_ptde_accepted_attempt_history_sequence: int,
    expected_ptde_accepted_attempt_history_digest: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_digest: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> bool:
    try:
        requirements_content = _stable_bytes(root, "requirements.txt")
        production_hash_lock_content = _stable_bytes(
            root, "requirements-production.lock.txt"
        )
        assurance_hash_lock_content = _stable_bytes(
            root, "requirements-test.lock.txt"
        )
        lock = strict_load_json(
            resolve_safe_path(root, "python-dependencies.lock.json")
        )
        packages = lock.get("packages") if type(lock) is dict else None
        installed_packages: list[dict[str, str]] = []
        if type(packages) is list:
            for item in packages:
                if type(item) is dict:
                    name = item.get("name")
                    version = item.get("version")
                    if type(name) is str and type(version) is str:
                        installed_packages.append(
                            {"name": name, "version": version}
                        )
        evidence = _local_python_dependency_evidence(
            requirements_content,
            production_hash_lock_content,
            assurance_hash_lock_content,
            lock,
            installed_packages,
            expected_ptde_accepted_attempt_history_sequence=(
                expected_ptde_accepted_attempt_history_sequence
            ),
            expected_ptde_accepted_attempt_history_digest=(
                expected_ptde_accepted_attempt_history_digest
            ),
            expected_local_trust_accepted_package_history_sequence=(
                expected_local_trust_accepted_package_history_sequence
            ),
            expected_local_trust_accepted_package_history_digest=(
                expected_local_trust_accepted_package_history_digest
            ),
            expected_python_dependency_prior_lock_sha512=(
                expected_python_dependency_prior_lock_sha512
            ),
        )
        return evidence.get("dependency_evidence_status") == "COMPLETE"
    except (LocalTrustPathError, OSError, TypeError, ValueError):
        return False


def _installed_versions() -> dict[str, str]:
    result: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        raw_name = distribution.metadata.get("Name")
        if type(raw_name) is not str or not raw_name or not distribution.version:
            continue
        name = _normalise_name(raw_name)
        if name in BOOTSTRAP_PACKAGES:
            continue
        if name in result:
            raise RepositoryGuardError("installed_package_duplicate")
        result[name] = distribution.version
    return result


def _pip_check(root: Path) -> bool:
    del root
    executable = Path(sys.executable).resolve(strict=True)
    try:
        return_code, _stdout, _stderr = _run_bounded(
            (str(executable), "-I", "-m", "pip", "check"),
            cwd=executable.parent,
            env={
                "PATH": "",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONSAFEPATH": "1",
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "WINDIR": os.environ.get("WINDIR", ""),
            },
            timeout_seconds=60,
        )
    except RepositoryGuardError:
        return False
    return return_code == 0


def _change_control_valid() -> bool:
    return CHANGE_CONTROL_POLICY == _CANONICAL_CHANGE_CONTROL_POLICY


def change_control_policy_document() -> dict[str, Any]:
    """Return a detached JSON-safe copy of the immutable lifecycle policy."""

    return {
        "schema_id": _CANONICAL_CHANGE_CONTROL_POLICY["schema_id"],
        "authority_granted": False,
        "baseline_comparison_required": True,
        "reversibility_required": True,
        "release_requires_clean_tree": True,
        "change_classes": {
            name: {
                "required_checks": list(
                    cast(tuple[str, ...], value["required_checks"])
                ),
                "rollback_plan_required": True,
            }
            for name, value in _CHANGE_CLASSES.items()
        },
        "prohibited": list(
            cast(tuple[str, ...], _CANONICAL_CHANGE_CONTROL_POLICY["prohibited"])
        ),
    }


def _tracked_inventory(
    root: Path, runner: PinnedGit
) -> tuple[str, list[dict[str, Any]]]:
    commit_oid = _git(
        runner, root, "rev-parse", "--verify", "HEAD"
    ).decode("ascii").strip()
    if len(commit_oid) != 40 or re.fullmatch(r"[0-9a-f]{40}", commit_oid) is None:
        raise RepositoryGuardError("commit_oid_invalid")
    if _git(runner, root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RepositoryGuardError("critical_inventory_worktree_not_clean")
    raw_paths = _git(runner, root, "ls-files", "-z")
    paths = sorted(
        item.decode("utf-8", errors="strict")
        for item in raw_paths.split(b"\0")
        if item
    )
    if (
        len(paths) > MAX_TRACKED_PATHS
        or sum(len(path.encode("utf-8")) for path in paths)
        > MAX_COMMAND_OUTPUT_BYTES
    ):
        raise RepositoryGuardError("critical_inventory_path_limit")
    required_paths = REQUIRED_CRITICAL_FILES | frozenset(DEPENDENCY_LOCK_PATHS)
    if (
        not required_paths.issubset(paths)
        or any("\n" in path or "\r" in path for path in paths)
        or not any(
        path.startswith("sbp_lex/") and path.endswith(".py") for path in paths
        )
        or not any(path.startswith("tests/") for path in paths)
        or not any(path.startswith("tools/") for path in paths)
        or not any(path.endswith("Cargo.toml") for path in paths)
        or not any(path.startswith("formal/tla/") for path in paths)
        or not any(path.startswith("spark_safety_monitor/") for path in paths)
    ):
        raise RepositoryGuardError("critical_inventory_incomplete")
    tree_output = _git(runner, root, "ls-tree", "-r", "-z", "HEAD")
    tree_entries: dict[str, tuple[str, str]] = {}
    for item in tree_output.split(b"\0"):
        if not item:
            continue
        metadata, raw_path = item.split(b"\t", maxsplit=1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="strict")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise RepositoryGuardError("critical_inventory_mode_invalid")
        tree_entries[path] = (mode, oid)
    if set(tree_entries) != set(paths):
        raise RepositoryGuardError("critical_inventory_tree_mismatch")
    inventory: list[dict[str, Any]] = []
    inventory_bytes = 0
    for path in paths:
        content = _stable_bytes(root, path)
        inventory_bytes += len(content)
        if inventory_bytes > MAX_TRACKED_INVENTORY_BYTES:
            raise RepositoryGuardError("critical_inventory_byte_limit")
        mode, blob_oid = tree_entries[path]
        inventory.append(
            {
                "path": path,
                "bytes": len(content),
                "git_mode": mode,
                "git_blob_oid": blob_oid,
                "sha512": sha512(content).hexdigest(),
            }
        )
    if _git(runner, root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise RepositoryGuardError("critical_inventory_changed_during_measurement")
    return commit_oid, inventory


def verify_repository_guard(
    repository_root: str | Path,
    *,
    expected_ptde_accepted_attempt_history_sequence: int,
    expected_ptde_accepted_attempt_history_digest: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_digest: str,
    expected_python_dependency_prior_lock_sha512: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    scope: str = "test",
) -> dict[str, Any]:
    failures: list[str] = []
    checks: dict[str, bool] = {}
    commit_oid: str | None = None
    inventory: list[dict[str, Any]] = []
    git_sha512: str | None = None
    runner: PinnedGit | None = None
    try:
        root = validated_root(repository_root)
    except LocalTrustPathError:
        root = Path(repository_root)
        failures.append("repository_root_not_safe")
    try:
        runner = PinnedGit(git_executable, expected_git_executable_sha512)
        git_sha512 = runner.executable_sha512
        checks["git_executable_measured"] = True
    except SecureGitError:
        checks["git_executable_measured"] = False
        failures.append("git_executable_not_measured_or_pinned")
    try:
        if runner is None:
            raise RepositoryGuardError("git_executable_not_pinned")
        status = _git(
            runner, root, "status", "--porcelain=v1", "--untracked-files=all"
        ).decode(
            "utf-8", errors="strict"
        )
        checks["working_tree_clean"] = status == ""
        if status:
            failures.append("working_tree_not_clean")
            if any(line.startswith("?? ") for line in status.splitlines()):
                failures.append("untracked_files_present")
    except (RepositoryGuardError, UnicodeError):
        checks["working_tree_clean"] = False
        failures.append("working_tree_status_unavailable")
    try:
        if runner is None:
            raise RepositoryGuardError("git_executable_not_pinned")
        commit_oid, inventory = _tracked_inventory(root, runner)
        checks["critical_inventory_matches_commit"] = True
    except (RepositoryGuardError, UnicodeError, LocalTrustPathError) as error:
        checks["critical_inventory_matches_commit"] = False
        failures.append("critical_inventory_not_bound_to_commit")
        failures.append(str(error) or type(error).__name__)
    try:
        runtime_record = _stable_bytes(root, "runtime.txt").decode("ascii", errors="strict").strip()
        checks["known_good_runtime"] = (
            runtime_record == EXPECTED_RUNTIME_RECORD
            and sys.implementation.name == "cpython"
            and sys.version_info[:3] == (3, 12, 13)
        )
    except (RepositoryGuardError, UnicodeError, LocalTrustPathError):
        checks["known_good_runtime"] = False
    if not checks["known_good_runtime"]:
        failures.append("known_good_runtime_mismatch")
    try:
        production = _parse_lock(root, "requirements-production.lock.txt")
        test = _parse_lock(root, "requirements-test.lock.txt")
        production_versions = {name: value[0] for name, value in production.items()}
        test_versions = {name: value[0] for name, value in test.items()}
        checks["dependency_locks"] = (
            _direct_requirements(root) == DIRECT_REQUIREMENTS
            and production_versions == PRODUCTION_PACKAGES
            and test_versions == TEST_PACKAGES
            and all(test[name] == value for name, value in production.items())
        )
    except (RepositoryGuardError, UnicodeError, LocalTrustPathError):
        checks["dependency_locks"] = False
    if not checks["dependency_locks"]:
        failures.append("dependency_lock_validation_failed")
    checks["governed_python_lock_binding"] = _python_dependency_lock_bound(
        root,
        expected_ptde_accepted_attempt_history_sequence=(
            expected_ptde_accepted_attempt_history_sequence
        ),
        expected_ptde_accepted_attempt_history_digest=(
            expected_ptde_accepted_attempt_history_digest
        ),
        expected_local_trust_accepted_package_history_sequence=(
            expected_local_trust_accepted_package_history_sequence
        ),
        expected_local_trust_accepted_package_history_digest=(
            expected_local_trust_accepted_package_history_digest
        ),
        expected_python_dependency_prior_lock_sha512=(
            expected_python_dependency_prior_lock_sha512
        ),
    )
    if not checks["governed_python_lock_binding"]:
        failures.append("governed_python_lock_binding_invalid")
    expected_environment = TEST_PACKAGES if scope == "test" else PRODUCTION_PACKAGES
    if scope not in {"production", "test"}:
        checks["installed_environment"] = False
        failures.append("verification_scope_invalid")
    else:
        try:
            checks["installed_environment"] = (
                _installed_versions() == expected_environment and _pip_check(root)
            )
        except RepositoryGuardError:
            checks["installed_environment"] = False
        if not checks["installed_environment"]:
            failures.append("installed_environment_not_exact_lock_closure")
    checks["lifecycle_change_control"] = _change_control_valid()
    if not checks["lifecycle_change_control"]:
        failures.append("lifecycle_change_control_invalid")
    return {
        "schema_id": GUARD_SCHEMA,
        "status": "PASS" if not failures and all(checks.values()) else "FAIL",
        "repository_root": str(root),
        "commit_oid": commit_oid,
        "critical_inventory": inventory,
        "critical_inventory_sha512": digest(inventory) if inventory else None,
        "git_executable_sha512": git_sha512,
        "python_implementation": EXPECTED_IMPLEMENTATION,
        "python_version": EXPECTED_PYTHON_VERSION,
        "verification_scope": scope,
        "checks": checks,
        "failures": sorted(set(failures)),
        "change_control_policy_sha512": digest(change_control_policy_document()),
        "accepted_history_created": False,
        "self_referential_hash_manifest_created": False,
        "no_authority": dict(NO_AUTHORITY),
    }


__all__ = [
    "CHANGE_CONTROL_POLICY",
    "GUARD_SCHEMA",
    "RepositoryGuardError",
    "change_control_policy_document",
    "verify_repository_guard",
]
