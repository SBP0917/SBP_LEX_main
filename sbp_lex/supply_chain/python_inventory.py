"""Fail-closed Python dependency evidence derived only from committed P blobs."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from sbp_ptde.canonical import (
    canonical_sha512,
    exact_fields,
    positive_int,
    require_sha512,
    strict_json_document,
)
from sbp_ptde.errors import PTDEVerificationError, reject

from .source_binding import PObjectBinding, p_blob_content

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EXACT_REQUIREMENT = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?)$"
)
_EXACT_VERSION = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*(?:(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?(?:\+[a-z0-9]+(?:[._-][a-z0-9]+)*)?$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HASH_LOCK_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^ ]+) "
    r"--hash=(?P<hash>sha256:[0-9a-f]{64})$"
)

PYTHON_REQUIREMENTS_PATH = "requirements.txt"
PYTHON_PRODUCTION_HASH_LOCK_PATH = "requirements-production.lock.txt"
PYTHON_ASSURANCE_HASH_LOCK_PATH = "requirements-test.lock.txt"
PYTHON_LOCK_PATH = "python-dependencies.lock.json"
PYTHON_LOCK_SCHEMA = "sbp.lex.v2.python-dependency-lock/3"
PYTHON_LOCK_VALID = "COMMITTED_LOCK_VALID"
PYTHON_LOCK_INVALID = "COMMITTED_LOCK_INVALID"
PYTHON_LOCK_MISSING = "COMMITTED_LOCK_MISSING"

_LOCK_FIELDS = frozenset({
    "schema_id",
    "lock_sequence",
    "prior_lock_sha512",
    "requirements_sha512",
    "production_hash_lock_sha512",
    "assurance_hash_lock_sha512",
    "target_environment",
    "rollback_guard",
    "packages",
})
_ENVIRONMENT_FIELDS = frozenset({
    "implementation",
    "python_version",
    "abi_tag",
    "platform_tag",
    "installed_scope",
})
_ROLLBACK_FIELDS = frozenset({
    "ptde_accepted_attempt_history_sequence",
    "ptde_accepted_attempt_history_sha512",
    "local_trust_accepted_package_history_sequence",
    "local_trust_accepted_package_history_sha512",
})
_PACKAGE_FIELDS = frozenset({
    "name",
    "version",
    "hashes",
    "scopes",
    "direct_scopes",
    "dependencies",
})
_SCOPES = ("assurance", "production")
_ASSURANCE_DIRECT_REQUIREMENTS = frozenset({"pytest"})
GOVERNED_PYTHON_ENVIRONMENT = MappingProxyType({
    "implementation": "CPython",
    "python_version": "3.12.13",
    "abi_tag": "cpython-312",
    "platform_tag": "win-amd64",
    "installed_scope": "assurance",
})


def _normalize_name(value: str) -> str:
    if type(value) is not str or _NAME.fullmatch(value) is None:
        raise reject("SUPPLY_CHAIN_PYTHON_REQUIREMENT_INVALID")
    return re.sub(r"[-_.]+", "-", value).casefold()


def _parse_requirement(line: str) -> dict[str, str]:
    matched = _EXACT_REQUIREMENT.fullmatch(line)
    if matched is None:
        raise reject("SUPPLY_CHAIN_PYTHON_REQUIREMENT_INVALID")
    return {
        "identity": _normalize_name(matched.group("name")),
        "version": matched.group("version"),
        "source_requirement": line,
    }


def _parse_requirements(content: bytes) -> tuple[list[dict[str, str]], list[str]]:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError:
        return [], ["SUPPLY_CHAIN_PYTHON_REQUIREMENTS_ENCODING_INVALID"]
    requirements: list[dict[str, str]] = []
    failures: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = _parse_requirement(line)
        except PTDEVerificationError as error:
            failures.append(error.code)
            continue
        if parsed["identity"] in seen:
            failures.append(
                "SUPPLY_CHAIN_PYTHON_REQUIREMENT_DUPLICATE_OR_CASE_VARIANT"
            )
            continue
        seen.add(parsed["identity"])
        requirements.append(parsed)
    if not requirements:
        failures.append("SUPPLY_CHAIN_PYTHON_REQUIREMENTS_EMPTY")
    requirements.sort(key=lambda item: item["identity"])
    return requirements, sorted(set(failures))


def _parse_hash_lock(
    content: bytes,
    *,
    label: str,
) -> dict[str, dict[str, Any]]:
    try:
        lines = content.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise reject(
            f"SUPPLY_CHAIN_PYTHON_{label}_HASH_LOCK_ENCODING_INVALID"
        ) from exc
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
        try:
            identity = _normalize_name(matched.group("name")) if matched else None
        except PTDEVerificationError as exc:
            raise reject(
                f"SUPPLY_CHAIN_PYTHON_{label}_HASH_LOCK_ENTRY_INVALID"
            ) from exc
        if (
            matched is None
            or identity is None
            or matched.group("name") != identity
            or identity in packages
            or _EXACT_VERSION.fullmatch(matched.group("version")) is None
        ):
            raise reject(
                f"SUPPLY_CHAIN_PYTHON_{label}_HASH_LOCK_ENTRY_INVALID"
            )
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
        raise reject(f"SUPPLY_CHAIN_PYTHON_{label}_HASH_LOCK_POLICY_INVALID")
    return packages


def _require_text(value: Any, *, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise reject(code)
    return value


def _validate_target_environment(
    value: Any,
    *,
    expected_environment: Mapping[str, str],
) -> dict[str, str]:
    environment = exact_fields(
        value,
        _ENVIRONMENT_FIELDS,
        code="SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT",
    )
    for field in ("implementation", "abi_tag", "platform_tag"):
        text = _require_text(
            environment[field],
            code="SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID",
        )
        if _NAME.fullmatch(text) is None:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID")
    if (
        type(environment["python_version"]) is not str
        or _EXACT_VERSION.fullmatch(environment["python_version"]) is None
        or environment["installed_scope"] != "assurance"
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID")
    if (
        not isinstance(expected_environment, Mapping)
        or dict(expected_environment) != GOVERNED_PYTHON_ENVIRONMENT
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_ENVIRONMENT_INVALID")
    if environment != dict(expected_environment):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_MISMATCH")
    return environment


def _validate_package(value: Any) -> dict[str, Any]:
    package = exact_fields(
        value,
        _PACKAGE_FIELDS,
        code="SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE",
    )
    identity = _normalize_name(package["name"])
    if package["name"] != identity:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_CASE_VARIANT")
    if (
        type(package["version"]) is not str
        or _EXACT_VERSION.fullmatch(package["version"]) is None
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_UNPINNED")
    hashes = package["hashes"]
    if (
        type(hashes) is not list
        or not hashes
        or any(
            type(item) is not str or _SHA256.fullmatch(item) is None
            for item in hashes
        )
        or hashes != sorted(hashes)
        or len(hashes) != len(set(hashes))
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_UNHASHED_OR_DUPLICATE")
    scopes = package["scopes"]
    if (
        type(scopes) is not list
        or not scopes
        or any(scope not in _SCOPES for scope in scopes)
        or scopes != sorted(scopes)
        or len(scopes) != len(set(scopes))
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_SCOPE_INVALID")
    direct_scopes = package["direct_scopes"]
    if (
        type(direct_scopes) is not list
        or any(scope not in scopes for scope in direct_scopes)
        or direct_scopes != sorted(direct_scopes)
        or len(direct_scopes) != len(set(direct_scopes))
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_DIRECT_SCOPES_INVALID")
    dependencies = package["dependencies"]
    if type(dependencies) is not list:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DEPENDENCIES_INVALID")
    normalized_dependencies: list[str] = []
    for dependency in dependencies:
        normalized = _normalize_name(dependency)
        if dependency != normalized:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DEPENDENCY_CASE_VARIANT")
        normalized_dependencies.append(normalized)
    if (
        normalized_dependencies != sorted(normalized_dependencies)
        or len(normalized_dependencies) != len(set(normalized_dependencies))
        or identity in normalized_dependencies
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DEPENDENCIES_DUPLICATE_OR_CYCLIC")
    return package


def validate_python_lock_document(
    value: Any,
    *,
    requirements: list[dict[str, str]],
    production_hash_lock_content: bytes,
    assurance_hash_lock_content: bytes,
    expected_environment: Mapping[str, str],
    expected_ptde_accepted_attempt_history_sequence: int,
    expected_ptde_accepted_attempt_history_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> dict[str, Any]:
    """Validate the sole governed /3 lock contract without granting authority."""

    production_hash_lock = _parse_hash_lock(
        production_hash_lock_content,
        label="PRODUCTION",
    )
    assurance_hash_lock = _parse_hash_lock(
        assurance_hash_lock_content,
        label="ASSURANCE",
    )
    lock = exact_fields(value, _LOCK_FIELDS, code="SUPPLY_CHAIN_PYTHON_LOCK")
    if lock["schema_id"] != PYTHON_LOCK_SCHEMA:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_SCHEMA_INVALID")
    lock_sequence = positive_int(
        lock["lock_sequence"],
        code="SUPPLY_CHAIN_PYTHON_LOCK_SEQUENCE_INVALID",
    )
    if lock["requirements_sha512"] != canonical_sha512(requirements):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_REQUIREMENTS_MISMATCH")
    if (
        lock["production_hash_lock_sha512"]
        != hashlib.sha512(production_hash_lock_content).hexdigest()
        or lock["assurance_hash_lock_sha512"]
        != hashlib.sha512(assurance_hash_lock_content).hexdigest()
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_HASH_LOCK_BINDING_MISMATCH")
    _validate_target_environment(
        lock["target_environment"],
        expected_environment=expected_environment,
    )
    rollback = exact_fields(
        lock["rollback_guard"],
        _ROLLBACK_FIELDS,
        code="SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_GUARD",
    )
    ptde_sequence = rollback["ptde_accepted_attempt_history_sequence"]
    local_trust_sequence = rollback[
        "local_trust_accepted_package_history_sequence"
    ]
    if (
        type(ptde_sequence) is not int
        or ptde_sequence < 0
        or type(local_trust_sequence) is not int
        or local_trust_sequence < 0
        or type(expected_ptde_accepted_attempt_history_sequence) is not int
        or expected_ptde_accepted_attempt_history_sequence < 0
        or type(expected_local_trust_accepted_package_history_sequence) is not int
        or expected_local_trust_accepted_package_history_sequence < 0
        or ptde_sequence
        != expected_ptde_accepted_attempt_history_sequence
        or local_trust_sequence
        != expected_local_trust_accepted_package_history_sequence
        or lock_sequence != ptde_sequence + local_trust_sequence + 1
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_SEQUENCE_MISMATCH")
    prior = lock["prior_lock_sha512"]
    genesis = ptde_sequence == 0 and local_trust_sequence == 0
    if genesis:
        if (
            expected_python_dependency_prior_lock_sha512 != "GENESIS"
            or prior != "GENESIS"
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID")
    else:
        expected_prior = require_sha512(
            expected_python_dependency_prior_lock_sha512,
            "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_PRIOR_INVALID",
        )
        actual_prior = require_sha512(
            prior,
            "SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID",
        )
        if actual_prior != expected_prior:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PRIOR_MISMATCH")
    ptde_history_sha512 = require_sha512(
        rollback["ptde_accepted_attempt_history_sha512"],
        "SUPPLY_CHAIN_PYTHON_LOCK_PTDE_HISTORY_INVALID",
    )
    local_trust_history_sha512 = require_sha512(
        rollback["local_trust_accepted_package_history_sha512"],
        "SUPPLY_CHAIN_PYTHON_LOCK_LOCAL_TRUST_HISTORY_INVALID",
    )
    expected_ptde_history = require_sha512(
        expected_ptde_accepted_attempt_history_sha512,
        "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_PTDE_HISTORY_INVALID",
    )
    expected_local_trust_history = require_sha512(
        expected_local_trust_accepted_package_history_sha512,
        "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_LOCAL_TRUST_HISTORY_INVALID",
    )
    if ptde_history_sha512 != expected_ptde_history:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PTDE_HISTORY_MISMATCH")
    if local_trust_history_sha512 != expected_local_trust_history:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_LOCAL_TRUST_HISTORY_MISMATCH")
    if ptde_history_sha512 == local_trust_history_sha512:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_HISTORY_LANES_NOT_INDEPENDENT")

    packages_raw = lock["packages"]
    if type(packages_raw) is not list or not packages_raw:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGES_INVALID")
    packages = [_validate_package(item) for item in packages_raw]
    identities = [item["name"] for item in packages]
    if identities != sorted(identities) or len(identities) != len(set(identities)):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_DUPLICATE_OR_CASE_VARIANT")
    by_identity = {item["name"]: item for item in packages}
    if any(
        dependency not in by_identity
        for package in packages
        for dependency in package["dependencies"]
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DEPENDENCY_MISSING")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(identity: str) -> None:
        if identity in visiting:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DEPENDENCY_CYCLE")
        if identity in visited:
            return
        visiting.add(identity)
        for dependency in by_identity[identity]["dependencies"]:
            visit(dependency)
        visiting.remove(identity)
        visited.add(identity)

    for identity in identities:
        visit(identity)

    expected_production_direct = {
        item["identity"]: item["version"] for item in requirements
    }
    if not _ASSURANCE_DIRECT_REQUIREMENTS.issubset(assurance_hash_lock):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DIRECT_REQUIREMENTS_MISMATCH")
    expected_assurance_direct = {
        **expected_production_direct,
        **{
            name: assurance_hash_lock[name]["version"]
            for name in _ASSURANCE_DIRECT_REQUIREMENTS
        },
    }
    actual_direct_by_scope = {
        scope: {
            item["name"]: item["version"]
            for item in packages
            if scope in item["direct_scopes"]
        }
        for scope in _SCOPES
    }
    if (
        expected_production_direct != actual_direct_by_scope["production"]
        or expected_assurance_direct != actual_direct_by_scope["assurance"]
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DIRECT_REQUIREMENTS_MISMATCH")

    for scope, expected_hash_lock in (
        ("production", production_hash_lock),
        ("assurance", assurance_hash_lock),
    ):
        scoped = {
            item["name"]: item for item in packages if scope in item["scopes"]
        }
        if set(scoped) != set(expected_hash_lock):
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_SCOPE_CLOSURE_MISMATCH")
        for name, item in scoped.items():
            if (
                item["version"] != expected_hash_lock[name]["version"]
                or item["hashes"] != expected_hash_lock[name]["hashes"]
                or any(
                    dependency not in scoped for dependency in item["dependencies"]
                )
            ):
                raise reject("SUPPLY_CHAIN_PYTHON_LOCK_SCOPE_PACKAGE_MISMATCH")
        reachable = set(actual_direct_by_scope[scope])
        pending = list(reachable)
        while pending:
            for dependency in scoped[pending.pop()]["dependencies"]:
                if dependency not in reachable:
                    reachable.add(dependency)
                    pending.append(dependency)
        if reachable != set(scoped):
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_EXTRA_PACKAGE")
    return lock


def evaluate_python_dependency_evidence(
    requirements_content: bytes,
    production_hash_lock_content: bytes | None,
    assurance_hash_lock_content: bytes | None,
    lock_document: Any | None,
    *,
    expected_environment: Mapping[str, str],
    expected_ptde_accepted_attempt_history_sequence: int,
    expected_ptde_accepted_attempt_history_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> dict[str, Any]:
    requirements, failures = _parse_requirements(requirements_content)
    requirement_failures = list(failures)
    if production_hash_lock_content is None:
        failures.append("SUPPLY_CHAIN_PYTHON_PRODUCTION_HASH_LOCK_MISSING")
    if assurance_hash_lock_content is None:
        failures.append("SUPPLY_CHAIN_PYTHON_ASSURANCE_HASH_LOCK_MISSING")
    production_hash_lock_sha512 = (
        hashlib.sha512(production_hash_lock_content).hexdigest()
        if production_hash_lock_content is not None
        else None
    )
    assurance_hash_lock_sha512 = (
        hashlib.sha512(assurance_hash_lock_content).hexdigest()
        if assurance_hash_lock_content is not None
        else None
    )
    if lock_document is None:
        failures.append("SUPPLY_CHAIN_PYTHON_LOCK_MISSING")
        lock_status = PYTHON_LOCK_MISSING
    elif failures:
        lock_status = PYTHON_LOCK_INVALID
    else:
        try:
            if (
                production_hash_lock_content is None
                or assurance_hash_lock_content is None
            ):
                raise reject("SUPPLY_CHAIN_PYTHON_HASH_LOCK_MISSING")
            validate_python_lock_document(
                lock_document,
                requirements=requirements,
                production_hash_lock_content=production_hash_lock_content,
                assurance_hash_lock_content=assurance_hash_lock_content,
                expected_environment=expected_environment,
                expected_ptde_accepted_attempt_history_sequence=(
                    expected_ptde_accepted_attempt_history_sequence
                ),
                expected_ptde_accepted_attempt_history_sha512=(
                    expected_ptde_accepted_attempt_history_sha512
                ),
                expected_local_trust_accepted_package_history_sequence=(
                    expected_local_trust_accepted_package_history_sequence
                ),
                expected_local_trust_accepted_package_history_sha512=(
                    expected_local_trust_accepted_package_history_sha512
                ),
                expected_python_dependency_prior_lock_sha512=(
                    expected_python_dependency_prior_lock_sha512
                ),
            )
            lock_status = PYTHON_LOCK_VALID
        except PTDEVerificationError as error:
            failures.append(error.code)
            lock_status = PYTHON_LOCK_INVALID
    return {
        "requirements": requirements,
        "requirements_sha512": canonical_sha512(requirements),
        "production_hash_lock_path": PYTHON_PRODUCTION_HASH_LOCK_PATH,
        "production_hash_lock_sha512": production_hash_lock_sha512,
        "assurance_hash_lock_path": PYTHON_ASSURANCE_HASH_LOCK_PATH,
        "assurance_hash_lock_sha512": assurance_hash_lock_sha512,
        "requirements_status": (
            "EXACTLY_PINNED" if not requirement_failures else "INVALID_OR_UNPINNED"
        ),
        "lock_path": PYTHON_LOCK_PATH,
        "lock_status": lock_status,
        "lock_failures": sorted(set(failures)),
        "dependency_evidence_status": (
            "COMPLETE" if lock_status == PYTHON_LOCK_VALID else "INCOMPLETE"
        ),
        "runtime_attachment": "NONE",
        "authority_granted": False,
    }


def _committed_blob_input(
    binding: PObjectBinding,
    path: str,
    *,
    label: str,
) -> tuple[dict[str, Any] | None, bytes | None, str | None]:
    matches = [
        candidate
        for candidate in binding.tree
        if candidate.casefold() == path.casefold()
    ]
    if matches == [path]:
        return binding.tree[path].record(), p_blob_content(binding, path), None
    if matches:
        return (
            None,
            None,
            f"SUPPLY_CHAIN_PYTHON_{label}_PATH_CASE_VARIANT_OR_DUPLICATE",
        )
    return None, None, f"SUPPLY_CHAIN_PYTHON_{label}_MISSING"


def build_python_dependency_inputs(binding: PObjectBinding) -> dict[str, Any]:
    """Bind the governed /3 lock and both exact hash locks to immutable P."""

    requirements_content = p_blob_content(binding, PYTHON_REQUIREMENTS_PATH)
    requirements_record = binding.tree[PYTHON_REQUIREMENTS_PATH].record()
    production_record, production_content, production_failure = _committed_blob_input(
        binding,
        PYTHON_PRODUCTION_HASH_LOCK_PATH,
        label="PRODUCTION_HASH_LOCK",
    )
    assurance_record, assurance_content, assurance_failure = _committed_blob_input(
        binding,
        PYTHON_ASSURANCE_HASH_LOCK_PATH,
        label="ASSURANCE_HASH_LOCK",
    )
    lock_record, lock_content, lock_failure = _committed_blob_input(
        binding,
        PYTHON_LOCK_PATH,
        label="LOCK",
    )
    lock_document: dict[str, Any] | None = None
    if lock_content is not None:
        try:
            lock_document = strict_json_document(
                lock_content,
                code="SUPPLY_CHAIN_PYTHON_LOCK",
            )
        except PTDEVerificationError as error:
            lock_failure = error.code
    evidence = evaluate_python_dependency_evidence(
        requirements_content,
        production_content,
        assurance_content,
        lock_document,
        expected_environment=GOVERNED_PYTHON_ENVIRONMENT,
        expected_ptde_accepted_attempt_history_sequence=(
            binding.ptde_accepted_attempt_history.sequence
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            binding.expected_ptde_accepted_attempt_history_sha512
        ),
        expected_local_trust_accepted_package_history_sequence=(
            binding.expected_local_trust_accepted_package_history_sequence
        ),
        expected_local_trust_accepted_package_history_sha512=(
            binding.expected_local_trust_accepted_package_history_sha512
        ),
        expected_python_dependency_prior_lock_sha512=(
            binding.expected_python_dependency_prior_lock_sha512
        ),
    )
    path_failures = {
        failure
        for failure in (production_failure, assurance_failure, lock_failure)
        if failure is not None
    }
    if path_failures:
        evidence["lock_status"] = (
            PYTHON_LOCK_MISSING
            if lock_record is None
            else PYTHON_LOCK_INVALID
        )
        evidence["dependency_evidence_status"] = "INCOMPLETE"
        evidence["lock_failures"] = sorted(
            {*evidence["lock_failures"], *path_failures}
        )
    payload = {
        "schema_id": "sbp.lex.v2.supply-chain.python-inputs/2",
        "p_commit_oid": binding.commit.oid,
        "requirements_blob": requirements_record,
        "production_hash_lock_blob": production_record,
        "assurance_hash_lock_blob": assurance_record,
        "python_lock_blob": lock_record,
        **evidence,
        "host_distribution_observation": "REQUIRES_DECLARED_T_OR_E_LANE",
        "network_access": "NOT_USED",
    }
    payload["payload_sha512"] = canonical_sha512(payload)
    return payload


__all__ = [
    "GOVERNED_PYTHON_ENVIRONMENT",
    "PYTHON_ASSURANCE_HASH_LOCK_PATH",
    "PYTHON_LOCK_INVALID",
    "PYTHON_LOCK_MISSING",
    "PYTHON_LOCK_PATH",
    "PYTHON_LOCK_SCHEMA",
    "PYTHON_LOCK_VALID",
    "PYTHON_PRODUCTION_HASH_LOCK_PATH",
    "build_python_dependency_inputs",
    "evaluate_python_dependency_evidence",
    "validate_python_lock_document",
]
