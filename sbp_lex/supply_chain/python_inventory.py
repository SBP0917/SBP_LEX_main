"""Fail-closed Python dependency evidence derived only from committed P blobs."""

from __future__ import annotations

import re
from typing import Any, Mapping

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

PYTHON_REQUIREMENTS_PATH = "requirements.txt"
PYTHON_LOCK_PATH = "python-dependencies.lock.json"
PYTHON_LOCK_SCHEMA = "sbp.lex.v2.python-dependency-lock/1"
PYTHON_LOCK_VALID = "COMMITTED_LOCK_VALID"
PYTHON_LOCK_INVALID = "COMMITTED_LOCK_INVALID"
PYTHON_LOCK_MISSING = "COMMITTED_LOCK_MISSING"

_LOCK_FIELDS = {
    "schema_id", "lock_sequence", "prior_lock_sha512", "requirements_sha512",
    "target_environment", "rollback_guard", "packages",
}
_ENVIRONMENT_FIELDS = {"implementation", "python_version", "abi_tag", "platform_tag"}
_ROLLBACK_FIELDS = {"accepted_attempt_history_sequence", "accepted_attempt_history_sha512"}
_PACKAGE_FIELDS = {"name", "version", "hashes", "scopes", "direct", "dependencies"}
_SCOPES = ("development", "production")


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
            failures.append("SUPPLY_CHAIN_PYTHON_REQUIREMENT_DUPLICATE_OR_CASE_VARIANT")
            continue
        seen.add(parsed["identity"])
        requirements.append(parsed)
    if not requirements:
        failures.append("SUPPLY_CHAIN_PYTHON_REQUIREMENTS_EMPTY")
    requirements.sort(key=lambda item: item["identity"])
    return requirements, sorted(set(failures))


def _require_text(value: Any, *, code: str) -> str:
    if type(value) is not str or not value or value.strip() != value:
        raise reject(code)
    return value


def _validate_target_environment(
    value: Any,
    *,
    expected_environment: Mapping[str, str] | None,
) -> dict[str, str]:
    environment = exact_fields(value, _ENVIRONMENT_FIELDS, code="SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT")
    for field in ("implementation", "abi_tag", "platform_tag"):
        text = _require_text(
            environment[field], code="SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID"
        )
        if _NAME.fullmatch(text) is None:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID")
    if (
        type(environment["python_version"]) is not str
        or _EXACT_VERSION.fullmatch(environment["python_version"]) is None
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_INVALID")
    if expected_environment is not None and environment != dict(expected_environment):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ENVIRONMENT_MISMATCH")
    return environment


def _validate_package(value: Any) -> dict[str, Any]:
    package = exact_fields(value, _PACKAGE_FIELDS, code="SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE")
    identity = _normalize_name(package["name"])
    if package["name"] != identity:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_CASE_VARIANT")
    if type(package["version"]) is not str or _EXACT_VERSION.fullmatch(package["version"]) is None:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_UNPINNED")
    hashes = package["hashes"]
    if (
        type(hashes) is not list
        or not hashes
        or any(type(item) is not str or _SHA256.fullmatch(item) is None for item in hashes)
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
    if type(package["direct"]) is not bool:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PACKAGE_DIRECT_INVALID")
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
    expected_environment: Mapping[str, str] | None = None,
    expected_history_sequence: int | None = None,
    expected_history_sha512: str | None = None,
) -> dict[str, Any]:
    """Validate resolver-neutral, canonical lock evidence without granting authority."""

    lock = exact_fields(value, _LOCK_FIELDS, code="SUPPLY_CHAIN_PYTHON_LOCK")
    if lock["schema_id"] != PYTHON_LOCK_SCHEMA:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_SCHEMA_INVALID")
    lock_sequence = positive_int(
        lock["lock_sequence"], code="SUPPLY_CHAIN_PYTHON_LOCK_SEQUENCE_INVALID"
    )
    prior = lock["prior_lock_sha512"]
    if lock_sequence == 1:
        if prior != "GENESIS":
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID")
    else:
        require_sha512(prior, "SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID")
    if lock["requirements_sha512"] != canonical_sha512(requirements):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_REQUIREMENTS_MISMATCH")
    _validate_target_environment(lock["target_environment"], expected_environment=expected_environment)
    rollback = exact_fields(
        lock["rollback_guard"], _ROLLBACK_FIELDS, code="SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_GUARD"
    )
    history_sequence = rollback["accepted_attempt_history_sequence"]
    if type(history_sequence) is not int or history_sequence < 0:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_SEQUENCE_INVALID")
    history_sha512 = require_sha512(
        rollback["accepted_attempt_history_sha512"],
        "SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_HISTORY_INVALID",
    )
    if lock_sequence != history_sequence + 1:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_SEQUENCE_MISMATCH")
    if expected_history_sequence is not None and history_sequence != expected_history_sequence:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_SEQUENCE_MISMATCH")
    if expected_history_sha512 is not None and history_sha512 != expected_history_sha512:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_HISTORY_MISMATCH")

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

    expected_direct = {item["identity"]: item["version"] for item in requirements}
    actual_direct = {
        item["name"]: item["version"] for item in packages if item["direct"]
    }
    if expected_direct != actual_direct or any(
        "production" not in item["scopes"] for item in packages if item["direct"]
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_DIRECT_REQUIREMENTS_MISMATCH")

    reachable = set(actual_direct)
    pending = list(actual_direct)
    while pending:
        for dependency in by_identity[pending.pop()]["dependencies"]:
            if dependency not in reachable:
                reachable.add(dependency)
                pending.append(dependency)
    if reachable != set(by_identity):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_EXTRA_PACKAGE")
    return lock


def evaluate_python_dependency_evidence(
    requirements_content: bytes,
    lock_document: Any | None,
    *,
    expected_environment: Mapping[str, str] | None = None,
    expected_history_sequence: int | None = None,
    expected_history_sha512: str | None = None,
) -> dict[str, Any]:
    requirements, failures = _parse_requirements(requirements_content)
    requirement_failures = list(failures)
    if lock_document is None:
        failures.append("SUPPLY_CHAIN_PYTHON_LOCK_MISSING")
        lock_status = PYTHON_LOCK_MISSING
    elif failures:
        lock_status = PYTHON_LOCK_INVALID
    else:
        try:
            validate_python_lock_document(
                lock_document,
                requirements=requirements,
                expected_environment=expected_environment,
                expected_history_sequence=expected_history_sequence,
                expected_history_sha512=expected_history_sha512,
            )
            lock_status = PYTHON_LOCK_VALID
        except PTDEVerificationError as error:
            failures.append(error.code)
            lock_status = PYTHON_LOCK_INVALID
    return {
        "requirements": requirements,
        "requirements_sha512": canonical_sha512(requirements),
        "requirements_status": "EXACTLY_PINNED" if not requirement_failures else "INVALID_OR_UNPINNED",
        "lock_path": PYTHON_LOCK_PATH,
        "lock_status": lock_status,
        "lock_failures": sorted(set(failures)),
        "dependency_evidence_status": "COMPLETE" if lock_status == PYTHON_LOCK_VALID else "INCOMPLETE",
        "runtime_attachment": "NONE",
        "authority_granted": False,
    }


def build_python_dependency_inputs(binding: PObjectBinding) -> dict[str, Any]:
    """Bind declarations and an explicit canonical lock artifact to immutable P."""

    content = p_blob_content(binding, PYTHON_REQUIREMENTS_PATH)
    requirement_record = binding.tree[PYTHON_REQUIREMENTS_PATH].record()
    matches = [path for path in binding.tree if path.casefold() == PYTHON_LOCK_PATH.casefold()]
    lock_record: dict[str, Any] | None = None
    lock_document: dict[str, Any] | None = None
    path_failure: str | None = None
    if matches == [PYTHON_LOCK_PATH]:
        lock_record = binding.tree[PYTHON_LOCK_PATH].record()
        try:
            lock_document = strict_json_document(
                p_blob_content(binding, PYTHON_LOCK_PATH), code="SUPPLY_CHAIN_PYTHON_LOCK"
            )
        except PTDEVerificationError as error:
            path_failure = error.code
    elif matches:
        path_failure = "SUPPLY_CHAIN_PYTHON_LOCK_PATH_CASE_VARIANT_OR_DUPLICATE"
    evidence = evaluate_python_dependency_evidence(
        content,
        lock_document,
        expected_history_sequence=binding.accepted_attempt_history.sequence,
        expected_history_sha512=binding.expected_attempt_history_sha512,
    )
    if path_failure is not None:
        evidence["lock_status"] = PYTHON_LOCK_INVALID
        evidence["dependency_evidence_status"] = "INCOMPLETE"
        evidence["lock_failures"] = sorted(set([*evidence["lock_failures"], path_failure]))
    payload = {
        "schema_id": "sbp.lex.v2.supply-chain.python-inputs/1",
        "p_commit_oid": binding.commit.oid,
        "requirements_blob": requirement_record,
        "python_lock_blob": lock_record,
        **evidence,
        "host_distribution_observation": "REQUIRES_DECLARED_T_OR_E_LANE",
        "network_access": "NOT_USED",
    }
    payload["payload_sha512"] = canonical_sha512(payload)
    return payload


__all__ = [
    "PYTHON_LOCK_INVALID", "PYTHON_LOCK_MISSING", "PYTHON_LOCK_PATH",
    "PYTHON_LOCK_SCHEMA", "PYTHON_LOCK_VALID", "build_python_dependency_inputs",
    "evaluate_python_dependency_evidence", "validate_python_lock_document",
]
