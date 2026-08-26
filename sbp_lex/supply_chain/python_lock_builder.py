"""Offline, deterministic builder for the governed Python dependency lock /3."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import stat
import struct
import sys
import sysconfig
import unicodedata
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.tags import sys_tags
from packaging.utils import (
    InvalidWheelFilename,
    canonicalize_name,
    parse_wheel_filename,
)

from sbp_ptde.canonical import (
    canonical_json_document_bytes,
    canonical_sha512,
    exact_fields,
    positive_int,
    require_sha512,
    strict_json_document,
)
from sbp_ptde.errors import PTDEVerificationError, reject

from .python_inventory import (
    _ASSURANCE_DIRECT_REQUIREMENTS,
    GOVERNED_PYTHON_ENVIRONMENT,
    PYTHON_LOCK_SCHEMA,
    _parse_hash_lock,
    _parse_requirements,
    validate_python_lock_document,
)

_MAX_WHEEL_BYTES = 268_435_456
_MAX_METADATA_BYTES = 16_777_216
_MAX_WHEEL_MEMBERS = 20_000
_MAX_WHEEL_CENTRAL_DIRECTORY_BYTES = 16_777_216
_MAX_WHEEL_MEMBER_NAME_BYTES = 4_096
_MAX_WHEEL_MEMBER_NAME_TOTAL_BYTES = 16_777_216
_MAX_WHEEL_COMMENT_BYTES = 1_024
_WINDOWS_REPARSE_POINT = 0x400
_ZIP_END_SIGNATURE = b"PK\x05\x06"
_ALLOWED_ZIP_COMPRESSION = frozenset(
    {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
)
_WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _is_reparse(value: os.stat_result) -> bool:
    return bool(getattr(value, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT)


def _require_safe_directory(path: Path, *, code: str) -> os.stat_result:
    try:
        supplied = path.lstat()
        if stat.S_ISLNK(supplied.st_mode) or _is_reparse(supplied):
            raise reject(code)
        resolved = path.resolve(strict=True)
        if (
            not path.is_absolute()
            or os.path.normcase(os.path.abspath(path))
            != os.path.normcase(str(resolved))
        ):
            raise reject(code)
        current = resolved
        while True:
            info = current.lstat()
            if _is_reparse(info) or stat.S_ISLNK(info.st_mode):
                raise reject(code)
            if current.parent == current:
                break
            current = current.parent
        info = resolved.lstat()
    except PTDEVerificationError:
        raise
    except OSError as exc:
        raise reject(code) from exc
    if not stat.S_ISDIR(info.st_mode):
        raise reject(code)
    return info


def _stable_read(path: Path, *, maximum: int, code: str) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > maximum
        ):
            raise reject(code)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise reject(code)
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, min(1_048_576, maximum + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > maximum:
                    raise reject(code)
        finally:
            os.close(descriptor)
        after = path.lstat()
    except PTDEVerificationError:
        raise
    except OSError as exc:
        raise reject(code) from exc
    if (
        (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        or len(b"".join(chunks)) != before.st_size
    ):
        raise reject(code)
    return b"".join(chunks)


def _host_environment() -> dict[str, str]:
    abi_tag = sys.implementation.cache_tag
    platform_tag = sysconfig.get_platform()
    if type(abi_tag) is not str or type(platform_tag) is not str:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_HOST_ENVIRONMENT_UNAVAILABLE")
    return {
        "implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "abi_tag": abi_tag,
        "platform_tag": platform_tag,
        "installed_scope": "assurance",
    }


def _marker_environment(expected: Mapping[str, str]) -> dict[str, str]:
    version = expected["python_version"]
    return {
        "implementation_name": "cpython",
        "implementation_version": version,
        "os_name": "nt",
        "platform_machine": "AMD64",
        "platform_python_implementation": expected["implementation"],
        "platform_release": "",
        "platform_system": "Windows",
        "platform_version": "",
        "python_full_version": version,
        "python_version": ".".join(version.split(".")[:2]),
        "sys_platform": "win32",
        "extra": "",
    }


def _metadata_dependencies(
    metadata: bytes,
    *,
    expected_name: str,
    expected_version: str,
    marker_environment: Mapping[str, str],
    locked_versions: Mapping[str, str],
) -> list[str]:
    if len(metadata) > _MAX_METADATA_BYTES:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_METADATA_TOO_LARGE")
    message = BytesParser().parsebytes(metadata, headersonly=True)
    name = message.get("Name")
    version = message.get("Version")
    if (
        type(name) is not str
        or canonicalize_name(name) != expected_name
        or version != expected_version
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_METADATA_IDENTITY_MISMATCH")
    requires_python = message.get("Requires-Python")
    if type(requires_python) is str:
        try:
            python_specifier = SpecifierSet(requires_python)
        except InvalidSpecifier as exc:
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_REQUIRES_PYTHON_INVALID") from exc
        if not python_specifier.contains(
            marker_environment["python_full_version"],
            prereleases=True,
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_REQUIRES_PYTHON_MISMATCH")
    dependencies: set[str] = set()
    for raw in message.get_all("Requires-Dist", []):
        try:
            requirement = Requirement(raw)
        except InvalidRequirement as exc:
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_DEPENDENCY_INVALID") from exc
        if requirement.url is not None or requirement.extras:
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_DEPENDENCY_INVALID")
        if requirement.marker is not None and not requirement.marker.evaluate(
            environment=dict(marker_environment)
        ):
            continue
        identity = canonicalize_name(requirement.name)
        locked_version = locked_versions.get(identity)
        if locked_version is None or not requirement.specifier.contains(
            locked_version,
            prereleases=True,
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_DEPENDENCY_UNSATISFIED")
        dependencies.add(identity)
    return sorted(dependencies)


def _preflight_wheel_zip(content: bytes) -> None:
    """Bound the central directory before ZipFile allocates member objects."""

    minimum = struct.calcsize("<4s4H2LH")
    if len(content) < minimum:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID")
    search_start = max(0, len(content) - (65_535 + minimum))
    end_offset = content.rfind(_ZIP_END_SIGNATURE, search_start)
    if end_offset < 0 or end_offset + minimum > len(content):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID")
    try:
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", content, end_offset)
    except struct.error as exc:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID") from exc
    if (
        signature != _ZIP_END_SIGNATURE
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or not 1 <= total_entries <= _MAX_WHEEL_MEMBERS
        or central_size > _MAX_WHEEL_CENTRAL_DIRECTORY_BYTES
        or comment_size > _MAX_WHEEL_COMMENT_BYTES
        or end_offset + minimum + comment_size != len(content)
        or central_offset + central_size != end_offset
        or total_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID")


def _wheel_member_valid(item: zipfile.ZipInfo) -> bool:
    name = item.filename
    encoded_name = name.encode("utf-8", errors="strict")
    canonical = name.removesuffix("/")
    path = PurePosixPath(canonical)
    unix_mode = (item.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(unix_mode) if unix_mode else 0
    safe_parts = bool(path.parts) and all(
        part not in {"", ".", ".."}
        and ":" not in part
        and not part.endswith((" ", "."))
        and part.split(".", maxsplit=1)[0].upper() not in _WINDOWS_DEVICE_NAMES
        for part in path.parts
    )
    return (
        bool(canonical)
        and len(encoded_name) <= _MAX_WHEEL_MEMBER_NAME_BYTES
        and unicodedata.normalize("NFC", name) == name
        and "\x00" not in name
        and "\\" not in name
        and not name.startswith("/")
        and canonical == path.as_posix()
        and safe_parts
        and item.compress_type in _ALLOWED_ZIP_COMPRESSION
        and not item.flag_bits & 0x1
        and file_type in {0, stat.S_IFREG, stat.S_IFDIR}
        and (not item.is_dir() or file_type in {0, stat.S_IFDIR})
        and (item.is_dir() or file_type in {0, stat.S_IFREG})
    )


def _read_wheel_record(
    path: Path,
    *,
    expected_name: str,
    expected_version: str,
    expected_hash: str,
    supported_tags: frozenset[Any],
    marker_environment: Mapping[str, str],
    locked_versions: Mapping[str, str],
) -> dict[str, Any]:
    content = _stable_read(
        path,
        maximum=_MAX_WHEEL_BYTES,
        code="SUPPLY_CHAIN_PYTHON_WHEEL_PATH_OR_CONTENT_INVALID",
    )
    actual_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
    if actual_hash != expected_hash:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_HASH_MISMATCH")
    _preflight_wheel_zip(content)
    try:
        wheel_name, wheel_version, _build, wheel_tags = parse_wheel_filename(path.name)
    except InvalidWheelFilename as exc:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_FILENAME_INVALID") from exc
    if (
        canonicalize_name(wheel_name) != expected_name
        or str(wheel_version) != expected_version
        or not supported_tags.intersection(wheel_tags)
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_TARGET_MISMATCH")
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            names = [item.filename for item in members]
            if (
                len(members) > _MAX_WHEEL_MEMBERS
                or len(names) != len(set(names))
                or len({name.casefold() for name in names}) != len(names)
                or sum(len(name.encode("utf-8")) for name in names)
                > _MAX_WHEEL_MEMBER_NAME_TOTAL_BYTES
                or any(not _wheel_member_valid(item) for item in members)
                or sum(item.file_size for item in members) > _MAX_WHEEL_BYTES
                or any(
                    item.file_size > _MAX_WHEEL_BYTES
                    or (item.compress_size == 0 and item.file_size > 0)
                    or item.file_size > max(item.compress_size * 200, 1_048_576)
                    for item in members
                )
            ):
                raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID")
            metadata_names = [
                item
                for item in archive.infolist()
                if item.filename.endswith(".dist-info/METADATA")
            ]
            wheel_names = [
                item
                for item in members
                if item.filename.endswith(".dist-info/WHEEL")
            ]
            if (
                len(metadata_names) != 1
                or len(wheel_names) != 1
                or metadata_names[0].is_dir()
                or wheel_names[0].is_dir()
                or metadata_names[0].file_size > _MAX_METADATA_BYTES
                or wheel_names[0].file_size > _MAX_METADATA_BYTES
                or metadata_names[0].flag_bits & 0x1
                or wheel_names[0].flag_bits & 0x1
                or metadata_names[0].filename.rsplit("/", 1)[0]
                != wheel_names[0].filename.rsplit("/", 1)[0]
            ):
                raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_METADATA_INVALID")
            metadata = b""
            wheel_metadata = b""
            observed_total = 0
            for item in members:
                if item.is_dir():
                    continue
                retained = (
                    item is metadata_names[0] or item is wheel_names[0]
                )
                chunks: list[bytes] = []
                observed_member = 0
                with archive.open(item, "r") as member_stream:
                    while True:
                        chunk = member_stream.read(65_536)
                        if not chunk:
                            break
                        observed_member += len(chunk)
                        observed_total += len(chunk)
                        if (
                            observed_member > item.file_size
                            or observed_total > _MAX_WHEEL_BYTES
                        ):
                            raise reject(
                                "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID"
                            )
                        if retained:
                            chunks.append(chunk)
                if observed_member != item.file_size:
                    raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID")
                if item is metadata_names[0]:
                    metadata = b"".join(chunks)
                elif item is wheel_names[0]:
                    wheel_metadata = b"".join(chunks)
            if b"Wheel-Version:" not in wheel_metadata:
                raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_METADATA_INVALID")
    except PTDEVerificationError:
        raise
    except (
        EOFError,
        NotImplementedError,
        OSError,
        KeyError,
        RuntimeError,
        UnicodeError,
        ValueError,
        zipfile.BadZipFile,
    ) as exc:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID") from exc
    return {
        "name": expected_name,
        "version": expected_version,
        "hashes": [expected_hash],
        "dependencies": _metadata_dependencies(
            metadata,
            expected_name=expected_name,
            expected_version=expected_version,
            marker_environment=marker_environment,
            locked_versions=locked_versions,
        ),
    }


def _scope_records(
    wheelhouse: Path,
    *,
    scope: str,
    hash_lock: Mapping[str, Mapping[str, Any]],
    supported_tags: frozenset[Any],
    marker_environment: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    _require_safe_directory(
        wheelhouse,
        code="SUPPLY_CHAIN_PYTHON_WHEELHOUSE_INVALID",
    )
    try:
        candidates = sorted(wheelhouse.iterdir(), key=lambda item: item.name.casefold())
    except OSError as exc:
        raise reject("SUPPLY_CHAIN_PYTHON_WHEELHOUSE_INVALID") from exc
    if any(not item.name.endswith(".whl") for item in candidates):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEELHOUSE_EXTRA_ENTRY")
    by_name: dict[str, Path] = {}
    for candidate in candidates:
        try:
            name, _version, _build, _tags = parse_wheel_filename(candidate.name)
        except InvalidWheelFilename as exc:
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_FILENAME_INVALID") from exc
        identity = str(canonicalize_name(name))
        if identity in by_name:
            raise reject("SUPPLY_CHAIN_PYTHON_WHEEL_DUPLICATE")
        by_name[identity] = candidate
    if set(by_name) != set(hash_lock):
        raise reject("SUPPLY_CHAIN_PYTHON_WHEELHOUSE_SCOPE_MISMATCH")
    records: dict[str, dict[str, Any]] = {}
    locked_versions = {
        identity: value["version"] for identity, value in hash_lock.items()
    }
    for identity in sorted(hash_lock):
        locked = hash_lock[identity]
        records[identity] = _read_wheel_record(
            by_name[identity],
            expected_name=identity,
            expected_version=locked["version"],
            expected_hash=locked["hashes"][0],
            supported_tags=supported_tags,
            marker_environment=marker_environment,
            locked_versions=locked_versions,
        )
        records[identity]["scopes"] = [scope]
    return records


def build_python_lock_document(
    repository_root: str | Path,
    *,
    production_wheelhouse: str | Path,
    assurance_wheelhouse: str | Path,
    expected_environment: Mapping[str, str],
    ptde_accepted_attempt_history_sequence: int,
    ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_sequence: int,
    local_trust_accepted_package_history_sha512: str,
    prior_lock_document: bytes | None,
    expected_python_dependency_prior_lock_sha512: str,
) -> dict[str, Any]:
    """Build and self-validate a lock using only exact local files and pins."""

    root = Path(repository_root)
    _require_safe_directory(root, code="SUPPLY_CHAIN_PYTHON_REPOSITORY_INVALID")
    environment = dict(expected_environment)
    if environment != GOVERNED_PYTHON_ENVIRONMENT or _host_environment() != environment:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_HOST_ENVIRONMENT_MISMATCH")
    if (
        type(ptde_accepted_attempt_history_sequence) is not int
        or ptde_accepted_attempt_history_sequence < 0
        or type(local_trust_accepted_package_history_sequence) is not int
        or local_trust_accepted_package_history_sequence < 0
    ):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_SEQUENCE_INVALID")
    ptde_digest = require_sha512(
        ptde_accepted_attempt_history_sha512,
        "SUPPLY_CHAIN_PYTHON_LOCK_PTDE_HISTORY_INVALID",
    )
    local_trust_digest = require_sha512(
        local_trust_accepted_package_history_sha512,
        "SUPPLY_CHAIN_PYTHON_LOCK_LOCAL_TRUST_HISTORY_INVALID",
    )
    genesis = (
        ptde_accepted_attempt_history_sequence == 0
        and local_trust_accepted_package_history_sequence == 0
    )
    lock_sequence = (
        ptde_accepted_attempt_history_sequence
        + local_trust_accepted_package_history_sequence
        + 1
    )
    if genesis:
        if (
            prior_lock_document is not None
            or expected_python_dependency_prior_lock_sha512 != "GENESIS"
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_ROLLBACK_EVIDENCE_INVALID")
        prior_lock_sha512 = "GENESIS"
    else:
        expected_prior = require_sha512(
            expected_python_dependency_prior_lock_sha512,
            "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_PRIOR_INVALID",
        )
        if prior_lock_document is None:
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_PRIOR_DOCUMENT_REQUIRED")
        prior_document = strict_json_document(
            prior_lock_document,
            code="SUPPLY_CHAIN_PYTHON_PRIOR_LOCK",
        )
        if canonical_json_document_bytes(prior_document) != prior_lock_document:
            raise reject("SUPPLY_CHAIN_PYTHON_PRIOR_LOCK_NOT_CANONICAL")
        prior = exact_fields(
            prior_document,
            {
                "schema_id", "lock_sequence", "prior_lock_sha512",
                "requirements_sha512", "production_hash_lock_sha512",
                "assurance_hash_lock_sha512", "target_environment",
                "rollback_guard", "packages",
            },
            code="SUPPLY_CHAIN_PYTHON_PRIOR_LOCK",
        )
        if (
            prior["schema_id"] != PYTHON_LOCK_SCHEMA
            or positive_int(
                prior["lock_sequence"],
                code="SUPPLY_CHAIN_PYTHON_PRIOR_LOCK_SEQUENCE_INVALID",
            )
            >= lock_sequence
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_PRIOR_LOCK_INVALID")
        prior_lock_sha512 = canonical_sha512(prior_document)
        if prior_lock_sha512 != expected_prior:
            raise reject("SUPPLY_CHAIN_PYTHON_PRIOR_LOCK_PIN_MISMATCH")

    requirements_content = _stable_read(
        root / "requirements.txt",
        maximum=16_777_216,
        code="SUPPLY_CHAIN_PYTHON_REQUIREMENTS_READ_INVALID",
    )
    production_content = _stable_read(
        root / "requirements-production.lock.txt",
        maximum=16_777_216,
        code="SUPPLY_CHAIN_PYTHON_PRODUCTION_HASH_LOCK_READ_INVALID",
    )
    assurance_content = _stable_read(
        root / "requirements-test.lock.txt",
        maximum=16_777_216,
        code="SUPPLY_CHAIN_PYTHON_ASSURANCE_HASH_LOCK_READ_INVALID",
    )
    requirements, failures = _parse_requirements(requirements_content)
    if failures:
        raise reject(failures[0])
    production_lock = _parse_hash_lock(production_content, label="PRODUCTION")
    assurance_lock = _parse_hash_lock(assurance_content, label="ASSURANCE")
    marker_environment = _marker_environment(environment)
    supported_tags = frozenset(sys_tags())
    scoped_records = {
        "production": _scope_records(
            Path(production_wheelhouse),
            scope="production",
            hash_lock=production_lock,
            supported_tags=supported_tags,
            marker_environment=marker_environment,
        ),
        "assurance": _scope_records(
            Path(assurance_wheelhouse),
            scope="assurance",
            hash_lock=assurance_lock,
            supported_tags=supported_tags,
            marker_environment=marker_environment,
        ),
    }
    merged: dict[str, dict[str, Any]] = {}
    production_direct = {item["identity"] for item in requirements}
    for scope in ("assurance", "production"):
        for identity, record in scoped_records[scope].items():
            comparable = {
                key: record[key]
                for key in ("name", "version", "hashes", "dependencies")
            }
            existing = merged.get(identity)
            if existing is None:
                merged[identity] = {
                    **comparable,
                    "scopes": [scope],
                    "direct_scopes": [],
                }
            else:
                if any(existing[key] != comparable[key] for key in comparable):
                    raise reject("SUPPLY_CHAIN_PYTHON_CROSS_SCOPE_PACKAGE_MISMATCH")
                existing["scopes"].append(scope)
            if identity in production_direct or (
                scope == "assurance" and identity in _ASSURANCE_DIRECT_REQUIREMENTS
            ):
                merged[identity]["direct_scopes"].append(scope)
    packages = []
    for identity in sorted(merged):
        record = merged[identity]
        record["scopes"] = sorted(record["scopes"])
        record["direct_scopes"] = sorted(record["direct_scopes"])
        packages.append(record)
    document = {
        "schema_id": PYTHON_LOCK_SCHEMA,
        "lock_sequence": lock_sequence,
        "prior_lock_sha512": prior_lock_sha512,
        "requirements_sha512": hashlib.sha512(b"").hexdigest(),
        "production_hash_lock_sha512": hashlib.sha512(production_content).hexdigest(),
        "assurance_hash_lock_sha512": hashlib.sha512(assurance_content).hexdigest(),
        "target_environment": environment,
        "rollback_guard": {
            "ptde_accepted_attempt_history_sequence": (
                ptde_accepted_attempt_history_sequence
            ),
            "ptde_accepted_attempt_history_sha512": ptde_digest,
            "local_trust_accepted_package_history_sequence": (
                local_trust_accepted_package_history_sequence
            ),
            "local_trust_accepted_package_history_sha512": local_trust_digest,
        },
        "packages": packages,
    }
    document["requirements_sha512"] = canonical_sha512(requirements)
    return validate_python_lock_document(
        document,
        requirements=requirements,
        production_hash_lock_content=production_content,
        assurance_hash_lock_content=assurance_content,
        expected_environment=environment,
        expected_ptde_accepted_attempt_history_sequence=(
            ptde_accepted_attempt_history_sequence
        ),
        expected_ptde_accepted_attempt_history_sha512=ptde_digest,
        expected_local_trust_accepted_package_history_sequence=(
            local_trust_accepted_package_history_sequence
        ),
        expected_local_trust_accepted_package_history_sha512=local_trust_digest,
        expected_python_dependency_prior_lock_sha512=prior_lock_sha512,
    )


def write_python_lock_document_exclusive(
    document: Mapping[str, Any],
    output_path: str | Path,
) -> str:
    """Create a canonical lock exactly once and verify the persisted bytes."""

    path = Path(output_path)
    parent_before = _require_safe_directory(
        path.parent,
        code="SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_PARENT_INVALID",
    )
    content = canonical_json_document_bytes(dict(document))
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_INVALID")
            total = 0
            while total < len(content):
                written = os.write(descriptor, content[total:])
                if written <= 0:
                    raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_WRITE_FAILED")
                total += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            parent_descriptor = os.open(path.parent, os.O_RDONLY)
        except OSError as exc:
            if os.name != "nt":
                raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_PARENT_SYNC_FAILED") from exc
        else:
            try:
                os.fsync(parent_descriptor)
            except OSError as exc:
                if os.name != "nt":
                    raise reject(
                        "SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_PARENT_SYNC_FAILED"
                    ) from exc
            finally:
                os.close(parent_descriptor)
        parent_after = path.parent.resolve(strict=True).lstat()
        if (parent_before.st_dev, parent_before.st_ino) != (
            parent_after.st_dev,
            parent_after.st_ino,
        ):
            raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_PARENT_CHANGED")
        persisted = _stable_read(
            path,
            maximum=len(content),
            code="SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_INVALID",
        )
    except PTDEVerificationError:
        raise
    except OSError as exc:
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_EXCLUSIVE_CREATE_FAILED") from exc
    if persisted != content or strict_json_document(
        persisted,
        code="SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT",
    ) != dict(document):
        raise reject("SUPPLY_CHAIN_PYTHON_LOCK_OUTPUT_SELF_VALIDATION_FAILED")
    return hashlib.sha512(content).hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the offline governed Python dependency lock /3"
    )
    parser.add_argument("repository")
    parser.add_argument("--production-wheelhouse", required=True)
    parser.add_argument("--assurance-wheelhouse", required=True)
    parser.add_argument("--implementation", required=True)
    parser.add_argument("--python-version", required=True)
    parser.add_argument("--abi-tag", required=True)
    parser.add_argument("--platform-tag", required=True)
    parser.add_argument("--ptde-accepted-attempt-history-sequence", type=int, required=True)
    parser.add_argument("--ptde-accepted-attempt-history-sha512", required=True)
    parser.add_argument(
        "--local-trust-accepted-package-history-sequence", type=int, required=True
    )
    parser.add_argument("--local-trust-accepted-package-history-sha512", required=True)
    parser.add_argument("--prior-lock")
    parser.add_argument(
        "--expected-python-dependency-prior-lock-sha512",
        required=True,
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    environment = {
        "implementation": arguments.implementation,
        "python_version": arguments.python_version,
        "abi_tag": arguments.abi_tag,
        "platform_tag": arguments.platform_tag,
        "installed_scope": "assurance",
    }
    try:
        prior_lock_document = (
            _stable_read(
                Path(arguments.prior_lock),
                maximum=16_777_216,
                code="SUPPLY_CHAIN_PYTHON_PRIOR_LOCK_READ_INVALID",
            )
            if arguments.prior_lock is not None
            else None
        )
        document = build_python_lock_document(
            arguments.repository,
            production_wheelhouse=arguments.production_wheelhouse,
            assurance_wheelhouse=arguments.assurance_wheelhouse,
            expected_environment=environment,
            ptde_accepted_attempt_history_sequence=(
                arguments.ptde_accepted_attempt_history_sequence
            ),
            ptde_accepted_attempt_history_sha512=(
                arguments.ptde_accepted_attempt_history_sha512
            ),
            local_trust_accepted_package_history_sequence=(
                arguments.local_trust_accepted_package_history_sequence
            ),
            local_trust_accepted_package_history_sha512=(
                arguments.local_trust_accepted_package_history_sha512
            ),
            prior_lock_document=prior_lock_document,
            expected_python_dependency_prior_lock_sha512=(
                arguments.expected_python_dependency_prior_lock_sha512
            ),
        )
        output = Path(arguments.repository) / "python-dependencies.lock.json"
        digest = write_python_lock_document_exclusive(document, output)
    except (OSError, PTDEVerificationError, ValueError) as error:
        code = error.code if isinstance(error, PTDEVerificationError) else type(error).__name__
        print(
            json.dumps(
                {
                    "admitted": False,
                    "authority_granted": False,
                    "failure": code,
                    "status": "FAIL",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2
    print(
        json.dumps(
            {
                "admitted": False,
                "authority_granted": False,
                "lock_sha512": digest,
                "output": str(output),
                "status": "BUILT_NOT_ADMITTED",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


__all__ = [
    "build_python_lock_document",
    "main",
    "write_python_lock_document_exclusive",
]
