"""Safe, bounded filesystem measurement for detached local-trust evidence."""

from __future__ import annotations

import json
import os
import stat
import unicodedata
from collections.abc import Iterable
from hashlib import sha512
from pathlib import Path, PurePosixPath
from typing import Any

from .constants import (
    IGNORED_DIRECTORY_NAMES,
    IGNORED_SUFFIXES,
    MAX_EVIDENCE_FILES,
    MAX_FILE_BYTES,
)
from .digests import canonical_bytes

_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
MAX_PATH_UTF8_BYTES = 4096
MAX_PATH_SEGMENT_UTF8_BYTES = 255


class LocalTrustPathError(ValueError):
    pass


def canonical_relative_path(value: Any) -> str:
    if type(value) is not str or not value or unicodedata.normalize("NFC", value) != value:
        raise LocalTrustPathError("path_not_canonical_text")
    if (
        "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 for character in value)
        or len(value.encode("utf-8", errors="strict")) > MAX_PATH_UTF8_BYTES
    ):
        raise LocalTrustPathError("path_not_posix_relative")
    candidate = PurePosixPath(value)
    if (
        candidate.is_absolute()
        or candidate.as_posix() != value
        or any(
            part in {"", ".", ".."}
            or ":" in part
            or part.endswith((" ", "."))
            or len(part.encode("utf-8", errors="strict")) > MAX_PATH_SEGMENT_UTF8_BYTES
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
            for part in candidate.parts
        )
    ):
        raise LocalTrustPathError("path_escape_or_ambiguity")
    return value


def _is_reparse(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError as exc:
        raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def validated_root(value: str | Path) -> Path:
    try:
        root = Path(value)
    except (TypeError, ValueError, OSError) as exc:
        raise LocalTrustPathError("root_invalid") from exc
    if not root.is_absolute():
        raise LocalTrustPathError("root_must_be_absolute")
    try:
        current = Path(root.anchor)
        for part in root.parts[1:]:
            current = current / part
            component = current.lstat()
            if stat.S_ISLNK(component.st_mode) or _is_reparse(current):
                raise LocalTrustPathError("root_ancestor_symlink_or_reparse")
        metadata = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LocalTrustPathError("root_unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(root):
        raise LocalTrustPathError("root_not_safe_directory")
    if os.path.normcase(str(root)) != os.path.normcase(str(resolved)):
        raise LocalTrustPathError("root_resolution_changed")
    return resolved


def resolve_safe_path(root: Path, relative_path: str, *, must_exist: bool = True) -> Path:
    relative = canonical_relative_path(relative_path)
    current = root
    for part in PurePosixPath(relative).parts:
        try:
            names = [child.name for child in current.iterdir()]
        except OSError as exc:
            raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
        case_matches = [name for name in names if name.casefold() == part.casefold()]
        if len(case_matches) > 1:
            raise LocalTrustPathError("casefold_path_collision")
        if must_exist and case_matches != [part]:
            raise LocalTrustPathError("path_case_or_presence_mismatch")
        if not must_exist and case_matches and case_matches != [part]:
            raise LocalTrustPathError("path_case_mismatch")
        current = current / part
        if not case_matches and not must_exist:
            continue
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(current):
            raise LocalTrustPathError("symlink_or_reparse_rejected")
    if must_exist:
        try:
            resolved = current.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise LocalTrustPathError("path_escape_or_missing") from exc
        return resolved
    try:
        current.parent.resolve(strict=True).relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise LocalTrustPathError("output_parent_escape_or_missing") from exc
    return current


def _identity(metadata: os.stat_result) -> tuple[Any, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
    )


def _directory_identity(metadata: os.stat_result) -> tuple[Any, ...]:
    return (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode))


def measure_file(root: Path, relative_path: str) -> dict[str, Any]:
    relative = canonical_relative_path(relative_path)
    path = resolve_safe_path(root, relative)
    descriptor = -1
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise LocalTrustPathError("evidence_not_regular_file")
        if before.st_nlink != 1:
            raise LocalTrustPathError("evidence_hard_link_rejected")
        if before.st_size > MAX_FILE_BYTES:
            raise LocalTrustPathError("evidence_file_too_large")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened_before = os.fstat(descriptor)
        if _identity(before) != _identity(opened_before):
            raise LocalTrustPathError("evidence_identity_changed")
        digest_state = sha512()
        measured_size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            measured_size += len(chunk)
            if measured_size > MAX_FILE_BYTES:
                raise LocalTrustPathError("evidence_file_too_large")
            digest_state.update(chunk)
        opened_after = os.fstat(descriptor)
        after = path.lstat()
    except LocalTrustPathError:
        raise
    except OSError as exc:
        raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len({_identity(before), _identity(opened_before), _identity(opened_after), _identity(after)}) != 1:
        raise LocalTrustPathError("evidence_changed_during_measurement")
    if measured_size != after.st_size:
        raise LocalTrustPathError("evidence_size_changed")
    return {
        "path": relative,
        "status": "PRESENT",
        "size_bytes": measured_size,
        "sha512": digest_state.hexdigest(),
    }


def inventory_root(root: Path, relative_root: str) -> list[str]:
    relative = canonical_relative_path(relative_root)
    boundary = resolve_safe_path(root, relative)
    if not boundary.is_dir():
        raise LocalTrustPathError("evidence_root_not_directory")
    paths: list[str] = []
    pending = [boundary]
    while pending:
        directory = pending.pop()
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name.casefold())
        except OSError as exc:
            raise LocalTrustPathError("filesystem_evidence_unavailable") from exc
        names = [child.name.casefold() for child in children]
        if len(names) != len(set(names)):
            raise LocalTrustPathError("casefold_path_collision")
        for child in children:
            metadata = child.lstat()
            if stat.S_ISLNK(metadata.st_mode) or _is_reparse(child):
                raise LocalTrustPathError("symlink_or_reparse_rejected")
            if stat.S_ISDIR(metadata.st_mode):
                if child.name not in IGNORED_DIRECTORY_NAMES:
                    pending.append(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise LocalTrustPathError("evidence_special_file_rejected")
            if child.suffix.lower() in IGNORED_SUFFIXES:
                continue
            resolved = child.resolve(strict=True)
            try:
                child_relative = resolved.relative_to(root)
            except ValueError as exc:
                raise LocalTrustPathError("path_escape") from exc
            paths.append(PurePosixPath(*child_relative.parts).as_posix())
            if len(paths) > MAX_EVIDENCE_FILES:
                raise LocalTrustPathError("evidence_file_count_exceeded")
    return sorted(paths)


def collect_group_files(root: Path, group: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    candidate_paths: set[str] = set()
    missing: list[str] = []
    for relative in group.get("paths", ()):
        try:
            candidate_paths.add(canonical_relative_path(relative))
            resolve_safe_path(root, relative)
        except LocalTrustPathError:
            missing.append(relative)
    for relative_root in group.get("roots", ()):
        try:
            found = inventory_root(root, relative_root)
        except LocalTrustPathError:
            missing.append(relative_root)
            continue
        if not found:
            missing.append(relative_root)
        candidate_paths.update(found)
    records = [measure_file(root, path) for path in sorted(candidate_paths) if path not in missing]
    return records, sorted(set(missing))


def _read_safe_absolute_file(path: Path) -> bytes:
    try:
        absolute = path if path.is_absolute() else Path.cwd() / path
        parent = validated_root(absolute.parent)
        relative = canonical_relative_path(absolute.name)
        safe = resolve_safe_path(parent, relative)
        before = safe.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or _is_reparse(safe):
            raise LocalTrustPathError("json_artifact_not_regular")
        if before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
            raise LocalTrustPathError("json_artifact_link_or_size_invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(safe, flags)
        try:
            opened_before = os.fstat(descriptor)
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise LocalTrustPathError("json_artifact_too_large")
                chunks.append(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = safe.lstat()
        if len({_identity(before), _identity(opened_before), _identity(opened_after), _identity(after)}) != 1:
            raise LocalTrustPathError("json_artifact_changed_during_read")
        return b"".join(chunks)
    except LocalTrustPathError:
        raise
    except OSError as exc:
        raise LocalTrustPathError("json_artifact_unavailable") from exc


def strict_load_json(path: Path) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise LocalTrustPathError(f"duplicate_json_key:{key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise LocalTrustPathError(f"non_finite_json_number:{value}")

    try:
        data = _read_safe_absolute_file(path)
        if not data.endswith(b"\n") or data.endswith(b"\n\n") or b"\r" in data:
            raise LocalTrustPathError("json_artifact_document_form_invalid")
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
        if canonical_bytes(value) + b"\n" != data:
            raise LocalTrustPathError("json_artifact_not_canonical")
        return value
    except LocalTrustPathError:
        raise
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise LocalTrustPathError("json_artifact_invalid") from exc


def write_json_exclusive(value: Any, path: Path) -> Path:
    """Create a new artifact without overwriting an existing receipt."""

    return write_bytes_exclusive(canonical_bytes(value) + b"\n", path)


def write_bytes_exclusive(document: bytes, path: Path) -> Path:
    """Create one regular no-follow file under an existing safe directory."""

    if type(document) is not bytes or len(document) > MAX_FILE_BYTES:
        raise LocalTrustPathError("immutable_receipt_bytes_invalid")
    if not path.is_absolute():
        path = Path.cwd() / path
    parent = validated_root(path.parent)
    name = canonical_relative_path(path.name)
    target = resolve_safe_path(parent, name, must_exist=False)
    parent_before = parent.lstat()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(target, flags, 0o600)
    except FileExistsError as exc:
        raise LocalTrustPathError("immutable_receipt_already_exists") from exc
    try:
        written = 0
        while written < len(document):
            written += os.write(descriptor, document[written:])
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != len(document):
            raise LocalTrustPathError("immutable_receipt_write_invalid")
    finally:
        os.close(descriptor)
    target_after = target.lstat()
    if (
        not stat.S_ISREG(target_after.st_mode)
        or target_after.st_nlink != 1
        or target_after.st_dev != metadata.st_dev
        or target_after.st_ino != metadata.st_ino
        or target_after.st_size != metadata.st_size
    ):
        raise LocalTrustPathError("immutable_receipt_identity_changed")
    parent_after = parent.lstat()
    if _directory_identity(parent_before) != _directory_identity(parent_after):
        raise LocalTrustPathError("output_parent_changed_during_write")
    return target


def ensure_unique_sorted_paths(records: Iterable[dict[str, Any]]) -> bool:
    paths: list[str] = []
    for record in records:
        path = record.get("path")
        if type(path) is not str:
            return False
        paths.append(path)
    return (
        paths == sorted(paths)
        and len(paths) == len(set(paths))
        and len({path.casefold() for path in paths}) == len(paths)
    )


__all__ = [
    "LocalTrustPathError",
    "canonical_relative_path",
    "collect_group_files",
    "ensure_unique_sorted_paths",
    "inventory_root",
    "measure_file",
    "resolve_safe_path",
    "strict_load_json",
    "validated_root",
    "write_bytes_exclusive",
    "write_json_exclusive",
]
