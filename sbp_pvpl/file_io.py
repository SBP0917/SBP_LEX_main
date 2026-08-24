"""Bounded canonical input and exclusive local export for V2 PVPL."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_document_bytes, parse_canonical_document
from .constants import MAX_DOCUMENT_BYTES
from .errors import PVPLValidationError, reject


def _is_reparse(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(getattr(metadata, "st_file_attributes", 0) & marker)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return (int(metadata.st_dev), int(metadata.st_ino))


def _require_safe_directory(path: Path, code: str) -> os.stat_result:
    absolute = path.absolute()
    chain = list(reversed(absolute.parents)) + [absolute]
    final: os.stat_result | None = None
    for component in chain:
        metadata = component.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(metadata)
        ):
            raise reject(code)
        final = metadata
    if final is None:
        raise reject(code)
    return final


def read_canonical_file(path_value: str | os.PathLike[str]) -> dict[str, Any]:
    path = Path(path_value)
    descriptor: int | None = None
    try:
        parent_before = _require_safe_directory(path.parent, "INPUT_DIRECTORY_INVALID")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
        ):
            raise reject("INPUT_FILE_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
            raise reject("INPUT_FILE_IDENTITY_CHANGED")
        chunks: list[bytes] = []
        remaining = int(before.st_size)
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise reject("INPUT_FILE_SHORT_READ")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise reject("INPUT_FILE_GREW")
        after = path.lstat()
        parent_after = path.parent.lstat()
        if (
            _identity(after) != _identity(before)
            or _directory_identity(parent_after) != _directory_identity(parent_before)
        ):
            raise reject("INPUT_FILE_IDENTITY_CHANGED")
        return parse_canonical_document(b"".join(chunks))
    except PVPLValidationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("INPUT_FILE_UNAVAILABLE") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_exclusive_canonical_file(
    value: Any, path_value: str | os.PathLike[str]
) -> Path:
    """Write a new local file without following links or replacing any object."""

    path = Path(path_value)
    descriptor: int | None = None
    created = False
    try:
        if not path.name or path.name in {".", ".."}:
            raise reject("OUTPUT_PATH_INVALID")
        parent = path.parent if str(path.parent) else Path(".")
        parent_before = _require_safe_directory(parent, "OUTPUT_DIRECTORY_INVALID")
        try:
            existing = path.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            raise reject("OUTPUT_ALREADY_EXISTS")
        payload = canonical_document_bytes(value)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags, 0o600)
        created = True
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _is_reparse(opened):
            raise reject("OUTPUT_FILE_INVALID")
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise reject("OUTPUT_WRITE_INCOMPLETE")
            view = view[count:]
        os.fsync(descriptor)
        final = os.fstat(descriptor)
        path_final = path.lstat()
        parent_after = parent.lstat()
        if (
            final.st_size != len(payload)
            or not stat.S_ISREG(path_final.st_mode)
            or _identity(path_final) != _identity(final)
            or _directory_identity(parent_after) != _directory_identity(parent_before)
        ):
            raise reject("OUTPUT_WRITE_IDENTITY_CHANGED")
        return path
    except PVPLValidationError:
        raise
    except FileExistsError as exc:
        raise reject("OUTPUT_ALREADY_EXISTS") from exc
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        code = "OUTPUT_WRITE_FAILED_AFTER_CREATE" if created else "OUTPUT_PATH_UNAVAILABLE"
        raise reject(code) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


__all__ = ["read_canonical_file", "write_exclusive_canonical_file"]
