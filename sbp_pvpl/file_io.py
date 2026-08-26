"""Bounded canonical input and exclusive local export for V2 PVPL."""

from __future__ import annotations

import ctypes
import os
import stat
import unicodedata
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .canonical import canonical_document_bytes, parse_canonical_document
from .constants import MAX_DOCUMENT_BYTES
from .errors import PVPLValidationError, reject


def _is_reparse(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(getattr(metadata, "st_file_attributes", 0) & marker)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        0 if os.name == "nt" else int(metadata.st_ctime_ns),
    )


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return (int(metadata.st_dev), int(metadata.st_ino))


class _WindowsUnicodeString(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.USHORT),
        ("maximum_length", wintypes.USHORT),
        ("buffer", wintypes.LPWSTR),
    ]


class _WindowsObjectAttributes(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.ULONG),
        ("root_directory", wintypes.HANDLE),
        ("object_name", ctypes.POINTER(_WindowsUnicodeString)),
        ("attributes", wintypes.ULONG),
        ("security_descriptor", wintypes.LPVOID),
        ("security_quality_of_service", wintypes.LPVOID),
    ]


class _WindowsIoStatusBlock(ctypes.Structure):
    _fields_ = [
        ("status_or_pointer", wintypes.LPVOID),
        ("information", ctypes.c_size_t),
    ]


def _windows_kernel32() -> Any:
    if os.name != "nt":
        raise reject("WINDOWS_HANDLE_UNAVAILABLE")
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _close_windows_handle(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    if not close(wintypes.HANDLE(handle)):
        raise ctypes.WinError(ctypes.get_last_error())


def _close_resources(
    descriptors: tuple[int | None, ...],
    windows_handle: int | None,
    code: str,
) -> None:
    first_error: OSError | None = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if windows_handle is not None:
        try:
            _close_windows_handle(windows_handle)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise reject(code) from first_error


def _windows_parent_path(handle: int, code: str) -> Path:
    kernel32 = _windows_kernel32()
    final_path = kernel32.GetFinalPathNameByHandleW
    final_path.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    final_path.restype = wintypes.DWORD
    capacity = 32_768
    buffer = ctypes.create_unicode_buffer(capacity)
    length = final_path(wintypes.HANDLE(handle), buffer, capacity, 0)
    if length == 0 or length >= capacity:
        raise reject(code)
    rendered = buffer.value
    if rendered.startswith("\\\\?\\UNC\\"):
        rendered = "\\\\" + rendered[8:]
    elif rendered.startswith("\\\\?\\"):
        rendered = rendered[4:]
    return Path(rendered)


def _open_windows_parent(path: Path, *, writable: bool, code: str) -> int:
    kernel32 = _windows_kernel32()
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    desired_access = 0x00100081 | (0x40000000 if writable else 0)
    handle = create_file(
        str(path),
        desired_access,
        0x00000001 | 0x00000002,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or int(handle) == invalid_handle:
        raise reject(code)
    return int(handle)


def _open_windows_relative_file(
    parent_handle: int,
    leaf_name: str,
    *,
    create: bool,
    code: str,
) -> int:
    if os.name != "nt":
        raise reject(code)
    import msvcrt

    name_buffer = ctypes.create_unicode_buffer(leaf_name)
    name = _WindowsUnicodeString(
        length=len(leaf_name.encode("utf-16-le")),
        maximum_length=len(name_buffer) * 2,
        buffer=ctypes.cast(name_buffer, wintypes.LPWSTR),
    )
    attributes = _WindowsObjectAttributes(
        length=ctypes.sizeof(_WindowsObjectAttributes),
        root_directory=wintypes.HANDLE(parent_handle),
        object_name=ctypes.pointer(name),
        attributes=0x00000040,
        security_descriptor=None,
        security_quality_of_service=None,
    )
    io_status = _WindowsIoStatusBlock()
    file_handle = wintypes.HANDLE()
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    nt_create_file = ntdll.NtCreateFile
    nt_create_file.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_WindowsObjectAttributes),
        ctypes.POINTER(_WindowsIoStatusBlock),
        ctypes.c_void_p,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        ctypes.c_void_p,
        wintypes.ULONG,
    ]
    nt_create_file.restype = wintypes.LONG
    status = nt_create_file(
        ctypes.byref(file_handle),
        0xC0100080 if create else 0x80100080,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0x00000080,
        0,
        2 if create else 1,
        0x00000020 | 0x00000040 | 0x00200000,
        None,
        0,
    )
    if status != 0 or not file_handle.value:
        if file_handle.value:
            _close_windows_handle(int(file_handle.value))
        if create and ctypes.c_ulong(status).value == 0xC0000035:
            raise reject("OUTPUT_ALREADY_EXISTS")
        raise reject(code)
    flags = (os.O_RDWR if create else os.O_RDONLY) | getattr(os, "O_BINARY", 0)
    try:
        return msvcrt.open_osfhandle(int(file_handle.value), flags)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _close_windows_handle(int(file_handle.value))
        raise reject(code) from exc


def _flush_windows_parent(handle: int, code: str) -> None:
    kernel32 = _windows_kernel32()
    flush = kernel32.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    if not flush(wintypes.HANDLE(handle)):
        error = ctypes.get_last_error()
        if error not in {1, 6, 50}:
            raise reject(code)


def _require_unambiguous_path(path: Path, code: str) -> None:
    """Reject lexical aliases, control characters, and Windows device/ADS paths."""

    if any(part == ".." for part in path.parts):
        raise reject(code)
    for component in path.parts:
        if component in {path.anchor, path.drive, "\\", "/"}:
            continue
        try:
            encoded = component.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise reject(code) from exc
        if (
            not encoded
            or unicodedata.normalize("NFC", component) != component
            or any(
                ord(character) < 32 or 127 <= ord(character) <= 159
                for character in component
            )
        ):
            raise reject(code)
    if os.name != "nt":
        return
    if path.drive.startswith(("\\\\", "//")):
        raise reject(code)
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
        f"{prefix}{number}"
        for prefix in ("COM", "LPT")
        for number in range(1, 10)
    }
    reserved.update(
        f"{prefix}{number}"
        for prefix in ("COM", "LPT")
        for number in ("¹", "²", "³")
    )
    for component in path.parts:
        if component in {path.anchor, path.drive, "\\", "/"}:
            continue
        stem = component.split(".", 1)[0].upper()
        if (
            ":" in component
            or component.rstrip(" .") != component
            or stem in reserved
        ):
            raise reject(code)


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


def _open_held_directory(
    path: Path,
    code: str,
    *,
    writable: bool = False,
) -> tuple[os.stat_result, int | None, int | None]:
    before = _require_safe_directory(path, code)
    if os.name == "nt":
        windows_handle = _open_windows_parent(path, writable=writable, code=code)
        try:
            after = path.lstat()
            opened_path = _windows_parent_path(windows_handle, code)
            if (
                _directory_identity(after) != _directory_identity(before)
                or os.path.normcase(os.path.abspath(str(opened_path)))
                != os.path.normcase(str(path.absolute()))
            ):
                raise reject(code)
        except BaseException:
            _close_windows_handle(windows_handle)
            raise
        return before, None, windows_handle
    if os.open not in os.supports_dir_fd:
        raise reject(code)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or stat.S_ISLNK(opened.st_mode)
            or _is_reparse(opened)
            or _directory_identity(opened) != _directory_identity(before)
        ):
            raise reject(code)
    except BaseException:
        os.close(descriptor)
        raise
    return before, descriptor, None


def _child_lstat(path: Path, parent_descriptor: int | None) -> os.stat_result:
    if parent_descriptor is None:
        return path.lstat()
    return os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)


def _child_open(
    path: Path,
    flags: int,
    parent_descriptor: int | None,
    windows_parent_handle: int | None,
    *,
    create: bool,
    mode: int | None = None,
) -> int:
    if windows_parent_handle is not None:
        code = "OUTPUT_PATH_UNAVAILABLE" if create else "INPUT_FILE_UNAVAILABLE"
        return _open_windows_relative_file(
            windows_parent_handle,
            path.name,
            create=create,
            code=code,
        )
    target: str | Path = path if parent_descriptor is None else path.name
    if mode is None:
        if parent_descriptor is None:
            return os.open(target, flags)
        return os.open(target, flags, dir_fd=parent_descriptor)
    if parent_descriptor is None:
        return os.open(target, flags, mode)
    return os.open(target, flags, mode, dir_fd=parent_descriptor)


def _parent_after(path: Path, parent_descriptor: int | None) -> os.stat_result:
    if parent_descriptor is None:
        return path.parent.lstat()
    return os.fstat(parent_descriptor)


def read_canonical_file(path_value: str | os.PathLike[str]) -> dict[str, Any]:
    supplied_path = Path(path_value)
    descriptor: int | None = None
    parent_descriptor: int | None = None
    windows_parent_handle: int | None = None
    try:
        if not supplied_path.name or supplied_path.name in {".", ".."}:
            raise reject("INPUT_PATH_INVALID")
        _require_unambiguous_path(supplied_path, "INPUT_PATH_INVALID")
        if os.name == "nt" and supplied_path.drive and not supplied_path.is_absolute():
            raise reject("INPUT_PATH_INVALID")
        path = supplied_path.absolute()
        _require_unambiguous_path(path, "INPUT_PATH_INVALID")
        parent_before, parent_descriptor, windows_parent_handle = _open_held_directory(
            path.parent, "INPUT_DIRECTORY_INVALID"
        )
        before = _child_lstat(path, parent_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or _is_reparse(before)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > MAX_DOCUMENT_BYTES
        ):
            raise reject("INPUT_FILE_INVALID")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = _child_open(
            path,
            flags,
            parent_descriptor,
            windows_parent_handle,
            create=False,
        )
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(opened) != _identity(before)
        ):
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
        after = _child_lstat(path, parent_descriptor)
        parent_after = _parent_after(path, parent_descriptor)
        if (
            _identity(after) != _identity(before)
            or after.st_nlink != 1
            or _directory_identity(parent_after) != _directory_identity(parent_before)
        ):
            raise reject("INPUT_FILE_IDENTITY_CHANGED")
        return parse_canonical_document(b"".join(chunks))
    except PVPLValidationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError, MemoryError) as exc:
        raise reject("INPUT_FILE_UNAVAILABLE") from exc
    finally:
        _close_resources(
            (descriptor, parent_descriptor),
            windows_parent_handle,
            "INPUT_HANDLE_CLOSE_FAILED",
        )


def write_exclusive_canonical_file(
    value: Any, path_value: str | os.PathLike[str]
) -> Path:
    """Write a new local file without following links or replacing any object."""

    supplied_path = Path(path_value)
    descriptor: int | None = None
    parent_descriptor: int | None = None
    windows_parent_handle: int | None = None
    created = False
    parent_identity: tuple[int, int] | None = None
    try:
        if not supplied_path.name or supplied_path.name in {".", ".."}:
            raise reject("OUTPUT_PATH_INVALID")
        _require_unambiguous_path(supplied_path, "OUTPUT_PATH_INVALID")
        if os.name == "nt" and supplied_path.drive and not supplied_path.is_absolute():
            raise reject("OUTPUT_PATH_INVALID")
        path = supplied_path.absolute()
        _require_unambiguous_path(path, "OUTPUT_PATH_INVALID")
        payload = canonical_document_bytes(value)
        parent = path.parent if str(path.parent) else Path(".")
        parent_before, parent_descriptor, windows_parent_handle = _open_held_directory(
            parent,
            "OUTPUT_DIRECTORY_INVALID",
            writable=True,
        )
        parent_identity = _directory_identity(parent_before)
        try:
            existing = _child_lstat(path, parent_descriptor)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            raise reject("OUTPUT_ALREADY_EXISTS")
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = _child_open(
            path,
            flags,
            parent_descriptor,
            windows_parent_handle,
            create=True,
            mode=0o600,
        )
        created = True
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_reparse(opened)
            or opened.st_nlink != 1
        ):
            raise reject("OUTPUT_FILE_INVALID")
        path_before_write = _child_lstat(path, parent_descriptor)
        parent_before_write = _parent_after(path, parent_descriptor)
        if (
            _identity(path_before_write) != _identity(opened)
            or path_before_write.st_nlink != 1
            or _directory_identity(parent_before_write) != parent_identity
        ):
            raise reject("OUTPUT_WRITE_IDENTITY_CHANGED")
        view = memoryview(payload)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise reject("OUTPUT_WRITE_INCOMPLETE")
            view = view[count:]
        os.fsync(descriptor)
        written = os.fstat(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        persisted = bytearray()
        while len(persisted) < len(payload):
            chunk = os.read(descriptor, min(len(payload) - len(persisted), 65_536))
            if not chunk:
                raise reject("OUTPUT_PERSISTED_READ_INCOMPLETE")
            persisted.extend(chunk)
        if bytes(persisted) != payload or os.read(descriptor, 1):
            raise reject("OUTPUT_PERSISTED_CONTENT_MISMATCH")
        final = os.fstat(descriptor)
        path_final = _child_lstat(path, parent_descriptor)
        parent_after = _parent_after(path, parent_descriptor)
        if (
            final.st_size != len(payload)
            or _identity(final) != _identity(written)
            or not stat.S_ISREG(path_final.st_mode)
            or final.st_nlink != 1
            or path_final.st_nlink != 1
            or _identity(path_final) != _identity(final)
            or _directory_identity(parent_after) != _directory_identity(parent_before)
        ):
            raise reject("OUTPUT_WRITE_IDENTITY_CHANGED")
        if parent_descriptor is not None:
            os.fsync(parent_descriptor)
        elif windows_parent_handle is not None:
            _flush_windows_parent(
                windows_parent_handle, "OUTPUT_PARENT_FLUSH_FAILED"
            )
            if (
                os.path.normcase(
                    os.path.abspath(
                        str(
                            _windows_parent_path(
                                windows_parent_handle,
                                "OUTPUT_DIRECTORY_INVALID",
                            )
                        )
                    )
                )
                != os.path.normcase(str(parent.absolute()))
            ):
                raise reject("OUTPUT_WRITE_IDENTITY_CHANGED")
        return path
    except PVPLValidationError:
        raise
    except FileExistsError as exc:
        raise reject("OUTPUT_ALREADY_EXISTS") from exc
    except (OSError, RuntimeError, TypeError, ValueError, MemoryError) as exc:
        code = "OUTPUT_WRITE_FAILED_AFTER_CREATE" if created else "OUTPUT_PATH_UNAVAILABLE"
        raise reject(code) from exc
    finally:
        _close_resources(
            (descriptor, parent_descriptor),
            windows_parent_handle,
            "OUTPUT_HANDLE_CLOSE_FAILED",
        )


__all__ = ["read_canonical_file", "write_exclusive_canonical_file"]
