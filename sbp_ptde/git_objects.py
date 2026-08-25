"""Read and independently hash explicit objects from a bare Git object database."""

from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .canonical import canonical_path, require_sha512, sha512_hex
from .constants import (
    GITLINK_MODE,
    MAX_BLOB_COUNT,
    MAX_COMMIT_PARENT_COUNT,
    MAX_GIT_EXECUTABLE_BYTES,
    MAX_GIT_OBJECT_BYTES,
    MAX_GIT_SUBPROCESS_METADATA_BYTES,
    MAX_GIT_SUBPROCESS_SECONDS,
    MAX_TOTAL_GIT_OBJECT_BYTES,
    MAX_TREE_COUNT,
    MAX_TREE_DEPTH,
    MAX_TREE_ENTRY_COUNT,
    REGULAR_BLOB_MODES,
    SYMLINK_MODE,
    TREE_MODE,
)
from .errors import PTDEVerificationError, reject


_WINDOWS_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_REJECTED_GIT_ENVIRONMENT = frozenset(
    {
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_SHALLOW_FILE",
        "GIT_WORK_TREE",
    }
)


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    ]


class _JobIoCounters(ctypes.Structure):
    _fields_ = [
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    ]


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("basic_limit_information", _JobBasicLimitInformation),
        ("io_info", _JobIoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    ]


def _kernel32() -> Any:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p)
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        wintypes.INT,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (
        wintypes.HANDLE,
        wintypes.HANDLE,
    )
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


def _windows_process_handle(process: subprocess.Popen[bytes]) -> int:
    handle = getattr(process, "_handle", None)
    if not isinstance(handle, int) or handle <= 0:
        raise reject("GIT_PROCESS_HANDLE_INVALID")
    return handle


def _resume_suspended_process(process: subprocess.Popen[bytes]) -> bool:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = wintypes.LONG
    return (
        ntdll.NtResumeProcess(
            wintypes.HANDLE(_windows_process_handle(process))
        )
        == 0
    )


class _WindowsProcessTree:
    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION_CLASS = 9

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = _kernel32()
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise reject("GIT_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")
        self._handle = int(handle)
        limits = _JobExtendedLimitInformation()
        limits.basic_limit_information.limit_flags = self._KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(
            wintypes.HANDLE(self._handle),
            self._EXTENDED_LIMIT_INFORMATION_CLASS,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            self.close()
            raise reject("GIT_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")
        if not kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(self._handle),
            wintypes.HANDLE(_windows_process_handle(process)),
        ):
            self.close()
            raise reject("GIT_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")
        if not _resume_suspended_process(process):
            self.terminate()
            self.close()
            raise reject("GIT_PROCESS_TREE_RESUME_FAILED")

    def terminate(self) -> bool:
        if self._handle is None:
            return False
        return bool(
            _kernel32().TerminateJobObject(wintypes.HANDLE(self._handle), 1)
        )

    def close(self) -> None:
        if self._handle is not None:
            _kernel32().CloseHandle(wintypes.HANDLE(self._handle))
            self._handle = None


def _process_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    )


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    windows_tree: _WindowsProcessTree | None,
) -> bool:
    try:
        if os.name == "nt":
            if windows_tree is None or not windows_tree.terminate():
                return False
        else:
            kill_process_group = getattr(os, "killpg", None)
            kill_signal = getattr(signal, "SIGKILL", None)
            if not callable(kill_process_group) or not isinstance(kill_signal, int):
                return False
            try:
                kill_process_group(process.pid, kill_signal)
            except ProcessLookupError:
                return process.poll() is not None
        process.wait(timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass(frozen=True, slots=True)
class _ExecutableMeasurement:
    device: int
    inode: int
    byte_count: int
    modified_at_ns: int
    raw_sha512: str


def _is_reparse_or_symlink(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
    )


def _reject_unsafe_path_components(path: Path, *, code: str) -> None:
    try:
        absolute = Path(os.path.abspath(str(path)))
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if _is_reparse_or_symlink(metadata):
                raise reject(code)
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject(code) from exc


def _reject_hostile_inherited_git_environment() -> None:
    if any(name in os.environ for name in _REJECTED_GIT_ENVIRONMENT):
        raise reject("INHERITED_GIT_REDIRECTION_REJECTED")
    home = os.environ.get("HOME")
    if home:
        try:
            if (Path(home) / ".gitconfig").exists():
                raise reject("INHERITED_GIT_HOME_CONFIG_REJECTED")
        except PTDEVerificationError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise reject("INHERITED_GIT_HOME_CONFIG_UNAVAILABLE") from exc
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        try:
            if (Path(xdg) / "git" / "config").exists():
                raise reject("INHERITED_GIT_XDG_CONFIG_REJECTED")
        except PTDEVerificationError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise reject("INHERITED_GIT_XDG_CONFIG_UNAVAILABLE") from exc


def _measure_pinned_regular_file(
    path: Path, *, maximum_bytes: int
) -> _ExecutableMeasurement:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_or_symlink(before)
            or before.st_size > maximum_bytes
        ):
            raise reject("GIT_EXECUTABLE_FILE_INVALID")
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            identity_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            )
            identity_opened = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            )
            if identity_opened != identity_before:
                raise reject("GIT_EXECUTABLE_IDENTITY_CHANGED")
            digest = hashlib.sha512()
            observed = 0
            while True:
                chunk = os.read(descriptor, min(1_048_576, maximum_bytes + 1 - observed))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise reject("GIT_EXECUTABLE_SIZE_LIMIT_EXCEEDED")
                digest.update(chunk)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != identity_before
            or _is_reparse_or_symlink(after)
        ):
            raise reject("GIT_EXECUTABLE_IDENTITY_CHANGED")
        return _ExecutableMeasurement(
            device=before.st_dev,
            inode=before.st_ino,
            byte_count=before.st_size,
            modified_at_ns=before.st_mtime_ns,
            raw_sha512=digest.hexdigest(),
        )
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("GIT_EXECUTABLE_UNAVAILABLE") from exc


def _resolve_and_pin_git_executable(
    value: Any, expected_sha512: str
) -> tuple[Path, _ExecutableMeasurement]:
    if type(value) is not str or not value or "\x00" in value:
        raise reject("GIT_EXECUTABLE_INVALID")
    located = shutil.which(value) if not Path(value).is_absolute() else value
    if not located:
        raise reject("GIT_EXECUTABLE_NOT_FOUND")
    path = Path(located)
    if path.suffix.casefold() in {".bat", ".cmd", ".ps1"}:
        raise reject("GIT_EXECUTABLE_PROXY_REJECTED")
    _reject_unsafe_path_components(path, code="GIT_EXECUTABLE_PATH_UNSAFE")
    resolved = path.resolve(strict=True)
    if os.path.normcase(os.path.abspath(str(path))) != os.path.normcase(str(resolved)):
        raise reject("GIT_EXECUTABLE_PATH_RESOLUTION_CHANGED")
    measurement = _measure_pinned_regular_file(
        resolved, maximum_bytes=MAX_GIT_EXECUTABLE_BYTES
    )
    if measurement.raw_sha512 != expected_sha512:
        raise reject("GIT_EXECUTABLE_NOT_OUT_OF_BAND_PINNED")
    return resolved, measurement


def _verify_pinned_executable(
    path: Path,
    expected_sha512: str,
    baseline: _ExecutableMeasurement,
) -> _ExecutableMeasurement:
    observed = _measure_pinned_regular_file(
        path, maximum_bytes=MAX_GIT_EXECUTABLE_BYTES
    )
    if observed.raw_sha512 != expected_sha512 or observed != baseline:
        raise reject("GIT_EXECUTABLE_CHANGED")
    return observed


@dataclass(frozen=True, slots=True)
class GitObject:
    oid: str
    object_type: str
    content: bytes
    raw_bytes: bytes
    raw_sha512: str


@dataclass(frozen=True, slots=True)
class CommitObject:
    oid: str
    tree_oid: str
    parent_oids: tuple[str, ...]
    raw_sha512: str


@dataclass(frozen=True, slots=True)
class TreeBlob:
    path: str
    mode: str
    blob_oid: str
    byte_count: int
    blob_sha512: str
    blob_raw_sha512: str

    def record(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "mode": self.mode,
            "blob_oid": self.blob_oid,
            "blob_sha512": self.blob_sha512,
            "blob_raw_sha512": self.blob_raw_sha512,
            "byte_count": self.byte_count,
        }


class GitObjectDatabase:
    """A no-checkout object reader. Refs, HEAD, replacements and grafts are not inputs."""

    def __init__(
        self,
        object_database: str | Path,
        *,
        git_executable: str,
        expected_git_executable_sha512: str,
    ) -> None:
        try:
            supplied = Path(object_database)
            if not supplied.is_absolute():
                raise reject("OBJECT_DATABASE_NOT_ABSOLUTE")
            _reject_unsafe_path_components(supplied, code="OBJECT_DATABASE_PATH_UNSAFE")
            metadata = supplied.lstat()
            resolved = supplied.resolve(strict=True)
        except PTDEVerificationError:
            raise
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            raise reject("OBJECT_DATABASE_UNAVAILABLE") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise reject("OBJECT_DATABASE_NOT_DIRECTORY")
        if os.path.normcase(os.path.abspath(str(supplied))) != os.path.normcase(str(resolved)):
            raise reject("OBJECT_DATABASE_PATH_RESOLUTION_CHANGED")
        _reject_unsafe_path_components(resolved / "objects", code="OBJECT_DATABASE_OBJECTS_PATH_UNSAFE")
        if not (resolved / "objects").is_dir() or not (resolved / "HEAD").is_file():
            raise reject("OBJECT_DATABASE_NOT_BARE_GIT_DIR")
        _reject_unsafe_path_components(resolved / "HEAD", code="OBJECT_DATABASE_HEAD_PATH_UNSAFE")
        if (resolved / "config").exists():
            _reject_unsafe_path_components(
                resolved / "config", code="OBJECT_DATABASE_CONFIG_PATH_UNSAFE"
            )
        if (resolved / ".git").exists():
            raise reject("WORKING_TREE_ROOT_REJECTED")
        forbidden = (
            resolved / "info" / "grafts",
            resolved / "objects" / "info" / "alternates",
            resolved / "objects" / "info" / "http-alternates",
            resolved / "refs" / "replace",
            resolved / "shallow",
            resolved / "shallow.lock",
            resolved / "commondir",
        )
        for path in forbidden:
            if path.exists():
                raise reject("OBJECT_SUBSTITUTION_MECHANISM_PRESENT")
        _reject_hostile_inherited_git_environment()
        self._git_dir = resolved
        self._expected_git_executable_sha512 = require_sha512(
            expected_git_executable_sha512, "EXPECTED_GIT_EXECUTABLE_DIGEST_INVALID"
        )
        self._git_executable, self._git_executable_measurement = _resolve_and_pin_git_executable(
            git_executable, self._expected_git_executable_sha512
        )
        self._object_cache: dict[str, GitObject] = {}
        self._total_object_bytes = 0
        object_format = self._run_text("rev-parse", "--show-object-format").strip()
        if object_format not in {"sha1", "sha256"}:
            raise reject("GIT_OBJECT_FORMAT_UNSUPPORTED")
        self.object_format = object_format
        self.oid_hex_length = 40 if object_format == "sha1" else 64
        self.oid_byte_length = self.oid_hex_length // 2

    @property
    def git_dir(self) -> Path:
        return self._git_dir

    def require_oid(self, value: Any, *, code: str = "OID_INVALID") -> str:
        if (
            type(value) is not str
            or len(value) != self.oid_hex_length
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise reject(code)
        return value

    def _environment(self) -> dict[str, str]:
        environment = {
            key: os.environ[key]
            for key in ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
            if key in os.environ
        }
        environment.update(
            {
                "GIT_CONFIG_COUNT": "0",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "LC_ALL": "C",
            }
        )
        return environment

    def _run(
        self,
        *arguments: str,
        stdout_limit: int = MAX_GIT_SUBPROCESS_METADATA_BYTES,
    ) -> bytes:
        if type(stdout_limit) is not int or stdout_limit < 0 or stdout_limit > MAX_GIT_OBJECT_BYTES:
            raise reject("GIT_SUBPROCESS_OUTPUT_LIMIT_INVALID")
        before_executable = _verify_pinned_executable(
            self._git_executable,
            self._expected_git_executable_sha512,
            self._git_executable_measurement,
        )
        command = (
            str(self._git_executable),
            f"--git-dir={self._git_dir}",
            "-c",
            "core.replaceRefs=false",
            "-c",
            "core.useReplaceRefs=false",
            *arguments,
        )
        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process: subprocess.Popen[bytes] | None = None
                windows_tree: _WindowsProcessTree | None = None
                tree_terminated = False
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        shell=False,
                        env=self._environment(),
                        start_new_session=os.name != "nt",
                        creationflags=_process_creation_flags(),
                    )
                    try:
                        windows_tree = _WindowsProcessTree(process)
                    except BaseException as exc:
                        try:
                            process.kill()
                            process.wait(timeout=5)
                            tree_terminated = True
                        except (OSError, subprocess.SubprocessError) as cleanup_exc:
                            raise reject(
                                "GIT_PROCESS_TREE_TERMINATION_FAILED"
                            ) from cleanup_exc
                        raise exc
                    deadline = time.monotonic() + MAX_GIT_SUBPROCESS_SECONDS
                    exceeded = False
                    while process.poll() is None:
                        if (
                            os.fstat(stdout_file.fileno()).st_size > stdout_limit
                            or os.fstat(stderr_file.fileno()).st_size
                            > MAX_GIT_SUBPROCESS_METADATA_BYTES
                        ):
                            exceeded = True
                            tree_terminated = _terminate_process_tree(
                                process, windows_tree
                            )
                            if not tree_terminated:
                                raise reject(
                                    "GIT_PROCESS_TREE_TERMINATION_FAILED"
                                )
                            break
                        if time.monotonic() >= deadline:
                            tree_terminated = _terminate_process_tree(
                                process, windows_tree
                            )
                            if not tree_terminated:
                                raise reject(
                                    "GIT_PROCESS_TREE_TERMINATION_FAILED"
                                )
                            raise reject("GIT_OBJECT_READ_TIMEOUT")
                        time.sleep(0.01)
                    returncode = process.wait(timeout=5)
                    if not tree_terminated:
                        tree_terminated = _terminate_process_tree(
                            process, windows_tree
                        )
                        if not tree_terminated:
                            raise reject(
                                "GIT_PROCESS_TREE_TERMINATION_FAILED"
                            )
                    stdout_size = os.fstat(stdout_file.fileno()).st_size
                    stderr_size = os.fstat(stderr_file.fileno()).st_size
                    if (
                        exceeded
                        or stdout_size > stdout_limit
                        or stderr_size > MAX_GIT_SUBPROCESS_METADATA_BYTES
                    ):
                        raise reject("GIT_SUBPROCESS_OUTPUT_LIMIT_EXCEEDED")
                    stdout_file.seek(0)
                    stderr_file.seek(0)
                    stdout = stdout_file.read(stdout_limit + 1)
                    stderr = stderr_file.read(
                        MAX_GIT_SUBPROCESS_METADATA_BYTES + 1
                    )
                except BaseException as exc:
                    if process is not None and not tree_terminated:
                        tree_terminated = _terminate_process_tree(
                            process, windows_tree
                        )
                        if not tree_terminated:
                            raise reject(
                                "GIT_PROCESS_TREE_TERMINATION_FAILED"
                            ) from exc
                    raise
                finally:
                    if windows_tree is not None:
                        windows_tree.close()
        except PTDEVerificationError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise reject("GIT_OBJECT_READ_UNAVAILABLE") from exc
        after_executable = _verify_pinned_executable(
            self._git_executable,
            self._expected_git_executable_sha512,
            self._git_executable_measurement,
        )
        if after_executable != before_executable:
            raise reject("GIT_EXECUTABLE_CHANGED_DURING_INVOCATION")
        if returncode != 0 or stderr:
            raise reject("GIT_OBJECT_READ_FAILED")
        return stdout

    def _run_text(self, *arguments: str) -> str:
        try:
            return self._run(*arguments).decode("ascii", errors="strict")
        except UnicodeError as exc:
            raise reject("GIT_METADATA_NOT_ASCII") from exc

    def read_object(self, oid: Any, *, expected_type: str | None = None) -> GitObject:
        exact_oid = self.require_oid(oid)
        cached = self._object_cache.get(exact_oid)
        if cached is not None:
            if expected_type is not None and cached.object_type != expected_type:
                raise reject("GIT_OBJECT_TYPE_MISMATCH")
            return cached
        object_type = self._run_text("cat-file", "-t", exact_oid).strip()
        if object_type not in {"blob", "tree", "commit"}:
            raise reject("GIT_OBJECT_TYPE_REJECTED")
        if expected_type is not None and object_type != expected_type:
            raise reject("GIT_OBJECT_TYPE_MISMATCH")
        size_text = self._run_text("cat-file", "-s", exact_oid).strip()
        if not size_text.isascii() or not size_text.isdecimal():
            raise reject("GIT_OBJECT_SIZE_INVALID")
        size = int(size_text, 10)
        raw_header = f"{object_type} {size}\0".encode("ascii")
        raw_size = len(raw_header) + size
        if raw_size > MAX_GIT_OBJECT_BYTES:
            raise reject("GIT_OBJECT_SIZE_LIMIT_EXCEEDED")
        if self._total_object_bytes + raw_size > MAX_TOTAL_GIT_OBJECT_BYTES:
            raise reject("GIT_TOTAL_OBJECT_BYTE_BUDGET_EXCEEDED")
        content = self._run("cat-file", object_type, exact_oid, stdout_limit=size)
        if len(content) != size:
            raise reject("GIT_OBJECT_SIZE_CHANGED")
        raw = raw_header + content
        algorithm = hashlib.sha1 if self.object_format == "sha1" else hashlib.sha256
        if algorithm(raw).hexdigest() != exact_oid:
            raise reject("GIT_OBJECT_OID_MISMATCH")
        result = GitObject(
            oid=exact_oid,
            object_type=object_type,
            content=content,
            raw_bytes=raw,
            raw_sha512=sha512_hex(raw),
        )
        self._object_cache[exact_oid] = result
        self._total_object_bytes += raw_size
        return result

    def read_commit(self, oid: Any) -> CommitObject:
        obj = self.read_object(oid, expected_type="commit")
        header = obj.content.split(b"\n\n", 1)[0]
        tree_oids: list[str] = []
        parent_oids: list[str] = []
        for line in header.splitlines():
            if line.startswith(b"tree "):
                try:
                    tree_oids.append(line[5:].decode("ascii", errors="strict"))
                except UnicodeError as exc:
                    raise reject("COMMIT_TREE_OID_INVALID") from exc
            elif line.startswith(b"parent "):
                try:
                    parent_oids.append(line[7:].decode("ascii", errors="strict"))
                    if len(parent_oids) > MAX_COMMIT_PARENT_COUNT:
                        raise reject("COMMIT_PARENT_COUNT_LIMIT_EXCEEDED")
                except UnicodeError as exc:
                    raise reject("COMMIT_PARENT_OID_INVALID") from exc
        if len(tree_oids) != 1:
            raise reject("COMMIT_TREE_HEADER_INVALID")
        tree_oid = self.require_oid(tree_oids[0], code="COMMIT_TREE_OID_INVALID")
        parents = tuple(
            self.require_oid(parent, code="COMMIT_PARENT_OID_INVALID")
            for parent in parent_oids
        )
        self.read_object(tree_oid, expected_type="tree")
        return CommitObject(obj.oid, tree_oid, parents, obj.raw_sha512)

    def read_blob(self, oid: Any) -> GitObject:
        return self.read_object(oid, expected_type="blob")

    def flatten_tree(self, tree_oid: Any) -> dict[str, TreeBlob]:
        root_oid = self.require_oid(tree_oid, code="TREE_OID_INVALID")
        records: dict[str, TreeBlob] = {}
        casefolded: dict[str, str] = {}
        active_trees: set[str] = set()
        tree_count = 0
        entry_count = 0
        blob_count = 0

        def walk(current_oid: str, prefix: str, depth: int) -> None:
            nonlocal tree_count, entry_count, blob_count
            if depth > MAX_TREE_DEPTH:
                raise reject("TREE_DEPTH_LIMIT_EXCEEDED")
            if current_oid in active_trees:
                raise reject("TREE_CYCLE_REJECTED")
            tree_count += 1
            if tree_count > MAX_TREE_COUNT:
                raise reject("TREE_COUNT_LIMIT_EXCEEDED")
            active_trees.add(current_oid)
            tree = self.read_object(current_oid, expected_type="tree")
            offset = 0
            names: set[bytes] = set()
            previous_sort_key: bytes | None = None
            while offset < len(tree.content):
                entry_count += 1
                if entry_count > MAX_TREE_ENTRY_COUNT:
                    raise reject("TREE_ENTRY_COUNT_LIMIT_EXCEEDED")
                space = tree.content.find(b" ", offset)
                nul = tree.content.find(b"\0", space + 1)
                if space <= offset or nul < 0:
                    raise reject("TREE_ENTRY_ENCODING_INVALID")
                mode_bytes = tree.content[offset:space]
                name_bytes = tree.content[space + 1 : nul]
                oid_start = nul + 1
                oid_end = oid_start + self.oid_byte_length
                if oid_end > len(tree.content) or not name_bytes or name_bytes in names:
                    raise reject("TREE_ENTRY_ENCODING_INVALID")
                names.add(name_bytes)
                try:
                    mode = mode_bytes.decode("ascii", errors="strict")
                    name = name_bytes.decode("utf-8", errors="strict")
                except UnicodeError as exc:
                    raise reject("TREE_ENTRY_TEXT_INVALID") from exc
                child_oid = tree.content[oid_start:oid_end].hex()
                sort_key = name_bytes + (b"/" if mode == TREE_MODE else b"\0")
                if previous_sort_key is not None and sort_key <= previous_sort_key:
                    raise reject("TREE_ENTRY_ORDER_INVALID")
                previous_sort_key = sort_key
                path = canonical_path(f"{prefix}/{name}" if prefix else name)
                folded = path.casefold()
                if folded in casefolded and casefolded[folded] != path:
                    raise reject("TREE_PATH_CASEFOLD_COLLISION")
                casefolded[folded] = path
                if mode == TREE_MODE:
                    self.read_object(child_oid, expected_type="tree")
                    walk(child_oid, path, depth + 1)
                elif mode in REGULAR_BLOB_MODES:
                    blob_count += 1
                    if blob_count > MAX_BLOB_COUNT:
                        raise reject("TREE_BLOB_COUNT_LIMIT_EXCEEDED")
                    blob = self.read_blob(child_oid)
                    records[path] = TreeBlob(
                        path=path,
                        mode=mode,
                        blob_oid=child_oid,
                        byte_count=len(blob.content),
                        blob_sha512=sha512_hex(blob.content),
                        blob_raw_sha512=blob.raw_sha512,
                    )
                elif mode in {SYMLINK_MODE, GITLINK_MODE}:
                    raise reject("TREE_SYMLINK_OR_GITLINK_REJECTED")
                else:
                    raise reject("TREE_NON_BLOB_ENTRY_REJECTED")
                offset = oid_end
            if offset != len(tree.content):
                raise reject("TREE_ENTRY_TRAILING_BYTES")
            active_trees.remove(current_oid)

        walk(root_oid, "", 1)
        return {path: records[path] for path in sorted(records)}


def require_direct_child(child: CommitObject, parent_oid: str, *, stage: str) -> None:
    if child.parent_oids != (parent_oid,):
        raise reject(f"{stage}_NOT_SOLE_DIRECT_CHILD")


def exact_added_blob_delta(
    parent: dict[str, TreeBlob],
    child: dict[str, TreeBlob],
    *,
    added_path: str,
    stage: str,
) -> TreeBlob:
    target = canonical_path(added_path)
    parent_paths = set(parent)
    child_paths = set(child)
    if child_paths - parent_paths != {target} or parent_paths - child_paths:
        raise reject(f"{stage}_DELTA_INVALID")
    for path in parent_paths:
        if parent[path] != child[path]:
            raise reject(f"{stage}_MODIFICATION_OR_MODE_CHANGE")
    return child[target]


__all__ = [
    "CommitObject",
    "GitObject",
    "GitObjectDatabase",
    "TreeBlob",
    "exact_added_blob_delta",
    "require_direct_child",
]
