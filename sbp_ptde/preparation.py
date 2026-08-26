"""Fail-closed preparation of non-authorizing P/T/D/E inputs.

This module prepares candidate documents only.  It never selects P, creates
commits, executes assurance lanes, accepts evidence, or grants admission.
"""

from __future__ import annotations

import ast
import ctypes
import os
import stat
import subprocess
import tempfile
import time
from collections.abc import Mapping
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbp_lex.local_trust.constants import (
    ACCEPTED_HISTORY_SCHEMA,
    HISTORY_SIGNING_PURPOSE,
    PRODUCTION,
)
from sbp_lex.local_trust.history import validate_accepted_package_history
from sbp_lex.local_trust.signing import (
    LocalTrustSignatureError,
    verification_context_from_record,
)
from sbp_lex.supply_chain.python_inventory import (
    PYTHON_LOCK_PATH,
    PYTHON_LOCK_SCHEMA,
    build_python_dependency_inputs,
)
from sbp_lex.supply_chain.source_binding import (
    PObjectBinding,
    bind_p_object,
    p_blob_content,
    validate_p_binding_document,
)

from .canonical import (
    campaign_id,
    canonical_json_document_bytes,
    canonical_path,
    canonical_sha512,
    exact_fields,
    identifier,
    require_sha512,
    sha512_hex,
    strict_json_document,
)
from .constants import (
    ASSURANCE_LIMITS,
    CALLABLE_ALLOWED_SET,
    D_DESCRIPTOR_PATH,
    D_SCHEMA_ID,
    E_MANIFEST_NAME,
    E_SCHEMA_ID,
    EVIDENCE_ROOT,
    INVENTORY_CLASSES,
    MAX_GIT_SUBPROCESS_METADATA_BYTES,
    MAX_GIT_SUBPROCESS_SECONDS,
    MAX_JSON_DOCUMENT_BYTES,
    MAX_TRANSCRIPT_BYTE_COUNT,
    NO_AUTHORITY,
    POLICY_PATH,
    T_PROFILE_PATH,
    T_SCHEMA_ID,
    TRANSCRIPT_SCHEMA_ID,
    assurance_limits_document,
)
from .errors import PTDEVerificationError, reject
from .git_objects import (
    CommitObject,
    GitObjectDatabase,
    TreeBlob,
    _is_reparse_or_symlink,
    _process_creation_flags,
    _reject_hostile_inherited_git_environment,
    _reject_unsafe_path_components,
    _resolve_and_pin_git_executable,
    _terminate_process_tree,
    _verify_pinned_executable,
    _WindowsProcessTree,
    exact_added_blob_delta,
    require_direct_child,
)
from .policy import policy_document_bytes
from .schemas import validate_d_descriptor, validate_lanes, validate_t_profile
from .trust import AcceptedAttemptHistory, accepted_attempt_history_from_document

P_PREPARATION_SCHEMA = "sbp.lex.v2.ptde.p-selection-preparation/1"
E_INPUT_PREPARATION_SCHEMA = "sbp.lex.v2.ptde.e-campaign-inputs/1"
P_PREPARATION_STATE = "CANDIDATE_VALIDATED_OWNER_SELECTION_REQUIRED"
E_INPUT_PREPARATION_STATE = "EXTERNAL_LANE_EXECUTION_INPUTS_REQUIRED"
NOT_SELECTED = "NOT_SELECTED"
NOT_ADMITTED = "NOT_ADMITTED"

_P_PACKET_FIELDS = frozenset({
    "schema_id",
    "stage_sequence",
    "candidate_binding",
    "local_trust_history_binding",
    "python_dependency_binding",
    "preparation_state",
    "p_selection_state",
    "admission_state",
    "no_authority",
    "packet_sha512",
})
_LOCAL_HISTORY_BINDING_FIELDS = frozenset({
    "schema_id",
    "history_id",
    "sequence",
    "history_digest",
    "repository_identity_digest",
    "history_context_digest",
    "signing_purpose",
    "validation_status",
})
_PYTHON_BINDING_FIELDS = frozenset({
    "schema_id",
    "python_lock_schema_id",
    "python_lock_blob",
    "python_inputs_sha512",
    "dependency_evidence_status",
})
_TREE_BLOB_FIELDS = frozenset({
    "path",
    "mode",
    "blob_oid",
    "blob_sha512",
    "blob_raw_sha512",
    "byte_count",
})
_E_INPUT_FIELDS = frozenset({
    "schema_id",
    "stage_sequence",
    "p_packet_sha512",
    "object_bindings",
    "fixed_manifest_bindings",
    "campaign_id",
    "expected_e_parent_commit_oid",
    "campaign_root",
    "manifest_path",
    "required_manifest_schema_id",
    "approved_lane_order",
    "lane_input_requirements",
    "e_commit_state",
    "evidence_state",
    "preparation_state",
    "admission_state",
    "no_authority",
    "assurance_limits",
    "skeleton_sha512",
})
_OBJECT_BINDING_FIELDS = frozenset({
    "commit_oid",
    "commit_raw_sha512",
    "tree_oid",
    "tree_raw_sha512",
})
_FIXED_E_MANIFEST_BINDING_FIELDS = frozenset({
    "p_commit_oid",
    "p_tree_oid",
    "t_commit_oid",
    "t_tree_oid",
    "d_commit_oid",
    "d_tree_oid",
    "d_descriptor_path",
    "d_descriptor_blob_oid",
    "d_descriptor_sha512",
    "d_descriptor_blob_raw_sha512",
    "policy_sha512",
    "t_profile_sha512",
    "p_inventory_sha512",
    "lanes_sha512",
})
_LANE_INPUT_FIELDS = frozenset({
    "lane_id",
    "order",
    "committed_lane_contract",
    "lane_contract_sha512",
    "required_transcript_schema_id",
    "transcript_relative_path",
    "transcript_maximum_byte_count",
    "required_external_result_fields",
})
_D_FINGERPRINT_FIELDS = frozenset({
    "os_fingerprint_sha512",
    "build_fingerprint_sha512",
    "architecture_fingerprint_sha512",
    "runtime_fingerprint_sha512",
    "toolchain_fingerprint_sha512",
})
_REQUIRED_EXTERNAL_RESULT_FIELDS = (
    "attempt_id",
    "argv",
    "authority_mutation_observed",
    "cleanup_completed",
    "command_executed",
    "d_commit_oid",
    "d_descriptor_sha512",
    "error",
    "exit_status",
    "finished_at_unix_ms",
    "lane_id",
    "ledger_mutation_observed",
    "output_truncated",
    "process_tree_terminated",
    "produced_artifacts",
    "setup_completed",
    "source_mutation_observed",
    "started_at_unix_ms",
    "status",
    "stderr_byte_count",
    "stderr_full_bytes",
    "stderr_path",
    "stderr_sha512",
    "stdout_byte_count",
    "stdout_full_bytes",
    "stdout_path",
    "stdout_sha512",
    "timed_out",
    "timeout_seconds",
    "timeout_status",
    "transcript_byte_count",
    "transcript_path",
    "transcript_sha512",
    "wall_clock_milliseconds",
)
_SCRIPT_GIT_SUFFIXES = frozenset({".bat", ".cmd", ".ps1", ".py", ".sh"})


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
    )


def _require_native_pinned_git_executable(
    git_executable: str, expected_git_executable_sha512: str
) -> None:
    """Reject script/proxy Git launchers even when their bytes are pinned."""

    expected = require_sha512(
        expected_git_executable_sha512,
        "PTDE_PREPARATION_EXPECTED_GIT_EXECUTABLE_INVALID",
    )
    executable, baseline = _resolve_and_pin_git_executable(
        git_executable, expected
    )
    if executable.suffix.casefold() in _SCRIPT_GIT_SUFFIXES:
        raise reject("PTDE_PREPARATION_GIT_SCRIPT_REJECTED")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(executable, flags)
        try:
            opened = os.fstat(descriptor)
            header = os.read(descriptor, 4)
        finally:
            os.close(descriptor)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("PTDE_PREPARATION_GIT_EXECUTABLE_UNAVAILABLE") from exc
    if (
        opened.st_dev != baseline.device
        or opened.st_ino != baseline.inode
        or opened.st_size != baseline.byte_count
        or opened.st_mtime_ns != baseline.modified_at_ns
    ):
        raise reject("PTDE_PREPARATION_GIT_EXECUTABLE_CHANGED")
    _verify_pinned_executable(executable, expected, baseline)
    if header.startswith(b"#!"):
        raise reject("PTDE_PREPARATION_GIT_SCRIPT_REJECTED")


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
        raise reject("PTDE_PREPARATION_WINDOWS_HANDLE_UNAVAILABLE")
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _open_windows_output_parent(parent: Path) -> int:
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
    handle = create_file(
        str(parent),
        0x40100081,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle is None or int(handle) == invalid_handle:
        raise reject("PTDE_PREPARATION_OUTPUT_PARENT_HANDLE_FAILED")
    return int(handle)


def _windows_output_parent_path(handle: int) -> Path:
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
        raise reject("PTDE_PREPARATION_OUTPUT_PARENT_HANDLE_PATH_FAILED")
    rendered = buffer.value
    if rendered.startswith("\\\\?\\UNC\\"):
        rendered = "\\\\" + rendered[8:]
    elif rendered.startswith("\\\\?\\"):
        rendered = rendered[4:]
    return Path(rendered)


def _open_windows_relative_output(parent_handle: int, leaf_name: str) -> int:
    if os.name != "nt":
        raise reject("PTDE_PREPARATION_WINDOWS_HANDLE_UNAVAILABLE")
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
        0x40100080,
        ctypes.byref(attributes),
        ctypes.byref(io_status),
        None,
        0x00000080,
        0,
        2,
        0x00000020 | 0x00000040 | 0x00200000,
        None,
        0,
    )
    if status != 0 or not file_handle.value:
        raise reject("PTDE_PREPARATION_OUTPUT_EXCLUSIVE_CREATE_FAILED")
    try:
        return msvcrt.open_osfhandle(
            int(file_handle.value),
            os.O_WRONLY | getattr(os, "O_BINARY", 0),
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        _close_windows_handle(int(file_handle.value))
        raise reject("PTDE_PREPARATION_OUTPUT_EXCLUSIVE_CREATE_FAILED") from exc


def _flush_windows_output_parent(handle: int) -> None:
    kernel32 = _windows_kernel32()
    flush = kernel32.FlushFileBuffers
    flush.argtypes = [wintypes.HANDLE]
    flush.restype = wintypes.BOOL
    if not flush(wintypes.HANDLE(handle)):
        error = ctypes.get_last_error()
        if error not in {1, 6, 50}:
            raise reject("PTDE_PREPARATION_OUTPUT_PARENT_FLUSH_FAILED")


def _close_windows_handle(handle: int) -> None:
    kernel32 = _windows_kernel32()
    close = kernel32.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    close(wintypes.HANDLE(handle))


def read_canonical_document_file(path_value: str | Path, *, code: str) -> dict[str, Any]:
    """Read one stable, unaliased canonical JSON document."""

    try:
        path = Path(path_value)
        if not path.is_absolute():
            raise reject(f"{code}_PATH_NOT_ABSOLUTE")
        _reject_unsafe_path_components(path, code=f"{code}_PATH_UNSAFE")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_or_symlink(before)
            or before.st_nlink != 1
            or before.st_size > MAX_JSON_DOCUMENT_BYTES
        ):
            raise reject(f"{code}_FILE_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            if _file_identity(opened_before) != _file_identity(before):
                raise reject(f"{code}_FILE_CHANGED")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(descriptor, min(1_048_576, MAX_JSON_DOCUMENT_BYTES + 1 - observed))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_JSON_DOCUMENT_BYTES:
                    raise reject(f"{code}_FILE_INVALID")
                chunks.append(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            len(
                {
                    _file_identity(before),
                    _file_identity(opened_before),
                    _file_identity(opened_after),
                    _file_identity(after),
                }
            )
            != 1
            or _is_reparse_or_symlink(after)
        ):
            raise reject(f"{code}_FILE_CHANGED")
        return strict_json_document(b"".join(chunks), code=code)
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject(f"{code}_FILE_UNAVAILABLE") from exc


def write_canonical_document_exclusive(
    document: Mapping[str, Any], output_path: str | Path
) -> str:
    """Persist canonical bytes exactly once without replacing an existing path."""

    path = Path(output_path)
    if not path.is_absolute():
        raise reject("PTDE_PREPARATION_OUTPUT_PATH_NOT_ABSOLUTE")
    content = canonical_json_document_bytes(dict(document))
    parent_descriptor: int | None = None
    windows_parent_handle: int | None = None
    try:
        _reject_unsafe_path_components(
            path.parent, code="PTDE_PREPARATION_OUTPUT_PARENT_UNSAFE"
        )
        resolved_parent = path.parent.resolve(strict=True)
        if os.path.normcase(os.path.abspath(str(path.parent))) != os.path.normcase(
            str(resolved_parent)
        ):
            raise reject("PTDE_PREPARATION_OUTPUT_PARENT_RESOLUTION_CHANGED")
        parent_before = resolved_parent.lstat()
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or _is_reparse_or_symlink(parent_before)
        ):
            raise reject("PTDE_PREPARATION_OUTPUT_PARENT_INVALID")
        canonical_path(
            path.name, code="PTDE_PREPARATION_OUTPUT_NAME_INVALID"
        )
        if os.name == "nt":
            windows_parent_handle = _open_windows_output_parent(resolved_parent)
            held_parent = _windows_output_parent_path(windows_parent_handle)
            if os.path.normcase(os.path.abspath(str(held_parent))) != os.path.normcase(
                str(resolved_parent)
            ):
                raise reject("PTDE_PREPARATION_OUTPUT_PARENT_CHANGED")
        elif os.open in os.supports_dir_fd:
            parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            parent_flags |= getattr(os, "O_CLOEXEC", 0)
            parent_flags |= getattr(os, "O_NOFOLLOW", 0)
            parent_descriptor = os.open(resolved_parent, parent_flags)
            parent_opened = os.fstat(parent_descriptor)
            if (
                parent_opened.st_dev != parent_before.st_dev
                or parent_opened.st_ino != parent_before.st_ino
                or not stat.S_ISDIR(parent_opened.st_mode)
            ):
                raise reject("PTDE_PREPARATION_OUTPUT_PARENT_CHANGED")
        else:
            raise reject("PTDE_PREPARATION_OUTPUT_RELATIVE_CREATE_UNAVAILABLE")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        if windows_parent_handle is not None:
            descriptor = _open_windows_relative_output(
                windows_parent_handle, path.name
            )
        elif parent_descriptor is not None:
            descriptor = os.open(
                path.name,
                flags,
                0o600,
                dir_fd=parent_descriptor,
            )
        else:
            raise reject("PTDE_PREPARATION_OUTPUT_RELATIVE_CREATE_UNAVAILABLE")
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise reject("PTDE_PREPARATION_OUTPUT_INVALID")
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise reject("PTDE_PREPARATION_OUTPUT_WRITE_FAILED")
                offset += written
            os.fsync(descriptor)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if parent_descriptor is not None:
            os.fsync(parent_descriptor)
        elif windows_parent_handle is not None:
            _flush_windows_output_parent(windows_parent_handle)
        parent_after = path.parent.resolve(strict=True).lstat()
        leaf = path.lstat()
        if (
            (parent_before.st_dev, parent_before.st_ino)
            != (parent_after.st_dev, parent_after.st_ino)
            or _is_reparse_or_symlink(leaf)
            or not stat.S_ISREG(leaf.st_mode)
            or leaf.st_nlink != 1
            or (opened_after.st_dev, opened_after.st_ino)
            != (leaf.st_dev, leaf.st_ino)
        ):
            raise reject("PTDE_PREPARATION_OUTPUT_CHANGED")
        persisted_document = read_canonical_document_file(
            path, code="PTDE_PREPARATION_OUTPUT_PERSISTED"
        )
        persisted = canonical_json_document_bytes(persisted_document)
        parent_final = path.parent.resolve(strict=True).lstat()
        leaf_final = path.lstat()
        parent_descriptor_final = (
            os.fstat(parent_descriptor)
            if parent_descriptor is not None
            else parent_final
        )
        windows_parent_final = (
            _windows_output_parent_path(windows_parent_handle)
            if windows_parent_handle is not None
            else resolved_parent
        )
        if (
            (parent_before.st_dev, parent_before.st_ino)
            != (parent_final.st_dev, parent_final.st_ino)
            or (parent_before.st_dev, parent_before.st_ino)
            != (
                parent_descriptor_final.st_dev,
                parent_descriptor_final.st_ino,
            )
            or (opened_after.st_dev, opened_after.st_ino)
            != (leaf_final.st_dev, leaf_final.st_ino)
            or _is_reparse_or_symlink(leaf_final)
            or leaf_final.st_nlink != 1
            or os.path.normcase(os.path.abspath(str(windows_parent_final)))
            != os.path.normcase(str(resolved_parent))
        ):
            raise reject("PTDE_PREPARATION_OUTPUT_CHANGED")
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("PTDE_PREPARATION_OUTPUT_EXCLUSIVE_CREATE_FAILED") from exc
    finally:
        if parent_descriptor is not None:
            try:
                os.close(parent_descriptor)
            except OSError:
                pass
        if windows_parent_handle is not None:
            _close_windows_handle(windows_parent_handle)
    if (
        persisted != content
        or strict_json_document(persisted, code="PTDE_PREPARATION_OUTPUT")
        != dict(document)
    ):
        raise reject("PTDE_PREPARATION_OUTPUT_SELF_VALIDATION_FAILED")
    return sha512_hex(content)


def _worktree_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if name in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        }
    )
    return environment


def _run_worktree_git(
    repository_root: Path,
    *,
    git_executable: str,
    expected_git_executable_sha512: str,
    arguments: tuple[str, ...],
) -> tuple[int, bytes]:
    """Run pinned Git with bounded full-byte output and tree containment."""

    _require_native_pinned_git_executable(
        git_executable, expected_git_executable_sha512
    )
    expected = require_sha512(
        expected_git_executable_sha512,
        "PTDE_PREPARATION_EXPECTED_GIT_EXECUTABLE_INVALID",
    )
    _reject_hostile_inherited_git_environment()
    executable, baseline = _resolve_and_pin_git_executable(git_executable, expected)
    before = _verify_pinned_executable(executable, expected, baseline)
    command = (
        str(executable),
        "--no-optional-locks",
        "-C",
        str(repository_root),
        "-c",
        "core.replaceRefs=false",
        "-c",
        "core.useReplaceRefs=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        *arguments,
    )
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process: subprocess.Popen[bytes] | None = None
            windows_tree: _WindowsProcessTree | None = None
            terminated = False
            try:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    env=_worktree_environment(),
                    start_new_session=os.name != "nt",
                    creationflags=_process_creation_flags(),
                )
                try:
                    windows_tree = _WindowsProcessTree(process)
                except BaseException:
                    try:
                        process.kill()
                        process.wait(timeout=5)
                        terminated = True
                    except (OSError, subprocess.SubprocessError) as cleanup_exc:
                        raise reject("PTDE_PREPARATION_GIT_TREE_TERMINATION_FAILED") from cleanup_exc
                    raise
                deadline = time.monotonic() + MAX_GIT_SUBPROCESS_SECONDS
                while process.poll() is None:
                    if (
                        os.fstat(stdout_file.fileno()).st_size
                        > MAX_GIT_SUBPROCESS_METADATA_BYTES
                        or os.fstat(stderr_file.fileno()).st_size
                        > MAX_GIT_SUBPROCESS_METADATA_BYTES
                    ):
                        terminated = _terminate_process_tree(process, windows_tree)
                        if not terminated:
                            raise reject("PTDE_PREPARATION_GIT_TREE_TERMINATION_FAILED")
                        raise reject("PTDE_PREPARATION_GIT_OUTPUT_LIMIT_EXCEEDED")
                    if time.monotonic() >= deadline:
                        terminated = _terminate_process_tree(process, windows_tree)
                        if not terminated:
                            raise reject("PTDE_PREPARATION_GIT_TREE_TERMINATION_FAILED")
                        raise reject("PTDE_PREPARATION_GIT_TIMEOUT")
                    time.sleep(0.01)
                returncode = process.wait(timeout=5)
                if not terminated:
                    terminated = _terminate_process_tree(process, windows_tree)
                    if not terminated:
                        raise reject("PTDE_PREPARATION_GIT_TREE_TERMINATION_FAILED")
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if (
                    stdout_size > MAX_GIT_SUBPROCESS_METADATA_BYTES
                    or stderr_size > MAX_GIT_SUBPROCESS_METADATA_BYTES
                ):
                    raise reject("PTDE_PREPARATION_GIT_OUTPUT_LIMIT_EXCEEDED")
                stdout_file.seek(0)
                stderr_file.seek(0)
                stdout = stdout_file.read(MAX_GIT_SUBPROCESS_METADATA_BYTES + 1)
                stderr = stderr_file.read(MAX_GIT_SUBPROCESS_METADATA_BYTES + 1)
            except BaseException as exc:
                if process is not None and not terminated:
                    terminated = _terminate_process_tree(process, windows_tree)
                    if not terminated:
                        raise reject("PTDE_PREPARATION_GIT_TREE_TERMINATION_FAILED") from exc
                raise
            finally:
                if windows_tree is not None:
                    windows_tree.close()
    except PTDEVerificationError:
        raise
    except (OSError, subprocess.SubprocessError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("PTDE_PREPARATION_GIT_UNAVAILABLE") from exc
    after = _verify_pinned_executable(executable, expected, baseline)
    if after != before:
        raise reject("PTDE_PREPARATION_GIT_CHANGED_DURING_INVOCATION")
    if stderr:
        raise reject("PTDE_PREPARATION_GIT_STDERR_REJECTED")
    return returncode, stdout


def _read_exact_worktree_blob(path: Path, expected: TreeBlob) -> None:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_or_symlink(before)
            or before.st_nlink != 1
            or before.st_size != expected.byte_count
        ):
            raise reject("PTDE_PREPARATION_WORKTREE_FILE_INVALID")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            if _file_identity(opened_before) != _file_identity(before):
                raise reject("PTDE_PREPARATION_WORKTREE_FILE_CHANGED")
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(1_048_576, expected.byte_count + 1 - observed),
                )
                if not chunk:
                    break
                observed += len(chunk)
                if observed > expected.byte_count:
                    raise reject("PTDE_PREPARATION_WORKTREE_FILE_SIZE_CHANGED")
                chunks.append(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (
            len(
                {
                    _file_identity(before),
                    _file_identity(opened_before),
                    _file_identity(opened_after),
                    _file_identity(after),
                }
            )
            != 1
            or _is_reparse_or_symlink(after)
        ):
            raise reject("PTDE_PREPARATION_WORKTREE_FILE_CHANGED")
        content = b"".join(chunks)
        if (
            len(content) != expected.byte_count
            or sha512_hex(content) != expected.blob_sha512
        ):
            raise reject("PTDE_PREPARATION_WORKTREE_BLOB_MISMATCH")
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("PTDE_PREPARATION_WORKTREE_FILE_UNAVAILABLE") from exc


def _verify_exact_worktree_files(
    repository_root: Path, p_tree: Mapping[str, TreeBlob]
) -> None:
    expected_paths = set(p_tree)
    expected_directories: set[str] = set()
    for expected_path in expected_paths:
        parts = expected_path.split("/")
        for index in range(1, len(parts)):
            expected_directories.add("/".join(parts[:index]))
    observed_paths: set[str] = set()
    pending = [repository_root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as scanner:
                entries = sorted(scanner, key=lambda item: item.name)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise reject("PTDE_PREPARATION_WORKTREE_ENUMERATION_FAILED") from exc
        for entry in entries:
            if directory == repository_root and entry.name == ".git":
                continue
            entry_path = Path(entry.path)
            try:
                metadata = entry.stat(follow_symlinks=False)
                relative = canonical_path(
                    entry_path.relative_to(repository_root).as_posix(),
                    code="PTDE_PREPARATION_WORKTREE_PATH_INVALID",
                )
            except PTDEVerificationError:
                raise
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                raise reject("PTDE_PREPARATION_WORKTREE_ENTRY_INVALID") from exc
            if _is_reparse_or_symlink(metadata):
                raise reject("PTDE_PREPARATION_WORKTREE_LINK_REJECTED")
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in expected_directories:
                    raise reject("PTDE_PREPARATION_WORKTREE_EXTRA_DIRECTORY")
                pending.append(entry_path)
            elif stat.S_ISREG(metadata.st_mode):
                expected = p_tree.get(relative)
                if expected is None or relative in observed_paths:
                    raise reject("PTDE_PREPARATION_WORKTREE_EXTRA_FILE")
                _read_exact_worktree_blob(entry_path, expected)
                observed_paths.add(relative)
            else:
                raise reject("PTDE_PREPARATION_WORKTREE_SPECIAL_FILE_REJECTED")
    if observed_paths != expected_paths:
        raise reject("PTDE_PREPARATION_WORKTREE_FILE_SET_MISMATCH")


def _validate_clean_candidate_worktree(
    repository_root: str | Path,
    *,
    candidate_oid: str,
    p_tree: Mapping[str, TreeBlob],
    git_executable: str,
    expected_git_executable_sha512: str,
) -> None:
    try:
        supplied = Path(repository_root)
        if not supplied.is_absolute():
            raise reject("PTDE_PREPARATION_REPOSITORY_NOT_ABSOLUTE")
        _reject_unsafe_path_components(supplied, code="PTDE_PREPARATION_REPOSITORY_UNSAFE")
        root = supplied.resolve(strict=True)
        if os.path.normcase(os.path.abspath(str(supplied))) != os.path.normcase(str(root)):
            raise reject("PTDE_PREPARATION_REPOSITORY_RESOLUTION_CHANGED")
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or _is_reparse_or_symlink(metadata):
            raise reject("PTDE_PREPARATION_REPOSITORY_INVALID")
        _reject_unsafe_path_components(root / ".git", code="PTDE_PREPARATION_GIT_DIR_UNSAFE")
        if not (root / ".git").is_dir():
            raise reject("PTDE_PREPARATION_WORKTREE_REQUIRED")
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("PTDE_PREPARATION_REPOSITORY_UNAVAILABLE") from exc
    _verify_exact_worktree_files(root, p_tree)
    returncode, output = _run_worktree_git(
        root,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        arguments=(
            "diff-index",
            "--cached",
            "--quiet",
            "--no-ext-diff",
            "--no-renames",
            candidate_oid,
            "--",
        ),
    )
    if returncode != 0 or output:
        raise reject("PTDE_PREPARATION_INDEX_NOT_EXACT_CANDIDATE")


def _packet_digest(document: Mapping[str, Any], digest_field: str) -> str:
    unsigned = {key: value for key, value in document.items() if key != digest_field}
    return canonical_sha512(unsigned)


def _commit_binding(database: GitObjectDatabase, commit: CommitObject) -> dict[str, str]:
    tree = database.read_object(commit.tree_oid, expected_type="tree")
    return {
        "commit_oid": commit.oid,
        "commit_raw_sha512": commit.raw_sha512,
        "tree_oid": commit.tree_oid,
        "tree_raw_sha512": tree.raw_sha512,
    }


@dataclass(frozen=True, slots=True)
class _ExternalPTrust:
    ptde_history: AcceptedAttemptHistory
    expected_ptde_history_sha512: str
    local_history: dict[str, Any]
    local_history_id: str
    local_context_sha512: str
    local_repository_identity_sha512: str
    local_history_sequence: int
    local_history_sha512: str
    python_prior_lock_sha512: str


def _validate_external_p_trust(
    *,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> _ExternalPTrust:
    ptde_history = accepted_attempt_history_from_document(
        ptde_accepted_attempt_history_document
    )
    ptde_pin = require_sha512(
        expected_ptde_accepted_attempt_history_sha512,
        "PTDE_PREPARATION_PTDE_HISTORY_PIN_INVALID",
    )
    identifier(
        ptde_history.history_id,
        code="PTDE_PREPARATION_PTDE_HISTORY_ID_INVALID",
    )
    local_history = strict_json_document(
        local_trust_accepted_package_history_document,
        code="PTDE_PREPARATION_LOCAL_HISTORY",
    )
    local_history_id = identifier(
        local_history.get("history_id"),
        code="PTDE_PREPARATION_LOCAL_HISTORY_ID_INVALID",
    )
    local_context_record = strict_json_document(
        local_trust_history_context_document,
        code="PTDE_PREPARATION_LOCAL_HISTORY_CONTEXT",
    )
    context_pin = require_sha512(
        owner_pinned_local_trust_history_context_sha512,
        "PTDE_PREPARATION_LOCAL_HISTORY_CONTEXT_PIN_INVALID",
    )
    repository_identity_pin = require_sha512(
        expected_local_trust_repository_identity_sha512,
        "PTDE_PREPARATION_LOCAL_REPOSITORY_IDENTITY_PIN_INVALID",
    )
    local_history_pin = require_sha512(
        expected_local_trust_accepted_package_history_sha512,
        "PTDE_PREPARATION_LOCAL_HISTORY_PIN_INVALID",
    )
    if (
        type(expected_local_trust_accepted_package_history_sequence) is not int
        or expected_local_trust_accepted_package_history_sequence < 0
    ):
        raise reject("PTDE_PREPARATION_LOCAL_HISTORY_SEQUENCE_INVALID")
    try:
        local_context = verification_context_from_record(
            local_context_record,
            owner_pinned_context_digest=context_pin,
            allow_test_only=False,
        )
    except LocalTrustSignatureError as exc:
        raise reject("PTDE_PREPARATION_LOCAL_HISTORY_CONTEXT_INVALID") from exc
    if (
        local_context.signer_class != PRODUCTION
        or local_context.purpose != HISTORY_SIGNING_PURPOSE
        or local_context.allow_test_only
    ):
        raise reject("PTDE_PREPARATION_LOCAL_HISTORY_CONTEXT_NOT_PRODUCTION")
    local_validation = validate_accepted_package_history(
        local_history,
        repository_identity_digest=repository_identity_pin,
        trust_context=local_context,
        owner_pinned_context_digest=context_pin,
        expected_history_digest=local_history_pin,
        minimum_sequence=expected_local_trust_accepted_package_history_sequence,
    )
    if (
        local_validation["status"] != "PASS"
        or local_validation["sequence"]
        != expected_local_trust_accepted_package_history_sequence
        or local_history.get("sequence")
        != expected_local_trust_accepted_package_history_sequence
        or local_history.get("history_digest") != local_history_pin
        or local_history.get("repository_identity_digest")
        != repository_identity_pin
    ):
        raise reject("PTDE_PREPARATION_LOCAL_HISTORY_NOT_EXACTLY_PINNED")
    return _ExternalPTrust(
        ptde_history=ptde_history,
        expected_ptde_history_sha512=ptde_pin,
        local_history=local_history,
        local_history_id=local_history_id,
        local_context_sha512=context_pin,
        local_repository_identity_sha512=repository_identity_pin,
        local_history_sequence=(
            expected_local_trust_accepted_package_history_sequence
        ),
        local_history_sha512=local_history_pin,
        python_prior_lock_sha512=expected_python_dependency_prior_lock_sha512,
    )


def _local_history_binding(trust: _ExternalPTrust) -> dict[str, Any]:
    return {
        "schema_id": trust.local_history["schema_id"],
        "history_id": trust.local_history_id,
        "sequence": trust.local_history_sequence,
        "history_digest": trust.local_history_sha512,
        "repository_identity_digest": trust.local_repository_identity_sha512,
        "history_context_digest": trust.local_context_sha512,
        "signing_purpose": HISTORY_SIGNING_PURPOSE,
        "validation_status": "PASS_EXTERNALLY_PINNED_STRICT_DUAL_SIGNATURES",
    }


def _python_dependency_binding(binding: PObjectBinding) -> dict[str, Any]:
    python_inputs = build_python_dependency_inputs(binding)
    lock_content = p_blob_content(binding, PYTHON_LOCK_PATH)
    lock_document = strict_json_document(
        lock_content, code="PTDE_PREPARATION_PYTHON_LOCK"
    )
    if (
        lock_document.get("schema_id") != PYTHON_LOCK_SCHEMA
        or python_inputs.get("dependency_evidence_status") != "COMPLETE"
        or python_inputs.get("python_lock_blob") is None
    ):
        raise reject("PTDE_PREPARATION_GOVERNED_PYTHON_LOCK_REQUIRED")
    return {
        "schema_id": python_inputs["schema_id"],
        "python_lock_schema_id": PYTHON_LOCK_SCHEMA,
        "python_lock_blob": python_inputs["python_lock_blob"],
        "python_inputs_sha512": python_inputs["payload_sha512"],
        "dependency_evidence_status": "COMPLETE",
    }


def _database_for_packet(
    packet: Mapping[str, Any],
    *,
    expected_packet_sha512: str,
    object_database: str | Path,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> tuple[GitObjectDatabase, CommitObject, dict[str, TreeBlob]]:
    _, binding = _validated_p_packet_and_binding(
        packet,
        expected_packet_sha512=expected_packet_sha512,
        object_database=object_database,
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    return binding.database, binding.commit, binding.tree


def prepare_p_selection_packet(
    repository_root: str | Path,
    object_database: str | Path,
    *,
    candidate_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> dict[str, Any]:
    """Validate a clean immutable candidate and prepare an unselected P packet."""

    try:
        _require_native_pinned_git_executable(
            git_executable, expected_git_executable_sha512
        )
        trust = _validate_external_p_trust(
            ptde_accepted_attempt_history_document=(
                ptde_accepted_attempt_history_document
            ),
            expected_ptde_accepted_attempt_history_sha512=(
                expected_ptde_accepted_attempt_history_sha512
            ),
            local_trust_accepted_package_history_document=(
                local_trust_accepted_package_history_document
            ),
            local_trust_history_context_document=(
                local_trust_history_context_document
            ),
            owner_pinned_local_trust_history_context_sha512=(
                owner_pinned_local_trust_history_context_sha512
            ),
            expected_local_trust_repository_identity_sha512=(
                expected_local_trust_repository_identity_sha512
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
        binding = bind_p_object(
            object_database,
            p_oid=candidate_oid,
            expected_p_oid=candidate_oid,
            git_executable=git_executable,
            expected_git_executable_sha512=expected_git_executable_sha512,
            ptde_accepted_attempt_history=trust.ptde_history,
            expected_ptde_accepted_attempt_history_sha512=(
                trust.expected_ptde_history_sha512
            ),
            expected_local_trust_accepted_package_history_sequence=(
                trust.local_history_sequence
            ),
            expected_local_trust_accepted_package_history_sha512=(
                trust.local_history_sha512
            ),
            expected_python_dependency_prior_lock_sha512=(
                trust.python_prior_lock_sha512
            ),
        )
        _validate_clean_candidate_worktree(
            repository_root,
            candidate_oid=binding.commit.oid,
            p_tree=binding.tree,
            git_executable=git_executable,
            expected_git_executable_sha512=expected_git_executable_sha512,
        )
        binding_document = binding.document()
        validate_p_binding_document(binding_document)
        unsigned: dict[str, Any] = {
            "schema_id": P_PREPARATION_SCHEMA,
            "stage_sequence": ["P_CANDIDATE_PREPARATION"],
            "candidate_binding": binding_document,
            "local_trust_history_binding": _local_history_binding(trust),
            "python_dependency_binding": _python_dependency_binding(binding),
            "preparation_state": P_PREPARATION_STATE,
            "p_selection_state": NOT_SELECTED,
            "admission_state": NOT_ADMITTED,
            "no_authority": dict(NO_AUTHORITY),
        }
        packet = {**unsigned, "packet_sha512": canonical_sha512(unsigned)}
        return validate_p_selection_packet(
            packet,
            expected_packet_sha512=packet["packet_sha512"],
            object_database=object_database,
            expected_p_oid=candidate_oid,
            git_executable=git_executable,
            expected_git_executable_sha512=expected_git_executable_sha512,
            ptde_accepted_attempt_history_document=(
                ptde_accepted_attempt_history_document
            ),
            expected_ptde_accepted_attempt_history_sha512=(
                expected_ptde_accepted_attempt_history_sha512
            ),
            local_trust_accepted_package_history_document=(
                local_trust_accepted_package_history_document
            ),
            local_trust_history_context_document=(
                local_trust_history_context_document
            ),
            owner_pinned_local_trust_history_context_sha512=(
                owner_pinned_local_trust_history_context_sha512
            ),
            expected_local_trust_repository_identity_sha512=(
                expected_local_trust_repository_identity_sha512
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
    except PTDEVerificationError:
        raise
    except (Exception, MemoryError) as exc:
        raise reject(f"PTDE_PREPARATION_P_FAIL_CLOSED:{type(exc).__name__}") from exc


def _validate_p_packet_structure(
    value: Mapping[str, Any], *, expected_packet_sha512: str
) -> dict[str, Any]:
    packet = exact_fields(dict(value), _P_PACKET_FIELDS, code="PTDE_P_PREPARATION_PACKET")
    expected_digest = require_sha512(
        expected_packet_sha512, "PTDE_P_PREPARATION_EXPECTED_PACKET_DIGEST_INVALID"
    )
    if (
        packet["schema_id"] != P_PREPARATION_SCHEMA
        or packet["stage_sequence"] != ["P_CANDIDATE_PREPARATION"]
        or packet["preparation_state"] != P_PREPARATION_STATE
        or packet["p_selection_state"] != NOT_SELECTED
        or packet["admission_state"] != NOT_ADMITTED
        or packet["no_authority"] != NO_AUTHORITY
        or packet["packet_sha512"] != expected_digest
        or packet["packet_sha512"] != _packet_digest(packet, "packet_sha512")
    ):
        raise reject("PTDE_P_PREPARATION_PACKET_CONTRACT_INVALID")
    binding = validate_p_binding_document(packet["candidate_binding"])
    local = exact_fields(
        packet["local_trust_history_binding"],
        _LOCAL_HISTORY_BINDING_FIELDS,
        code="PTDE_P_PREPARATION_LOCAL_HISTORY_BINDING",
    )
    python = exact_fields(
        packet["python_dependency_binding"],
        _PYTHON_BINDING_FIELDS,
        code="PTDE_P_PREPARATION_PYTHON_BINDING",
    )
    python_lock_blob = exact_fields(
        python["python_lock_blob"],
        _TREE_BLOB_FIELDS,
        code="PTDE_P_PREPARATION_PYTHON_LOCK_BLOB",
    )
    inventory_lock_records = [
        record
        for record in binding["p_inventory"]
        if type(record) is dict and record.get("path") == PYTHON_LOCK_PATH
    ]
    for field in (
        "history_digest",
        "repository_identity_digest",
        "history_context_digest",
    ):
        require_sha512(local[field], f"PTDE_P_PREPARATION_LOCAL_{field.upper()}_INVALID")
    identifier(
        local["history_id"], code="PTDE_P_PREPARATION_LOCAL_HISTORY_ID_INVALID"
    )
    if (
        local["schema_id"] != ACCEPTED_HISTORY_SCHEMA
        or type(local["sequence"]) is not int
        or local["sequence"] < 0
        or local["signing_purpose"] != HISTORY_SIGNING_PURPOSE
        or local["validation_status"]
        != "PASS_EXTERNALLY_PINNED_STRICT_DUAL_SIGNATURES"
        or local["sequence"]
        != binding["expected_local_trust_accepted_package_history_sequence"]
        or local["history_digest"]
        != binding["expected_local_trust_accepted_package_history_sha512"]
        or python["python_lock_schema_id"] != PYTHON_LOCK_SCHEMA
        or python["dependency_evidence_status"] != "COMPLETE"
        or python_lock_blob.get("path") != PYTHON_LOCK_PATH
        or inventory_lock_records != [python_lock_blob]
        or python["schema_id"] != "sbp.lex.v2.supply-chain.python-inputs/2"
    ):
        raise reject("PTDE_P_PREPARATION_BINDING_CONTRACT_INVALID")
    require_sha512(
        python["python_inputs_sha512"],
        "PTDE_P_PREPARATION_PYTHON_INPUTS_DIGEST_INVALID",
    )
    return packet


def _validated_p_packet_and_binding(
    value: Mapping[str, Any],
    *,
    expected_packet_sha512: str,
    object_database: str | Path,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> tuple[dict[str, Any], PObjectBinding]:
    packet = _validate_p_packet_structure(
        value, expected_packet_sha512=expected_packet_sha512
    )
    _require_native_pinned_git_executable(
        git_executable, expected_git_executable_sha512
    )
    trust = _validate_external_p_trust(
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    carried_binding = validate_p_binding_document(packet["candidate_binding"])
    recomputed = bind_p_object(
        object_database,
        p_oid=carried_binding["p_commit_oid"],
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history=trust.ptde_history,
        expected_ptde_accepted_attempt_history_sha512=(
            trust.expected_ptde_history_sha512
        ),
        expected_local_trust_accepted_package_history_sequence=(
            trust.local_history_sequence
        ),
        expected_local_trust_accepted_package_history_sha512=(
            trust.local_history_sha512
        ),
        expected_python_dependency_prior_lock_sha512=(
            trust.python_prior_lock_sha512
        ),
    )
    if recomputed.document() != carried_binding:
        raise reject("PTDE_P_PREPARATION_CANDIDATE_BINDING_NOT_RECOMPUTED")
    if packet["local_trust_history_binding"] != _local_history_binding(trust):
        raise reject("PTDE_P_PREPARATION_LOCAL_BINDING_NOT_RECOMPUTED")
    if packet["python_dependency_binding"] != _python_dependency_binding(
        recomputed
    ):
        raise reject("PTDE_P_PREPARATION_PYTHON_BINDING_NOT_RECOMPUTED")
    return packet, recomputed


def validate_p_selection_packet(
    value: Mapping[str, Any],
    *,
    expected_packet_sha512: str,
    object_database: str | Path,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
) -> dict[str, Any]:
    packet, _ = _validated_p_packet_and_binding(
        value,
        expected_packet_sha512=expected_packet_sha512,
        object_database=object_database,
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    return packet


def _policy_blob(
    database: GitObjectDatabase, p_tree: Mapping[str, TreeBlob]
) -> TreeBlob:
    record = p_tree.get(POLICY_PATH)
    if record is None:
        raise reject("PTDE_PREPARATION_P_POLICY_MISSING")
    if database.read_blob(record.blob_oid).content != policy_document_bytes():
        raise reject("PTDE_PREPARATION_P_POLICY_NOT_FIXED")
    return record


def _build_inventories(
    p_tree: Mapping[str, TreeBlob], inventory_assignments: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    assignments = exact_fields(
        dict(inventory_assignments), set(INVENTORY_CLASSES), code="PTDE_T_INVENTORY_ASSIGNMENTS"
    )
    observed: set[str] = set()
    inventories: dict[str, dict[str, Any]] = {}
    for inventory_class in INVENTORY_CLASSES:
        paths = assignments[inventory_class]
        if type(paths) is not list:
            raise reject("PTDE_T_INVENTORY_ASSIGNMENT_NOT_LIST")
        checked = [canonical_path(path, code="PTDE_T_INVENTORY_ASSIGNMENT_PATH_INVALID") for path in paths]
        if checked != sorted(checked) or len(checked) != len(set(checked)):
            raise reject("PTDE_T_INVENTORY_ASSIGNMENT_ORDER_INVALID")
        if any(path in observed or path not in p_tree for path in checked):
            raise reject("PTDE_T_INVENTORY_ASSIGNMENT_NOT_EXACT_P_PATH")
        observed.update(checked)
        entries = [p_tree[path].record() for path in checked]
        inventories[inventory_class] = {
            "entries": entries,
            "inventory_sha512": canonical_sha512(entries),
        }
    if observed != set(p_tree):
        raise reject("PTDE_T_INVENTORY_ASSIGNMENTS_NOT_EXHAUSTIVE")
    return inventories


def prepare_t_profile(
    p_packet: Mapping[str, Any],
    object_database: str | Path,
    *,
    expected_p_packet_sha512: str,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
    test_profile_id: str,
    inventory_assignments: Mapping[str, Any],
    lanes: Any,
) -> dict[str, Any]:
    """Prepare the exact T profile; committing it remains an owner action."""

    database, p_commit, p_tree = _database_for_packet(
        p_packet,
        expected_packet_sha512=expected_p_packet_sha512,
        object_database=object_database,
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    policy_blob = _policy_blob(database, p_tree)
    inventories = _build_inventories(p_tree, inventory_assignments)
    checked_lanes = validate_lanes(lanes)
    profile = {
        "schema_id": T_SCHEMA_ID,
        "policy_blob_oid": policy_blob.blob_oid,
        "policy_sha512": policy_blob.blob_sha512,
        "policy_blob_raw_sha512": policy_blob.blob_raw_sha512,
        "p_commit_oid": p_commit.oid,
        "p_tree_oid": p_commit.tree_oid,
        "p_commit_raw_sha512": p_commit.raw_sha512,
        "p_tree_raw_sha512": database.read_object(
            p_commit.tree_oid, expected_type="tree"
        ).raw_sha512,
        "inventories": inventories,
        "p_inventory_sha512": canonical_sha512(inventories),
        "test_profile_id": identifier(
            test_profile_id, code="PTDE_T_TEST_PROFILE_ID_INVALID"
        ),
        "lanes": checked_lanes,
        "lanes_sha512": canonical_sha512(checked_lanes),
        "no_authority": dict(NO_AUTHORITY),
        "runtime_attachment": "NONE",
    }
    return validate_t_profile(
        profile,
        database=database,
        p_commit=p_commit,
        p_tree=p_tree,
        policy_blob=policy_blob,
    )


def _committed_t(
    database: GitObjectDatabase,
    p_commit: CommitObject,
    p_tree: dict[str, TreeBlob],
    t_oid: str,
) -> tuple[CommitObject, dict[str, TreeBlob], TreeBlob, dict[str, Any]]:
    t_commit = database.read_commit(database.require_oid(t_oid, code="PTDE_T_OID_INVALID"))
    require_direct_child(t_commit, p_commit.oid, stage="T")
    t_tree = database.flatten_tree(t_commit.tree_oid)
    profile_record = exact_added_blob_delta(
        p_tree, t_tree, added_path=T_PROFILE_PATH, stage="T"
    )
    profile = strict_json_document(
        database.read_blob(profile_record.blob_oid).content,
        code="PTDE_PREPARATION_T_PROFILE",
    )
    validate_t_profile(
        profile,
        database=database,
        p_commit=p_commit,
        p_tree=p_tree,
        policy_blob=_policy_blob(database, p_tree),
    )
    return t_commit, t_tree, profile_record, profile


def _function_ast_digest(source: bytes, qualified_name: str) -> str:
    try:
        module = ast.parse(source.decode("utf-8", errors="strict"))
        function_name = qualified_name.rsplit(".", 1)[-1]
        matches = [
            node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ]
        if len(matches) != 1:
            raise reject("PTDE_D_CALLABLE_DEFINITION_NOT_EXACT")
        rendered = ast.dump(matches[0], annotate_fields=True, include_attributes=False)
        return sha512_hex(rendered.encode("utf-8"))
    except PTDEVerificationError:
        raise
    except (UnicodeError, SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise reject("PTDE_D_CALLABLE_SOURCE_INVALID") from exc


def _callable_records(
    database: GitObjectDatabase, tree: Mapping[str, TreeBlob]
) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for item in CALLABLE_ALLOWED_SET:
        path = item["source_path"]
        record = tree.get(path)
        if record is None:
            raise reject("PTDE_D_CALLABLE_SOURCE_MISSING")
        source = database.read_blob(record.blob_oid).content
        result.append(
            {
                **item,
                "source_blob_oid": record.blob_oid,
                "source_blob_sha512": record.blob_sha512,
                "function_ast_sha512": _function_ast_digest(
                    source, item["qualified_name"]
                ),
            }
        )
    return result


def prepare_d_descriptor(
    p_packet: Mapping[str, Any],
    object_database: str | Path,
    *,
    expected_p_packet_sha512: str,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
    t_oid: str,
    campaign: str,
    external_fingerprints: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate committed T and prepare exact D from external fingerprints."""

    database, p_commit, p_tree = _database_for_packet(
        p_packet,
        expected_packet_sha512=expected_p_packet_sha512,
        object_database=object_database,
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    t_commit, t_tree, t_profile_blob, t_profile = _committed_t(
        database, p_commit, p_tree, t_oid
    )
    fingerprints = exact_fields(
        dict(external_fingerprints),
        _D_FINGERPRINT_FIELDS,
        code="PTDE_D_EXTERNAL_FINGERPRINTS",
    )
    for field in sorted(_D_FINGERPRINT_FIELDS):
        require_sha512(fingerprints[field], f"PTDE_D_{field.upper()}_INVALID")
    if (
        any(value == "0" * 128 for value in fingerprints.values())
        or len(set(fingerprints.values())) != len(fingerprints)
    ):
        raise reject("PTDE_D_EXTERNAL_FINGERPRINTS_NOT_INDEPENDENT")
    descriptor = {
        "schema_id": D_SCHEMA_ID,
        "campaign_id": campaign_id(campaign),
        "p_commit_oid": p_commit.oid,
        "p_tree_oid": p_commit.tree_oid,
        "p_commit_raw_sha512": p_commit.raw_sha512,
        "p_tree_raw_sha512": database.read_object(
            p_commit.tree_oid, expected_type="tree"
        ).raw_sha512,
        "t_commit_oid": t_commit.oid,
        "t_tree_oid": t_commit.tree_oid,
        "t_commit_raw_sha512": t_commit.raw_sha512,
        "t_tree_raw_sha512": database.read_object(
            t_commit.tree_oid, expected_type="tree"
        ).raw_sha512,
        "t_profile_path": T_PROFILE_PATH,
        "t_profile_blob_oid": t_profile_blob.blob_oid,
        "t_profile_sha512": t_profile_blob.blob_sha512,
        "t_profile_blob_raw_sha512": t_profile_blob.blob_raw_sha512,
        "policy_sha512": t_profile["policy_sha512"],
        "p_inventory_sha512": t_profile["p_inventory_sha512"],
        "p_contract_inventory_sha512": t_profile["inventories"]["contract"][
            "inventory_sha512"
        ],
        "p_architecture_inventory_sha512": t_profile["inventories"][
            "architecture"
        ]["inventory_sha512"],
        "p_configuration_inventory_sha512": t_profile["inventories"][
            "configuration"
        ]["inventory_sha512"],
        **fingerprints,
        "lanes": t_profile["lanes"],
        "lanes_sha512": t_profile["lanes_sha512"],
        "single_pipeline_callables": _callable_records(database, t_tree),
        "no_authority": dict(NO_AUTHORITY),
        "assurance_limits": assurance_limits_document(),
    }
    return validate_d_descriptor(
        descriptor,
        database=database,
        p_commit=p_commit,
        t_commit=t_commit,
        d_tree=t_tree,
        t_profile=t_profile,
        t_profile_blob=t_profile_blob,
    )


def _committed_d(
    database: GitObjectDatabase,
    p_commit: CommitObject,
    t_commit: CommitObject,
    t_tree: dict[str, TreeBlob],
    t_profile: dict[str, Any],
    t_profile_blob: TreeBlob,
    d_oid: str,
) -> tuple[CommitObject, dict[str, TreeBlob], TreeBlob, dict[str, Any]]:
    d_commit = database.read_commit(database.require_oid(d_oid, code="PTDE_D_OID_INVALID"))
    require_direct_child(d_commit, t_commit.oid, stage="D")
    d_tree = database.flatten_tree(d_commit.tree_oid)
    descriptor_record = exact_added_blob_delta(
        t_tree, d_tree, added_path=D_DESCRIPTOR_PATH, stage="D"
    )
    descriptor = strict_json_document(
        database.read_blob(descriptor_record.blob_oid).content,
        code="PTDE_PREPARATION_D_DESCRIPTOR",
    )
    validate_d_descriptor(
        descriptor,
        database=database,
        p_commit=p_commit,
        t_commit=t_commit,
        d_tree=d_tree,
        t_profile=t_profile,
        t_profile_blob=t_profile_blob,
    )
    return d_commit, d_tree, descriptor_record, descriptor


def _lane_input_requirements(
    lanes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    requirements: list[dict[str, Any]] = []
    for lane in lanes:
        lane_id = lane["lane_id"]
        requirements.append(
            {
                "lane_id": lane_id,
                "order": lane["order"],
                "committed_lane_contract": lane,
                "lane_contract_sha512": canonical_sha512(lane),
                "required_transcript_schema_id": TRANSCRIPT_SCHEMA_ID,
                "transcript_relative_path": f"{lane_id}/transcript.json",
                "transcript_maximum_byte_count": MAX_TRANSCRIPT_BYTE_COUNT,
                "required_external_result_fields": list(
                    _REQUIRED_EXTERNAL_RESULT_FIELDS
                ),
            }
        )
    return requirements


def prepare_e_campaign_input_skeleton(
    p_packet: Mapping[str, Any],
    object_database: str | Path,
    *,
    expected_p_packet_sha512: str,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    ptde_accepted_attempt_history_document: bytes,
    expected_ptde_accepted_attempt_history_sha512: str,
    local_trust_accepted_package_history_document: bytes,
    local_trust_history_context_document: bytes,
    owner_pinned_local_trust_history_context_sha512: str,
    expected_local_trust_repository_identity_sha512: str,
    expected_local_trust_accepted_package_history_sequence: int,
    expected_local_trust_accepted_package_history_sha512: str,
    expected_python_dependency_prior_lock_sha512: str,
    t_oid: str,
    d_oid: str,
    campaign: str,
) -> dict[str, Any]:
    """Validate P→T→D and describe exact external inputs needed for E."""

    database, p_commit, p_tree = _database_for_packet(
        p_packet,
        expected_packet_sha512=expected_p_packet_sha512,
        object_database=object_database,
        expected_p_oid=expected_p_oid,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
        ptde_accepted_attempt_history_document=(
            ptde_accepted_attempt_history_document
        ),
        expected_ptde_accepted_attempt_history_sha512=(
            expected_ptde_accepted_attempt_history_sha512
        ),
        local_trust_accepted_package_history_document=(
            local_trust_accepted_package_history_document
        ),
        local_trust_history_context_document=(
            local_trust_history_context_document
        ),
        owner_pinned_local_trust_history_context_sha512=(
            owner_pinned_local_trust_history_context_sha512
        ),
        expected_local_trust_repository_identity_sha512=(
            expected_local_trust_repository_identity_sha512
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
    t_commit, t_tree, t_profile_blob, t_profile = _committed_t(
        database, p_commit, p_tree, t_oid
    )
    d_commit, _d_tree, descriptor_blob, descriptor = _committed_d(
        database,
        p_commit,
        t_commit,
        t_tree,
        t_profile,
        t_profile_blob,
        d_oid,
    )
    checked_campaign = campaign_id(campaign)
    if descriptor["campaign_id"] != checked_campaign:
        raise reject("PTDE_E_CAMPAIGN_NOT_D_DESCRIPTOR_CAMPAIGN")
    unsigned: dict[str, Any] = {
        "schema_id": E_INPUT_PREPARATION_SCHEMA,
        "stage_sequence": [
            "P_CANDIDATE_PREPARATION",
            "T_PROFILE_COMMITTED",
            "D_DESCRIPTOR_COMMITTED",
            "E_INPUTS_REQUIRED",
        ],
        "p_packet_sha512": require_sha512(
            expected_p_packet_sha512, "PTDE_E_P_PACKET_PIN_INVALID"
        ),
        "object_bindings": {
            "P": _commit_binding(database, p_commit),
            "T": _commit_binding(database, t_commit),
            "D": _commit_binding(database, d_commit),
        },
        "fixed_manifest_bindings": {
            "p_commit_oid": p_commit.oid,
            "p_tree_oid": p_commit.tree_oid,
            "t_commit_oid": t_commit.oid,
            "t_tree_oid": t_commit.tree_oid,
            "d_commit_oid": d_commit.oid,
            "d_tree_oid": d_commit.tree_oid,
            "d_descriptor_path": D_DESCRIPTOR_PATH,
            "d_descriptor_blob_oid": descriptor_blob.blob_oid,
            "d_descriptor_sha512": descriptor_blob.blob_sha512,
            "d_descriptor_blob_raw_sha512": descriptor_blob.blob_raw_sha512,
            "policy_sha512": descriptor["policy_sha512"],
            "t_profile_sha512": descriptor["t_profile_sha512"],
            "p_inventory_sha512": descriptor["p_inventory_sha512"],
            "lanes_sha512": descriptor["lanes_sha512"],
        },
        "campaign_id": checked_campaign,
        "expected_e_parent_commit_oid": d_commit.oid,
        "campaign_root": f"{EVIDENCE_ROOT}/{checked_campaign}",
        "manifest_path": f"{EVIDENCE_ROOT}/{checked_campaign}/{E_MANIFEST_NAME}",
        "required_manifest_schema_id": E_SCHEMA_ID,
        "approved_lane_order": [lane["lane_id"] for lane in t_profile["lanes"]],
        "lane_input_requirements": _lane_input_requirements(t_profile["lanes"]),
        "e_commit_state": "NOT_CREATED",
        "evidence_state": "NOT_SUPPLIED",
        "preparation_state": E_INPUT_PREPARATION_STATE,
        "admission_state": NOT_ADMITTED,
        "no_authority": dict(NO_AUTHORITY),
        "assurance_limits": assurance_limits_document(),
    }
    skeleton = {**unsigned, "skeleton_sha512": canonical_sha512(unsigned)}
    return validate_e_campaign_input_skeleton(
        skeleton,
        expected_skeleton_sha512=skeleton["skeleton_sha512"],
    )


def validate_e_campaign_input_skeleton(
    value: Mapping[str, Any], *, expected_skeleton_sha512: str
) -> dict[str, Any]:
    skeleton = exact_fields(
        dict(value), _E_INPUT_FIELDS, code="PTDE_E_INPUT_PREPARATION"
    )
    expected_digest = require_sha512(
        expected_skeleton_sha512, "PTDE_E_INPUT_EXPECTED_DIGEST_INVALID"
    )
    require_sha512(skeleton["p_packet_sha512"], "PTDE_E_P_PACKET_PIN_INVALID")
    if (
        skeleton["schema_id"] != E_INPUT_PREPARATION_SCHEMA
        or skeleton["stage_sequence"]
        != [
            "P_CANDIDATE_PREPARATION",
            "T_PROFILE_COMMITTED",
            "D_DESCRIPTOR_COMMITTED",
            "E_INPUTS_REQUIRED",
        ]
        or skeleton["required_manifest_schema_id"] != E_SCHEMA_ID
        or skeleton["e_commit_state"] != "NOT_CREATED"
        or skeleton["evidence_state"] != "NOT_SUPPLIED"
        or skeleton["preparation_state"] != E_INPUT_PREPARATION_STATE
        or skeleton["admission_state"] != NOT_ADMITTED
        or skeleton["no_authority"] != NO_AUTHORITY
        or skeleton["assurance_limits"] != ASSURANCE_LIMITS
        or skeleton["skeleton_sha512"] != expected_digest
        or skeleton["skeleton_sha512"]
        != _packet_digest(skeleton, "skeleton_sha512")
    ):
        raise reject("PTDE_E_INPUT_PREPARATION_CONTRACT_INVALID")
    bindings = exact_fields(
        skeleton["object_bindings"], {"P", "T", "D"}, code="PTDE_E_INPUT_BINDINGS"
    )
    fixed = exact_fields(
        skeleton["fixed_manifest_bindings"],
        _FIXED_E_MANIFEST_BINDING_FIELDS,
        code="PTDE_E_FIXED_MANIFEST_BINDINGS",
    )
    oid_lengths: set[int] = set()
    for binding in bindings.values():
        exact_fields(binding, _OBJECT_BINDING_FIELDS, code="PTDE_E_INPUT_OBJECT_BINDING")
        for field in ("commit_oid", "tree_oid"):
            oid = binding[field]
            if (
                type(oid) is not str
                or len(oid) not in {40, 64}
                or any(character not in "0123456789abcdef" for character in oid)
            ):
                raise reject("PTDE_E_INPUT_OBJECT_OID_INVALID")
            oid_lengths.add(len(oid))
        require_sha512(binding["commit_raw_sha512"], "PTDE_E_INPUT_COMMIT_DIGEST_INVALID")
        require_sha512(binding["tree_raw_sha512"], "PTDE_E_INPUT_TREE_DIGEST_INVALID")
    if len(oid_lengths) != 1:
        raise reject("PTDE_E_INPUT_OBJECT_FORMAT_MISMATCH")
    oid_length = next(iter(oid_lengths))
    for field in (
        "p_commit_oid",
        "p_tree_oid",
        "t_commit_oid",
        "t_tree_oid",
        "d_commit_oid",
        "d_tree_oid",
        "d_descriptor_blob_oid",
    ):
        oid = fixed[field]
        if (
            type(oid) is not str
            or len(oid) != oid_length
            or any(character not in "0123456789abcdef" for character in oid)
        ):
            raise reject("PTDE_E_FIXED_OBJECT_OID_INVALID")
    for field in (
        "d_descriptor_sha512",
        "d_descriptor_blob_raw_sha512",
        "policy_sha512",
        "t_profile_sha512",
        "p_inventory_sha512",
        "lanes_sha512",
    ):
        require_sha512(fixed[field], f"PTDE_E_FIXED_{field.upper()}_INVALID")
    if (
        fixed["p_commit_oid"] != bindings["P"]["commit_oid"]
        or fixed["p_tree_oid"] != bindings["P"]["tree_oid"]
        or fixed["t_commit_oid"] != bindings["T"]["commit_oid"]
        or fixed["t_tree_oid"] != bindings["T"]["tree_oid"]
        or fixed["d_commit_oid"] != bindings["D"]["commit_oid"]
        or fixed["d_tree_oid"] != bindings["D"]["tree_oid"]
        or fixed["d_descriptor_path"] != D_DESCRIPTOR_PATH
    ):
        raise reject("PTDE_E_FIXED_MANIFEST_BINDING_INVALID")
    checked_campaign = campaign_id(skeleton["campaign_id"])
    if (
        skeleton["expected_e_parent_commit_oid"] != bindings["D"]["commit_oid"]
        or skeleton["campaign_root"] != f"{EVIDENCE_ROOT}/{checked_campaign}"
        or skeleton["manifest_path"]
        != f"{EVIDENCE_ROOT}/{checked_campaign}/{E_MANIFEST_NAME}"
    ):
        raise reject("PTDE_E_INPUT_BINDING_INVALID")
    lane_requirements = skeleton["lane_input_requirements"]
    lane_order = skeleton["approved_lane_order"]
    if (
        type(lane_requirements) is not list
        or not lane_requirements
        or type(lane_order) is not list
        or not lane_order
        or len(lane_requirements) != len(lane_order)
    ):
        raise reject("PTDE_E_INPUT_LANES_INVALID")
    observed: list[str] = []
    observed_paths: set[str] = set()
    committed_lanes: list[dict[str, Any]] = []
    for expected_order, requirement in enumerate(lane_requirements, start=1):
        checked = exact_fields(
            requirement, _LANE_INPUT_FIELDS, code="PTDE_E_INPUT_LANE"
        )
        lane_id = identifier(checked["lane_id"], code="PTDE_E_INPUT_LANE_ID_INVALID")
        if checked["order"] != expected_order:
            raise reject("PTDE_E_INPUT_LANE_ORDER_INVALID")
        lane_contract = checked["committed_lane_contract"]
        if (
            type(lane_contract) is not dict
            or lane_contract.get("lane_id") != lane_id
            or lane_contract.get("order") != expected_order
            or checked["lane_contract_sha512"] != canonical_sha512(lane_contract)
            or checked["required_transcript_schema_id"] != TRANSCRIPT_SCHEMA_ID
            or checked["transcript_maximum_byte_count"]
            != MAX_TRANSCRIPT_BYTE_COUNT
        ):
            raise reject("PTDE_E_INPUT_LANE_EXECUTION_CONTRACT_INVALID")
        transcript_path = canonical_path(
            checked["transcript_relative_path"],
            code="PTDE_E_INPUT_RELATIVE_PATH_INVALID",
        )
        if transcript_path != f"{lane_id}/transcript.json":
            raise reject("PTDE_E_INPUT_TRANSCRIPT_PATH_INVALID")
        lane_paths = [
            lane_contract["stdout_contract"]["relative_path"],
            lane_contract["stderr_contract"]["relative_path"],
            *lane_contract["produced_artifact_contract"][
                "required_relative_paths"
            ],
            *lane_contract["produced_artifact_contract"][
                "optional_relative_paths"
            ],
            transcript_path,
        ]
        if len(lane_paths) != len(set(lane_paths)) or observed_paths.intersection(
            lane_paths
        ):
            raise reject("PTDE_E_INPUT_EVIDENCE_PATH_COLLISION")
        observed_paths.update(lane_paths)
        if checked["required_external_result_fields"] != list(
            _REQUIRED_EXTERNAL_RESULT_FIELDS
        ):
            raise reject("PTDE_E_INPUT_EXTERNAL_FIELDS_INVALID")
        observed.append(lane_id)
        committed_lanes.append(lane_contract)
    if observed != lane_order:
        raise reject("PTDE_E_INPUT_LANE_BINDING_INVALID")
    validated_lanes = validate_lanes(committed_lanes)
    if canonical_sha512(validated_lanes) != fixed["lanes_sha512"]:
        raise reject("PTDE_E_INPUT_LANES_NOT_FIXED_D_BINDING")
    return skeleton


__all__ = [
    "E_INPUT_PREPARATION_SCHEMA",
    "P_PREPARATION_SCHEMA",
    "prepare_d_descriptor",
    "prepare_e_campaign_input_skeleton",
    "prepare_p_selection_packet",
    "prepare_t_profile",
    "read_canonical_document_file",
    "validate_e_campaign_input_skeleton",
    "validate_p_selection_packet",
    "write_canonical_document_exclusive",
]
