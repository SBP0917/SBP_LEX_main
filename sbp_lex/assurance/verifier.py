from __future__ import annotations

import ctypes
import json
import os
import signal
import stat
import subprocess
import tempfile
import threading
from collections.abc import Mapping, Sequence
from ctypes import wintypes
from dataclasses import dataclass
from enum import Enum
from hashlib import sha512
from pathlib import Path
from time import monotonic
from typing import Any

from .envelope import assurance_envelope_digest, canonical_json_bytes

ASSURANCE_VERDICT_VERSION = "sbp.v2.assurance-verdict/1"
MAX_VERIFIER_INPUT_BYTES = 1_048_576
MAX_VERIFIER_OUTPUT_BYTES = 65_536
DEFAULT_VERIFIER_TIMEOUT_SECONDS = 2.0
MAX_VERIFIER_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_VERIFIER_ARGUMENT_COUNT = 64
MAX_VERIFIER_ARGUMENT_BYTES = 32_768
MAX_VERIFIER_ARGUMENT_FILE_BYTES = 16_777_216
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)

_VERIFIER_REASON_CODES = frozenset(
    {
        "VERIFIED",
        "INPUT_TOO_LARGE",
        "MALFORMED_ENVELOPE",
        "UNSUPPORTED_VERSION",
        "INVALID_REQUEST_FINGERPRINT",
        "INVALID_CHECKPOINT",
        "INVALID_PREVIOUS_DIGEST",
        "INVALID_BASE64",
        "NON_CANONICAL_BASE64",
        "STATE_DIGEST_MISMATCH",
        "INVALID_CANONICAL_STATE",
        "FLOAT_FORBIDDEN",
        "NON_CANONICAL_STATE",
        "INTERNAL_VERIFIER_ERROR",
    }
)

_REQUIRED_VERDICT_FIELDS = frozenset(
    {
        "schema_version",
        "verifier_version",
        "accepted",
        "reason_code",
    }
)
_OPTIONAL_VERDICT_FIELDS = frozenset(
    {
        "request_fingerprint",
        "checkpoint",
        "observed_state_sha512",
        "envelope_sha512",
    }
)


class AssuranceMode(str, Enum):
    DISABLED = "disabled"
    SHADOW = "shadow"
    REQUIRED = "required"


@dataclass(frozen=True)
class VerifierInvocation:
    status: str
    accepted: bool
    reason_code: str
    exit_code: int | None
    verdict: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class _BoundedVerifierResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    failure_reason: str | None = None


@dataclass(frozen=True)
class _VerifierExecutableMeasurement:
    device: int
    inode: int
    byte_count: int
    modified_at_ns: int
    changed_at_ns: int
    link_count: int
    sha512: str


@dataclass(frozen=True)
class _VerifierArgumentFileMeasurement:
    argument_index: int
    argument_prefix: str
    resolved_path: str
    device: int
    inode: int
    byte_count: int
    modified_at_ns: int
    changed_at_ns: int
    link_count: int
    sha512: str


def _is_link_or_reparse(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _measure_verifier_executable(
    path: Path,
) -> _VerifierExecutableMeasurement | None:
    descriptor: int | None = None
    try:
        for component in (*reversed(path.parents), path):
            if _is_link_or_reparse(component.lstat()):
                return None
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
            or not 0 < before.st_size <= MAX_VERIFIER_EXECUTABLE_BYTES
            or path.suffix.casefold() in {".bat", ".cmd", ".com", ".ps1", ".py", ".sh"}
        ):
            return None
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        identity = (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_size),
            int(before.st_mtime_ns),
            int(before.st_ctime_ns),
            int(before.st_nlink),
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(opened)
            or (
                int(opened.st_dev),
                int(opened.st_ino),
                int(opened.st_size),
                int(opened.st_mtime_ns),
                int(opened.st_nlink),
            )
            != (identity[0], identity[1], identity[2], identity[3], identity[5])
        ):
            return None
        digest = sha512()
        observed = 0
        first = True
        while True:
            chunk = os.read(
                descriptor,
                min(1_048_576, MAX_VERIFIER_EXECUTABLE_BYTES + 1 - observed),
            )
            if not chunk:
                break
            if first:
                first = False
                if chunk.startswith(b"#!") or (
                    os.name == "nt" and not chunk.startswith(b"MZ")
                ):
                    return None
            observed += len(chunk)
            if observed > MAX_VERIFIER_EXECUTABLE_BYTES:
                return None
            digest.update(chunk)
        after = path.lstat()
        if (
            (
                int(after.st_dev),
                int(after.st_ino),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_ctime_ns),
                int(after.st_nlink),
            )
            != identity
            or _is_link_or_reparse(after)
            or observed != before.st_size
        ):
            return None
        return _VerifierExecutableMeasurement(*identity, digest.hexdigest())
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _measure_argument_file(
    index: int, argument: str
) -> _VerifierArgumentFileMeasurement | None:
    prefix = "@" if argument.startswith("@") else ""
    raw_path = argument[1:] if prefix else argument
    if not raw_path or (not prefix and argument.startswith("-")):
        return None
    candidate = Path(raw_path)
    try:
        initial = candidate.lstat()
    except (OSError, ValueError):
        if prefix:
            raise ValueError("verifier response file unavailable") from None
        return None
    if not candidate.is_absolute():
        raise ValueError("verifier file arguments must be absolute")
    try:
        resolved = candidate.resolve(strict=True)
        if os.path.normcase(os.path.abspath(candidate)) != os.path.normcase(
            str(resolved)
        ):
            raise ValueError("verifier file argument aliases are forbidden")
        for component in (*reversed(candidate.parents), candidate):
            if _is_link_or_reparse(component.lstat()):
                raise ValueError("verifier file argument links are forbidden")
        if (
            not stat.S_ISREG(initial.st_mode)
            or _is_link_or_reparse(initial)
            or initial.st_nlink != 1
            or not 0 <= initial.st_size <= MAX_VERIFIER_ARGUMENT_FILE_BYTES
        ):
            raise ValueError("verifier file argument is unsafe")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(resolved, flags)
        try:
            opened = os.fstat(descriptor)
            identity = (
                int(initial.st_dev),
                int(initial.st_ino),
                int(initial.st_size),
                int(initial.st_mtime_ns),
                int(initial.st_ctime_ns),
                int(initial.st_nlink),
            )
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_link_or_reparse(opened)
                or (
                    int(opened.st_dev),
                    int(opened.st_ino),
                    int(opened.st_size),
                    int(opened.st_mtime_ns),
                    int(opened.st_nlink),
                )
                != (
                    identity[0],
                    identity[1],
                    identity[2],
                    identity[3],
                    identity[5],
                )
            ):
                raise ValueError("verifier file argument changed")
            content_digest = sha512()
            observed = 0
            while True:
                chunk = os.read(
                    descriptor,
                    min(
                        1_048_576,
                        MAX_VERIFIER_ARGUMENT_FILE_BYTES + 1 - observed,
                    ),
                )
                if not chunk:
                    break
                observed += len(chunk)
                if observed > MAX_VERIFIER_ARGUMENT_FILE_BYTES:
                    raise ValueError("verifier file argument too large")
                content_digest.update(chunk)
        finally:
            os.close(descriptor)
        after = candidate.lstat()
        if (
            (
                int(after.st_dev),
                int(after.st_ino),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_ctime_ns),
                int(after.st_nlink),
            )
            != identity
            or _is_link_or_reparse(after)
            or observed != initial.st_size
        ):
            raise ValueError("verifier file argument changed")
        return _VerifierArgumentFileMeasurement(
            index,
            prefix,
            str(resolved),
            *identity,
            content_digest.hexdigest(),
        )
    except (OSError, RuntimeError, TypeError) as exc:
        raise ValueError("verifier file argument unavailable") from exc


def _measure_command_argument_files(
    command: Sequence[str | Path],
) -> tuple[_VerifierArgumentFileMeasurement, ...]:
    records: list[_VerifierArgumentFileMeasurement] = []
    for index, part in enumerate(command[1:], start=1):
        record = _measure_argument_file(index, str(part))
        if record is not None:
            records.append(record)
    return tuple(records)


def _command_digest(
    command: Sequence[str | Path],
    files: tuple[_VerifierArgumentFileMeasurement, ...],
) -> str:
    encoded = canonical_json_bytes(
        {
            "arguments": [str(part) for part in command],
            "argument_files": [
                {
                    "argument_index": item.argument_index,
                    "argument_prefix": item.argument_prefix,
                    "resolved_path": item.resolved_path,
                    "device": item.device,
                    "inode": item.inode,
                    "byte_count": item.byte_count,
                    "modified_at_ns": item.modified_at_ns,
                    "changed_at_ns": item.changed_at_ns,
                    "link_count": item.link_count,
                    "sha512": item.sha512,
                }
                for item in files
            ],
        }
    )
    return sha512(b"SBP-LEX/V2/ASSURANCE-VERIFIER-COMMAND/1\x00" + encoded).hexdigest()


def verifier_command_digest(command: Sequence[str | Path]) -> str:
    return _command_digest(command, _measure_command_argument_files(command))


def _verifier_environment() -> dict[str, str]:
    allowed = {
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "OS",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    environment = {
        name.upper(): value
        for name, value in os.environ.items()
        if name.upper() in allowed
    }
    environment.update(
        {
            "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PATH": "",
        }
    )
    return environment


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


def _resume_suspended_process(process: subprocess.Popen[bytes]) -> bool:
    ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    ntdll.NtResumeProcess.argtypes = (wintypes.HANDLE,)
    ntdll.NtResumeProcess.restype = wintypes.LONG
    process_handle = process.__dict__.get("_handle")
    if process_handle is None:
        return False
    return ntdll.NtResumeProcess(wintypes.HANDLE(process_handle)) == 0


class _WindowsVerifierJob:
    """Contain the verifier and descendants in a kill-on-close job."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION_CLASS = 9

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = _kernel32()
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise OSError("verifier process-tree containment unavailable")
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
            raise OSError("verifier process-tree containment unavailable")
        process_handle = process.__dict__.get("_handle")
        if process_handle is None or not kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(self._handle),
            wintypes.HANDLE(process_handle),
        ):
            self.close()
            raise OSError("verifier process-tree containment unavailable")
        if not _resume_suspended_process(process):
            self.terminate()
            self.close()
            raise OSError("verifier process-tree resume failed")

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


def _windows_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    )


def _terminate_process_tree(
    process: subprocess.Popen[bytes],
    windows_job: _WindowsVerifierJob | None,
) -> bool:
    try:
        if os.name == "nt":
            return windows_job is not None and windows_job.terminate()
        kill_process_group = os.__dict__.get("killpg")
        kill_signal = signal.__dict__.get("SIGKILL")
        if not callable(kill_process_group) or type(kill_signal) is not int:
            return False
        kill_process_group(process.pid, kill_signal)
        return True
    except (OSError, ProcessLookupError):
        return process.poll() is not None


def _read_bounded_stream(
    stream: Any,
    target: bytearray,
    overflow: threading.Event,
    stop: threading.Event,
) -> None:
    try:
        read = getattr(stream, "read1", stream.read)
        while not stop.is_set():
            chunk = read(64 * 1024)
            if not chunk:
                return
            if len(target) + len(chunk) > MAX_VERIFIER_OUTPUT_BYTES:
                overflow.set()
                stop.set()
                return
            target.extend(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _invoke_bounded(
    arguments: list[str],
    *,
    encoded_envelope: bytes,
    timeout_seconds: float,
) -> _BoundedVerifierResult:
    stdout = bytearray()
    stderr = bytearray()
    stdout_overflow = threading.Event()
    stderr_overflow = threading.Event()
    stop = threading.Event()
    process: subprocess.Popen[bytes] | None = None
    windows_job: _WindowsVerifierJob | None = None
    timed_out = False
    containment_failed = False
    readers: tuple[threading.Thread, ...] = ()
    try:
        with tempfile.TemporaryFile() as verifier_input, tempfile.TemporaryDirectory(
            prefix="sbp-lex-verifier-"
        ) as isolated_cwd:
            verifier_input.write(encoded_envelope)
            verifier_input.seek(0)
            process = subprocess.Popen(
                arguments,
                cwd=isolated_cwd,
                stdin=verifier_input,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=_verifier_environment(),
                close_fds=True,
                start_new_session=os.name != "nt",
                creationflags=_windows_creation_flags(),
            )
            try:
                windows_job = _WindowsVerifierJob(process)
            except OSError:
                process.kill()
                process.wait(timeout=5)
                raise
            if process.stdout is None or process.stderr is None:
                containment_failed = not _terminate_process_tree(
                    process,
                    windows_job,
                )
                process.wait(timeout=5)
                return _BoundedVerifierResult(
                    process.returncode,
                    b"",
                    b"",
                    "VERIFIER_CAPTURE_FAILED",
                )
            readers = (
                threading.Thread(
                    target=_read_bounded_stream,
                    args=(process.stdout, stdout, stdout_overflow, stop),
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_bounded_stream,
                    args=(process.stderr, stderr, stderr_overflow, stop),
                    daemon=True,
                ),
            )
            for reader in readers:
                reader.start()
            deadline = monotonic() + timeout_seconds
            while process.poll() is None:
                if stop.is_set():
                    containment_failed = not _terminate_process_tree(
                        process,
                        windows_job,
                    )
                    break
                remaining = deadline - monotonic()
                if remaining <= 0:
                    timed_out = True
                    containment_failed = not _terminate_process_tree(
                        process,
                        windows_job,
                    )
                    break
                stop.wait(min(0.05, remaining))
            if process.poll() is not None:
                # Closing the containment also kills descendants that retained
                # inherited pipe handles after the verifier itself exited.
                if os.name == "nt":
                    if windows_job is not None:
                        windows_job.close()
                        windows_job = None
                else:
                    _terminate_process_tree(process, windows_job)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                containment_failed = not _terminate_process_tree(
                    process,
                    windows_job,
                )
                process.wait(timeout=5)
            for reader in readers:
                reader.join(timeout=5)
            if any(reader.is_alive() for reader in readers):
                return _BoundedVerifierResult(
                    process.returncode,
                    bytes(stdout),
                    bytes(stderr),
                    "VERIFIER_CAPTURE_FAILED",
                )
    except (OSError, subprocess.SubprocessError):
        return _BoundedVerifierResult(
            None,
            bytes(stdout),
            bytes(stderr),
            "VERIFIER_LAUNCH_FAILED",
        )
    finally:
        if (
            process is not None
            and process.poll() is None
            and not _terminate_process_tree(process, windows_job)
        ):
            process.kill()
        if windows_job is not None:
            windows_job.close()

    exit_code = process.returncode if process is not None else None
    if containment_failed:
        return _BoundedVerifierResult(
            exit_code,
            bytes(stdout),
            bytes(stderr),
            "VERIFIER_PROCESS_TREE_TERMINATION_FAILED",
        )
    if stdout_overflow.is_set():
        return _BoundedVerifierResult(
            exit_code,
            bytes(stdout),
            bytes(stderr),
            "VERIFIER_OUTPUT_TOO_LARGE",
        )
    if stderr_overflow.is_set():
        return _BoundedVerifierResult(
            exit_code,
            bytes(stdout),
            bytes(stderr),
            "VERIFIER_ERROR_OUTPUT_TOO_LARGE",
        )
    if timed_out:
        return _BoundedVerifierResult(
            None,
            bytes(stdout),
            bytes(stderr),
            "VERIFIER_TIMEOUT",
        )
    return _BoundedVerifierResult(
        exit_code,
        bytes(stdout),
        bytes(stderr),
    )


def _invalid(reason_code: str, *, exit_code: int | None = None) -> VerifierInvocation:
    return VerifierInvocation(
        status="INVALID",
        accepted=False,
        reason_code=reason_code,
        exit_code=exit_code,
    )


def _is_sha512_or_none(value: Any) -> bool:
    return value is None or (
        isinstance(value, str)
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_verdict(value: Any, *, exit_code: int) -> VerifierInvocation:
    if not isinstance(value, dict):
        return _invalid("VERDICT_NOT_OBJECT", exit_code=exit_code)
    fields = frozenset(value)
    if not _REQUIRED_VERDICT_FIELDS.issubset(fields):
        return _invalid("VERDICT_REQUIRED_FIELD_MISSING", exit_code=exit_code)
    if fields - (_REQUIRED_VERDICT_FIELDS | _OPTIONAL_VERDICT_FIELDS):
        return _invalid("VERDICT_UNKNOWN_FIELD", exit_code=exit_code)
    if value.get("schema_version") != ASSURANCE_VERDICT_VERSION:
        return _invalid("VERDICT_VERSION_MISMATCH", exit_code=exit_code)
    if (
        not isinstance(value.get("verifier_version"), str)
        or not value["verifier_version"]
        or len(value["verifier_version"]) > 64
    ):
        return _invalid("VERDICT_VERIFIER_VERSION_INVALID", exit_code=exit_code)
    if not isinstance(value.get("accepted"), bool):
        return _invalid("VERDICT_ACCEPTED_INVALID", exit_code=exit_code)
    if value.get("reason_code") not in _VERIFIER_REASON_CODES:
        return _invalid("VERDICT_REASON_INVALID", exit_code=exit_code)
    if value.get("request_fingerprint") is not None and not _is_sha512_or_none(
        value.get("request_fingerprint")
    ):
        return _invalid("VERDICT_REQUEST_FINGERPRINT_INVALID", exit_code=exit_code)
    if value.get("checkpoint") is not None and not isinstance(value.get("checkpoint"), str):
        return _invalid("VERDICT_CHECKPOINT_INVALID", exit_code=exit_code)
    if not _is_sha512_or_none(value.get("observed_state_sha512")):
        return _invalid("VERDICT_STATE_DIGEST_INVALID", exit_code=exit_code)
    if not _is_sha512_or_none(value.get("envelope_sha512")):
        return _invalid("VERDICT_ENVELOPE_DIGEST_INVALID", exit_code=exit_code)

    accepted = value["accepted"]
    if accepted and exit_code != 0:
        return _invalid("VERDICT_EXIT_STATUS_CONTRADICTION", exit_code=exit_code)
    if not accepted and exit_code == 0:
        return _invalid("VERDICT_EXIT_STATUS_CONTRADICTION", exit_code=exit_code)
    if exit_code not in {0, 2}:
        return _invalid("VERIFIER_UNEXPECTED_EXIT", exit_code=exit_code)

    return VerifierInvocation(
        status="VERIFIED" if accepted else "REJECTED",
        accepted=accepted,
        reason_code=value["reason_code"],
        exit_code=exit_code,
        verdict=value,
    )


def invoke_veto_verifier(
    envelope: Mapping[str, Any],
    *,
    command: Sequence[str | Path],
    expected_executable_sha512: str,
    expected_command_sha512: str,
    timeout_seconds: float = DEFAULT_VERIFIER_TIMEOUT_SECONDS,
) -> VerifierInvocation:
    """Invoke a bounded veto verifier without a shell.

    The command is build configuration, not request data. Production callers
    must bind its executable and arguments into measured startup evidence.
    """

    if (
        not command
        or len(command) > MAX_VERIFIER_ARGUMENT_COUNT
        or any(
            not isinstance(part, (str, Path))
            or not str(part)
            or "\x00" in str(part)
            for part in command
        )
        or sum(len(str(part).encode("utf-8")) for part in command)
        > MAX_VERIFIER_ARGUMENT_BYTES
    ):
        return _invalid("VERIFIER_COMMAND_MISSING")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < timeout_seconds <= 300
    ):
        return _invalid("VERIFIER_TIMEOUT_INVALID")
    if not _is_sha512_or_none(expected_executable_sha512) or (
        expected_executable_sha512 is None
    ):
        return _invalid("VERIFIER_EXECUTABLE_PIN_INVALID")
    if not _is_sha512_or_none(expected_command_sha512) or (
        expected_command_sha512 is None
    ):
        return _invalid("VERIFIER_COMMAND_PIN_INVALID")
    try:
        argument_files = _measure_command_argument_files(command)
        observed_command_digest = _command_digest(command, argument_files)
    except ValueError:
        return _invalid("VERIFIER_COMMAND_ARGUMENT_FILE_INVALID")
    if observed_command_digest != expected_command_sha512:
        return _invalid("VERIFIER_COMMAND_PIN_MISMATCH")

    executable = Path(command[0])
    try:
        resolved_executable = executable.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return _invalid("VERIFIER_EXECUTABLE_INVALID")
    if (
        not executable.is_absolute()
        or os.path.normcase(os.path.abspath(executable))
        != os.path.normcase(str(resolved_executable))
    ):
        return _invalid("VERIFIER_EXECUTABLE_INVALID")
    executable_measurement = _measure_verifier_executable(resolved_executable)
    if executable_measurement is None:
        return _invalid("VERIFIER_EXECUTABLE_INVALID")
    if executable_measurement.sha512 != expected_executable_sha512:
        return _invalid("VERIFIER_EXECUTABLE_PIN_MISMATCH")

    encoded_envelope = canonical_json_bytes(envelope)
    if len(encoded_envelope) > MAX_VERIFIER_INPUT_BYTES:
        return _invalid("VERIFIER_INPUT_TOO_LARGE")
    completed = _invoke_bounded(
        [str(resolved_executable), *(str(part) for part in command[1:])],
        encoded_envelope=encoded_envelope,
        timeout_seconds=timeout_seconds,
    )
    if _measure_verifier_executable(resolved_executable) != executable_measurement:
        return _invalid("VERIFIER_EXECUTABLE_CHANGED")
    try:
        if _measure_command_argument_files(command) != argument_files:
            return _invalid("VERIFIER_COMMAND_ARGUMENT_FILE_CHANGED")
    except ValueError:
        return _invalid("VERIFIER_COMMAND_ARGUMENT_FILE_CHANGED")
    if completed.failure_reason is not None:
        return _invalid(
            completed.failure_reason,
            exit_code=completed.exit_code,
        )
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, child in pairs:
            if key in value:
                raise ValueError("duplicate JSON key")
            value[key] = child
        return value

    try:
        decoded = completed.stdout.decode("utf-8", errors="strict")
        verdict = json.loads(decoded, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return _invalid("VERIFIER_OUTPUT_MALFORMED", exit_code=completed.exit_code)
    if completed.exit_code is None:
        return _invalid("VERIFIER_LAUNCH_FAILED")
    invocation = _validate_verdict(verdict, exit_code=completed.exit_code)
    if not invocation.accepted or invocation.verdict is None:
        return invocation
    expected = {
        "request_fingerprint": envelope.get("request_fingerprint"),
        "checkpoint": envelope.get("checkpoint"),
        "observed_state_sha512": envelope.get("canonical_state_sha512"),
        "envelope_sha512": assurance_envelope_digest(envelope),
    }
    if any(invocation.verdict.get(field) != value for field, value in expected.items()):
        return _invalid(
            "VERDICT_BINDING_MISMATCH",
            exit_code=completed.exit_code,
        )
    return invocation


def mode_requires_denial(mode: AssuranceMode, invocation: VerifierInvocation | None) -> bool:
    """Return whether verifier state must deny progress under the configured mode."""

    if mode is not AssuranceMode.REQUIRED:
        return False
    return invocation is None or invocation.status != "VERIFIED" or not invocation.accepted
