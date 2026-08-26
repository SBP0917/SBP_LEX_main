"""Bounded, policy-locked, full-byte command transcripts; never uses a shell."""

from __future__ import annotations

import base64
import binascii
import ctypes
import os
import platform
import shutil
import signal
import stat
import subprocess
import sys
import threading
from ctypes import wintypes
from hashlib import sha512
from pathlib import Path
from time import monotonic, monotonic_ns
from typing import Any

from .constants import (
    COMMAND_POLICY,
    DEFAULT_COMMAND_TIMEOUT_SECONDS,
    MAX_COMMAND_OUTPUT_BYTES,
)
from .digests import digest
from .paths import validated_root


class CommandEvidenceError(ValueError):
    pass


_INHERITED_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "NUMBER_OF_PROCESSORS",
        "OS",
        "PROCESSOR_ARCHITECTURE",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "WINDIR",
    }
)
_ENVIRONMENT_POLICY_ID = "SBP_LEX_V2_LOCAL_TRUST_COMMAND_ENVIRONMENT_V1"


def _command_environment() -> dict[str, str]:
    """Build a minimal host environment and remove inherited code-injection knobs."""

    environment = {
        name.upper(): value
        for name, value in os.environ.items()
        if name.upper() in _INHERITED_ENVIRONMENT_ALLOWLIST
    }
    environment.update(
        {
            "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true",
            "CARGO_TERM_COLOR": "never",
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "NO_COLOR": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "PYTEST_ADDOPTS": "-p no:cacheprovider",
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "RUST_BACKTRACE": "0",
            "PATH": os.pathsep.join(
                sorted(
                    {
                        str(Path(executable).resolve(strict=True).parent)
                        for executable in (
                            sys.executable,
                            *(shutil.which(name) for name in ("alr", "cargo", "git", "java")),
                        )
                        if executable is not None
                    },
                    key=str.casefold,
                )
            ),
        }
    )
    return environment


_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)
_MAX_COMMAND_INPUT_FILE_BYTES = 268_435_456


def _is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _stable_file_measurement(
    path: Path, *, executable: bool
) -> tuple[str, int, int, int, int, int, int, str]:
    descriptor: int | None = None
    try:
        resolved = path.resolve(strict=True)
        if (
            not path.is_absolute()
            or os.path.normcase(os.path.abspath(path))
            != os.path.normcase(str(resolved))
        ):
            raise CommandEvidenceError("command_input_path_alias_rejected")
        for component in (*reversed(path.parents), path):
            if _is_link_or_reparse(component.lstat()):
                raise CommandEvidenceError("command_input_path_link_rejected")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_link_or_reparse(before)
            or before.st_nlink != 1
            or not 0 < before.st_size <= _MAX_COMMAND_INPUT_FILE_BYTES
            or (
                executable
                and path.suffix.casefold()
                in {".bat", ".cmd", ".com", ".ps1", ".py", ".sh"}
            )
        ):
            raise CommandEvidenceError("command_input_file_invalid")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(resolved, flags)
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
            int(opened.st_dev),
            int(opened.st_ino),
            int(opened.st_size),
            int(opened.st_mtime_ns),
            int(opened.st_nlink),
        ) != (identity[0], identity[1], identity[2], identity[3], identity[5]):
            raise CommandEvidenceError("command_input_file_changed")
        content_digest = sha512()
        observed = 0
        first = True
        while True:
            chunk = os.read(
                descriptor,
                min(1_048_576, _MAX_COMMAND_INPUT_FILE_BYTES + 1 - observed),
            )
            if not chunk:
                break
            if first:
                first = False
                if executable and (
                    chunk.startswith(b"#!")
                    or (os.name == "nt" and not chunk.startswith(b"MZ"))
                ):
                    raise CommandEvidenceError("command_executable_format_invalid")
            observed += len(chunk)
            if observed > _MAX_COMMAND_INPUT_FILE_BYTES:
                raise CommandEvidenceError("command_input_file_too_large")
            content_digest.update(chunk)
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
            or observed != before.st_size
            or _is_link_or_reparse(after)
        ):
            raise CommandEvidenceError("command_input_file_changed")
        return (str(resolved), *identity, content_digest.hexdigest())
    except CommandEvidenceError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise CommandEvidenceError("command_input_file_unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _command_file_measurements(
    arguments: tuple[str, ...], command_root: Path
) -> tuple[tuple[str, int, int, int, int, int, int, str], ...]:
    records = [_stable_file_measurement(Path(arguments[0]), executable=True)]
    for argument in arguments[1:]:
        raw = argument.removeprefix("@")
        if not raw or (argument.startswith("-") and not argument.startswith("@")):
            continue
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = command_root / candidate
        try:
            metadata = candidate.lstat()
        except (OSError, ValueError):
            if argument.startswith("@"):
                raise CommandEvidenceError("command_response_file_unavailable") from None
            continue
        if stat.S_ISREG(metadata.st_mode) or _is_link_or_reparse(metadata):
            records.append(_stable_file_measurement(candidate, executable=False))
    return tuple(records)


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
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
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


class _WindowsCommandJob:
    """Contain a Windows command and every descendant in one kill-on-close job."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION_CLASS = 9

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = _kernel32()
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise CommandEvidenceError("command_process_tree_containment_unavailable")
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
            raise CommandEvidenceError("command_process_tree_containment_unavailable")
        process_handle = process.__dict__.get("_handle")
        if process_handle is None or not kernel32.AssignProcessToJobObject(
            wintypes.HANDLE(self._handle), wintypes.HANDLE(process_handle)
        ):
            self.close()
            raise CommandEvidenceError("command_process_tree_containment_unavailable")
        if not _resume_suspended_process(process):
            self.terminate()
            self.close()
            raise CommandEvidenceError("command_process_tree_resume_failed")

    def terminate(self) -> bool:
        if self._handle is None:
            return False
        return bool(_kernel32().TerminateJobObject(wintypes.HANDLE(self._handle), 1))

    def close(self) -> None:
        if self._handle is not None:
            _kernel32().CloseHandle(wintypes.HANDLE(self._handle))
            self._handle = None


def resolved_command_policy() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in COMMAND_POLICY:
        command_id = raw[0]
        arguments: tuple[str, ...] = raw[1]
        required = raw[2]
        if len(raw) == 3:
            cwd_relative = "."
        else:
            cwd_relative = raw[3]
        resolved = [sys.executable if item == "{python}" else item for item in arguments]
        executable = resolved[0]
        if executable != sys.executable:
            selected = shutil.which(executable)
            if selected is not None:
                resolved[0] = str(Path(selected).resolve(strict=True))
        result.append({
            "command_id": command_id,
            "arguments": resolved,
            "required": required,
            "working_directory": cwd_relative,
        })
    return result


def _read_bounded(
    stream: Any,
    target: bytearray,
    overflow: threading.Event,
) -> None:
    try:
        while not overflow.is_set():
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            if len(target) + len(chunk) > MAX_COMMAND_OUTPUT_BYTES:
                overflow.set()
                return
            target.extend(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _terminate(
    process: subprocess.Popen[bytes], windows_job: _WindowsCommandJob | None
) -> None:
    try:
        if os.name != "nt":
            kill_process_group = os.__dict__.get("killpg")
            kill_signal = signal.__dict__.get("SIGKILL")
            if not callable(kill_process_group) or type(kill_signal) is not int:
                raise CommandEvidenceError(
                    "command_process_tree_termination_unavailable"
                )
            kill_process_group(process.pid, kill_signal)
        elif windows_job is None or not windows_job.terminate():
            raise CommandEvidenceError("command_process_tree_termination_failed")
    except (OSError, ProcessLookupError):
        pass


def _windows_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        | getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
    )


def capture_command(
    repository_root: str | Path,
    command: dict[str, Any],
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    root = validated_root(repository_root)
    if command not in resolved_command_policy():
        raise CommandEvidenceError("command_not_policy_admitted")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 7200:
        raise CommandEvidenceError("command_timeout_invalid")
    arguments = tuple(command["arguments"])
    if not arguments or any(type(argument) is not str or "\x00" in argument for argument in arguments):
        raise CommandEvidenceError("command_arguments_invalid")
    cwd_relative = command.get("working_directory")
    if cwd_relative == ".":
        command_root = root
    elif type(cwd_relative) is str:
        from .paths import resolve_safe_path
        command_root = resolve_safe_path(root, cwd_relative)
        if not command_root.is_dir():
            raise CommandEvidenceError("command_working_directory_invalid")
    else:
        raise CommandEvidenceError("command_working_directory_invalid")
    environment = _command_environment()
    command_root_identity = command_root.lstat()
    command_files = _command_file_measurements(arguments, command_root)
    started = monotonic_ns()
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    timed_out = False
    process: subprocess.Popen[bytes] | None = None
    windows_job: _WindowsCommandJob | None = None
    try:
        process = subprocess.Popen(
            arguments,
            cwd=command_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=environment,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=_windows_creation_flags(),
        )
        if process.stdout is None or process.stderr is None:
            process.kill()
            process.wait(timeout=5)
            raise CommandEvidenceError("command_capture_stream_unavailable")
        try:
            windows_job = _WindowsCommandJob(process)
        except BaseException:
            process.kill()
            process.wait(timeout=5)
            raise
        readers = (
            threading.Thread(target=_read_bounded, args=(process.stdout, stdout, overflow), daemon=True),
            threading.Thread(target=_read_bounded, args=(process.stderr, stderr, overflow), daemon=True),
        )
        for reader in readers:
            reader.start()
        deadline = monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set():
                _terminate(process, windows_job)
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process, windows_job)
                break
            overflow.wait(min(0.05, remaining))
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(process, windows_job)
            process.wait(timeout=5)
        if monotonic() >= deadline:
            timed_out = True
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise CommandEvidenceError("command_capture_thread_not_closed")
        exit_code: int | None = process.returncode
        if overflow.is_set():
            status = "COMMAND_OUTPUT_LIMIT"
        elif timed_out:
            status = "COMMAND_TIMEOUT"
        else:
            status = "COMMAND_PASS" if exit_code == 0 else "COMMAND_FAIL"
    except OSError:
        status = "COMMAND_ERROR"
        exit_code = None
    finally:
        if process is not None and process.poll() is None:
            _terminate(process, windows_job)
        if windows_job is not None:
            windows_job.close()
    stdout_bytes = bytes(stdout)
    stderr_bytes = bytes(stderr)
    duration_ms = max(0, (monotonic_ns() - started) // 1_000_000)
    full_bytes = not overflow.is_set()
    try:
        inputs_stable = (
            _command_file_measurements(arguments, command_root) == command_files
            and (
                command_root.lstat().st_dev,
                command_root.lstat().st_ino,
                stat.S_IFMT(command_root.lstat().st_mode),
            )
            == (
                command_root_identity.st_dev,
                command_root_identity.st_ino,
                stat.S_IFMT(command_root_identity.st_mode),
            )
        )
    except (CommandEvidenceError, OSError):
        inputs_stable = False
    if not inputs_stable:
        status = "COMMAND_INPUT_CHANGED"
    return {
        **command,
        "status": status,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "timed_out": timed_out,
        "stdout_bytes": len(stdout_bytes),
        "stdout_sha512": sha512(stdout_bytes).hexdigest(),
        "stdout_b64": base64.b64encode(stdout_bytes).decode("ascii"),
        "stdout_full_bytes": full_bytes,
        "stderr_bytes": len(stderr_bytes),
        "stderr_sha512": sha512(stderr_bytes).hexdigest(),
        "stderr_b64": base64.b64encode(stderr_bytes).decode("ascii"),
        "stderr_full_bytes": full_bytes,
        "output_truncated": not full_bytes,
        "shell_used": False,
    }


def capture_commands(
    repository_root: str | Path,
    *,
    timeout_seconds: int = DEFAULT_COMMAND_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    return [
        capture_command(repository_root, command, timeout_seconds=timeout_seconds)
        for command in resolved_command_policy()
    ]


def validate_full_byte_transcript(result: Any) -> bool:
    try:
        if type(result) is not dict:
            return False
        stdout_b64 = result.get("stdout_b64")
        stderr_b64 = result.get("stderr_b64")
        if type(stdout_b64) is not str or type(stderr_b64) is not str:
            return False
        stdout = base64.b64decode(stdout_b64, validate=True)
        stderr = base64.b64decode(stderr_b64, validate=True)
        return (
            result.get("stdout_full_bytes") is True
            and result.get("stderr_full_bytes") is True
            and result.get("output_truncated") is False
            and result.get("shell_used") is False
            and result.get("timed_out") is False
            and len(stdout) == result.get("stdout_bytes")
            and len(stderr) == result.get("stderr_bytes")
            and sha512(stdout).hexdigest() == result.get("stdout_sha512")
            and sha512(stderr).hexdigest() == result.get("stderr_sha512")
        )
    except (TypeError, ValueError, binascii.Error):
        return False


def environment_record(repository_root: str | Path) -> dict[str, Any]:
    root = validated_root(repository_root)
    environment = _command_environment()
    value_hashes = [
        {
            "name": name,
            "value_sha512": sha512(environment[name].encode("utf-8")).hexdigest(),
        }
        for name in sorted(environment)
    ]
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "working_directory": str(root),
        "environment_values_retained": False,
        "environment_policy_id": _ENVIRONMENT_POLICY_ID,
        "environment_name_index_digest": digest({"names": sorted(environment)}),
        "environment_value_hash_index_digest": digest(value_hashes),
    }


__all__ = [
    "CommandEvidenceError",
    "capture_command",
    "capture_commands",
    "environment_record",
    "resolved_command_policy",
    "validate_full_byte_transcript",
]
