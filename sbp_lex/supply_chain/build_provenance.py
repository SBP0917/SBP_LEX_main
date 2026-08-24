"""PTDE-compatible full-byte host lane execution, never an admission mechanism."""

from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import signal
import stat
import subprocess
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping

from sbp_ptde.canonical import canonical_json_document_bytes, canonical_path, canonical_sha512, identifier, require_sha512
from sbp_ptde.constants import MAX_LANE_TIMEOUT_SECONDS, MAX_STREAM_BYTE_COUNT, NO_AUTHORITY, TIMEOUT_STATUS, TRANSCRIPT_SCHEMA_ID
from sbp_ptde.errors import reject
from sbp_ptde.schemas import validate_lanes

from .constants import HOST_OBSERVATION_SCHEMA_ID, UNSIGNED_NOT_ADMITTED


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
    kernel32.SetInformationJobObject.argtypes = (wintypes.HANDLE, wintypes.INT, ctypes.c_void_p, wintypes.DWORD)
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    return kernel32


class _WindowsLaneJob:
    """Contain a Windows lane and terminate all of its processes on close."""

    _KILL_ON_JOB_CLOSE = 0x00002000
    _EXTENDED_LIMIT_INFORMATION_CLASS = 9

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._handle: int | None = None
        if os.name != "nt":
            return
        kernel32 = _kernel32()
        handle = kernel32.CreateJobObjectW(None, None)
        if not handle:
            raise reject("SUPPLY_CHAIN_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")
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
            raise reject("SUPPLY_CHAIN_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")
        if not kernel32.AssignProcessToJobObject(wintypes.HANDLE(self._handle), wintypes.HANDLE(process._handle)):
            self.close()
            raise reject("SUPPLY_CHAIN_PROCESS_TREE_CONTAINMENT_UNAVAILABLE")

    def terminate(self) -> bool:
        if self._handle is None:
            return False
        return bool(_kernel32().TerminateJobObject(wintypes.HANDLE(self._handle), 1))

    def close(self) -> None:
        if self._handle is not None:
            _kernel32().CloseHandle(wintypes.HANDLE(self._handle))
            self._handle = None


def _executable_measurement(path: Path, *, maximum_bytes: int = 268_435_456) -> tuple[Path, tuple[int, int, int, int], str]:
    """Resolve and measure a regular executable before or after a host lane."""

    candidate = path.resolve(strict=True)
    before = candidate.lstat()
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or bool(getattr(before, "st_file_attributes", 0) & reparse)
        or before.st_size > maximum_bytes
        or candidate.suffix.casefold() in {".bat", ".cmd", ".ps1"}
    ):
        raise reject("SUPPLY_CHAIN_EXECUTABLE_INVALID")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(candidate, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != identity:
            raise reject("SUPPLY_CHAIN_EXECUTABLE_IDENTITY_CHANGED")
        digest = hashlib.sha512()
        while True:
            chunk = os.read(descriptor, 1_048_576)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(descriptor)
    after = candidate.lstat()
    if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != identity:
        raise reject("SUPPLY_CHAIN_EXECUTABLE_IDENTITY_CHANGED")
    return candidate, identity, digest.hexdigest()


def resolve_pinned_executable(value: str, expected_sha512: str) -> tuple[Path, tuple[int, int, int, int]]:
    """Resolve a real executable and require its out-of-band SHA-512 pin."""

    if type(value) is not str or not value or "\x00" in value:
        raise reject("SUPPLY_CHAIN_EXECUTABLE_PATH_INVALID")
    located = str(Path(value)) if Path(value).is_absolute() else shutil.which(value)
    if not located:
        raise reject("SUPPLY_CHAIN_EXECUTABLE_UNAVAILABLE")
    path, identity, observed = _executable_measurement(Path(located))
    if observed != require_sha512(expected_sha512, "SUPPLY_CHAIN_EXECUTABLE_PIN_INVALID"):
        raise reject("SUPPLY_CHAIN_EXECUTABLE_NOT_OUT_OF_BAND_PINNED")
    return path, identity


def _confirm_executable(path: Path, identity: tuple[int, int, int, int], expected_sha512: str) -> None:
    _, observed_identity, observed_digest = _executable_measurement(path)
    if observed_identity != identity or observed_digest != expected_sha512:
        raise reject("SUPPLY_CHAIN_EXECUTABLE_CHANGED")


def _clean_checkout(git_executable: Path, git_identity: tuple[int, int, int, int], expected_git_sha512: str, checkout: Path) -> bool:
    _confirm_executable(git_executable, git_identity, expected_git_sha512)
    clean_environment = {
        key: os.environ[key]
        for key in ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
        if key in os.environ
    }
    clean_environment.update({
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    })
    result = subprocess.run(
        [str(git_executable), "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=checkout,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=120,
        env=clean_environment,
    )
    _confirm_executable(git_executable, git_identity, expected_git_sha512)
    return result.returncode == 0 and result.stdout == b""


def _terminate_process_tree(process: subprocess.Popen[bytes], windows_job: _WindowsLaneJob | None) -> bool:
    try:
        if os.name == "nt":
            if windows_job is None or not windows_job.terminate():
                return False
            process.wait(timeout=5)
            return True
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def _write_bytes(root: Path, relative: str, value: bytes) -> None:
    path = root.joinpath(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def execute_host_lane(
    *,
    lane: dict[str, Any],
    executable_path: str,
    expected_executable_sha512: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    source_checkout: Path,
    evidence_root: Path,
    campaign_id: str,
    attempt_id: str,
    d_commit_oid: str,
    d_descriptor_sha512: str,
    environment: Mapping[str, str],
) -> dict[str, Any]:
    """Execute one predeclared lane with full streams; timeout or dirtiness cannot pass."""

    validate_lanes([lane])
    identifier(campaign_id, code="SUPPLY_CHAIN_CAMPAIGN_INVALID")
    identifier(attempt_id, code="SUPPLY_CHAIN_ATTEMPT_INVALID")
    require_sha512(d_descriptor_sha512, "SUPPLY_CHAIN_D_DESCRIPTOR_INVALID")
    pinned_executable, executable_identity = resolve_pinned_executable(executable_path, expected_executable_sha512)
    pinned_git, git_identity = resolve_pinned_executable(git_executable, expected_git_executable_sha512)
    if lane["argv"][0] != lane["executable_id"]:
        raise reject("SUPPLY_CHAIN_ARGV_ZERO_INVALID")
    if lane["timeout_seconds"] < 1 or lane["timeout_seconds"] > MAX_LANE_TIMEOUT_SECONDS:
        raise reject("SUPPLY_CHAIN_TIMEOUT_INVALID")
    names = lane["environment_name_allowlist"]
    if sorted(environment) != names or any(type(value) is not str for value in environment.values()):
        raise reject("SUPPLY_CHAIN_ENVIRONMENT_INVALID")
    if not _clean_checkout(pinned_git, git_identity, expected_git_executable_sha512, source_checkout):
        raise reject("SUPPLY_CHAIN_SOURCE_DIRTY_BEFORE_LANE")
    stdout_relative = canonical_path(lane["stdout_contract"]["relative_path"], code="SUPPLY_CHAIN_STDOUT_PATH_INVALID")
    stderr_relative = canonical_path(lane["stderr_contract"]["relative_path"], code="SUPPLY_CHAIN_STDERR_PATH_INVALID")
    if stdout_relative == stderr_relative:
        raise reject("SUPPLY_CHAIN_STREAM_PATH_OVERLAP")
    stdout_path = evidence_root.joinpath(*stdout_relative.split("/"))
    stderr_path = evidence_root.joinpath(*stderr_relative.split("/"))
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = int(time.time() * 1000)
    timed_out = False
    tree_terminated = False
    with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
        launch_arguments = [str(pinned_executable), *lane["argv"][1:]]
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        process = subprocess.Popen(
            launch_arguments,
            cwd=source_checkout,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            shell=False,
            env=dict(environment),
            start_new_session=os.name != "nt",
            creationflags=creationflags,
        )
        windows_job: _WindowsLaneJob | None = None
        try:
            try:
                windows_job = _WindowsLaneJob(process)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
            deadline = time.monotonic() + lane["timeout_seconds"]
            while process.poll() is None:
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if stdout_size > lane["stdout_contract"]["maximum_byte_count"] or stderr_size > lane["stderr_contract"]["maximum_byte_count"]:
                    tree_terminated = _terminate_process_tree(process, windows_job)
                    timed_out = True
                    break
                if time.monotonic() >= deadline:
                    tree_terminated = _terminate_process_tree(process, windows_job)
                    timed_out = True
                    break
                time.sleep(0.01)
            exit_status = process.wait(timeout=5)
        finally:
            if windows_job is not None:
                windows_job.close()
    finished = int(time.time() * 1000)
    _confirm_executable(pinned_executable, executable_identity, expected_executable_sha512)
    source_dirty_after = not _clean_checkout(pinned_git, git_identity, expected_git_executable_sha512, source_checkout)
    stdout = stdout_path.read_bytes()
    stderr = stderr_path.read_bytes()
    stdout_limit = lane["stdout_contract"]["maximum_byte_count"]
    stderr_limit = lane["stderr_contract"]["maximum_byte_count"]
    if len(stdout) > stdout_limit or len(stderr) > stderr_limit:
        timed_out = True
    status = "LANE_PASS" if (
        not timed_out and not source_dirty_after and exit_status in lane["expected_exit_codes"]
    ) else "LANE_FAIL"
    timeout_status = "NOT_TIMED_OUT" if not timed_out else TIMEOUT_STATUS
    transcript = {
        "schema_id": TRANSCRIPT_SCHEMA_ID,
        "campaign_id": campaign_id,
        "lane_id": lane["lane_id"],
        "attempt_id": attempt_id,
        "lane_contract_sha512": canonical_sha512(lane),
        "d_commit_oid": d_commit_oid,
        "d_descriptor_sha512": d_descriptor_sha512,
        "command_executed": True,
        "setup_completed": True,
        "status": status,
        "exit_status": exit_status,
        "started_at_unix_ms": started,
        "finished_at_unix_ms": finished,
        "wall_clock_milliseconds": finished - started,
        "timeout_seconds": lane["timeout_seconds"],
        "timed_out": timed_out,
        "timeout_status": timeout_status,
        "cleanup_completed": True,
        "process_tree_terminated": tree_terminated,
        "stdout_path": stdout_relative,
        "stdout_byte_count": len(stdout),
        "stdout_sha512": hashlib.sha512(stdout).hexdigest(),
        "stdout_full_bytes": True,
        "stderr_path": stderr_relative,
        "stderr_byte_count": len(stderr),
        "stderr_sha512": hashlib.sha512(stderr).hexdigest(),
        "stderr_full_bytes": True,
        "output_truncated": False,
        "error": None if status == "LANE_PASS" else "LANE_FAIL_CLOSED",
        "produced_artifacts": [],
        "source_mutation_observed": source_dirty_after,
        "ledger_mutation_observed": False,
        "authority_mutation_observed": False,
        "no_authority": dict(NO_AUTHORITY),
    }
    transcript_relative = f"transcripts/{lane['lane_id']}-{attempt_id}.json"
    transcript_bytes = canonical_json_document_bytes(transcript)
    _write_bytes(evidence_root, transcript_relative, transcript_bytes)
    return {
        "schema_id": HOST_OBSERVATION_SCHEMA_ID,
        "pinned_host_lane": transcript,
        "transcript_path": transcript_relative,
        "transcript_byte_count": len(transcript_bytes),
        "transcript_sha512": hashlib.sha512(transcript_bytes).hexdigest(),
        "no_authority": dict(NO_AUTHORITY),
        "admission_state": UNSIGNED_NOT_ADMITTED,
    }
