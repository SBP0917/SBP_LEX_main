"""Bounded, policy-locked, full-byte command transcripts; never uses a shell."""

from __future__ import annotations

import base64
import binascii
import os
import platform
import signal
import subprocess
import sys
import threading
from hashlib import sha512
from pathlib import Path
from time import monotonic, monotonic_ns
from typing import Any

from .constants import COMMAND_POLICY, DEFAULT_COMMAND_TIMEOUT_SECONDS, MAX_COMMAND_OUTPUT_BYTES
from .digests import digest
from .paths import validated_root


class CommandEvidenceError(ValueError):
    pass


def resolved_command_policy() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in COMMAND_POLICY:
        if len(raw) == 3:
            command_id, arguments, required = raw
            cwd_relative = "."
        else:
            command_id, arguments, required, cwd_relative = raw
        resolved = [sys.executable if item == "{python}" else item for item in arguments]
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


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


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
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTEST_ADDOPTS"] = "-p no:cacheprovider"
    started = monotonic_ns()
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    timed_out = False
    process: subprocess.Popen[bytes] | None = None
    try:
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
        )
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
            creationflags=creationflags,
        )
        assert process.stdout is not None and process.stderr is not None
        readers = (
            threading.Thread(target=_read_bounded, args=(process.stdout, stdout, overflow), daemon=True),
            threading.Thread(target=_read_bounded, args=(process.stderr, stderr, overflow), daemon=True),
        )
        for reader in readers:
            reader.start()
        deadline = monotonic() + timeout_seconds
        while process.poll() is None:
            if overflow.is_set():
                _terminate(process)
                break
            remaining = deadline - monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process)
                break
            overflow.wait(min(0.05, remaining))
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate(process)
            process.wait(timeout=5)
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
            _terminate(process)
    stdout_bytes = bytes(stdout)
    stderr_bytes = bytes(stderr)
    duration_ms = max(0, (monotonic_ns() - started) // 1_000_000)
    full_bytes = not overflow.is_set()
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
        stdout = base64.b64decode(result.get("stdout_b64"), validate=True)
        stderr = base64.b64decode(result.get("stderr_b64"), validate=True)
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
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "working_directory": str(root),
        "environment_values_retained": False,
        "environment_name_index_digest": digest({"names": sorted(os.environ)}),
    }


__all__ = [
    "CommandEvidenceError",
    "capture_command",
    "capture_commands",
    "environment_record",
    "resolved_command_policy",
    "validate_full_byte_transcript",
]
