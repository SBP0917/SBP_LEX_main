"""Pinned, configuration-isolated and resource-bounded Git execution."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any

from .command_evidence import (
    CommandEvidenceError,
    _terminate,
    _windows_creation_flags,
    _WindowsCommandJob,
)
from .constants import MAX_COMMAND_OUTPUT_BYTES
from .digests import is_sha512

MAX_GIT_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_GIT_ARGUMENT_COUNT = 256
MAX_GIT_ARGUMENT_BYTES = 65_536
_SCRIPT_SUFFIXES = frozenset({".bat", ".cmd", ".com", ".ps1", ".py", ".sh"})
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x0400)


class SecureGitError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class GitExecutableMeasurement:
    device: int
    inode: int
    byte_count: int
    modified_at_ns: int
    changed_at_ns: int
    link_count: int
    sha512: str


def _is_reparse_or_symlink(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _REPARSE_POINT
    )


def _require_safe_path(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for component in (*reversed(absolute.parents), absolute):
        try:
            metadata = component.lstat()
        except OSError as exc:
            raise SecureGitError("git_executable_path_unavailable") from exc
        if _is_reparse_or_symlink(metadata):
            raise SecureGitError("git_executable_path_link_rejected")


def _measure_executable(path: Path) -> GitExecutableMeasurement:
    descriptor: int | None = None
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_or_symlink(before)
            or before.st_size <= 0
            or before.st_size > MAX_GIT_EXECUTABLE_BYTES
            or path.suffix.casefold() in _SCRIPT_SUFFIXES
        ):
            raise SecureGitError("git_executable_file_invalid")
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
            or _is_reparse_or_symlink(opened)
            or (
                int(opened.st_dev),
                int(opened.st_ino),
                int(opened.st_size),
                int(opened.st_mtime_ns),
                int(opened.st_nlink),
            )
            != (identity[0], identity[1], identity[2], identity[3], identity[5])
        ):
            raise SecureGitError("git_executable_identity_changed")
        digest = hashlib.sha512()
        first = True
        observed = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1_048_576, MAX_GIT_EXECUTABLE_BYTES + 1 - observed),
            )
            if not chunk:
                break
            if first:
                first = False
                if chunk.startswith(b"#!"):
                    raise SecureGitError("git_executable_script_rejected")
                if os.name == "nt" and not chunk.startswith(b"MZ"):
                    raise SecureGitError("git_executable_native_format_invalid")
            observed += len(chunk)
            if observed > MAX_GIT_EXECUTABLE_BYTES:
                raise SecureGitError("git_executable_size_limit")
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
            or _is_reparse_or_symlink(after)
            or observed != before.st_size
        ):
            raise SecureGitError("git_executable_identity_changed")
        return GitExecutableMeasurement(*identity, digest.hexdigest())
    except SecureGitError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise SecureGitError("git_executable_unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _resolve_executable(
    value: str | os.PathLike[str], expected_sha512: str
) -> tuple[Path, GitExecutableMeasurement]:
    if (
        not isinstance(value, (str, os.PathLike))
        or not os.fspath(value)
        or "\x00" in os.fspath(value)
        or not is_sha512(expected_sha512)
    ):
        raise SecureGitError("git_executable_or_pin_invalid")
    raw = os.fspath(value)
    located = raw if Path(raw).is_absolute() else shutil.which(raw)
    if not located:
        raise SecureGitError("git_executable_not_found")
    candidate = Path(located)
    if candidate.suffix.casefold() in _SCRIPT_SUFFIXES:
        raise SecureGitError("git_executable_script_rejected")
    _require_safe_path(candidate)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise SecureGitError("git_executable_unavailable") from exc
    if os.path.normcase(os.path.abspath(candidate)) != os.path.normcase(str(resolved)):
        raise SecureGitError("git_executable_path_resolution_changed")
    measurement = _measure_executable(resolved)
    if measurement.link_count != 1:
        canonical_git = shutil.which("git")
        try:
            canonical_path = (
                Path(canonical_git).resolve(strict=True)
                if canonical_git is not None
                else None
            )
        except OSError as exc:
            raise SecureGitError("git_executable_hard_link_rejected") from exc
        if canonical_path is None or os.path.normcase(str(canonical_path)) != os.path.normcase(
            str(resolved)
        ):
            raise SecureGitError("git_executable_hard_link_rejected")
    if measurement.sha512 != expected_sha512:
        raise SecureGitError("git_executable_pin_mismatch")
    return resolved, measurement


def _read_bounded(
    stream: Any,
    target: bytearray,
    peer: bytearray,
    lock: threading.Lock,
    overflow: threading.Event,
    maximum: int,
) -> None:
    try:
        while not overflow.is_set():
            chunk = stream.read(64 * 1024)
            if not chunk:
                return
            with lock:
                if len(target) + len(peer) + len(chunk) > maximum:
                    overflow.set()
                    return
                target.extend(chunk)
    finally:
        try:
            stream.close()
        except OSError:
            pass


class PinnedGit:
    """Run one exact Git executable without inherited configuration or helpers."""

    def __init__(
        self,
        git_executable: str | os.PathLike[str],
        expected_sha512: str,
    ) -> None:
        self._path, self._baseline = _resolve_executable(
            git_executable, expected_sha512
        )
        self._expected_sha512 = expected_sha512
        self._repository_identity: tuple[str, int, int, int, int] | None = None

    @property
    def executable_sha512(self) -> str:
        return self._expected_sha512

    def _verify_executable(self) -> None:
        if _measure_executable(self._path) != self._baseline:
            raise SecureGitError("git_executable_changed")

    def _verify_repository_root(self, root: Path) -> Path:
        try:
            supplied = Path(root)
            resolved = supplied.resolve(strict=True)
            metadata = supplied.lstat()
            for component in (*reversed(supplied.parents), supplied):
                if _is_reparse_or_symlink(component.lstat()):
                    raise SecureGitError("git_repository_root_link_rejected")
        except SecureGitError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise SecureGitError("git_repository_root_invalid") from exc
        if (
            not supplied.is_absolute()
            or not stat.S_ISDIR(metadata.st_mode)
            or _is_reparse_or_symlink(metadata)
            or os.path.normcase(os.path.abspath(supplied))
            != os.path.normcase(str(resolved))
        ):
            raise SecureGitError("git_repository_root_invalid")
        identity = (
            os.path.normcase(str(resolved)),
            int(metadata.st_dev),
            int(metadata.st_ino),
            int(metadata.st_mode),
            int(metadata.st_ctime_ns),
        )
        if self._repository_identity is None:
            self._repository_identity = identity
        elif identity != self._repository_identity:
            raise SecureGitError("git_repository_root_changed")
        return resolved

    @staticmethod
    def _environment() -> dict[str, str]:
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
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "",
            }
        )
        return environment

    def run(
        self,
        root: Path,
        *arguments: str,
        timeout_seconds: int = 30,
        maximum_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES,
    ) -> bytes:
        if (
            type(timeout_seconds) is not int
            or not 1 <= timeout_seconds <= 300
            or type(maximum_output_bytes) is not int
            or not 1 <= maximum_output_bytes <= MAX_COMMAND_OUTPUT_BYTES
            or not arguments
            or any(type(item) is not str or "\x00" in item for item in arguments)
            or len(arguments) > MAX_GIT_ARGUMENT_COUNT
            or sum(len(item.encode("utf-8")) for item in arguments)
            > MAX_GIT_ARGUMENT_BYTES
        ):
            raise SecureGitError("git_command_invalid")
        resolved_root = self._verify_repository_root(root)
        self._verify_executable()
        command = (
            str(self._path),
            "-C",
            str(resolved_root),
            "-c",
            f"safe.directory={resolved_root}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            f"core.hooksPath={os.devnull}",
            "-c",
            "core.replaceRefs=false",
            "-c",
            "core.useReplaceRefs=false",
            "-c",
            "protocol.allow=never",
            *arguments,
        )
        stdout = bytearray()
        stderr = bytearray()
        output_lock = threading.Lock()
        overflow = threading.Event()
        process: subprocess.Popen[bytes] | None = None
        windows_job: _WindowsCommandJob | None = None
        timed_out = False
        try:
            process = subprocess.Popen(
                command,
                cwd=self._path.parent,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=self._environment(),
                close_fds=True,
                start_new_session=os.name != "nt",
                creationflags=_windows_creation_flags(),
            )
            if process.stdout is None or process.stderr is None:
                process.kill()
                process.wait(timeout=5)
                raise SecureGitError("git_command_stream_unavailable")
            try:
                windows_job = _WindowsCommandJob(process)
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
            readers = (
                threading.Thread(
                    target=_read_bounded,
                    args=(
                        process.stdout,
                        stdout,
                        stderr,
                        output_lock,
                        overflow,
                        maximum_output_bytes,
                    ),
                    daemon=True,
                ),
                threading.Thread(
                    target=_read_bounded,
                    args=(
                        process.stderr,
                        stderr,
                        stdout,
                        output_lock,
                        overflow,
                        maximum_output_bytes,
                    ),
                    daemon=True,
                ),
            )
            for reader in readers:
                reader.start()
            deadline = monotonic() + timeout_seconds
            while process.poll() is None:
                if overflow.is_set() or monotonic() >= deadline:
                    timed_out = not overflow.is_set()
                    _terminate(process, windows_job)
                    break
                overflow.wait(0.05)
            process.wait(timeout=5)
            if monotonic() >= deadline and not overflow.is_set():
                timed_out = True
            _terminate(process, windows_job)
            for reader in readers:
                reader.join(timeout=5)
            if any(reader.is_alive() for reader in readers):
                raise SecureGitError("git_command_capture_not_closed")
        except SecureGitError:
            raise
        except (CommandEvidenceError, OSError, subprocess.SubprocessError) as exc:
            raise SecureGitError("git_command_unavailable") from exc
        finally:
            if process is not None and process.poll() is None:
                _terminate(process, windows_job)
            if windows_job is not None:
                windows_job.close()
        self._verify_executable()
        self._verify_repository_root(root)
        if timed_out:
            raise SecureGitError("git_command_timeout")
        if overflow.is_set():
            raise SecureGitError("git_command_output_limit")
        if process is None or process.returncode != 0 or stderr:
            raise SecureGitError("git_command_failed")
        return bytes(stdout)


__all__ = [
    "GitExecutableMeasurement",
    "PinnedGit",
    "SecureGitError",
]
