"""Fail-closed CLI for detached P/T/D/E verification only."""

from __future__ import annotations

import argparse
import json
import os
import stat
import unicodedata
from pathlib import Path
from typing import Sequence

from .constants import (
    MAX_JSON_DOCUMENT_BYTES,
    MAX_PATH_SEGMENT_UTF8_BYTES,
    MAX_PATH_UTF8_BYTES,
)
from .errors import PTDEVerificationError, reject
from .policy import expected_policy
from .trust import accepted_attempt_history_from_document
from .verifier import verify_ptde_chain


_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _history_file_path(value: str) -> Path:
    if (
        type(value) is not str
        or not value
        or unicodedata.normalize("NFC", value) != value
        or "\x00" in value
        or len(value.encode("utf-8", errors="strict")) > MAX_PATH_UTF8_BYTES
    ):
        raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_PATH_INVALID")
    supplied = Path(value)
    anchor = supplied.anchor
    for part in supplied.parts:
        if part == anchor:
            continue
        if (
            part in {"", ".", ".."}
            or "\\" in part
            or ":" in part
            or any(ord(character) < 32 for character in part)
            or part.endswith((" ", "."))
            or len(part.encode("utf-8", errors="strict")) > MAX_PATH_SEGMENT_UTF8_BYTES
            or part.split(".", 1)[0].upper() in _WINDOWS_RESERVED
        ):
            raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_PATH_INVALID")
    return supplied


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_size,
        metadata.st_nlink,
        metadata.st_mtime_ns,
    )


def _is_reparse_or_symlink(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _read_accepted_attempt_history_file(value: str) -> bytes:
    try:
        supplied = _history_file_path(value)
        path = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(path.anchor)
        for part in path.parts[1:-1]:
            current /= part
            component = current.lstat()
            if not stat.S_ISDIR(component.st_mode) or _is_reparse_or_symlink(component):
                raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_PATH_UNSAFE")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or _is_reparse_or_symlink(before)
            or before.st_nlink != 1
            or before.st_size > MAX_JSON_DOCUMENT_BYTES
        ):
            raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_INVALID")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        try:
            opened_before = os.fstat(descriptor)
            if _file_identity(opened_before) != _file_identity(before):
                raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_CHANGED")
            chunks: list[bytes] = []
            byte_count = 0
            while True:
                chunk = os.read(descriptor, 1_048_576)
                if not chunk:
                    break
                byte_count += len(chunk)
                if byte_count > MAX_JSON_DOCUMENT_BYTES:
                    raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_INVALID")
                chunks.append(chunk)
            opened_after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        after = path.lstat()
        identities = {
            _file_identity(before),
            _file_identity(opened_before),
            _file_identity(opened_after),
            _file_identity(after),
        }
        if len(identities) != 1 or _is_reparse_or_symlink(after):
            raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_CHANGED")
        return b"".join(chunks)
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_UNAVAILABLE") from exc


def _verify(arguments: argparse.Namespace) -> int:
    history = accepted_attempt_history_from_document(
        _read_accepted_attempt_history_file(arguments.accepted_attempt_history)
    )
    result = verify_ptde_chain(
        arguments.object_database,
        p_oid=arguments.p_oid,
        t_oid=arguments.t_oid,
        d_oid=arguments.d_oid,
        e_oid=arguments.e_oid,
        expected_p_oid=arguments.expected_p_oid,
        expected_git_executable_sha512=arguments.expected_git_executable_sha512,
        accepted_attempt_history=history,
        expected_attempt_history_sha512=arguments.expected_attempt_history_sha512,
        git_executable=arguments.git_executable,
    )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


def _show_policy(_: argparse.Namespace) -> int:
    print(json.dumps(expected_policy(), ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detached SBP-LEX V2 P/T/D/E Git-object verifier"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--object-database", required=True)
    verify.add_argument("--p-oid", required=True)
    verify.add_argument("--t-oid", required=True)
    verify.add_argument("--d-oid", required=True)
    verify.add_argument("--e-oid", required=True)
    verify.add_argument("--expected-p-oid", required=True)
    verify.add_argument("--expected-git-executable-sha512", required=True)
    verify.add_argument("--accepted-attempt-history", required=True)
    verify.add_argument("--expected-attempt-history-sha512", required=True)
    verify.add_argument("--git-executable", default="git")
    verify.set_defaults(handler=_verify)

    policy = commands.add_parser("show-policy")
    policy.set_defaults(handler=_show_policy)

    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except PTDEVerificationError as exc:
        print(json.dumps({"error_code": exc.code}, separators=(",", ":"), sort_keys=True))
        return 2
    except Exception as exc:
        print(
            json.dumps(
                {"error_code": f"PTDE_INTERNAL_FAIL_CLOSED:{type(exc).__name__}"},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


__all__ = ["main"]
