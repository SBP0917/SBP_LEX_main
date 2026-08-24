"""Fail-closed CLI for detached P/T/D/E verification only."""

from __future__ import annotations

import argparse
import json
import stat
from pathlib import Path
from typing import Sequence

from .constants import MAX_JSON_DOCUMENT_BYTES
from .errors import PTDEVerificationError, reject
from .policy import expected_policy
from .trust import accepted_attempt_history_from_document
from .verifier import verify_ptde_chain


def _verify(arguments: argparse.Namespace) -> int:
    try:
        history_path = Path(arguments.accepted_attempt_history)
        metadata = history_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_size > MAX_JSON_DOCUMENT_BYTES
        ):
            raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_INVALID")
        history = accepted_attempt_history_from_document(history_path.read_bytes())
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise reject("ACCEPTED_ATTEMPT_HISTORY_FILE_UNAVAILABLE") from exc
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
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0


def _show_policy(_: argparse.Namespace) -> int:
    print(json.dumps(expected_policy(), ensure_ascii=False, separators=(",", ":"), sort_keys=True))
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
