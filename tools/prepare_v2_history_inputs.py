from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from sbp_lex.local_trust.history_preparation import (
    EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED,
    NOT_ADMITTED,
    NOT_INDEPENDENTLY_PINNED,
    OWNER_ACTION_REQUIRED,
    prepare_local_trust_genesis_signing_request_from_files,
    prepare_ptde_genesis_history,
    write_history_preparation_document_exclusive,
)
from sbp_lex.local_trust.signing import LocalTrustSignatureError
from sbp_ptde.canonical import canonical_json_document_bytes, canonical_path
from sbp_ptde.errors import PTDEVerificationError, reject
from sbp_ptde.preparation import (
    read_canonical_document_file,
    write_canonical_document_exclusive,
)
from sbp_ptde.trust import accepted_attempt_history_from_document


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare unsigned V2 history inputs without signing, pinning, "
            "admission, or authority"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    ptde = commands.add_parser(
        "ptde-genesis",
        help="prepare an unsigned sequence-zero PTDE history snapshot",
    )
    ptde.add_argument("--history-id", required=True)
    ptde.add_argument(
        "--output",
        required=True,
        help=(
            "absolute, non-existing output path for the non-authorizing "
            "preparation envelope beneath a trusted parent"
        ),
    )
    ptde.add_argument(
        "--raw-history-output",
        required=True,
        help=(
            "separate absolute, non-existing output path for the canonical raw "
            "accepted-attempt history required by P"
        ),
    )

    local = commands.add_parser(
        "local-trust-genesis-request",
        help="prepare an unsigned external-production history signing request",
    )
    local.add_argument("--repository-identity-sha512", required=True)
    local.add_argument("--history-id", required=True)
    local.add_argument(
        "--verification-context",
        required=True,
        help="absolute path to the canonical production public context",
    )
    local.add_argument(
        "--owner-pinned-verification-context-sha512",
        required=True,
    )
    local.add_argument(
        "--production-custody-metadata",
        required=True,
        help="absolute path to separately owner-pinned canonical custody metadata",
    )
    local.add_argument(
        "--owner-pinned-production-custody-metadata-sha512",
        required=True,
    )
    local.add_argument(
        "--output",
        required=True,
        help="absolute, non-existing output path beneath a trusted parent",
    )
    return parser


def _require_distinct_nonexisting_outputs(
    envelope_output: Path, raw_history_output: Path
) -> None:
    paths = (envelope_output, raw_history_output)
    if any(not path.is_absolute() for path in paths):
        raise reject("HISTORY_PREPARATION_OUTPUT_PATH_NOT_ABSOLUTE")
    try:
        resolved: list[str] = []
        for path in paths:
            canonical_path(
                path.name,
                code="HISTORY_PREPARATION_OUTPUT_NAME_INVALID",
            )
            parent = path.parent
            resolved_parent = parent.resolve(strict=True)
            parent_metadata = parent.lstat()
            is_reparse = bool(
                getattr(parent_metadata, "st_file_attributes", 0) & 0x400
            )
            if (
                os.path.normcase(os.path.abspath(str(parent)))
                != os.path.normcase(str(resolved_parent))
                or not stat.S_ISDIR(parent_metadata.st_mode)
                or stat.S_ISLNK(parent_metadata.st_mode)
                or is_reparse
            ):
                raise reject("HISTORY_PREPARATION_OUTPUT_PARENT_INVALID")
            resolved.append(
                os.path.normcase(
                    os.path.abspath(str(resolved_parent / path.name))
                )
            )
        if resolved[0] == resolved[1]:
            raise reject("HISTORY_PREPARATION_OUTPUT_PATHS_NOT_DISTINCT")
        if any(os.path.lexists(path) for path in paths):
            raise reject("HISTORY_PREPARATION_OUTPUT_ALREADY_EXISTS")
    except PTDEVerificationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise reject("HISTORY_PREPARATION_OUTPUT_PATH_INVALID") from error


def _failure(error: BaseException) -> int:
    if isinstance(error, PTDEVerificationError):
        code = error.code
    elif isinstance(error, LocalTrustSignatureError):
        code = str(error) or type(error).__name__
    else:
        code = type(error).__name__
    print(
        json.dumps(
            {
                "admitted": False,
                "authority_granted": False,
                "failure": code,
                "status": "FAIL",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    output = Path(arguments.output)
    try:
        result: dict[str, Any]
        if arguments.command == "ptde-genesis":
            document = prepare_ptde_genesis_history(arguments.history_id)
            raw_history_output = Path(arguments.raw_history_output)
            _require_distinct_nonexisting_outputs(output, raw_history_output)
            raw_history = document["accepted_attempt_history"]
            raw_history_bytes = canonical_json_document_bytes(raw_history)
            parsed_history = accepted_attempt_history_from_document(
                raw_history_bytes
            )
            if (
                parsed_history.sha512()
                != document["accepted_attempt_history_sha512"]
            ):
                raise reject("HISTORY_PREPARATION_RAW_HISTORY_BINDING_INVALID")
            envelope_output_sha512 = (
                write_history_preparation_document_exclusive(document, output)
            )
            raw_history_output_sha512 = write_canonical_document_exclusive(
                raw_history, raw_history_output
            )
            persisted_raw_history = read_canonical_document_file(
                raw_history_output,
                code="HISTORY_PREPARATION_RAW_HISTORY_OUTPUT",
            )
            reparsed_history = accepted_attempt_history_from_document(
                canonical_json_document_bytes(persisted_raw_history)
            )
            if (
                persisted_raw_history != raw_history
                or reparsed_history.sha512()
                != document["accepted_attempt_history_sha512"]
            ):
                raise reject("HISTORY_PREPARATION_RAW_HISTORY_OUTPUT_INVALID")
            result = {
                "admitted": False,
                "accepted_attempt_history_sha512": document[
                    "accepted_attempt_history_sha512"
                ],
                "authority_granted": False,
                "digest_domains": {
                    "accepted_attempt_history_sha512": (
                        "CANONICAL_JSON_WITHOUT_TERMINAL_LF"
                    ),
                    "document_sha512": (
                        "CANONICAL_JSON_DOCUMENT_WITH_TERMINAL_LF"
                    ),
                },
                "envelope_output_sha512": envelope_output_sha512,
                "output": str(output),
                "pin_state": NOT_INDEPENDENTLY_PINNED,
                "raw_history_output_sha512": raw_history_output_sha512,
                "raw_history_output": str(raw_history_output),
                "status": OWNER_ACTION_REQUIRED,
            }
        elif arguments.command == "local-trust-genesis-request":
            document = prepare_local_trust_genesis_signing_request_from_files(
                repository_identity_digest=(
                    arguments.repository_identity_sha512
                ),
                history_id=arguments.history_id,
                verification_context_path=arguments.verification_context,
                owner_pinned_verification_context_sha512=(
                    arguments.owner_pinned_verification_context_sha512
                ),
                production_custody_metadata_path=(
                    arguments.production_custody_metadata
                ),
                owner_pinned_production_custody_metadata_sha512=(
                    arguments.owner_pinned_production_custody_metadata_sha512
                ),
            )
            output_sha512 = write_history_preparation_document_exclusive(
                document, output
            )
            result = {
                "admission_state": NOT_ADMITTED,
                "admitted": False,
                "authority_granted": False,
                "output": str(output),
                "output_sha512": output_sha512,
                "request_sha512": document["request_sha512"],
                "signature_state": document["signature_state"],
                "status": EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED,
            }
        else:
            raise ValueError("unsupported_history_preparation_command")
    except (
        LocalTrustSignatureError,
        OSError,
        PTDEVerificationError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        return _failure(error)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
