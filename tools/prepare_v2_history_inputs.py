from __future__ import annotations

import argparse
import json
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
from sbp_ptde.errors import PTDEVerificationError


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
        help="absolute, non-existing output path beneath a trusted parent",
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
            output_sha512 = write_history_preparation_document_exclusive(
                document, output
            )
            result = {
                "admitted": False,
                "authority_granted": False,
                "history_sha512": document["accepted_attempt_history_sha512"],
                "output": str(output),
                "output_sha512": output_sha512,
                "pin_state": NOT_INDEPENDENTLY_PINNED,
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
