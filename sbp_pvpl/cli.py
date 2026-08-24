"""Local-only V2 PVPL validate, show and export-redacted CLI."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from .canonical import canonical_document_bytes
from .errors import PVPLValidationError, reject
from .file_io import read_canonical_file, write_exclusive_canonical_file
from .verifier import build_publication_claim, validation_report


def _emit(value: Any) -> None:
    sys.stdout.buffer.write(canonical_document_bytes(value))


def _inputs(arguments: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    sources = [
        read_canonical_file(arguments.ptde_result),
        read_canonical_file(arguments.local_trust_result),
    ]
    receipts = [
        read_canonical_file(arguments.ptde_receipt),
        read_canonical_file(arguments.local_trust_receipt),
    ]
    return (
        sources,
        receipts,
        read_canonical_file(arguments.external_pins),
        read_canonical_file(arguments.accepted_history),
    )


def _claim(arguments: argparse.Namespace) -> dict[str, Any]:
    return build_publication_claim(*_inputs(arguments))


def _validate(arguments: argparse.Namespace) -> int:
    _emit(validation_report(_claim(arguments)))
    return 0


def _show(arguments: argparse.Namespace) -> int:
    _emit(_claim(arguments))
    return 0


def _export_redacted(arguments: argparse.Namespace) -> int:
    claim = _claim(arguments)
    write_exclusive_canonical_file(claim, arguments.output)
    _emit(validation_report(claim))
    return 0


def _add_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ptde-result", required=True)
    parser.add_argument("--ptde-receipt", required=True)
    parser.add_argument("--local-trust-result", required=True)
    parser.add_argument("--local-trust-receipt", required=True)
    parser.add_argument("--external-pins", required=True)
    parser.add_argument("--accepted-history", required=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detached, local-only SBP-LEX V2 public-verification claim validator"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    _add_inputs(validate)
    validate.set_defaults(handler=_validate)
    show = commands.add_parser("show")
    _add_inputs(show)
    show.set_defaults(handler=_show)
    export = commands.add_parser("export-redacted")
    _add_inputs(export)
    export.add_argument("--output", required=True)
    export.set_defaults(handler=_export_redacted)
    arguments = parser.parse_args(argv)
    try:
        return int(arguments.handler(arguments))
    except PVPLValidationError as exc:
        _emit({"error_code": exc.code})
        return 2
    except (Exception, MemoryError) as exc:
        _emit({"error_code": f"PVPL_INTERNAL_FAIL_CLOSED:{type(exc).__name__}"})
        return 2


__all__ = ["main"]
