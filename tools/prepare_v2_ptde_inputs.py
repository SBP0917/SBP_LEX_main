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

from sbp_ptde.canonical import canonical_json_document_bytes, exact_fields
from sbp_ptde.errors import PTDEVerificationError
from sbp_ptde.preparation import (
    prepare_d_descriptor,
    prepare_e_campaign_input_skeleton,
    prepare_p_selection_packet,
    prepare_t_profile,
    read_canonical_document_file,
    write_canonical_document_exclusive,
)


def _common(command: argparse.ArgumentParser) -> None:
    command.add_argument("--object-database", required=True)
    command.add_argument("--git-executable", required=True)
    command.add_argument("--expected-git-executable-sha512", required=True)
    command.add_argument("--output", required=True)


def _external_p_trust_options(
    command: argparse.ArgumentParser, *, include_expected_p_oid: bool
) -> None:
    if include_expected_p_oid:
        command.add_argument("--expected-p-oid", required=True)
    command.add_argument("--ptde-accepted-attempt-history", required=True)
    command.add_argument(
        "--expected-ptde-accepted-attempt-history-sha512", required=True
    )
    command.add_argument(
        "--local-trust-accepted-package-history", required=True
    )
    command.add_argument("--local-trust-history-context", required=True)
    command.add_argument(
        "--owner-pinned-local-trust-history-context-sha512", required=True
    )
    command.add_argument(
        "--expected-local-trust-repository-identity-sha512", required=True
    )
    command.add_argument(
        "--expected-local-trust-accepted-package-history-sequence",
        type=int,
        required=True,
    )
    command.add_argument(
        "--expected-local-trust-accepted-package-history-sha512", required=True
    )
    command.add_argument(
        "--expected-python-dependency-prior-lock-sha512", required=True
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare non-authorizing SBP-LEX V2 P/T/D/E inputs; never select, "
            "commit, execute, admit, or accept evidence"
        )
    )
    commands = parser.add_subparsers(dest="command", required=True)

    p_command = commands.add_parser("p-candidate")
    _common(p_command)
    p_command.add_argument("--repository", required=True)
    p_command.add_argument("--candidate-oid", required=True)
    _external_p_trust_options(p_command, include_expected_p_oid=False)

    t_command = commands.add_parser("t-profile")
    _common(t_command)
    _external_p_trust_options(t_command, include_expected_p_oid=True)
    t_command.add_argument("--p-packet", required=True)
    t_command.add_argument("--expected-p-packet-sha512", required=True)
    t_command.add_argument("--t-inputs", required=True)

    d_command = commands.add_parser("d-descriptor")
    _common(d_command)
    _external_p_trust_options(d_command, include_expected_p_oid=True)
    d_command.add_argument("--p-packet", required=True)
    d_command.add_argument("--expected-p-packet-sha512", required=True)
    d_command.add_argument("--t-oid", required=True)
    d_command.add_argument("--campaign-id", required=True)
    d_command.add_argument("--external-fingerprints", required=True)

    e_command = commands.add_parser("e-inputs")
    _common(e_command)
    _external_p_trust_options(e_command, include_expected_p_oid=True)
    e_command.add_argument("--p-packet", required=True)
    e_command.add_argument("--expected-p-packet-sha512", required=True)
    e_command.add_argument("--t-oid", required=True)
    e_command.add_argument("--d-oid", required=True)
    e_command.add_argument("--campaign-id", required=True)
    return parser


def _p_candidate(arguments: argparse.Namespace) -> dict[str, Any]:
    return prepare_p_selection_packet(
        arguments.repository,
        arguments.object_database,
        candidate_oid=arguments.candidate_oid,
        git_executable=arguments.git_executable,
        expected_git_executable_sha512=(
            arguments.expected_git_executable_sha512
        ),
        **_external_p_trust_arguments(arguments),
    )


def _external_p_trust_arguments(arguments: argparse.Namespace) -> dict[str, Any]:
    ptde_history = read_canonical_document_file(
        arguments.ptde_accepted_attempt_history,
        code="PTDE_PREPARATION_PTDE_HISTORY_INPUT",
    )
    local_history = read_canonical_document_file(
        arguments.local_trust_accepted_package_history,
        code="PTDE_PREPARATION_LOCAL_HISTORY_INPUT",
    )
    local_context = read_canonical_document_file(
        arguments.local_trust_history_context,
        code="PTDE_PREPARATION_LOCAL_CONTEXT_INPUT",
    )
    return {
        "ptde_accepted_attempt_history_document": canonical_json_document_bytes(
            ptde_history
        ),
        "expected_ptde_accepted_attempt_history_sha512": (
            arguments.expected_ptde_accepted_attempt_history_sha512
        ),
        "local_trust_accepted_package_history_document": (
            canonical_json_document_bytes(local_history)
        ),
        "local_trust_history_context_document": canonical_json_document_bytes(
            local_context
        ),
        "owner_pinned_local_trust_history_context_sha512": (
            arguments.owner_pinned_local_trust_history_context_sha512
        ),
        "expected_local_trust_repository_identity_sha512": (
            arguments.expected_local_trust_repository_identity_sha512
        ),
        "expected_local_trust_accepted_package_history_sequence": (
            arguments.expected_local_trust_accepted_package_history_sequence
        ),
        "expected_local_trust_accepted_package_history_sha512": (
            arguments.expected_local_trust_accepted_package_history_sha512
        ),
        "expected_python_dependency_prior_lock_sha512": (
            arguments.expected_python_dependency_prior_lock_sha512
        ),
    }


def _p_packet(arguments: argparse.Namespace) -> dict[str, Any]:
    return read_canonical_document_file(
        arguments.p_packet, code="PTDE_PREPARATION_P_PACKET_INPUT"
    )


def _t_profile(arguments: argparse.Namespace) -> dict[str, Any]:
    inputs = exact_fields(
        read_canonical_document_file(
            arguments.t_inputs, code="PTDE_PREPARATION_T_INPUTS"
        ),
        {"test_profile_id", "inventory_assignments", "lanes"},
        code="PTDE_PREPARATION_T_INPUTS",
    )
    return prepare_t_profile(
        _p_packet(arguments),
        arguments.object_database,
        expected_p_packet_sha512=arguments.expected_p_packet_sha512,
        expected_p_oid=arguments.expected_p_oid,
        git_executable=arguments.git_executable,
        expected_git_executable_sha512=(
            arguments.expected_git_executable_sha512
        ),
        test_profile_id=inputs["test_profile_id"],
        inventory_assignments=inputs["inventory_assignments"],
        lanes=inputs["lanes"],
        **_external_p_trust_arguments(arguments),
    )


def _d_descriptor(arguments: argparse.Namespace) -> dict[str, Any]:
    fingerprints = read_canonical_document_file(
        arguments.external_fingerprints,
        code="PTDE_PREPARATION_D_FINGERPRINTS",
    )
    return prepare_d_descriptor(
        _p_packet(arguments),
        arguments.object_database,
        expected_p_packet_sha512=arguments.expected_p_packet_sha512,
        expected_p_oid=arguments.expected_p_oid,
        git_executable=arguments.git_executable,
        expected_git_executable_sha512=(
            arguments.expected_git_executable_sha512
        ),
        t_oid=arguments.t_oid,
        campaign=arguments.campaign_id,
        external_fingerprints=fingerprints,
        **_external_p_trust_arguments(arguments),
    )


def _e_inputs(arguments: argparse.Namespace) -> dict[str, Any]:
    return prepare_e_campaign_input_skeleton(
        _p_packet(arguments),
        arguments.object_database,
        expected_p_packet_sha512=arguments.expected_p_packet_sha512,
        expected_p_oid=arguments.expected_p_oid,
        git_executable=arguments.git_executable,
        expected_git_executable_sha512=(
            arguments.expected_git_executable_sha512
        ),
        t_oid=arguments.t_oid,
        d_oid=arguments.d_oid,
        campaign=arguments.campaign_id,
        **_external_p_trust_arguments(arguments),
    )


def _result_report(
    arguments: argparse.Namespace,
    document: dict[str, Any],
    persisted_output_document_sha512: str,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "admission_state": "NOT_ADMITTED",
        "authority_granted": False,
        "no_authority": document["no_authority"],
        "output": str(Path(arguments.output)),
        "persisted_output_document_sha512": (
            persisted_output_document_sha512
        ),
    }
    if arguments.command == "p-candidate":
        report["p_selection_state"] = document["p_selection_state"]
        report["p_packet_internal_sha512"] = document["packet_sha512"]
    else:
        report["validated_p_packet_internal_sha512"] = (
            arguments.expected_p_packet_sha512
        )
        if arguments.command == "e-inputs":
            report["e_input_skeleton_internal_sha512"] = document[
                "skeleton_sha512"
            ]
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    try:
        handlers = {
            "p-candidate": _p_candidate,
            "t-profile": _t_profile,
            "d-descriptor": _d_descriptor,
            "e-inputs": _e_inputs,
        }
        document = handlers[arguments.command](arguments)
        output_digest = write_canonical_document_exclusive(
            document, arguments.output
        )
        print(
            json.dumps(
                _result_report(arguments, document, output_digest),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 0
    except PTDEVerificationError as exc:
        print(
            json.dumps(
                {"error_code": exc.code}, separators=(",", ":"), sort_keys=True
            )
        )
        return 2
    except (KeyError, MemoryError, OSError, RuntimeError, TypeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "error_code": (
                        f"PTDE_PREPARATION_INTERNAL_FAIL_CLOSED:{type(exc).__name__}"
                    )
                },
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
