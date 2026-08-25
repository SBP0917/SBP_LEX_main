"""P-binding CLI. It never writes evidence, executes host lanes, or admits a package."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sbp_ptde.trust import accepted_attempt_history_from_document

from .package import assemble_p_source_package
from .source_binding import bind_p_object
from .verifier import verify_p_source_package


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sbp_lex.supply_chain")
    parser.add_argument("--object-database", required=True)
    parser.add_argument("--p-oid", required=True)
    parser.add_argument("--expected-p-oid", required=True)
    parser.add_argument("--git-executable", required=True)
    parser.add_argument("--expected-git-executable-sha512", required=True)
    parser.add_argument("--ptde-accepted-attempt-history", required=True)
    parser.add_argument(
        "--expected-ptde-accepted-attempt-history-sha512",
        required=True,
    )
    parser.add_argument(
        "--expected-local-trust-accepted-package-history-sequence",
        required=True,
        type=int,
    )
    parser.add_argument(
        "--expected-local-trust-accepted-package-history-sha512",
        required=True,
    )
    parser.add_argument(
        "--expected-python-dependency-prior-lock-sha512",
        required=True,
    )
    arguments = parser.parse_args(argv)
    history = accepted_attempt_history_from_document(
        Path(arguments.ptde_accepted_attempt_history).read_bytes()
    )
    binding = bind_p_object(
        arguments.object_database,
        p_oid=arguments.p_oid,
        expected_p_oid=arguments.expected_p_oid,
        git_executable=arguments.git_executable,
        expected_git_executable_sha512=arguments.expected_git_executable_sha512,
        ptde_accepted_attempt_history=history,
        expected_ptde_accepted_attempt_history_sha512=(
            arguments.expected_ptde_accepted_attempt_history_sha512
        ),
        expected_local_trust_accepted_package_history_sequence=(
            arguments.expected_local_trust_accepted_package_history_sequence
        ),
        expected_local_trust_accepted_package_history_sha512=(
            arguments.expected_local_trust_accepted_package_history_sha512
        ),
        expected_python_dependency_prior_lock_sha512=(
            arguments.expected_python_dependency_prior_lock_sha512
        ),
    )
    package = assemble_p_source_package(binding)
    report = verify_p_source_package(package.document, binding=binding)
    print(json.dumps({"status": report.status, "admitted": False, "package": package.document}, sort_keys=True))
    return 1
