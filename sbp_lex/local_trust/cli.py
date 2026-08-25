"""Verify or show detached V2 packages; the CLI cannot build or admit them."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .deployment import DeploymentTrust, RepositoryIdentity
from .digests import digest_equal
from .package_io import load_local_trust_package
from .paths import strict_load_json
from .signing import verification_context_from_record
from .summary import build_local_trust_summary
from .verifier import verify_local_trust_package


def _context(path: str, pin: str, *, allow_test_only: bool):
    return verification_context_from_record(
        strict_load_json(Path(path)),
        owner_pinned_context_digest=pin,
        allow_test_only=allow_test_only,
    )


def _validate(args: argparse.Namespace) -> int:
    if not args.allow_test_only:
        raise ValueError("cli_production_composition_rejected_use_external_provider_api")
    package = load_local_trust_package(args.package)
    accepted_history = strict_load_json(Path(args.accepted_history))
    repository_root = Path(args.repository_root)
    repository_identity = RepositoryIdentity.measure(
        repository_root, repository_id=args.repository_id
    )
    if not digest_equal(
        repository_identity.identity_digest, args.expected_repository_identity_digest
    ):
        raise ValueError("repository_identity_not_deployment_pinned")
    artifact_context = _context(
        args.artifact_context, args.expected_artifact_context_digest, allow_test_only=True
    )
    clock_context = _context(
        args.clock_context, args.expected_clock_context_digest, allow_test_only=True
    )
    history_context = _context(
        args.history_context, args.expected_history_context_digest, allow_test_only=True
    )
    deployment = DeploymentTrust(
        composition_class="TEST_ONLY",
        repository_identity=repository_identity,
        artifact_context=artifact_context,
        clock_context=clock_context,
        history_context=history_context,
        owner_pinned_artifact_context_digest=args.expected_artifact_context_digest,
        owner_pinned_clock_context_digest=args.expected_clock_context_digest,
        owner_pinned_history_context_digest=args.expected_history_context_digest,
        expected_ptde_accepted_attempt_history_sequence=(
            args.expected_ptde_accepted_attempt_history_sequence
        ),
        expected_ptde_accepted_attempt_history_digest=(
            args.expected_ptde_accepted_attempt_history_digest
        ),
        expected_local_trust_accepted_package_history_sequence=(
            args.expected_local_trust_accepted_package_history_sequence
        ),
        expected_local_trust_accepted_package_history_digest=(
            args.expected_local_trust_accepted_package_history_digest
        ),
        expected_python_dependency_prior_lock_sha512=(
            args.expected_python_dependency_prior_lock_sha512
        ),
        expected_executable_sha512_pins={
            "python": args.expected_python_executable_sha512,
            "cargo": args.expected_cargo_executable_sha512,
            "java": args.expected_java_executable_sha512,
            "alr": args.expected_alr_executable_sha512,
            "git": args.expected_git_executable_sha512,
        },
    )
    result = verify_local_trust_package(
        package,
        repository_root,
        deployment=deployment,
        accepted_history=accepted_history,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


def _show(args: argparse.Namespace) -> int:
    package = load_local_trust_package(args.package)
    print(json.dumps(build_local_trust_summary(package), sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detached SBP-LEX V2 local-trust verifier (no build/admit operation)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser("validate")
    validate.add_argument("--repository-root", required=True)
    validate.add_argument("--repository-id", required=True)
    validate.add_argument("--expected-repository-identity-digest", required=True)
    validate.add_argument("--package", required=True)
    validate.add_argument("--accepted-history", required=True)
    validate.add_argument(
        "--expected-ptde-accepted-attempt-history-sequence",
        type=int,
        required=True,
    )
    validate.add_argument(
        "--expected-ptde-accepted-attempt-history-digest",
        required=True,
    )
    validate.add_argument(
        "--expected-local-trust-accepted-package-history-sequence",
        type=int,
        required=True,
    )
    validate.add_argument(
        "--expected-local-trust-accepted-package-history-digest",
        required=True,
    )
    validate.add_argument(
        "--expected-python-dependency-prior-lock-sha512",
        required=True,
    )
    validate.add_argument("--expected-python-executable-sha512", required=True)
    validate.add_argument("--expected-cargo-executable-sha512", required=True)
    validate.add_argument("--expected-java-executable-sha512", required=True)
    validate.add_argument("--expected-alr-executable-sha512", required=True)
    validate.add_argument("--expected-git-executable-sha512", required=True)
    validate.add_argument("--artifact-context", required=True)
    validate.add_argument("--expected-artifact-context-digest", required=True)
    validate.add_argument("--clock-context", required=True)
    validate.add_argument("--expected-clock-context-digest", required=True)
    validate.add_argument("--history-context", required=True)
    validate.add_argument("--expected-history-context-digest", required=True)
    validate.add_argument("--allow-test-only", action="store_true")
    validate.set_defaults(handler=_validate)
    show = subparsers.add_parser("show")
    show.add_argument("--package", required=True)
    show.set_defaults(handler=_show)
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "reason": type(exc).__name__}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
