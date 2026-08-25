from __future__ import annotations

import sys
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.local_trust import command_evidence, repository
from sbp_lex.provenance import digital_provenance
from sbp_lex.security.authority_trust import role_pin_from_provider
from sbp_lex.security.hybrid_signature import HYBRID_SUITE_ID
from sbp_lex.security.signature_provider import Ed25519SoftwareProvider
from tests import test_digital_provenance as _digital_provenance_tests


class _StreamlessProcess:
    stdout = None
    stderr = None
    pid = 1

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


def test_command_capture_rejects_missing_subprocess_streams(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    arguments = (sys.executable, "-c", "pass")
    monkeypatch.setattr(
        command_evidence,
        "COMMAND_POLICY",
        (("streamless", arguments, True),),
    )
    process = _StreamlessProcess()
    monkeypatch.setattr(
        command_evidence.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )

    with pytest.raises(
        command_evidence.CommandEvidenceError,
        match="command_capture_stream_unavailable",
    ):
        command_evidence.capture_command(
            tmp_path,
            command_evidence.resolved_command_policy()[0],
        )
    assert process.killed is True


def test_repository_capture_rejects_missing_subprocess_streams(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    process = _StreamlessProcess()
    monkeypatch.setattr(
        repository.subprocess,
        "Popen",
        lambda *args, **kwargs: process,
    )

    with pytest.raises(
        repository.RepositoryEvidenceError,
        match="git_evidence_stream_unavailable",
    ):
        repository._git(tmp_path, "status", "--porcelain=v1")
    assert process.killed is True


@pytest.mark.parametrize("algorithm", ("Ed25519", HYBRID_SUITE_ID))
def test_authority_role_pin_document_rejects_corrupted_key_material(
    algorithm: str,
) -> None:
    provider = Ed25519SoftwareProvider.from_private_key(
        Ed25519PrivateKey.generate()
    )
    pin = role_pin_from_provider(
        role="test-role",
        provider=provider,
        evaluator_id="test-evaluator",
        evaluator_version="1",
        authority_credential_id="test-credential",
    )
    if algorithm == HYBRID_SUITE_ID:
        object.__setattr__(pin, "algorithm", HYBRID_SUITE_ID)
        object.__setattr__(pin, "hybrid_verification_context", None)
    else:
        object.__setattr__(pin, "ed25519_public_key", None)

    with pytest.raises(ValueError, match="AUTHORITY_TRUST_ROLE_PIN_INVALID"):
        pin.document()


def test_provenance_context_invariant_failure_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _digital_provenance_tests.DigitalProvenanceTests(
        methodName="test_exact_lineage_receipt_is_deterministic_and_non_authorizing"
    )
    fixture.setUp()
    graph = fixture.graph()
    invalid_context = replace(fixture.trust_context, _owner_pin_bytes=b"null")
    monkeypatch.setattr(
        digital_provenance,
        "_deployment_context_error",
        lambda _context: None,
    )

    decision = fixture.verify(graph, trust_context=invalid_context)

    assert decision.result == digital_provenance.DENY
    assert decision.reason == "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"


def test_provenance_snapshot_invariant_failure_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _digital_provenance_tests.DigitalProvenanceTests(
        methodName="test_exact_lineage_receipt_is_deterministic_and_non_authorizing"
    )
    fixture.setUp()
    graph = fixture.graph()
    monkeypatch.setattr(
        digital_provenance,
        "_snapshot_admissions",
        lambda *args, **kwargs: ({}, None),
    )

    decision = fixture.verify(graph, registry_snapshot=None)

    assert decision.result == digital_provenance.DENY
    assert decision.reason == "PROVENANCE_REGISTRY_SNAPSHOT_INVALID"
