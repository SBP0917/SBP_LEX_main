from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.local_trust.constants import (
    ARTIFACT_SIGNING_PURPOSE,
    CLOCK_SIGNING_PURPOSE,
    HISTORY_SIGNING_PURPOSE,
    TEST_ONLY,
)
from sbp_lex.local_trust.deployment import DeploymentTrust, RepositoryIdentity
from sbp_lex.local_trust.history import build_accepted_history_genesis
from sbp_lex.local_trust.signing import HybridSigningContext


def signing_context(purpose: str, suffix: str) -> HybridSigningContext:
    return HybridSigningContext(
        context_id=f"test-context-{suffix}",
        provider_id=f"test-provider-{suffix}",
        key_id=f"test-key-{suffix}",
        custody_class="TEST_ONLY_SOFTWARE",
        signer_class=TEST_ONLY,
        purpose=purpose,
        mldsa87_private_key=MLDSA87PrivateKey.generate(),
        ed448_private_key=Ed448PrivateKey.generate(),
    )


@pytest.fixture(scope="session")
def signers() -> dict[str, HybridSigningContext]:
    return {
        "artifact": signing_context(ARTIFACT_SIGNING_PURPOSE, "artifact"),
        "clock": signing_context(CLOCK_SIGNING_PURPOSE, "clock"),
        "history": signing_context(HISTORY_SIGNING_PURPOSE, "history"),
    }


@pytest.fixture
def deployment_material(
    tmp_path: Path,
    signers: dict[str, HybridSigningContext],
) -> dict[str, Any]:
    root = tmp_path / "repo"
    root.mkdir()
    (root / ".git").mkdir()
    identity = RepositoryIdentity.measure(root, repository_id="test-v2-repository")
    history = build_accepted_history_genesis(
        repository_identity_digest=identity.identity_digest,
        history_id="test-accepted-history",
        signer=signers["history"],
    )
    artifact_context = signers["artifact"].verification_context(allow_test_only=True)
    clock_context = signers["clock"].verification_context(allow_test_only=True)
    history_context = signers["history"].verification_context(allow_test_only=True)
    ptde_history_digest = "a" * 128
    executable_pins = {
        "python": "1" * 128,
        "cargo": "2" * 128,
        "java": "3" * 128,
        "alr": "4" * 128,
        "git": "5" * 128,
    }
    deployment = DeploymentTrust(
        composition_class=TEST_ONLY,
        repository_identity=identity,
        artifact_context=artifact_context,
        clock_context=clock_context,
        history_context=history_context,
        owner_pinned_artifact_context_digest=artifact_context.context_digest,
        owner_pinned_clock_context_digest=clock_context.context_digest,
        owner_pinned_history_context_digest=history_context.context_digest,
        expected_ptde_accepted_attempt_history_sequence=0,
        expected_ptde_accepted_attempt_history_digest=ptde_history_digest,
        expected_local_trust_accepted_package_history_sequence=0,
        expected_local_trust_accepted_package_history_digest=(
            history["history_digest"]
        ),
        expected_python_dependency_prior_lock_sha512="GENESIS",
        expected_executable_sha512_pins=executable_pins,
    )
    return {
        "root": root,
        "identity": identity,
        "history": history,
        "deployment": deployment,
        "ptde_history_digest": ptde_history_digest,
        "executable_pins": executable_pins,
    }
