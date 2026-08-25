from __future__ import annotations

import os
import shutil
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
from hashlib import sha512
from pathlib import Path
from threading import Event
from unittest.mock import patch

import pytest

import sbp_lex.identity.impersonation_protection as impersonation_module
from sbp_lex.governance.three_p_doctrine import THREE_P_DOCTRINE_ID
from sbp_lex.identity.durable_boundaries import (
    AuthenticatedMonotonicClock,
    ImpersonationDurabilityError,
    SQLiteImpersonationClockHead,
    SQLiteImpersonationReplayGuard,
    SQLiteOwnerPinnedTrustRegistry,
)
from sbp_lex.identity.impersonation_protection import (
    CLOCK_HEAD_TRANSITION_SCHEMA,
    DEPLOYMENT_DEPENDENCIES,
    IMPERSONATION_PASS,
    IMPERSONATION_PROTECTION_CONTRACT_ID,
    IMPERSONATION_PROTECTION_SCHEMA_STATUS,
    IMPERSONATION_PROTECTION_SEMANTICS,
    NO_AUTHORIZATION_EFFECT,
    REPLAY_CLAIM_SCHEMA,
    REPLAY_CLAIMED,
    TRUST_ACTIVE,
    TRUST_CONTEXT_SCHEMA,
    _register_test_only_impersonation_composition_boundary,
    _reset_test_only_impersonation_composition_boundaries,
    impersonation_signing_purpose,
    install_production_impersonation_composition_boundary,
)
from sbp_lex.response_controller.runner import run_pipeline
from sbp_lex.security.integrity import GENESIS_HASH, canonical_integrity_hash
from sbp_lex.security.signature_provider import build_signed_object
from tests.test_controlled_local_adapter import BoundaryEvidenceProvider
from tests.test_foundational_public_pipeline import (
    _pass_aurion,
    _public_inputs,
    _run_arguments,
)
from tests.test_impersonation_protection import (
    Ed25519FixtureProvider,
)

pytest_plugins = ("tests.test_foundational_public_pipeline",)

CONTEXT_ID = "durable-impersonation-context"
CONTEXT_DIGEST = "a" * 128
SUBJECT_DIGEST = "b" * 128
REPLAY_KEY = "c" * 128


def _paths(root: Path, name: str) -> tuple[Path, Path]:
    return root / f"{name}.sqlite3", root / f"{name}.anchor.json"


def _test_replay(root: Path, provider=None) -> SQLiteImpersonationReplayGuard:
    database, anchor = _paths(root, "replay")
    return SQLiteImpersonationReplayGuard(
        database_path=database,
        anchor_path=anchor,
        store_id="replay-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        signer=provider or Ed25519FixtureProvider("durable-replay"),
        allow_test_only=True,
    )


def _claim(head: dict) -> dict:
    return {
        "schema": REPLAY_CLAIM_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": CONTEXT_ID,
        "context_digest": CONTEXT_DIGEST,
        "namespace": "sbp-lex-v2:impersonation",
        "replay_key": REPLAY_KEY,
        "claim_sequence": 1,
        "prior_claim_receipt_digest": GENESIS_HASH,
        "pre_claim_head_digest": canonical_integrity_hash(head),
        "claimed_at_ms": 1_000,
        "expires_at_ms": 1_100,
        "request_fingerprint": "d" * 128,
        "snapshot_digest": "e" * 128,
        "registry_record_digest": "f" * 128,
        "possession_proof_digest": "1" * 128,
        "subject_binding_digest": SUBJECT_DIGEST,
        "session_binding_digest": "2" * 128,
        "challenge_binding_digest": "3" * 128,
        "registry_sequence": 7,
        "authority_sequence": 11,
        "revocation_sequence": 3,
        "clock_sequence": 1,
        "clock_record_digest": "4" * 128,
        "result": REPLAY_CLAIMED,
        "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
    }


def _registry_payload() -> dict:
    return {
        "schema": impersonation_module.LIVE_REGISTRY_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "context_id": CONTEXT_ID,
        "context_digest": CONTEXT_DIGEST,
        "registry_id": "registry-one",
        "registry_sequence": 7,
        "subject_id": "subject-one",
        "participant_id": "participant-one",
        "stakeholder_class": "regulators",
        "role_id": "reviewer",
        "mandate_id": "mandate-one",
        "mandate_actions": ["review"],
        "mandate_jurisdictions": ["AU"],
        "jurisdiction": "AU",
        "subject_provider_binding": {"binding": "subject"},
        "authority_sequence": 11,
        "revocation_status": TRUST_ACTIVE,
        "revocation_sequence": 3,
        "valid_from_ms": 900,
        "valid_until_ms": 1_100,
    }


def test_replay_claim_survives_restart_and_persists_signed_receipts(
    tmp_path: Path,
) -> None:
    provider = Ed25519FixtureProvider("durable-replay")
    first = _test_replay(tmp_path, provider)
    pre_head = first.current_head(
        namespace="sbp-lex-v2:impersonation",
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    claim = _claim(pre_head)
    receipt = first.claim_once(claim=claim)
    receipt_digest = canonical_integrity_hash(receipt)
    assert first.validate_store()

    restarted = _test_replay(tmp_path, provider)
    post_head = restarted.current_head(
        namespace=claim["namespace"],
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    persisted = restarted.is_claimed(
        namespace=claim["namespace"],
        replay_key=REPLAY_KEY,
        receipt_digest=receipt_digest,
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
        current_head_digest=canonical_integrity_hash(post_head),
    )

    assert persisted["persisted"] is True
    assert persisted["claim_receipt_digest"] == receipt_digest
    assert restarted.validate_store()
    with pytest.raises(ImpersonationDurabilityError, match="REPLAY_DUPLICATE"):
        restarted.claim_once(claim=claim)


def test_replay_concurrent_duplicate_claim_has_exactly_one_winner(
    tmp_path: Path,
) -> None:
    provider = Ed25519FixtureProvider("concurrent-replay")
    first = _test_replay(tmp_path, provider)
    head = first.current_head(
        namespace="sbp-lex-v2:impersonation",
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    claim = _claim(head)
    guards = [_test_replay(tmp_path, provider) for _ in range(8)]

    def attempt(guard: SQLiteImpersonationReplayGuard) -> bool:
        try:
            guard.claim_once(claim=deepcopy(claim))
            return True
        except ImpersonationDurabilityError:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, guards))

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 7
    assert first.validate_store()


def test_replay_rejects_malformed_or_semantically_invalid_claims(
    tmp_path: Path,
) -> None:
    guard = _test_replay(tmp_path)
    head = guard.current_head(
        namespace="sbp-lex-v2:impersonation",
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    valid = _claim(head)

    extended = deepcopy(valid)
    extended["unadmitted_extension"] = True
    with pytest.raises(ImpersonationDurabilityError, match="CLAIM_SHAPE_INVALID"):
        guard.claim_once(claim=extended)

    for field, value in (
        ("schema", "UNADMITTED_REPLAY_SCHEMA"),
        ("request_fingerprint", "not-a-digest"),
        ("expires_at_ms", valid["claimed_at_ms"]),
        ("clock_sequence", 0),
    ):
        malformed = deepcopy(valid)
        malformed[field] = value
        with pytest.raises(ImpersonationDurabilityError):
            guard.claim_once(claim=malformed)

    assert guard.validate_store()


def test_replay_fails_closed_on_corruption_rollback_and_identity_mismatch(
    tmp_path: Path,
) -> None:
    provider = Ed25519FixtureProvider("hostile-replay")
    guard = _test_replay(tmp_path, provider)
    database, anchor = _paths(tmp_path, "replay")
    snapshot = tmp_path / "replay-before-claim.sqlite3"
    head = guard.current_head(
        namespace="sbp-lex-v2:impersonation",
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    with closing_sqlite(database) as source, closing_sqlite(snapshot) as target:
        source.backup(target)
    guard.claim_once(claim=_claim(head))

    with closing_sqlite(snapshot) as source, closing_sqlite(database) as target:
        source.backup(target)
    with pytest.raises(ImpersonationDurabilityError, match="ROLLBACK"):
        _test_replay(tmp_path, provider)

    database.unlink(missing_ok=True)
    anchor.unlink(missing_ok=True)
    guard = _test_replay(tmp_path, provider)
    head = guard.current_head(
        namespace="sbp-lex-v2:impersonation",
        subject_binding_digest=SUBJECT_DIGEST,
        observed_at_ms=1_000,
    )
    guard.claim_once(claim=_claim(head))
    with closing_sqlite(database) as connection:
        connection.execute("UPDATE replay_claims SET receipt_json='{}'")
        connection.commit()
    assert guard.validate_store() is False

    other = tmp_path / "identity-mismatch"
    shutil.copy2(database, other.with_suffix(".sqlite3"))
    shutil.copy2(anchor, other.with_suffix(".anchor.json"))
    with pytest.raises(ImpersonationDurabilityError, match="IDENTITY_MISMATCH"):
        SQLiteImpersonationReplayGuard(
            database_path=other.with_suffix(".sqlite3"),
            anchor_path=other.with_suffix(".anchor.json"),
            store_id="different-store",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=provider,
            allow_test_only=True,
        )


def test_durable_store_rejects_links_aliases_and_uses_owner_only_permissions(
    tmp_path: Path,
) -> None:
    provider = Ed25519FixtureProvider("path-hardening")
    alias_parent = tmp_path / "alias-parent"
    alias_parent.mkdir()
    with pytest.raises(ImpersonationDurabilityError, match="PATH_NORMALIZATION"):
        SQLiteImpersonationReplayGuard(
            database_path=tmp_path / "missing-alias.sqlite3",
            anchor_path=alias_parent / ".." / "missing-alias.sqlite3",
            store_id="missing-alias",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=provider,
            allow_test_only=True,
        )
    guard = _test_replay(tmp_path, provider)
    database, anchor = _paths(tmp_path, "replay")
    assert guard.validate_store()
    if os.name != "nt":
        assert stat.S_IMODE(database.stat().st_mode) & 0o077 == 0
        assert stat.S_IMODE(anchor.stat().st_mode) & 0o077 == 0

    original_anchor = anchor.read_bytes()
    anchor.write_bytes(b"x" * 20_000)
    assert guard.validate_store() is False
    anchor.write_bytes(original_anchor)
    assert guard.validate_store()

    hardlink = tmp_path / "hardlinked.sqlite3"
    os.link(database, hardlink)
    with pytest.raises(ImpersonationDurabilityError, match="PATH_ALIAS"):
        SQLiteImpersonationReplayGuard(
            database_path=hardlink,
            anchor_path=tmp_path / "hardlinked.anchor.json",
            store_id="hardlink-store",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=provider,
            allow_test_only=True,
        )
    hardlink.unlink()

    wal_path = Path(f"{database}-wal")
    wal_path.unlink(missing_ok=True)
    try:
        wal_path.symlink_to(anchor)
    except OSError:
        return
    with pytest.raises(ImpersonationDurabilityError, match="PATH_ALIAS"):
        _test_replay(tmp_path, provider)

    symlink = tmp_path / "linked.anchor.json"
    try:
        symlink.symlink_to(anchor)
    except OSError:
        pytest.skip("symlink creation is not available to this test process")
    with pytest.raises(ImpersonationDurabilityError, match="PATH_ALIAS"):
        SQLiteImpersonationReplayGuard(
            database_path=tmp_path / "linked.sqlite3",
            anchor_path=symlink,
            store_id="linked-store",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=provider,
            allow_test_only=True,
        )


class closing_sqlite:
    def __init__(self, path: Path) -> None:
        self.connection = sqlite3.connect(path)

    def __enter__(self) -> sqlite3.Connection:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        self.connection.close()


def test_registry_clock_and_clock_head_are_restart_safe_and_monotonic(
    tmp_path: Path,
) -> None:
    registry_provider = Ed25519FixtureProvider("durable-registry")
    registry_db, registry_anchor = _paths(tmp_path, "registry")
    registry = SQLiteOwnerPinnedTrustRegistry(
        database_path=registry_db,
        anchor_path=registry_anchor,
        store_id="registry-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        registry_id="registry-one",
        registry_provider=registry_provider,
        allow_test_only=True,
    )
    payload = _registry_payload()
    installed = registry.install_identity(payload)
    restarted_registry = SQLiteOwnerPinnedTrustRegistry(
        database_path=registry_db,
        anchor_path=registry_anchor,
        store_id="registry-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        registry_id="registry-one",
        registry_provider=registry_provider,
        allow_test_only=True,
    )
    assert (
        restarted_registry.lookup_identity(
            subject_id="subject-one", participant_id="participant-one"
        )
        == installed
    )
    assert restarted_registry.install_identity(deepcopy(payload)) == installed
    equivocation = deepcopy(payload)
    equivocation["role_id"] = "substituted-reviewer"
    with pytest.raises(ImpersonationDurabilityError, match="EQUIVOCATION"):
        restarted_registry.install_identity(equivocation)
    oversized_text = deepcopy(payload)
    oversized_text["registry_sequence"] = 8
    oversized_text["role_id"] = "x" * 513
    with pytest.raises(ImpersonationDurabilityError, match="BOUNDS_INVALID"):
        restarted_registry.install_identity(oversized_text)
    oversized_list = deepcopy(payload)
    oversized_list["registry_sequence"] = 8
    oversized_list["mandate_actions"] = [f"action-{index}" for index in range(65)]
    with pytest.raises(ImpersonationDurabilityError, match="BOUNDS_INVALID"):
        restarted_registry.install_identity(oversized_list)
    rolled_back = deepcopy(payload)
    rolled_back["registry_sequence"] = 6
    with pytest.raises(ImpersonationDurabilityError, match="ROLLBACK"):
        restarted_registry.install_identity(rolled_back)

    clock_provider = Ed25519FixtureProvider("durable-clock")
    times = iter((1_000, 999))
    clock_db, clock_anchor = _paths(tmp_path, "clock")
    clock = AuthenticatedMonotonicClock(
        database_path=clock_db,
        anchor_path=clock_anchor,
        store_id="clock-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        clock_id="clock-one",
        clock_version="1",
        clock_provider=clock_provider,
        trusted_time_source_admission_digest="5" * 128,
        maximum_forward_step_ms=100,
        time_source=lambda: next(times),
        allow_test_only=True,
    )
    clock_record = clock.current_time_record(
        context_id=CONTEXT_ID, context_digest=CONTEXT_DIGEST
    )
    with pytest.raises(ImpersonationDurabilityError, match="CLOCK_ROLLBACK"):
        clock.current_time_record(context_id=CONTEXT_ID, context_digest=CONTEXT_DIGEST)
    restarted_clock = AuthenticatedMonotonicClock(
        database_path=clock_db,
        anchor_path=clock_anchor,
        store_id="clock-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        clock_id="clock-one",
        clock_version="1",
        clock_provider=clock_provider,
        trusted_time_source_admission_digest="5" * 128,
        maximum_forward_step_ms=100,
        time_source=lambda: 1_101,
        allow_test_only=True,
    )
    with pytest.raises(ImpersonationDurabilityError, match="FORWARD_JUMP"):
        restarted_clock.current_time_record(
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
        )

    head_provider = Ed25519FixtureProvider("durable-clock-head")
    head_db, head_anchor = _paths(tmp_path, "clock-head")
    head_store = SQLiteImpersonationClockHead(
        database_path=head_db,
        anchor_path=head_anchor,
        store_id="clock-head-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        head_id="head-one",
        head_version="1",
        clock_head_provider=head_provider,
        allow_test_only=True,
    )
    pre_head = head_store.current_head(
        context_id=CONTEXT_ID, context_digest=CONTEXT_DIGEST
    )
    transition = {
        "schema": CLOCK_HEAD_TRANSITION_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "context_id": CONTEXT_ID,
        "context_digest": CONTEXT_DIGEST,
        "head_id": "head-one",
        "head_version": "1",
        "head_sequence": 1,
        "prior_head_digest": canonical_integrity_hash(pre_head),
        "clock_sequence": 1,
        "clock_record_digest": canonical_integrity_hash(clock_record),
        "prior_clock_record_digest": GENESIS_HASH,
        "observed_at_ms": 1_000,
        "result": "ADVANCED",
        "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
    }
    receipt = head_store.advance_once(transition=transition)
    restarted_head = SQLiteImpersonationClockHead(
        database_path=head_db,
        anchor_path=head_anchor,
        store_id="clock-head-store-one",
        context_id=CONTEXT_ID,
        context_digest=CONTEXT_DIGEST,
        head_id="head-one",
        head_version="1",
        clock_head_provider=head_provider,
        allow_test_only=True,
    )
    current = restarted_head.current_head(
        context_id=CONTEXT_ID, context_digest=CONTEXT_DIGEST
    )
    assert current["head_sequence"] == 1
    assert current["latest_transition_receipt_digest"] == (
        canonical_integrity_hash(receipt)
    )


def test_registry_read_serializes_with_anchor_and_database_update(
    tmp_path: Path,
) -> None:
    provider = Ed25519FixtureProvider("registry-concurrency")
    database, anchor = _paths(tmp_path, "registry-concurrency")

    def make_registry() -> SQLiteOwnerPinnedTrustRegistry:
        return SQLiteOwnerPinnedTrustRegistry(
            database_path=database,
            anchor_path=anchor,
            store_id="registry-concurrency-store",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            registry_id="registry-one",
            registry_provider=provider,
            allow_test_only=True,
        )

    writer = make_registry()
    reader = make_registry()
    writer.install_identity(_registry_payload())
    advanced = _registry_payload()
    advanced["registry_sequence"] = 8
    advanced["role_id"] = "advanced-reviewer"
    anchor_replaced = Event()
    permit_commit = Event()
    reader_connected = Event()
    original_write_anchor = writer._write_anchor
    original_reader_connect = reader._connect

    def blocking_anchor(record: dict) -> None:
        original_write_anchor(record)
        anchor_replaced.set()
        assert permit_commit.wait(timeout=5)

    def signaling_connect() -> sqlite3.Connection:
        connection = original_reader_connect()
        reader_connected.set()
        return connection

    with (
        patch.object(writer, "_write_anchor", side_effect=blocking_anchor),
        patch.object(reader, "_connect", side_effect=signaling_connect),
        ThreadPoolExecutor(max_workers=2) as pool,
    ):
        write_future = pool.submit(writer.install_identity, advanced)
        assert anchor_replaced.wait(timeout=5)
        read_future = pool.submit(
            reader.lookup_identity,
            subject_id="subject-one",
            participant_id="participant-one",
        )
        assert reader_connected.wait(timeout=5)
        permit_commit.set()
        installed = write_future.result(timeout=5)
        observed = read_future.result(timeout=5)

    assert observed == installed
    assert observed["registry_sequence"] == 8


def test_all_durable_boundaries_traverse_real_public_pipeline(
    tmp_path: Path,
    public_fixture,
) -> None:
    request, signals, proof = _public_inputs(public_fixture)
    fixture = public_fixture.foundation.impersonation
    context_record = fixture.context_record

    registry_db, registry_anchor = _paths(tmp_path, "public-registry")
    registry = SQLiteOwnerPinnedTrustRegistry(
        database_path=registry_db,
        anchor_path=registry_anchor,
        store_id="public-registry-store",
        context_id=context_record["context_id"],
        context_digest=context_record["digest"],
        registry_id=context_record["registry_id"],
        registry_provider=fixture.registry_provider,
        allow_test_only=True,
    )
    signed_registry = fixture.registry.lookup_identity(
        subject_id=context_record["subject_id"],
        participant_id=context_record["participant_id"],
    )
    registry.install_identity(
        {
            key: value
            for key, value in signed_registry.items()
            if key not in {"digest", "signature", "verified"}
        }
    )

    replay_db, replay_anchor = _paths(tmp_path, "public-replay")
    replay = SQLiteImpersonationReplayGuard(
        database_path=replay_db,
        anchor_path=replay_anchor,
        store_id="public-replay-store",
        context_id=context_record["context_id"],
        context_digest=context_record["digest"],
        signer=fixture.replay_provider,
        allow_test_only=True,
    )
    clock_db, clock_anchor = _paths(tmp_path, "public-clock")
    clock = AuthenticatedMonotonicClock(
        database_path=clock_db,
        anchor_path=clock_anchor,
        store_id="public-clock-store",
        context_id=context_record["context_id"],
        context_digest=context_record["digest"],
        clock_id=context_record["trusted_clock_id"],
        clock_version=context_record["trusted_clock_version"],
        clock_provider=fixture.clock_provider,
        trusted_time_source_admission_digest="6" * 128,
        maximum_forward_step_ms=100,
        time_source=lambda: fixture.now,
        allow_test_only=True,
    )
    head_db, head_anchor = _paths(tmp_path, "public-head")
    clock_head = SQLiteImpersonationClockHead(
        database_path=head_db,
        anchor_path=head_anchor,
        store_id="public-clock-head-store",
        context_id=context_record["context_id"],
        context_digest=context_record["digest"],
        head_id=context_record["clock_head_id"],
        head_version=context_record["clock_head_version"],
        clock_head_provider=fixture.clock_head_signer,
        allow_test_only=True,
    )

    _reset_test_only_impersonation_composition_boundaries(clear_pins=False)
    _register_test_only_impersonation_composition_boundary(
        signed_context_record=context_record,
        owner_provider=fixture.owner_provider,
        registry_provider=fixture.registry_provider,
        subject_provider=fixture.subject_provider,
        replay_provider=fixture.replay_provider,
        registry=registry,
        replay_guard=replay,
        sovereign_identity_verifier=fixture.sovereign_verifier,
        sovereign_identity_dependencies=fixture.sovereign_provider,
        authority_boundary_verifier=fixture.boundary_verifier,
        authority_boundary_dependencies=fixture.boundary_provider,
        trusted_clock=clock,
        clock_head_provider=clock_head,
        pseudonym_key=fixture.pseudonym_key,
    )
    context = fixture.make_context(
        registry=registry,
        replay_guard=replay,
        trusted_clock=clock,
        clock_head_provider=clock_head,
    )
    arguments = _run_arguments(public_fixture, possession_proof=proof)
    arguments["foundational_request_dependencies"] = replace(
        arguments["foundational_request_dependencies"],
        impersonation_trust_context=context,
    )
    with patch(
        "sbp_lex.pipeline.runner.run_aurion15",
        side_effect=_pass_aurion,
    ):
        result = run_pipeline(request, signals, **arguments)

    assert result["impersonation_protection_result"] == IMPERSONATION_PASS, result.get(
        "impersonation_protection_reason"
    )
    assert result["impersonation_effect_authority_granted"] is False
    assert replay.validate_store()
    assert registry.validate_store()
    assert clock.validate_store()
    assert clock_head.validate_store()
    assert "possession_proof" not in result


class _UpstreamVerifier:
    def __init__(self, component: str) -> None:
        self.verifier_id = f"production-shaped-{component}-verifier"
        self.verifier_version = "1"

    def verify_authenticated(self, **_kwargs) -> dict:
        return {}


def _production_provider(role: str) -> BoundaryEvidenceProvider:
    return BoundaryEvidenceProvider(
        role=role,
        effect_authority=False,
        three_p_attestation_admitted=False,
    )


def test_production_composition_accepts_durable_contract_and_requires_custody(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ImpersonationDurabilityError,
        match="EXTERNAL_CUSTODY_OR_PIN_ADMISSION_REQUIRED",
    ):
        SQLiteImpersonationReplayGuard(
            database_path=tmp_path / "bad.sqlite3",
            anchor_path=tmp_path / "bad.anchor.json",
            store_id="bad",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=Ed25519FixtureProvider("not-production"),
        )

    providers = {
        role: _production_provider(role)
        for role in (
            "owner",
            "registry",
            "subject",
            "replay",
            "clock",
            "clock_head",
            "sovereign",
            "authority",
        )
    }
    provider_contexts = {
        role: provider.hybrid_verification_context()
        for role, provider in providers.items()
    }
    owner_context = provider_contexts["owner"]
    with pytest.raises(
        ImpersonationDurabilityError,
        match="EXTERNAL_CUSTODY_OR_PIN_ADMISSION_REQUIRED",
    ):
        SQLiteImpersonationReplayGuard(
            database_path=tmp_path / "missing-pin.sqlite3",
            anchor_path=tmp_path / "missing-pin.anchor.json",
            store_id="missing-pin",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=providers["replay"],
        )
    with pytest.raises(
        ImpersonationDurabilityError,
        match="EXTERNAL_CUSTODY_OR_PIN_ADMISSION_REQUIRED",
    ):
        SQLiteImpersonationReplayGuard(
            database_path=tmp_path / "wrong-pin.sqlite3",
            anchor_path=tmp_path / "wrong-pin.anchor.json",
            store_id="wrong-pin",
            context_id=CONTEXT_ID,
            context_digest=CONTEXT_DIGEST,
            signer=providers["replay"],
            owner_pinned_signer_context_digest=owner_context.context_digest,
        )
    context_id = "production-shaped-context"
    pseudo = b"production-shaped-pseudonym-key-material"
    registry_db, registry_anchor = _paths(tmp_path, "prod-registry")
    registry = SQLiteOwnerPinnedTrustRegistry(
        database_path=registry_db,
        anchor_path=registry_anchor,
        store_id="prod-registry",
        context_id=context_id,
        context_digest=CONTEXT_DIGEST,
        registry_id="prod-registry-id",
        registry_provider=providers["registry"],
        owner_pinned_signer_context_digest=(
            provider_contexts["registry"].context_digest
        ),
    )
    replay_db, replay_anchor = _paths(tmp_path, "prod-replay")
    replay = SQLiteImpersonationReplayGuard(
        database_path=replay_db,
        anchor_path=replay_anchor,
        store_id="prod-replay",
        context_id=context_id,
        context_digest=CONTEXT_DIGEST,
        signer=providers["replay"],
        owner_pinned_signer_context_digest=(provider_contexts["replay"].context_digest),
    )
    clock_db, clock_anchor = _paths(tmp_path, "prod-clock")
    clock = AuthenticatedMonotonicClock(
        database_path=clock_db,
        anchor_path=clock_anchor,
        store_id="prod-clock",
        context_id=context_id,
        context_digest=CONTEXT_DIGEST,
        clock_id="prod-clock-id",
        clock_version="1",
        clock_provider=providers["clock"],
        trusted_time_source_admission_digest="7" * 128,
        maximum_forward_step_ms=100,
        time_source=lambda: 1_000,
        owner_pinned_signer_context_digest=(provider_contexts["clock"].context_digest),
    )
    head_db, head_anchor = _paths(tmp_path, "prod-head")
    clock_head = SQLiteImpersonationClockHead(
        database_path=head_db,
        anchor_path=head_anchor,
        store_id="prod-head",
        context_id=context_id,
        context_digest=CONTEXT_DIGEST,
        head_id="prod-head-id",
        head_version="1",
        clock_head_provider=providers["clock_head"],
        owner_pinned_signer_context_digest=(
            provider_contexts["clock_head"].context_digest
        ),
    )
    sovereign = _UpstreamVerifier("sovereign")
    authority = _UpstreamVerifier("authority")

    def binding(provider) -> dict:
        value = impersonation_module._provider_binding(provider)
        assert value is not None
        return value

    context_payload = {
        "schema": TRUST_CONTEXT_SCHEMA,
        "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
        "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
        "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
        "three_p_doctrine_id": THREE_P_DOCTRINE_ID,
        "context_id": context_id,
        "context_version": "1",
        "context_sequence": 1,
        "prior_context_digest": GENESIS_HASH,
        "owner_id": "prod-owner",
        "registry_id": "prod-registry-id",
        "owner_provider_binding": binding(providers["owner"]),
        "registry_provider_binding": binding(providers["registry"]),
        "subject_provider_binding": binding(providers["subject"]),
        "replay_provider_binding": binding(providers["replay"]),
        "clock_provider_binding": binding(clock),
        "clock_head_provider_binding": binding(clock_head),
        "subject_id": "subject-one",
        "participant_id": "participant-one",
        "stakeholder_class": "regulators",
        "role_id": "reviewer",
        "mandate_id": "mandate-one",
        "mandate_actions": ["review"],
        "mandate_jurisdictions": ["AU"],
        "jurisdiction": "AU",
        "audience": "sbp-lex-v2",
        "maximum_proof_age_ms": 100,
        "minimum_registry_sequence": 1,
        "minimum_authority_sequence": 1,
        "minimum_revocation_sequence": 1,
        "replay_namespace": "sbp-lex-v2:impersonation",
        "pseudonym_key_id": sha512(pseudo).hexdigest(),
        "sovereign_identity_verifier": {
            "verifier_id": sovereign.verifier_id,
            "verifier_version": sovereign.verifier_version,
            "hash_stage": "prod:sovereign",
            "receipt_provider_binding": binding(providers["sovereign"]),
        },
        "authority_boundary_verifier": {
            "verifier_id": authority.verifier_id,
            "verifier_version": authority.verifier_version,
            "hash_stage": "prod:authority",
            "receipt_provider_binding": binding(providers["authority"]),
        },
        "trusted_clock_id": clock.clock_id,
        "trusted_clock_version": clock.clock_version,
        "clock_head_id": clock_head.head_id,
        "clock_head_version": clock_head.head_version,
        "minimum_clock_sequence": 1,
        "valid_from_ms": 0,
        "valid_until_ms": 5_000,
        "authorization_effect": deepcopy(NO_AUTHORIZATION_EFFECT),
        "deployment_dependencies": deepcopy(DEPLOYMENT_DEPENDENCIES),
    }
    context_record = build_signed_object(
        context_payload,
        provider=providers["owner"],
        purpose=impersonation_signing_purpose(TRUST_CONTEXT_SCHEMA),
    )
    arguments = {
        "signed_context_record": context_record,
        "owner_provider": providers["owner"],
        "registry_provider": providers["registry"],
        "subject_provider": providers["subject"],
        "replay_provider": providers["replay"],
        "registry": registry,
        "replay_guard": replay,
        "sovereign_identity_verifier": sovereign,
        "sovereign_identity_dependencies": providers["sovereign"],
        "authority_boundary_verifier": authority,
        "authority_boundary_dependencies": providers["authority"],
        "trusted_clock": clock,
        "clock_head_provider": clock_head,
        "pseudonym_key": pseudo,
    }
    admission_digests = {
        "_PRODUCTION_REGISTRY_ADMISSION_DIGEST": canonical_integrity_hash(
            registry.production_admission_record()
        ),
        "_PRODUCTION_REPLAY_ADMISSION_DIGEST": canonical_integrity_hash(
            replay.production_admission_record()
        ),
        "_PRODUCTION_TRUSTED_CLOCK_ADMISSION_DIGEST": canonical_integrity_hash(
            clock.production_admission_record()
        ),
        "_PRODUCTION_CLOCK_HEAD_ADMISSION_DIGEST": canonical_integrity_hash(
            clock_head.production_admission_record()
        ),
    }
    with (
        patch.object(
            impersonation_module,
            "_RUNTIME_MODE",
            impersonation_module._RUNTIME_MODE_PRODUCTION,
        ),
        patch.object(impersonation_module, "_PRODUCTION_CONTEXT_ID", context_id),
        patch.object(
            impersonation_module,
            "_PRODUCTION_CONTEXT_DIGEST",
            context_record["digest"],
        ),
        patch.object(
            impersonation_module,
            "_PRODUCTION_OWNER_HYBRID_CONTEXT_DIGEST",
            owner_context.context_digest,
        ),
        patch.multiple(impersonation_module, **admission_digests),
        patch.dict(
            impersonation_module._REGISTERED_COMPOSITION_BOUNDARIES,
            {},
            clear=True,
        ),
    ):
        fake_arguments = dict(arguments)
        fake_arguments["registry"] = object()
        with pytest.raises(
            ValueError,
            match="PRODUCTION_DURABLE_BOUNDARY_ADMISSION_INVALID",
        ):
            install_production_impersonation_composition_boundary(**fake_arguments)
        provider_mismatch_arguments = dict(arguments)
        provider_mismatch_arguments["registry_provider"] = providers["subject"]
        with pytest.raises(
            ValueError,
            match="PRODUCTION_DURABLE_BOUNDARY_ADMISSION_INVALID",
        ):
            install_production_impersonation_composition_boundary(
                **provider_mismatch_arguments
            )
        install_production_impersonation_composition_boundary(**arguments)
        with pytest.raises(ValueError, match="ALREADY_REGISTERED"):
            install_production_impersonation_composition_boundary(**arguments)


def test_impersonation_signing_purpose_rejects_unknown_schema() -> None:
    with pytest.raises(ValueError, match="SCHEMA_NOT_ADMITTED"):
        impersonation_signing_purpose("UNKNOWN_IMPERSONATION_SCHEMA")
    with pytest.raises(ValueError, match="SCHEMA_NOT_ADMITTED"):
        impersonation_signing_purpose(None)
