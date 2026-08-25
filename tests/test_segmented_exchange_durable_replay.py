from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sbp_lex.exchange import (
    DurableExchangeReplayError,
    SQLiteExchangeReplayGuard,
)
from sbp_lex.security.integrity import canonical_integrity_hash

STORE_ID = "segmented-exchange-local-test-v1"
SCOPE = "authority|credential"


def _guard(path: Path) -> SQLiteExchangeReplayGuard:
    return SQLiteExchangeReplayGuard(path, store_id=STORE_ID)


def _consume(
    guard: SQLiteExchangeReplayGuard,
    exchange_id: str,
    sequence: int,
) -> bool:
    return guard.consume(
        exchange_id=exchange_id,
        envelope_digest=canonical_integrity_hash({"exchange_id": exchange_id}),
        revocation_scope=SCOPE,
        revocation_sequence=sequence,
    )


def test_public_api_keeps_durable_guard_local_and_non_production() -> None:
    assert SQLiteExchangeReplayGuard.production_durable_storage_admitted is False
    assert SQLiteExchangeReplayGuard.distributed_replay_admitted is False
    assert (
        SQLiteExchangeReplayGuard.externally_anchored_rollback_resistance
        is False
    )


def test_claim_survives_restart_and_rejects_revocation_rollback(tmp_path: Path) -> None:
    database = tmp_path / "exchange-replay.sqlite3"
    first = _guard(database)
    assert _consume(first, "exchange-1", 7) is True

    restarted = _guard(database)
    assert _consume(restarted, "exchange-1", 7) is False
    assert _consume(restarted, "exchange-2", 6) is False
    assert _consume(restarted, "exchange-2", 8) is True


def test_concurrent_duplicate_claim_has_exactly_one_winner(tmp_path: Path) -> None:
    database = tmp_path / "exchange-replay.sqlite3"
    guards = [_guard(database) for _ in range(12)]

    with ThreadPoolExecutor(max_workers=len(guards)) as executor:
        results = list(
            executor.map(
                lambda guard: _consume(guard, "exchange-concurrent", 4),
                guards,
            )
        )

    assert results.count(True) == 1
    assert results.count(False) == len(guards) - 1


def test_corrupt_database_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "exchange-replay.sqlite3"
    guard = _guard(database)
    assert _consume(guard, "exchange-before-corruption", 1) is True

    database.write_bytes(b"not-a-sqlite-database")

    with pytest.raises(DurableExchangeReplayError):
        _consume(guard, "exchange-after-corruption", 2)


def test_store_binding_and_database_path_are_fail_closed(tmp_path: Path) -> None:
    database = tmp_path / "exchange-replay.sqlite3"
    _guard(database)

    with pytest.raises(DurableExchangeReplayError, match="store_binding_mismatch"):
        SQLiteExchangeReplayGuard(database, store_id="different-store")

    hardlink = tmp_path / "exchange-replay-hardlink.sqlite3"
    os.link(database, hardlink)
    with pytest.raises(DurableExchangeReplayError, match="database_not_safe"):
        _guard(hardlink)

    sidecar_target = tmp_path / "attacker-controlled-sidecar"
    sidecar_target.write_bytes(b"attacker-controlled")
    sidecar = tmp_path / "sidecar-substitution.sqlite3-wal"
    os.link(sidecar_target, sidecar)
    with pytest.raises(DurableExchangeReplayError, match="auxiliary_not_safe"):
        _guard(tmp_path / "sidecar-substitution.sqlite3")


def test_database_path_replacement_after_open_fails_closed(tmp_path: Path) -> None:
    database = tmp_path / "exchange-replay.sqlite3"
    guard = _guard(database)
    replacement = tmp_path / "replacement.sqlite3"
    _guard(replacement)

    os.replace(replacement, database)

    with pytest.raises(DurableExchangeReplayError, match="identity_changed"):
        _consume(guard, "exchange-after-path-swap", 1)


def test_invalid_claim_inputs_are_never_persisted(tmp_path: Path) -> None:
    guard = _guard(tmp_path / "exchange-replay.sqlite3")
    assert guard.production_durable_storage_admitted is False
    assert guard.distributed_replay_admitted is False
    assert guard.externally_anchored_rollback_resistance is False
    assert guard.consume(
        exchange_id="exchange-invalid",
        envelope_digest="not-a-digest",
        revocation_scope=SCOPE,
        revocation_sequence=1,
    ) is False
    assert _consume(guard, "exchange-invalid", 1) is True
