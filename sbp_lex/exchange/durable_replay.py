"""Atomic same-host replay persistence for segmented exchange envelopes.

This adapter is deliberately local and non-distributed.  It provides durable
restart and concurrent-consumer protection, but it does not claim production
admission or externally anchored rollback resistance.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
from pathlib import Path
from threading import Lock

from sbp_lex.security.integrity import is_sha512

_SCHEMA_VERSION = 1
_STORE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_TEXT_BYTES = 1_024


class DurableExchangeReplayError(RuntimeError):
    """The durable replay store cannot provide a trustworthy answer."""


def _is_reparse(path: Path) -> bool:
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def _safe_database_path(value: str | Path) -> Path:
    try:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        parent = candidate.parent
        resolved_parent = parent.resolve(strict=True)
        current = Path(parent.anchor)
        for part in parent.parts[1:]:
            current = current / part
            metadata = current.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse(current):
                raise DurableExchangeReplayError("exchange_replay_parent_not_safe")
        if os.path.normcase(str(parent)) != os.path.normcase(str(resolved_parent)):
            raise DurableExchangeReplayError("exchange_replay_parent_alias_rejected")
        target = resolved_parent / candidate.name
        if target.exists() or target.is_symlink():
            metadata = target.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse(target)
                or metadata.st_nlink != 1
            ):
                raise DurableExchangeReplayError("exchange_replay_database_not_safe")
        return target
    except DurableExchangeReplayError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise DurableExchangeReplayError("exchange_replay_path_unavailable") from exc


def _text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and "\x00" not in value
        and len(value.encode("utf-8", errors="strict")) <= _MAX_TEXT_BYTES
    )


class SQLiteExchangeReplayGuard:
    """SQLite WAL-backed, atomic replay guard for one local host."""

    durable_storage_class = "LOCAL_SQLITE_WAL"
    production_durable_storage_admitted = False
    distributed_replay_admitted = False
    externally_anchored_rollback_resistance = False

    def __init__(self, database_path: str | Path, *, store_id: str) -> None:
        if type(store_id) is not str or _STORE_ID.fullmatch(store_id) is None:
            raise DurableExchangeReplayError("exchange_replay_store_id_invalid")
        self._database_path = _safe_database_path(database_path)
        self.store_id = store_id
        self._identity_lock = Lock()
        self._database_identity: tuple[int, int] | None = None
        self._initialise()

    @property
    def database_path(self) -> Path:
        return self._database_path

    def _validate_auxiliary_files(self, *, apply_permissions: bool) -> None:
        for suffix in ("-wal", "-shm"):
            auxiliary = Path(f"{self._database_path}{suffix}")
            if not auxiliary.exists() and not auxiliary.is_symlink():
                continue
            try:
                metadata = auxiliary.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or stat.S_ISLNK(metadata.st_mode)
                    or _is_reparse(auxiliary)
                    or metadata.st_nlink != 1
                ):
                    raise DurableExchangeReplayError(
                        "exchange_replay_auxiliary_not_safe"
                    )
                if apply_permissions:
                    os.chmod(auxiliary, stat.S_IRUSR | stat.S_IWUSR)
            except DurableExchangeReplayError:
                raise
            except OSError as exc:
                raise DurableExchangeReplayError(
                    "exchange_replay_auxiliary_unavailable"
                ) from exc

    def _connect(self) -> sqlite3.Connection:
        _safe_database_path(self._database_path)
        self._validate_auxiliary_files(apply_permissions=False)
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._database_path,
                timeout=10.0,
                isolation_level=None,
            )
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            self._pin_or_verify_identity()
            return connection
        except DurableExchangeReplayError:
            if connection is not None:
                connection.close()
            raise
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise DurableExchangeReplayError("exchange_replay_database_unavailable") from exc

    def _pin_or_verify_identity(self) -> None:
        try:
            metadata = self._database_path.lstat()
        except OSError as exc:
            raise DurableExchangeReplayError("exchange_replay_database_unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or _is_reparse(self._database_path)
            or metadata.st_nlink != 1
        ):
            raise DurableExchangeReplayError("exchange_replay_database_not_safe")
        identity = (metadata.st_dev, metadata.st_ino)
        with self._identity_lock:
            if self._database_identity is None:
                self._database_identity = identity
            elif self._database_identity != identity:
                raise DurableExchangeReplayError("exchange_replay_database_identity_changed")

    @staticmethod
    def _integrity_check(connection: sqlite3.Connection) -> None:
        try:
            result = connection.execute("PRAGMA quick_check").fetchone()
        except sqlite3.Error as exc:
            raise DurableExchangeReplayError("exchange_replay_database_corrupt") from exc
        if result != ("ok",):
            raise DurableExchangeReplayError("exchange_replay_database_corrupt")

    def _initialise(self) -> None:
        connection = self._connect()
        try:
            journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if journal_mode is None or str(journal_mode[0]).casefold() != "wal":
                raise DurableExchangeReplayError("exchange_replay_wal_unavailable")
            self._validate_auxiliary_files(apply_permissions=True)
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata ("
                "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                "schema_version INTEGER NOT NULL, store_id TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_exchange ("
                "exchange_id TEXT PRIMARY KEY, envelope_digest TEXT NOT NULL, "
                "revocation_scope TEXT NOT NULL, revocation_sequence INTEGER NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS revocation_head ("
                "revocation_scope TEXT PRIMARY KEY, highest_sequence INTEGER NOT NULL)"
            )
            metadata = connection.execute(
                "SELECT schema_version, store_id FROM metadata WHERE singleton = 1"
            ).fetchone()
            if metadata is None:
                connection.execute(
                    "INSERT INTO metadata(singleton, schema_version, store_id) VALUES(1, ?, ?)",
                    (_SCHEMA_VERSION, self.store_id),
                )
            elif metadata != (_SCHEMA_VERSION, self.store_id):
                raise DurableExchangeReplayError("exchange_replay_store_binding_mismatch")
            self._integrity_check(connection)
            connection.execute("COMMIT")
            self._validate_auxiliary_files(apply_permissions=True)
            self._pin_or_verify_identity()
        except DurableExchangeReplayError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise DurableExchangeReplayError("exchange_replay_initialisation_failed") from exc
        finally:
            connection.close()
        try:
            os.chmod(self._database_path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError as exc:
            raise DurableExchangeReplayError("exchange_replay_permissions_unavailable") from exc
        self._pin_or_verify_identity()

    def consume(
        self,
        *,
        exchange_id: str,
        envelope_digest: str,
        revocation_scope: str,
        revocation_sequence: int,
    ) -> bool:
        if (
            not _text(exchange_id)
            or not is_sha512(envelope_digest)
            or not _text(revocation_scope)
            or type(revocation_sequence) is not int
            or revocation_sequence < 0
        ):
            return False
        self._pin_or_verify_identity()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._validate_auxiliary_files(apply_permissions=True)
            self._integrity_check(connection)
            metadata = connection.execute(
                "SELECT schema_version, store_id FROM metadata WHERE singleton = 1"
            ).fetchone()
            if metadata != (_SCHEMA_VERSION, self.store_id):
                raise DurableExchangeReplayError("exchange_replay_store_binding_mismatch")
            if connection.execute(
                "SELECT 1 FROM consumed_exchange WHERE exchange_id = ?",
                (exchange_id,),
            ).fetchone() is not None:
                connection.execute("ROLLBACK")
                return False
            head = connection.execute(
                "SELECT highest_sequence FROM revocation_head WHERE revocation_scope = ?",
                (revocation_scope,),
            ).fetchone()
            if head is not None and revocation_sequence < head[0]:
                connection.execute("ROLLBACK")
                return False
            connection.execute(
                "INSERT INTO consumed_exchange("
                "exchange_id, envelope_digest, revocation_scope, revocation_sequence"
                ") VALUES(?, ?, ?, ?)",
                (exchange_id, envelope_digest, revocation_scope, revocation_sequence),
            )
            connection.execute(
                "INSERT INTO revocation_head(revocation_scope, highest_sequence) "
                "VALUES(?, ?) ON CONFLICT(revocation_scope) DO UPDATE SET "
                "highest_sequence = MAX(highest_sequence, excluded.highest_sequence)",
                (revocation_scope, revocation_sequence),
            )
            connection.execute("COMMIT")
            self._validate_auxiliary_files(apply_permissions=True)
            self._pin_or_verify_identity()
            return True
        except DurableExchangeReplayError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise DurableExchangeReplayError("exchange_replay_atomic_claim_failed") from exc
        finally:
            connection.close()


__all__ = ["DurableExchangeReplayError", "SQLiteExchangeReplayGuard"]
