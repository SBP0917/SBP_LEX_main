"""Durable repository-local impersonation composition boundaries.

These classes provide SQLite-backed, restart-safe implementations of the
impersonation protocols.  They require an explicitly admitted signing provider
and a separately persisted signed checkpoint.  They do not claim that the
provider's physical custody or the trusted-time source is independently
operated; production callers must supply those external admissions.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Callable
from contextlib import closing
from copy import deepcopy
from pathlib import Path
from typing import Any, Final, TypeVar

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.identity.impersonation_protection import (
    CLOCK_HEAD_SCHEMA,
    CLOCK_HEAD_TRANSITION_SCHEMA,
    CLOCK_RECORD_SCHEMA,
    IMPERSONATION_PROTECTION_CONTRACT_ID,
    IMPERSONATION_PROTECTION_SCHEMA_STATUS,
    IMPERSONATION_PROTECTION_SEMANTICS,
    LIVE_REGISTRY_SCHEMA,
    NO_AUTHORIZATION_EFFECT,
    REPLAY_CLAIM_SCHEMA,
    REPLAY_CLAIMED,
    REPLAY_HEAD_SCHEMA,
    REPLAY_PERSISTENCE_SCHEMA,
    impersonation_signing_purpose,
)
from sbp_lex.security.hybrid_signature import (
    PRODUCTION_SIGNER,
    HybridVerificationContext,
    is_hybrid_provider,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    canonical_integrity_hash,
    is_sha512,
)
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    build_legacy_non_effect_signed_object,
    build_signed_object,
    verify_legacy_non_effect_signed_object,
    verify_signed_object,
)

ANCHOR_SCHEMA: Final = "SBP_LEX_V2_IMPERSONATION_DURABLE_STORE_ANCHOR"
STORE_SCHEMA_VERSION: Final = "1"
TEST_ONLY_FIXTURE_CLASS: Final = "TEST_ONLY_NONPRODUCTION_FIXTURE"
_MAX_TEXT_UTF8_BYTES: Final = 512
_MAX_COLLECTION_ITEMS: Final = 64
_MAX_STRUCTURED_INPUT_BYTES: Final = 16_384
_MAX_SQLITE_INTEGER: Final = 9_223_372_036_854_775_807
_MAX_DATABASE_BYTES: Final = 256 * 1_024 * 1_024
_MAX_SQLITE_VALUE_BYTES: Final = 1_048_576
_MAX_SQL_BYTES: Final = 65_536
_REPLAY_CLAIM_FIELDS: Final = frozenset({
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "namespace",
    "replay_key",
    "claim_sequence",
    "prior_claim_receipt_digest",
    "pre_claim_head_digest",
    "claimed_at_ms",
    "expires_at_ms",
    "request_fingerprint",
    "snapshot_digest",
    "registry_record_digest",
    "possession_proof_digest",
    "subject_binding_digest",
    "session_binding_digest",
    "challenge_binding_digest",
    "registry_sequence",
    "authority_sequence",
    "revocation_sequence",
    "clock_sequence",
    "clock_record_digest",
    "result",
    "authorization_effect",
})
_CLOCK_TRANSITION_FIELDS: Final = frozenset({
    "schema",
    "contract_id",
    "context_id",
    "context_digest",
    "head_id",
    "head_version",
    "head_sequence",
    "prior_head_digest",
    "clock_sequence",
    "clock_record_digest",
    "prior_clock_record_digest",
    "observed_at_ms",
    "result",
    "authorization_effect",
})
_T = TypeVar("_T")


class ImpersonationDurabilityError(RuntimeError):
    """Fail-closed durable-boundary rejection."""


def _text(value: Any) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        return (
            len(value.encode("utf-8")) <= _MAX_TEXT_UTF8_BYTES
            and not any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in value
            )
        )
    except UnicodeEncodeError:
        return False


def _nonnegative_integer(value: Any) -> bool:
    return type(value) is int and 0 <= value <= _MAX_SQLITE_INTEGER


def _bounded_text_list(value: Any) -> bool:
    return (
        type(value) is list
        and 0 < len(value) <= _MAX_COLLECTION_ITEMS
        and all(_text(item) for item in value)
        and value == sorted(set(value))
    )


def _bounded_object(value: Any) -> bool:
    if type(value) is not dict:
        return False
    try:
        return len(canonical_json_bytes(value)) <= _MAX_STRUCTURED_INPUT_BYTES
    except (TypeError, UnicodeError, ValueError):
        return False


def _json(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def _object(value: str, error: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise ImpersonationDurabilityError(error) from exc
    if type(parsed) is not dict:
        raise ImpersonationDurabilityError(error)
    return parsed


def _is_reparse_or_link(path: Path) -> bool:
    metadata = path.lstat()
    attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & 0x400)


def _normalized_secure_target(value: str | Path) -> Path:
    raw_text = os.fspath(value)
    path = Path(raw_text)
    components = raw_text.replace("\\", "/").split("/")
    if not path.is_absolute() or any(part in {".", ".."} for part in components):
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_PATH_NORMALIZATION_INVALID"
        )
    try:
        lexical_parent = os.path.normcase(os.path.abspath(path.parent))
        resolved_parent = os.path.normcase(str(path.parent.resolve(strict=True)))
    except OSError as exc:
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_ABSOLUTE_EXISTING_PARENT_REQUIRED"
        ) from exc
    if lexical_parent != resolved_parent:
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_PATH_NORMALIZATION_INVALID"
        )
    return Path(os.path.abspath(path))


def _validate_secure_path(path: Path, *, may_be_missing: bool) -> None:
    if not path.is_absolute() or not path.parent.exists():
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_ABSOLUTE_EXISTING_PARENT_REQUIRED"
        )
    parent_metadata = path.parent.stat()
    if os.name != "nt" and stat.S_IMODE(parent_metadata.st_mode) & 0o022:
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_PARENT_PERMISSIONS_REJECTED"
        )
    current = path.parent
    while True:
        if _is_reparse_or_link(current):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_REPARSE_PATH_REJECTED"
            )
        if current.parent == current:
            break
        current = current.parent
    if not os.path.lexists(path):
        if may_be_missing:
            return
        raise ImpersonationDurabilityError("IMPERSONATION_DURABLE_PATH_UNAVAILABLE")
    metadata = path.lstat()
    if (
        _is_reparse_or_link(path)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
    ):
        raise ImpersonationDurabilityError("IMPERSONATION_DURABLE_PATH_ALIAS_REJECTED")


def _owner_only(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError as exc:
        if os.name != "nt":
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_OWNER_ONLY_PERMISSION_FAILED"
            ) from exc


def _fsync_parent(path: Path) -> None:
    try:
        descriptor = os.open(path.parent, os.O_RDONLY)
    except OSError as exc:
        if os.name != "nt":
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_PARENT_SYNC_FAILED"
            ) from exc
        return
    try:
        os.fsync(descriptor)
    except OSError as exc:
        if os.name != "nt":
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_PARENT_SYNC_FAILED"
            ) from exc
    finally:
        os.close(descriptor)


def _ensure_database_file(path: Path) -> None:
    if os.path.lexists(path):
        return
    try:
        with open(path, "xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        _owner_only(path)
        _fsync_parent(path)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_DATABASE_CREATION_FAILED"
        ) from exc
    _validate_secure_path(path, may_be_missing=False)


class _ReceiptSigner:
    def __init__(
        self,
        provider: SignatureProvider,
        *,
        allow_test_only: bool,
        owner_pinned_context_digest: str | None,
    ) -> None:
        self.provider = provider
        self.allow_test_only = allow_test_only
        context: HybridVerificationContext | None = None
        method = getattr(provider, "hybrid_verification_context", None)
        if callable(method):
            try:
                candidate = method(allow_test_only=allow_test_only)
            except Exception as exc:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_SIGNER_CONTEXT_UNAVAILABLE"
                ) from exc
            if isinstance(candidate, HybridVerificationContext):
                context = candidate
        if allow_test_only:
            if context is None and not callable(getattr(provider, "sign", None)):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_TEST_SIGNER_INVALID"
                )
        elif (
            context is None
            or context.signer_class != PRODUCTION_SIGNER
            or not context.external_custody_admitted
            or context.effect_authority
            or not is_sha512(owner_pinned_context_digest)
            or context.context_digest != owner_pinned_context_digest
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_EXTERNAL_CUSTODY_OR_PIN_ADMISSION_REQUIRED"
            )
        self.context = context
        self.owner_pinned_context_digest = owner_pinned_context_digest
        self.identity_digest = canonical_integrity_hash(
            context.public_record()
            if context is not None
            else {
                "provider_id": getattr(provider, "provider_id", None),
                "algorithm": getattr(provider, "algorithm", None),
                "key_id": getattr(provider, "key_id", None),
                "custody_class": getattr(provider, "custody_class", None),
                "test_only": True,
            }
        )

    def sign(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            if self.context is not None:
                return build_signed_object(
                    payload,
                    provider=self.provider,
                    purpose=impersonation_signing_purpose(payload.get("schema")),
                )
            if self.allow_test_only:
                return build_legacy_non_effect_signed_object(
                    payload,
                    provider=self.provider,
                )
        except Exception as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_SIGNING_FAILED"
            ) from exc
        raise ImpersonationDurabilityError(
            "IMPERSONATION_DURABLE_PRODUCTION_SIGNER_REQUIRED"
        )

    def verify(self, record: Any) -> bool:
        if type(record) is not dict:
            return False
        try:
            if self.context is not None:
                return verify_signed_object(
                    record,
                    provider=None,
                    purpose=impersonation_signing_purpose(record.get("schema")),
                    trust_context=self.context,
                    owner_pinned_context_digest=self.owner_pinned_context_digest,
                )
            return self.allow_test_only and verify_legacy_non_effect_signed_object(
                record,
                provider=self.provider,
            )
        except Exception:  # noqa: BLE001
            return False


class _AnchoredSQLiteStore:
    store_kind: str
    durable_storage_class = "SINGLE_HOST_LOCAL_SQLITE_WAL_SIGNED_ANCHOR"
    distributed_durability_admitted = False
    externally_operated_rollback_anchor_admitted = False
    hardware_custody_provided_by_store = False
    filesystem_owner_only_mode_enforced = os.name != "nt"

    def __init__(
        self,
        *,
        database_path: str | Path,
        anchor_path: str | Path,
        store_id: str,
        context_id: str,
        context_digest: str,
        signer: SignatureProvider,
        owner_pinned_signer_context_digest: str | None = None,
        allow_test_only: bool = False,
        extra_identity: dict[str, Any] | None = None,
    ) -> None:
        if (
            not _text(store_id)
            or not _text(context_id)
            or not is_sha512(context_digest)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_STORE_IDENTITY_INVALID"
            )
        self.database_path = _normalized_secure_target(database_path)
        self.anchor_path = _normalized_secure_target(anchor_path)
        if os.path.normcase(str(self.database_path)) == os.path.normcase(
            str(self.anchor_path)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_PATH_INVALID"
            )
        _validate_secure_path(self.database_path, may_be_missing=True)
        _validate_secure_path(self.anchor_path, may_be_missing=True)
        if (
            self.database_path.exists()
            and self.anchor_path.exists()
            and os.path.samefile(self.database_path, self.anchor_path)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_PATH_ALIAS_REJECTED"
            )
        if any(
            os.path.normcase(str(self.anchor_path))
            == os.path.normcase(f"{self.database_path}{suffix}")
            for suffix in ("-journal", "-wal", "-shm")
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_PATH_INVALID"
            )
        self.store_id = store_id
        self.context_id = context_id
        self.context_digest = context_digest
        self.allow_test_only = allow_test_only
        self.fixture_class = (
            TEST_ONLY_FIXTURE_CLASS if allow_test_only else "PRODUCTION_BOUNDARY"
        )
        self._signer = _ReceiptSigner(
            signer,
            allow_test_only=allow_test_only,
            owner_pinned_context_digest=owner_pinned_signer_context_digest,
        )
        self._extra_identity = deepcopy(extra_identity or {})
        self._lock = threading.RLock()
        self._database_identity: tuple[int, int] | None = None
        self._identity = {
            "schema_version": STORE_SCHEMA_VERSION,
            "store_kind": self.store_kind,
            "store_id": store_id,
            "context_id": context_id,
            "context_digest": context_digest,
            "signer_identity_digest": self._signer.identity_digest,
            "owner_pinned_signer_context_digest": (owner_pinned_signer_context_digest),
            "extra_identity": self._extra_identity,
        }
        self.store_identity_digest = canonical_integrity_hash(self._identity)
        self._initialize()

    @property
    def provider_id(self) -> Any:
        return getattr(self._signer.provider, "provider_id", None)

    @property
    def algorithm(self) -> Any:
        return getattr(self._signer.provider, "algorithm", None)

    @property
    def key_id(self) -> Any:
        return getattr(self._signer.provider, "key_id", None)

    @property
    def custody_class(self) -> Any:
        return getattr(self._signer.provider, "custody_class", None)

    @property
    def effect_authority(self) -> bool:
        return False

    @property
    def public_key(self) -> Any:
        return getattr(self._signer.provider, "public_key", None)

    def sign(self, message: bytes, *, key_id: str) -> bytes:
        method = self._signer.provider.sign
        return method(message, key_id=key_id)

    def verify(self, message: bytes, signature: bytes, *, key_id: str) -> bool:
        method = self._signer.provider.verify
        return method(message, signature, key_id=key_id) is True

    def hybrid_verification_context(
        self,
        *,
        allow_test_only: bool = False,
    ) -> HybridVerificationContext:
        provider = self._signer.provider
        if not is_hybrid_provider(provider):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_HYBRID_SIGNER_REQUIRED"
            )
        return provider.hybrid_verification_context(
            allow_test_only=allow_test_only
        )

    def production_admission_record(self) -> dict[str, Any]:
        """Return the exact externally pinnable identity of this boundary."""

        if self.allow_test_only or self.fixture_class != "PRODUCTION_BOUNDARY":
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_PRODUCTION_ADMISSION_UNAVAILABLE"
            )
        return {
            "schema": "SBP_LEX_V2_IMPERSONATION_DURABLE_BOUNDARY_ADMISSION",
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "store_kind": self.store_kind,
            "store_id": self.store_id,
            "store_identity_digest": self.store_identity_digest,
            "context_id": self.context_id,
            "context_digest": self.context_digest,
            "owner_pinned_signer_context_digest": (
                self._signer.owner_pinned_context_digest
            ),
            "fixture_class": self.fixture_class,
            "durable_storage_class": self.durable_storage_class,
            "distributed_durability_admitted": (
                self.distributed_durability_admitted
            ),
            "externally_operated_rollback_anchor_admitted": (
                self.externally_operated_rollback_anchor_admitted
            ),
            "hardware_custody_provided_by_store": (
                self.hardware_custody_provided_by_store
            ),
            "filesystem_owner_only_mode_enforced": (
                self.filesystem_owner_only_mode_enforced
            ),
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }

    def sign_hybrid_preimage(
        self,
        preimage: bytes,
        *,
        purpose: str,
        context_digest: str,
    ) -> tuple[bytes, bytes]:
        provider = self._signer.provider
        if not is_hybrid_provider(provider):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_HYBRID_SIGNER_REQUIRED"
            )
        return provider.sign_hybrid_preimage(
            preimage,
            purpose=purpose,
            context_digest=context_digest,
        )

    def _connect(self) -> sqlite3.Connection:
        _validate_secure_path(self.database_path, may_be_missing=True)
        _ensure_database_file(self.database_path)
        _validate_secure_path(self.database_path, may_be_missing=False)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.database_path}{suffix}")
            if os.path.lexists(sidecar):
                _validate_secure_path(sidecar, may_be_missing=False)
        connection: sqlite3.Connection | None = None
        try:
            before_open = self.database_path.lstat()
            connection = sqlite3.connect(
                self.database_path,
                isolation_level=None,
                timeout=30.0,
            )
            connection.setlimit(
                sqlite3.SQLITE_LIMIT_LENGTH,
                _MAX_SQLITE_VALUE_BYTES,
            )
            connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, _MAX_SQL_BYTES)
            connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 64)
            connection.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
            journal_mode = self._pragma_scalar(connection, "PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA recursive_triggers=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA secure_delete=ON")
            connection.execute("PRAGMA cell_size_check=ON")
            connection.execute("PRAGMA ignore_check_constraints=OFF")
            connection.execute("PRAGMA writable_schema=OFF")
            connection.execute("PRAGMA mmap_size=0")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute("PRAGMA wal_autocheckpoint=256")
            connection.execute("PRAGMA journal_size_limit=16777216")
            connection.execute("PRAGMA busy_timeout=30000")
            after_open = self.database_path.lstat()
            if not os.path.samestat(before_open, after_open):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_DATABASE_SUBSTITUTED_DURING_OPEN"
                )
            if (
                str(journal_mode).casefold() != "wal"
                or self._pragma_scalar(connection, "PRAGMA synchronous") != 2
                or self._pragma_scalar(connection, "PRAGMA foreign_keys") != 1
                or self._pragma_scalar(connection, "PRAGMA trusted_schema") != 0
                or self._pragma_scalar(connection, "PRAGMA recursive_triggers") != 0
                or self._pragma_scalar(connection, "PRAGMA temp_store") != 2
                or self._pragma_scalar(connection, "PRAGMA secure_delete") != 1
                or self._pragma_scalar(connection, "PRAGMA cell_size_check") != 1
                or self._pragma_scalar(
                    connection,
                    "PRAGMA ignore_check_constraints",
                )
                != 0
                or self._pragma_scalar(connection, "PRAGMA writable_schema") != 0
                or self._pragma_scalar(connection, "PRAGMA mmap_size") != 0
                or self._pragma_scalar(connection, "PRAGMA cache_size") != -2_048
                or self._pragma_scalar(connection, "PRAGMA wal_autocheckpoint")
                != 256
                or self._pragma_scalar(connection, "PRAGMA journal_size_limit")
                != 16_777_216
                or self._pragma_scalar(connection, "PRAGMA busy_timeout") != 30_000
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_SQLITE_PRAGMA_MISMATCH"
                )
            page_size = self._pragma_scalar(connection, "PRAGMA page_size")
            page_count = self._pragma_scalar(connection, "PRAGMA page_count")
            if (
                type(page_size) is not int
                or page_size <= 0
                or type(page_count) is not int
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_SQLITE_PAGE_BOUNDS_INVALID"
                )
            maximum_pages = max(1, _MAX_DATABASE_BYTES // page_size)
            enforced_pages = self._pragma_scalar(
                connection,
                f"PRAGMA max_page_count={maximum_pages}",
            )
            if page_count > maximum_pages or enforced_pages != maximum_pages:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_DATABASE_TOO_LARGE"
                )
            _owner_only(self.database_path)
            self._pin_or_verify_database_identity()
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{self.database_path}{suffix}")
                if os.path.lexists(sidecar):
                    _validate_secure_path(sidecar, may_be_missing=False)
                    _owner_only(sidecar)
            return connection
        except ImpersonationDurabilityError:
            if connection is not None:
                connection.close()
            raise
        except (OSError, sqlite3.Error, ValueError) as exc:
            if connection is not None:
                connection.close()
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_DATABASE_UNAVAILABLE"
            ) from exc

    @staticmethod
    def _pragma_scalar(connection: sqlite3.Connection, statement: str) -> object:
        row = connection.execute(statement).fetchone()
        if row is None or len(row) != 1:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_SQLITE_PRAGMA_UNAVAILABLE"
            )
        return row[0]

    def _pin_or_verify_database_identity(self) -> None:
        _validate_secure_path(self.database_path, may_be_missing=False)
        try:
            metadata = self.database_path.lstat()
        except OSError as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_DATABASE_UNAVAILABLE"
            ) from exc
        identity = (metadata.st_dev, metadata.st_ino)
        with self._lock:
            if self._database_identity is None:
                self._database_identity = identity
            elif self._database_identity != identity:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_DATABASE_IDENTITY_CHANGED"
                )

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        raise NotImplementedError

    def _state_rows(self, connection: sqlite3.Connection) -> Any:
        raise NotImplementedError

    def _state_digest(self, connection: sqlite3.Connection) -> str:
        return canonical_integrity_hash(
            {
                "identity": self._identity,
                "schema": connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_schema "
                    "WHERE name NOT LIKE 'sqlite_%' "
                    "ORDER BY type, name, tbl_name, sql"
                ).fetchall(),
                "rows": self._state_rows(connection),
            }
        )

    def _anchor_payload(
        self,
        *,
        generation: int,
        state_digest: str,
    ) -> dict[str, Any]:
        return {
            "schema": ANCHOR_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "store_kind": self.store_kind,
            "store_id": self.store_id,
            "store_identity_digest": self.store_identity_digest,
            "context_id": self.context_id,
            "context_digest": self.context_digest,
            "generation": generation,
            "state_digest": state_digest,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }

    def _write_anchor(self, anchor: dict[str, Any]) -> None:
        temporary = self.anchor_path.with_name(
            f".{self.anchor_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        data = canonical_json_bytes(anchor)
        try:
            _validate_secure_path(self.anchor_path, may_be_missing=True)
            if len(data) > _MAX_STRUCTURED_INPUT_BYTES:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_ANCHOR_SIZE_INVALID"
                )
            with open(temporary, "xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            _owner_only(temporary)
            os.replace(temporary, self.anchor_path)
            _validate_secure_path(self.anchor_path, may_be_missing=False)
            _owner_only(self.anchor_path)
            _fsync_parent(self.anchor_path)
        except Exception as exc:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_WRITE_FAILED"
            ) from exc

    def _read_anchor(self) -> dict[str, Any]:
        try:
            _validate_secure_path(self.anchor_path, may_be_missing=False)
            before = self.anchor_path.lstat()
            if before.st_size <= 0 or before.st_size > _MAX_STRUCTURED_INPUT_BYTES:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_ANCHOR_SIZE_INVALID"
                )
            with open(self.anchor_path, "rb") as stream:
                opened_before = os.fstat(stream.fileno())
                if not os.path.samestat(before, opened_before):
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_DURABLE_ANCHOR_SUBSTITUTED"
                    )
                data = stream.read(_MAX_STRUCTURED_INPUT_BYTES + 1)
                opened_after = os.fstat(stream.fileno())
            after = self.anchor_path.lstat()
            if (
                len(data) > _MAX_STRUCTURED_INPUT_BYTES
                or not os.path.samestat(opened_after, after)
                or opened_before.st_size != opened_after.st_size
                or opened_before.st_mtime_ns != opened_after.st_mtime_ns
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_ANCHOR_SUBSTITUTED"
                )
            anchor = _object(
                data.decode("utf-8"),
                "IMPERSONATION_DURABLE_ANCHOR_CORRUPT",
            )
        except (OSError, UnicodeError) as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_UNAVAILABLE"
            ) from exc
        if not self._signer.verify(anchor):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_SIGNATURE_INVALID"
            )
        return anchor

    def _initialize(self) -> None:
        with self._lock, closing(self._connect()) as connection:
            if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_DURABLE_DATABASE_CORRUPT"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS durable_metadata "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS durable_anchor_state "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton = 1), "
                "generation INTEGER NOT NULL, state_digest TEXT NOT NULL, "
                "anchor_digest TEXT NOT NULL)"
            )
            self._create_schema(connection)
            rows = dict(connection.execute("SELECT key, value FROM durable_metadata"))
            anchor_row = connection.execute(
                "SELECT generation, state_digest, anchor_digest "
                "FROM durable_anchor_state WHERE singleton = 1"
            ).fetchone()
            if not rows and anchor_row is None:
                if self.anchor_path.exists():
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_DURABLE_DATABASE_ROLLBACK_OR_REPLACEMENT"
                    )
                connection.execute("BEGIN IMMEDIATE")
                try:
                    connection.executemany(
                        "INSERT INTO durable_metadata(key, value) VALUES(?, ?)",
                        [(key, _json(value)) for key, value in self._identity.items()],
                    )
                    state_digest = self._state_digest(connection)
                    anchor = self._signer.sign(
                        self._anchor_payload(generation=0, state_digest=state_digest)
                    )
                    self._write_anchor(anchor)
                    connection.execute(
                        "INSERT INTO durable_anchor_state VALUES(1, 0, ?, ?)",
                        (state_digest, canonical_integrity_hash(anchor)),
                    )
                    connection.execute("COMMIT")
                    _fsync_parent(self.database_path)
                except Exception:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise
            else:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    self._validate_connection(connection)
                    connection.execute("COMMIT")
                except Exception:
                    if connection.in_transaction:
                        connection.execute("ROLLBACK")
                    raise

    def _validate_connection(self, connection: sqlite3.Connection) -> tuple[int, str]:
        if connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise ImpersonationDurabilityError("IMPERSONATION_DURABLE_DATABASE_CORRUPT")
        observed = {
            key: _object(value, "IMPERSONATION_DURABLE_METADATA_CORRUPT")
            if key == "extra_identity"
            else json.loads(value)
            for key, value in connection.execute(
                "SELECT key, value FROM durable_metadata"
            )
        }
        if observed != self._identity:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_STORE_IDENTITY_MISMATCH"
            )
        row = connection.execute(
            "SELECT generation, state_digest, anchor_digest "
            "FROM durable_anchor_state WHERE singleton = 1"
        ).fetchone()
        if row is None or type(row[0]) is not int or row[0] < 0:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_ANCHOR_STATE_INVALID"
            )
        generation, stored_digest, anchor_digest = row
        computed = self._state_digest(connection)
        anchor = self._read_anchor()
        expected = self._anchor_payload(
            generation=generation,
            state_digest=stored_digest,
        )
        if (
            computed != stored_digest
            or canonical_integrity_hash(anchor) != anchor_digest
            or any(anchor.get(key) != value for key, value in expected.items())
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_DURABLE_CORRUPTION_OR_ROLLBACK"
            )
        return generation, stored_digest

    def validate_store(self) -> bool:
        try:
            with self._lock, closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._validate_connection(connection)
                connection.execute("COMMIT")
            return True
        except Exception:  # noqa: BLE001
            return False

    def _read(self, operation: Callable[[sqlite3.Connection], _T]) -> _T:
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_connection(connection)
                result = operation(connection)
                connection.execute("COMMIT")
                return result
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _mutate(self, operation: Callable[[sqlite3.Connection], _T]) -> _T:
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                generation, prior_state_digest = self._validate_connection(connection)
                result = operation(connection)
                state_digest = self._state_digest(connection)
                if state_digest == prior_state_digest:
                    connection.execute("COMMIT")
                    return result
                if generation >= _MAX_SQLITE_INTEGER:
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_DURABLE_GENERATION_EXHAUSTED"
                    )
                anchor = self._signer.sign(
                    self._anchor_payload(
                        generation=generation + 1,
                        state_digest=state_digest,
                    )
                )
                self._write_anchor(anchor)
                connection.execute(
                    "UPDATE durable_anchor_state SET generation = ?, "
                    "state_digest = ?, anchor_digest = ? WHERE singleton = 1",
                    (
                        generation + 1,
                        state_digest,
                        canonical_integrity_hash(anchor),
                    ),
                )
                connection.execute("COMMIT")
                _fsync_parent(self.database_path)
                return result
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise


class SQLiteOwnerPinnedTrustRegistry(_AnchoredSQLiteStore):
    """Owner-pinned durable live-identity registry."""

    store_kind = "OWNER_PINNED_TRUST_REGISTRY"

    def __init__(
        self,
        *,
        database_path: str | Path,
        anchor_path: str | Path,
        store_id: str,
        context_id: str,
        context_digest: str,
        registry_id: str,
        registry_provider: SignatureProvider,
        owner_pinned_signer_context_digest: str | None = None,
        allow_test_only: bool = False,
    ) -> None:
        if not _text(registry_id):
            raise ImpersonationDurabilityError("IMPERSONATION_REGISTRY_ID_INVALID")
        self.registry_id = registry_id
        super().__init__(
            database_path=database_path,
            anchor_path=anchor_path,
            store_id=store_id,
            context_id=context_id,
            context_digest=context_digest,
            signer=registry_provider,
            owner_pinned_signer_context_digest=(owner_pinned_signer_context_digest),
            allow_test_only=allow_test_only,
            extra_identity={"registry_id": registry_id},
        )

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS live_identities ("
            "subject_id TEXT NOT NULL, participant_id TEXT NOT NULL, "
            "registry_sequence INTEGER NOT NULL, authority_sequence INTEGER NOT NULL, "
            "revocation_sequence INTEGER NOT NULL, record_digest TEXT NOT NULL, "
            "record_json TEXT NOT NULL, PRIMARY KEY(subject_id, participant_id))"
        )

    def _state_rows(self, connection: sqlite3.Connection) -> Any:
        return connection.execute(
            "SELECT subject_id, participant_id, registry_sequence, "
            "authority_sequence, revocation_sequence, record_digest, record_json "
            "FROM live_identities ORDER BY subject_id, participant_id"
        ).fetchall()

    def install_identity(self, payload: dict[str, Any]) -> dict[str, Any]:
        required = {
            "schema",
            "contract_id",
            "schema_status",
            "semantics",
            "context_id",
            "context_digest",
            "registry_id",
            "registry_sequence",
            "subject_id",
            "participant_id",
            "stakeholder_class",
            "role_id",
            "mandate_id",
            "mandate_actions",
            "mandate_jurisdictions",
            "jurisdiction",
            "subject_provider_binding",
            "authority_sequence",
            "revocation_status",
            "revocation_sequence",
            "valid_from_ms",
            "valid_until_ms",
        }
        if type(payload) is not dict or set(payload) != required:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REGISTRY_RECORD_SHAPE_INVALID"
            )
        exact = {
            "schema": LIVE_REGISTRY_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "schema_status": IMPERSONATION_PROTECTION_SCHEMA_STATUS,
            "semantics": IMPERSONATION_PROTECTION_SEMANTICS,
            "context_id": self.context_id,
            "context_digest": self.context_digest,
            "registry_id": self.registry_id,
        }
        if any(payload.get(key) != value for key, value in exact.items()):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REGISTRY_RECORD_BINDING_INVALID"
            )
        if (
            any(
                not _text(payload.get(field))
                for field in (
                    "subject_id",
                    "participant_id",
                    "stakeholder_class",
                    "role_id",
                    "mandate_id",
                    "jurisdiction",
                    "revocation_status",
                )
            )
            or not _bounded_text_list(payload.get("mandate_actions"))
            or not _bounded_text_list(payload.get("mandate_jurisdictions"))
            or not _bounded_object(payload.get("subject_provider_binding"))
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REGISTRY_RECORD_BOUNDS_INVALID"
            )
        for field in (
            "registry_sequence",
            "authority_sequence",
            "revocation_sequence",
            "valid_from_ms",
            "valid_until_ms",
        ):
            if not _nonnegative_integer(payload.get(field)):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REGISTRY_SEQUENCE_INVALID"
                )
        if payload["valid_until_ms"] <= payload["valid_from_ms"]:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REGISTRY_VALIDITY_INTERVAL_INVALID"
            )
        record = self._signer.sign(deepcopy(payload))
        digest = canonical_integrity_hash(record)

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            existing = connection.execute(
                "SELECT registry_sequence, authority_sequence, revocation_sequence, "
                "record_json "
                "FROM live_identities WHERE subject_id = ? AND participant_id = ?",
                (payload["subject_id"], payload["participant_id"]),
            ).fetchone()
            sequences = (
                payload["registry_sequence"],
                payload["authority_sequence"],
                payload["revocation_sequence"],
            )
            if existing is not None:
                prior_sequences = existing[:3]
                if any(
                    new < old
                    for new, old in zip(sequences, prior_sequences, strict=True)
                ):
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_REGISTRY_ROLLBACK_REJECTED"
                    )
                if sequences == prior_sequences:
                    prior_record = _object(
                        existing[3],
                        "IMPERSONATION_REGISTRY_RECORD_CORRUPT",
                    )
                    prior_payload = {key: prior_record.get(key) for key in required}
                    if (
                        set(prior_record).issuperset(required)
                        and prior_payload == payload
                    ):
                        if not self._signer.verify(prior_record):
                            raise ImpersonationDurabilityError(
                                "IMPERSONATION_REGISTRY_RECORD_INVALID"
                            )
                        return deepcopy(prior_record)
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_REGISTRY_EQUAL_SEQUENCE_EQUIVOCATION"
                    )
            connection.execute(
                "INSERT INTO live_identities VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(subject_id, participant_id) DO UPDATE SET "
                "registry_sequence=excluded.registry_sequence, "
                "authority_sequence=excluded.authority_sequence, "
                "revocation_sequence=excluded.revocation_sequence, "
                "record_digest=excluded.record_digest, record_json=excluded.record_json",
                (
                    payload["subject_id"],
                    payload["participant_id"],
                    *sequences,
                    digest,
                    _json(record),
                ),
            )
            return deepcopy(record)

        return self._mutate(operation)

    def lookup_identity(
        self,
        *,
        subject_id: str,
        participant_id: str,
    ) -> dict[str, Any]:
        if not _text(subject_id) or not _text(participant_id):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REGISTRY_LOOKUP_INPUT_INVALID"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT record_digest, record_json FROM live_identities "
                "WHERE subject_id = ? AND participant_id = ?",
                (subject_id, participant_id),
            ).fetchone()
            if row is None:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REGISTRY_IDENTITY_NOT_FOUND"
                )
            record = _object(row[1], "IMPERSONATION_REGISTRY_RECORD_CORRUPT")
            if canonical_integrity_hash(record) != row[0] or not self._signer.verify(
                record
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REGISTRY_RECORD_INVALID"
                )
            return deepcopy(record)

        return self._read(operation)


class SQLiteImpersonationReplayGuard(_AnchoredSQLiteStore):
    """Atomic, restart-safe impersonation replay guard."""

    store_kind = "IMPERSONATION_REPLAY_GUARD"

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_heads ("
            "namespace TEXT NOT NULL, subject_digest TEXT NOT NULL, "
            "registry_sequence INTEGER NOT NULL, authority_sequence INTEGER NOT NULL, "
            "revocation_sequence INTEGER NOT NULL, claim_sequence INTEGER NOT NULL, "
            "latest_receipt_digest TEXT NOT NULL, "
            "PRIMARY KEY(namespace, subject_digest))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_claims ("
            "namespace TEXT NOT NULL, replay_key TEXT NOT NULL, "
            "subject_digest TEXT NOT NULL, claim_sequence INTEGER NOT NULL, "
            "receipt_digest TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL, "
            "PRIMARY KEY(namespace, replay_key))"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_head_observations ("
            "head_digest TEXT PRIMARY KEY, namespace TEXT NOT NULL, "
            "subject_digest TEXT NOT NULL, observed_at_ms INTEGER NOT NULL, "
            "claim_sequence INTEGER NOT NULL, head_json TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS replay_persistence_receipts ("
            "receipt_digest TEXT PRIMARY KEY, receipt_json TEXT NOT NULL)"
        )

    def _state_rows(self, connection: sqlite3.Connection) -> Any:
        return {
            "heads": connection.execute(
                "SELECT * FROM replay_heads ORDER BY namespace, subject_digest"
            ).fetchall(),
            "claims": connection.execute(
                "SELECT * FROM replay_claims ORDER BY namespace, replay_key"
            ).fetchall(),
            "observations": connection.execute(
                "SELECT * FROM replay_head_observations ORDER BY head_digest"
            ).fetchall(),
            "persistence": connection.execute(
                "SELECT * FROM replay_persistence_receipts ORDER BY receipt_digest"
            ).fetchall(),
        }

    def _head_payload(
        self,
        connection: sqlite3.Connection,
        *,
        namespace: str,
        subject_binding_digest: str,
        observed_at_ms: int,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT registry_sequence, authority_sequence, revocation_sequence, "
            "claim_sequence, latest_receipt_digest FROM replay_heads "
            "WHERE namespace = ? AND subject_digest = ?",
            (namespace, subject_binding_digest),
        ).fetchone()
        values = row or (0, 0, 0, 0, GENESIS_HASH)
        return {
            "schema": REPLAY_HEAD_SCHEMA,
            "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
            "context_id": self.context_id,
            "context_digest": self.context_digest,
            "namespace": namespace,
            "subject_binding_digest": subject_binding_digest,
            "registry_sequence": values[0],
            "authority_sequence": values[1],
            "revocation_sequence": values[2],
            "claim_sequence": values[3],
            "latest_claim_receipt_digest": values[4],
            "observed_at_ms": observed_at_ms,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }

    def current_head(
        self,
        *,
        namespace: str,
        subject_binding_digest: str,
        observed_at_ms: int,
    ) -> dict[str, Any]:
        if (
            not _text(namespace)
            or not is_sha512(subject_binding_digest)
            or not _nonnegative_integer(observed_at_ms)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REPLAY_HEAD_INPUT_INVALID"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            payload = self._head_payload(
                connection,
                namespace=namespace,
                subject_binding_digest=subject_binding_digest,
                observed_at_ms=observed_at_ms,
            )
            existing = connection.execute(
                "SELECT head_digest, head_json FROM replay_head_observations WHERE "
                "namespace = ? AND subject_digest = ? AND observed_at_ms = ? "
                "AND claim_sequence = ?",
                (
                    namespace,
                    subject_binding_digest,
                    observed_at_ms,
                    payload["claim_sequence"],
                ),
            ).fetchone()
            if existing is not None:
                record = _object(existing[1], "IMPERSONATION_REPLAY_HEAD_CORRUPT")
                if (
                    canonical_integrity_hash(record) != existing[0]
                    or not self._signer.verify(record)
                ):
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_REPLAY_HEAD_SIGNATURE_INVALID"
                    )
                return record
            record = self._signer.sign(payload)
            connection.execute(
                "INSERT INTO replay_head_observations VALUES(?, ?, ?, ?, ?, ?)",
                (
                    canonical_integrity_hash(record),
                    namespace,
                    subject_binding_digest,
                    observed_at_ms,
                    payload["claim_sequence"],
                    _json(record),
                ),
            )
            return deepcopy(record)

        return self._mutate(operation)

    def claim_once(self, *, claim: dict[str, Any]) -> dict[str, Any]:
        if type(claim) is not dict or set(claim) != _REPLAY_CLAIM_FIELDS:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REPLAY_CLAIM_SHAPE_INVALID"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            namespace = claim.get("namespace")
            replay_key = claim.get("replay_key")
            subject_digest = claim.get("subject_binding_digest")
            if (
                claim.get("schema") != REPLAY_CLAIM_SCHEMA
                or claim.get("contract_id") != IMPERSONATION_PROTECTION_CONTRACT_ID
                or not _text(namespace)
                or not is_sha512(replay_key)
                or not is_sha512(subject_digest)
                or claim.get("context_id") != self.context_id
                or claim.get("context_digest") != self.context_digest
                or claim.get("result") != REPLAY_CLAIMED
                or claim.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REPLAY_CLAIM_BINDING_INVALID"
                )
            digest_fields = (
                "pre_claim_head_digest",
                "request_fingerprint",
                "snapshot_digest",
                "registry_record_digest",
                "possession_proof_digest",
                "session_binding_digest",
                "challenge_binding_digest",
                "clock_record_digest",
            )
            integer_fields = (
                "claim_sequence",
                "claimed_at_ms",
                "expires_at_ms",
                "registry_sequence",
                "authority_sequence",
                "revocation_sequence",
                "clock_sequence",
            )
            if (
                any(not is_sha512(claim.get(field)) for field in digest_fields)
                or (
                    claim.get("prior_claim_receipt_digest") != GENESIS_HASH
                    and not is_sha512(claim.get("prior_claim_receipt_digest"))
                )
                or any(
                    not _nonnegative_integer(claim.get(field))
                    for field in integer_fields
                )
                or claim["claim_sequence"] < 1
                or claim["clock_sequence"] < 1
                or claim["expires_at_ms"] <= claim["claimed_at_ms"]
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REPLAY_CLAIM_SEMANTICS_INVALID"
                )
            if (
                connection.execute(
                    "SELECT 1 FROM replay_claims WHERE namespace = ? AND replay_key = ?",
                    (namespace, replay_key),
                ).fetchone()
                is not None
            ):
                raise ImpersonationDurabilityError("IMPERSONATION_REPLAY_DUPLICATE")
            row = connection.execute(
                "SELECT registry_sequence, authority_sequence, revocation_sequence, "
                "claim_sequence, latest_receipt_digest FROM replay_heads "
                "WHERE namespace = ? AND subject_digest = ?",
                (namespace, subject_digest),
            ).fetchone() or (0, 0, 0, 0, GENESIS_HASH)
            if row[3] >= _MAX_SQLITE_INTEGER:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REPLAY_SEQUENCE_EXHAUSTED"
                )
            expected_sequence = row[3] + 1
            observation = connection.execute(
                "SELECT claim_sequence, observed_at_ms, head_json "
                "FROM replay_head_observations "
                "WHERE head_digest = ? AND namespace = ? AND subject_digest = ?",
                (claim.get("pre_claim_head_digest"), namespace, subject_digest),
            ).fetchone()
            observed_head = (
                _object(observation[2], "IMPERSONATION_REPLAY_HEAD_CORRUPT")
                if observation is not None
                else None
            )
            if (
                claim.get("claim_sequence") != expected_sequence
                or claim.get("prior_claim_receipt_digest") != row[4]
                or observation is None
                or observation[0] != row[3]
                or observation[1] != claim["claimed_at_ms"]
                or observed_head is None
                or not self._signer.verify(observed_head)
                or canonical_integrity_hash(observed_head)
                != claim["pre_claim_head_digest"]
                or any(
                    type(claim.get(field)) is not int or claim[field] < minimum
                    for field, minimum in (
                        ("registry_sequence", row[0]),
                        ("authority_sequence", row[1]),
                        ("revocation_sequence", row[2]),
                    )
                )
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_REPLAY_NONMONOTONIC_CLAIM"
                )
            receipt = self._signer.sign(deepcopy(claim))
            digest = canonical_integrity_hash(receipt)
            connection.execute(
                "INSERT INTO replay_claims VALUES(?, ?, ?, ?, ?, ?)",
                (
                    namespace,
                    replay_key,
                    subject_digest,
                    expected_sequence,
                    digest,
                    _json(receipt),
                ),
            )
            connection.execute(
                "INSERT INTO replay_heads VALUES(?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(namespace, subject_digest) DO UPDATE SET "
                "registry_sequence=excluded.registry_sequence, "
                "authority_sequence=excluded.authority_sequence, "
                "revocation_sequence=excluded.revocation_sequence, "
                "claim_sequence=excluded.claim_sequence, "
                "latest_receipt_digest=excluded.latest_receipt_digest",
                (
                    namespace,
                    subject_digest,
                    claim["registry_sequence"],
                    claim["authority_sequence"],
                    claim["revocation_sequence"],
                    expected_sequence,
                    digest,
                ),
            )
            return deepcopy(receipt)

        try:
            return self._mutate(operation)
        except sqlite3.IntegrityError as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REPLAY_DUPLICATE"
            ) from exc

    def is_claimed(
        self,
        *,
        namespace: str,
        replay_key: str,
        receipt_digest: str,
        subject_binding_digest: str,
        observed_at_ms: int,
        current_head_digest: str,
    ) -> dict[str, Any]:
        if (
            not _text(namespace)
            or not is_sha512(replay_key)
            or not is_sha512(receipt_digest)
            or not is_sha512(subject_binding_digest)
            or not _nonnegative_integer(observed_at_ms)
            or not is_sha512(current_head_digest)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_REPLAY_PERSISTENCE_INPUT_INVALID"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT claim_sequence, receipt_digest, receipt_json "
                "FROM replay_claims WHERE namespace = ? AND replay_key = ? "
                "AND subject_digest = ?",
                (namespace, replay_key, subject_binding_digest),
            ).fetchone()
            head = connection.execute(
                "SELECT registry_sequence, authority_sequence, revocation_sequence, "
                "claim_sequence, latest_receipt_digest FROM replay_heads "
                "WHERE namespace = ? AND subject_digest = ?",
                (namespace, subject_binding_digest),
            ).fetchone()
            observation = connection.execute(
                "SELECT claim_sequence FROM replay_head_observations "
                "WHERE head_digest = ? AND namespace = ? AND subject_digest = ?",
                (current_head_digest, namespace, subject_binding_digest),
            ).fetchone()
            claim_receipt = (
                _object(row[2], "IMPERSONATION_REPLAY_RECEIPT_CORRUPT")
                if row is not None
                else None
            )
            persisted = (
                row is not None
                and head is not None
                and claim_receipt is not None
                and row[1] == receipt_digest
                and canonical_integrity_hash(claim_receipt) == receipt_digest
                and self._signer.verify(claim_receipt)
                and observation == (head[3],)
                and head[4] == receipt_digest
            )
            payload = {
                "schema": REPLAY_PERSISTENCE_SCHEMA,
                "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                "context_id": self.context_id,
                "context_digest": self.context_digest,
                "namespace": namespace,
                "replay_key": replay_key,
                "claim_receipt_digest": receipt_digest,
                "subject_binding_digest": subject_binding_digest,
                "claim_sequence": row[0] if row is not None else -1,
                "current_head_digest": current_head_digest,
                "registry_sequence": head[0] if head is not None else -1,
                "authority_sequence": head[1] if head is not None else -1,
                "revocation_sequence": head[2] if head is not None else -1,
                "observed_at_ms": observed_at_ms,
                "persisted": persisted,
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            }
            receipt = self._signer.sign(payload)
            connection.execute(
                "INSERT OR IGNORE INTO replay_persistence_receipts VALUES(?, ?)",
                (canonical_integrity_hash(receipt), _json(receipt)),
            )
            return receipt

        return self._mutate(operation)


class AuthenticatedMonotonicClock(_AnchoredSQLiteStore):
    """Signed monotonic clock backed by an externally admitted time source."""

    store_kind = "AUTHENTICATED_MONOTONIC_CLOCK"

    def __init__(
        self,
        *,
        database_path: str | Path,
        anchor_path: str | Path,
        store_id: str,
        context_id: str,
        context_digest: str,
        clock_id: str,
        clock_version: str,
        clock_provider: SignatureProvider,
        trusted_time_source_admission_digest: str,
        maximum_forward_step_ms: int,
        time_source: Callable[[], int] | None = None,
        owner_pinned_signer_context_digest: str | None = None,
        allow_test_only: bool = False,
    ) -> None:
        if (
            not _text(clock_id)
            or not _text(clock_version)
            or not is_sha512(trusted_time_source_admission_digest)
            or not _nonnegative_integer(maximum_forward_step_ms)
            or maximum_forward_step_ms <= 0
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_TRUSTED_TIME_ADMISSION_INVALID"
            )
        self.clock_id = clock_id
        self.clock_version = clock_version
        self.maximum_forward_step_ms = maximum_forward_step_ms
        self._time_source = time_source or (lambda: time.time_ns() // 1_000_000)
        super().__init__(
            database_path=database_path,
            anchor_path=anchor_path,
            store_id=store_id,
            context_id=context_id,
            context_digest=context_digest,
            signer=clock_provider,
            owner_pinned_signer_context_digest=(owner_pinned_signer_context_digest),
            allow_test_only=allow_test_only,
            extra_identity={
                "clock_id": clock_id,
                "clock_version": clock_version,
                "trusted_time_source_admission_digest": (
                    trusted_time_source_admission_digest
                ),
                "maximum_forward_step_ms": maximum_forward_step_ms,
            },
        )

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS clock_records ("
            "clock_sequence INTEGER PRIMARY KEY, now_ms INTEGER NOT NULL, "
            "record_digest TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL)"
        )

    def _state_rows(self, connection: sqlite3.Connection) -> Any:
        return connection.execute(
            "SELECT * FROM clock_records ORDER BY clock_sequence"
        ).fetchall()

    def current_time_record(
        self,
        *,
        context_id: str,
        context_digest: str,
    ) -> dict[str, Any]:
        try:
            observed = self._time_source()
        except Exception as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_TRUSTED_TIME_SOURCE_UNAVAILABLE"
            ) from exc
        if (
            context_id != self.context_id
            or context_digest != self.context_digest
            or not _nonnegative_integer(observed)
        ):
            raise ImpersonationDurabilityError(
                "IMPERSONATION_TRUSTED_CLOCK_INPUT_INVALID"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT clock_sequence, now_ms, record_digest, record_json "
                "FROM clock_records "
                "ORDER BY clock_sequence DESC LIMIT 1"
            ).fetchone()
            sequence, previous_time, prior_digest, prior_json = (
                (0, -1, GENESIS_HASH, "") if row is None else row
            )
            if sequence >= _MAX_SQLITE_INTEGER:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_TRUSTED_CLOCK_SEQUENCE_EXHAUSTED"
                )
            if observed < previous_time:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_TRUSTED_CLOCK_ROLLBACK"
                )
            if (
                previous_time >= 0
                and observed - previous_time > self.maximum_forward_step_ms
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_TRUSTED_CLOCK_FORWARD_JUMP_INDETERMINATE"
                )
            if observed == previous_time:
                prior_record = _object(
                    prior_json,
                    "IMPERSONATION_TRUSTED_CLOCK_RECORD_CORRUPT",
                )
                if canonical_integrity_hash(
                    prior_record
                ) != prior_digest or not self._signer.verify(prior_record):
                    raise ImpersonationDurabilityError(
                        "IMPERSONATION_TRUSTED_CLOCK_RECORD_INVALID"
                    )
                return prior_record
            payload = {
                "schema": CLOCK_RECORD_SCHEMA,
                "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                "context_id": self.context_id,
                "context_digest": self.context_digest,
                "clock_id": self.clock_id,
                "clock_version": self.clock_version,
                "clock_sequence": sequence + 1,
                "prior_clock_record_digest": prior_digest,
                "now_ms": observed,
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            }
            record = self._signer.sign(payload)
            connection.execute(
                "INSERT INTO clock_records VALUES(?, ?, ?, ?)",
                (
                    sequence + 1,
                    observed,
                    canonical_integrity_hash(record),
                    _json(record),
                ),
            )
            return record

        return self._mutate(operation)


class SQLiteImpersonationClockHead(_AnchoredSQLiteStore):
    """Durable authenticated clock-head transition store."""

    store_kind = "IMPERSONATION_CLOCK_HEAD"

    def __init__(
        self,
        *,
        database_path: str | Path,
        anchor_path: str | Path,
        store_id: str,
        context_id: str,
        context_digest: str,
        head_id: str,
        head_version: str,
        clock_head_provider: SignatureProvider,
        owner_pinned_signer_context_digest: str | None = None,
        allow_test_only: bool = False,
    ) -> None:
        if not _text(head_id) or not _text(head_version):
            raise ImpersonationDurabilityError("IMPERSONATION_CLOCK_HEAD_ID_INVALID")
        self.head_id = head_id
        self.head_version = head_version
        super().__init__(
            database_path=database_path,
            anchor_path=anchor_path,
            store_id=store_id,
            context_id=context_id,
            context_digest=context_digest,
            signer=clock_head_provider,
            owner_pinned_signer_context_digest=(owner_pinned_signer_context_digest),
            allow_test_only=allow_test_only,
            extra_identity={"head_id": head_id, "head_version": head_version},
        )

    def _create_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS clock_head_state ("
            "singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "head_sequence INTEGER NOT NULL, clock_sequence INTEGER NOT NULL, "
            "clock_record_digest TEXT NOT NULL, prior_clock_record_digest TEXT NOT NULL, "
            "latest_transition_digest TEXT NOT NULL, observed_at_ms INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT OR IGNORE INTO clock_head_state VALUES(1,0,0,?,?,?,0)",
            (GENESIS_HASH, GENESIS_HASH, GENESIS_HASH),
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS clock_transitions ("
            "head_sequence INTEGER PRIMARY KEY, receipt_digest TEXT NOT NULL UNIQUE, "
            "receipt_json TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS clock_head_observations ("
            "head_digest TEXT PRIMARY KEY, head_sequence INTEGER NOT NULL, "
            "head_json TEXT NOT NULL)"
        )

    def _state_rows(self, connection: sqlite3.Connection) -> Any:
        return {
            "state": connection.execute("SELECT * FROM clock_head_state").fetchall(),
            "transitions": connection.execute(
                "SELECT * FROM clock_transitions ORDER BY head_sequence"
            ).fetchall(),
            "observations": connection.execute(
                "SELECT * FROM clock_head_observations ORDER BY head_digest"
            ).fetchall(),
        }

    def current_head(
        self,
        *,
        context_id: str,
        context_digest: str,
    ) -> dict[str, Any]:
        if context_id != self.context_id or context_digest != self.context_digest:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_CLOCK_HEAD_CONTEXT_MISMATCH"
            )

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT head_sequence, clock_sequence, clock_record_digest, "
                "prior_clock_record_digest, latest_transition_digest, observed_at_ms "
                "FROM clock_head_state WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_CLOCK_HEAD_STATE_MISSING"
                )
            payload = {
                "schema": CLOCK_HEAD_SCHEMA,
                "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                "context_id": self.context_id,
                "context_digest": self.context_digest,
                "head_id": self.head_id,
                "head_version": self.head_version,
                "head_sequence": row[0],
                "clock_sequence": row[1],
                "clock_record_digest": row[2],
                "prior_clock_record_digest": row[3],
                "latest_transition_receipt_digest": row[4],
                "observed_at_ms": row[5],
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            }
            record = self._signer.sign(payload)
            digest = canonical_integrity_hash(record)
            connection.execute(
                "INSERT OR IGNORE INTO clock_head_observations VALUES(?, ?, ?)",
                (digest, row[0], _json(record)),
            )
            return record

        return self._mutate(operation)

    def advance_once(self, *, transition: dict[str, Any]) -> dict[str, Any]:
        if (
            type(transition) is not dict
            or set(transition) != _CLOCK_TRANSITION_FIELDS
            or not _bounded_object(transition)
        ):
            raise ImpersonationDurabilityError("IMPERSONATION_CLOCK_TRANSITION_INVALID")

        def operation(connection: sqlite3.Connection) -> dict[str, Any]:
            row = connection.execute(
                "SELECT head_sequence, clock_sequence, clock_record_digest, "
                "observed_at_ms FROM clock_head_state WHERE singleton=1"
            ).fetchone()
            if row is None:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_CLOCK_HEAD_STATE_MISSING"
                )
            if row[0] >= _MAX_SQLITE_INTEGER or row[1] >= _MAX_SQLITE_INTEGER:
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_CLOCK_TRANSITION_SEQUENCE_EXHAUSTED"
                )
            observed = connection.execute(
                "SELECT head_sequence FROM clock_head_observations "
                "WHERE head_digest = ?",
                (transition.get("prior_head_digest"),),
            ).fetchone()
            exact = {
                "schema": CLOCK_HEAD_TRANSITION_SCHEMA,
                "contract_id": IMPERSONATION_PROTECTION_CONTRACT_ID,
                "context_id": self.context_id,
                "context_digest": self.context_digest,
                "head_id": self.head_id,
                "head_version": self.head_version,
                "head_sequence": row[0] + 1,
                "clock_sequence": row[1] + 1,
                "prior_clock_record_digest": row[2],
                "result": "ADVANCED",
                "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
            }
            if (
                observed != (row[0],)
                or any(transition.get(key) != value for key, value in exact.items())
                or not is_sha512(transition.get("prior_head_digest"))
                or not is_sha512(transition.get("clock_record_digest"))
                or not _nonnegative_integer(transition.get("observed_at_ms"))
                or transition["observed_at_ms"] < row[3]
            ):
                raise ImpersonationDurabilityError(
                    "IMPERSONATION_CLOCK_TRANSITION_NONMONOTONIC"
                )
            receipt = self._signer.sign(deepcopy(transition))
            digest = canonical_integrity_hash(receipt)
            connection.execute(
                "INSERT INTO clock_transitions VALUES(?, ?, ?)",
                (transition["head_sequence"], digest, _json(receipt)),
            )
            connection.execute(
                "UPDATE clock_head_state SET head_sequence=?, clock_sequence=?, "
                "clock_record_digest=?, prior_clock_record_digest=?, "
                "latest_transition_digest=?, observed_at_ms=? WHERE singleton=1",
                (
                    transition["head_sequence"],
                    transition["clock_sequence"],
                    transition["clock_record_digest"],
                    transition["prior_clock_record_digest"],
                    digest,
                    transition["observed_at_ms"],
                ),
            )
            return receipt

        try:
            return self._mutate(operation)
        except sqlite3.IntegrityError as exc:
            raise ImpersonationDurabilityError(
                "IMPERSONATION_CLOCK_TRANSITION_DUPLICATE"
            ) from exc


__all__ = [
    "ANCHOR_SCHEMA",
    "AuthenticatedMonotonicClock",
    "ImpersonationDurabilityError",
    "SQLiteImpersonationClockHead",
    "SQLiteImpersonationReplayGuard",
    "SQLiteOwnerPinnedTrustRegistry",
]
