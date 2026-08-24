"""Explicit immutable P-object binding; this module never consults a checkout."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbp_ptde.canonical import canonical_sha512, exact_fields, require_sha512
from sbp_ptde.constants import NO_AUTHORITY
from sbp_ptde.git_objects import CommitObject, GitObjectDatabase, TreeBlob
from sbp_ptde.trust import AcceptedAttemptHistory, validate_accepted_attempt_history

from .constants import MAX_SOURCE_BLOBS, MAX_SOURCE_TOTAL_BYTES, P_BINDING_SCHEMA_ID, UNSIGNED_NOT_ADMITTED


@dataclass(frozen=True, slots=True)
class PObjectBinding:
    """Verified P commit/tree plus the out-of-band trust inputs used to read it."""

    database: GitObjectDatabase
    commit: CommitObject
    tree: dict[str, TreeBlob]
    accepted_attempt_history: AcceptedAttemptHistory
    expected_git_executable_sha512: str
    expected_attempt_history_sha512: str

    def document(self) -> dict[str, Any]:
        entries = [self.tree[path].record() for path in sorted(self.tree)]
        return {
            "schema_id": P_BINDING_SCHEMA_ID,
            "p_commit_oid": self.commit.oid,
            "p_tree_oid": self.commit.tree_oid,
            "p_commit_raw_sha512": self.commit.raw_sha512,
            "p_tree_raw_sha512": self.database.read_object(self.commit.tree_oid, expected_type="tree").raw_sha512,
            "p_inventory": entries,
            "p_inventory_sha512": canonical_sha512(entries),
            "expected_git_executable_sha512": self.expected_git_executable_sha512,
            "accepted_attempt_history_id": self.accepted_attempt_history.history_id,
            "accepted_attempt_history_sequence": self.accepted_attempt_history.sequence,
            "expected_attempt_history_sha512": self.expected_attempt_history_sha512,
            "no_authority": dict(NO_AUTHORITY),
            "admission_state": UNSIGNED_NOT_ADMITTED,
        }


def bind_p_object(
    object_database: str | Path,
    *,
    p_oid: str,
    expected_p_oid: str,
    git_executable: str,
    expected_git_executable_sha512: str,
    accepted_attempt_history: AcceptedAttemptHistory,
    expected_attempt_history_sha512: str,
) -> PObjectBinding:
    """Read only the supplied, out-of-band pinned P object from a bare Git database."""

    database = GitObjectDatabase(
        object_database,
        git_executable=git_executable,
        expected_git_executable_sha512=require_sha512(
            expected_git_executable_sha512, "SUPPLY_CHAIN_EXPECTED_GIT_EXECUTABLE_INVALID"
        ),
    )
    supplied = database.require_oid(p_oid, code="SUPPLY_CHAIN_P_OID_INVALID")
    pinned = database.require_oid(expected_p_oid, code="SUPPLY_CHAIN_EXPECTED_P_OID_INVALID")
    if supplied != pinned:
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_NOT_OUT_OF_BAND_PINNED")
    commit = database.read_commit(supplied)
    if len(commit.parent_oids) > 1:
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_MERGE_COMMIT_REJECTED")
    tree = database.flatten_tree(commit.tree_oid)
    if len(tree) > MAX_SOURCE_BLOBS or sum(item.byte_count for item in tree.values()) > MAX_SOURCE_TOTAL_BYTES:
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_INVENTORY_LIMIT_EXCEEDED")
    history = validate_accepted_attempt_history(
        accepted_attempt_history,
        oid_hex_length=database.oid_hex_length,
        expected_sha512=require_sha512(
            expected_attempt_history_sha512, "SUPPLY_CHAIN_EXPECTED_HISTORY_INVALID"
        ),
    )
    return PObjectBinding(
        database=database,
        commit=commit,
        tree=tree,
        accepted_attempt_history=history,
        expected_git_executable_sha512=expected_git_executable_sha512,
        expected_attempt_history_sha512=expected_attempt_history_sha512,
    )


def p_blob_content(binding: PObjectBinding, path: str) -> bytes:
    """Return bytes only when the path is an exact P-tree blob."""

    from sbp_ptde.canonical import canonical_path
    from sbp_ptde.errors import reject

    canonical = canonical_path(path, code="SUPPLY_CHAIN_P_PATH_INVALID")
    record = binding.tree.get(canonical)
    if record is None:
        raise reject("SUPPLY_CHAIN_P_BLOB_NOT_IN_INVENTORY")
    blob = binding.database.read_blob(record.blob_oid)
    if len(blob.content) != record.byte_count:
        raise reject("SUPPLY_CHAIN_P_BLOB_SIZE_CHANGED")
    return blob.content


def validate_p_binding_document(value: Any) -> dict[str, Any]:
    fields = {
        "schema_id", "p_commit_oid", "p_tree_oid", "p_commit_raw_sha512", "p_tree_raw_sha512",
        "p_inventory", "p_inventory_sha512", "expected_git_executable_sha512",
        "accepted_attempt_history_id", "accepted_attempt_history_sequence", "expected_attempt_history_sha512",
        "no_authority", "admission_state",
    }
    document = exact_fields(value, fields, code="SUPPLY_CHAIN_P_BINDING")
    if document["schema_id"] != P_BINDING_SCHEMA_ID or document["no_authority"] != NO_AUTHORITY:
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_BINDING_CONTRACT_INVALID")
    if document["admission_state"] != UNSIGNED_NOT_ADMITTED:
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_BINDING_ADMISSION_INVALID")
    for field in (
        "p_commit_raw_sha512", "p_tree_raw_sha512", "p_inventory_sha512",
        "expected_git_executable_sha512", "expected_attempt_history_sha512",
    ):
        require_sha512(document[field], f"SUPPLY_CHAIN_{field.upper()}_INVALID")
    if document["p_inventory_sha512"] != canonical_sha512(document["p_inventory"]):
        from sbp_ptde.errors import reject

        raise reject("SUPPLY_CHAIN_P_INVENTORY_DIGEST_INVALID")
    return document
