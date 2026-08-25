"""Detached verification of one explicit P→T→D→E Git-object chain."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from .canonical import (
    campaign_id,
    canonical_json_bytes,
    canonical_sha512,
    exact_fields,
    identifier,
    nonnegative_int,
    require_sha512,
    strict_json_document,
)
from .constants import (
    ASSURANCE_LIMITS,
    D_DESCRIPTOR_PATH,
    EVIDENCE_ROOT,
    E_MANIFEST_NAME,
    NO_AUTHORITY,
    POLICY_PATH,
    RESULT_SCHEMA_ID,
    SUCCESS_CLAIM_TEXT,
    SUCCESS_RESULT,
    T_PROFILE_PATH,
)
from .errors import PTDEVerificationError, reject
from .git_objects import (
    CommitObject,
    GitObjectDatabase,
    TreeBlob,
    exact_added_blob_delta,
    require_direct_child,
)
from .policy import policy_document_bytes, validate_policy
from .schemas import validate_d_descriptor, validate_e_manifest, validate_t_profile
from .trust import (
    AcceptedAttemptHistory,
    reject_attempt_reuse,
    validate_accepted_attempt_history,
)


_RESULT_FIELDS = {
    "schema_id",
    "result",
    "claim_text",
    "object_format",
    "object_bindings",
    "policy_blob_oid",
    "policy_sha512",
    "t_profile_blob_oid",
    "t_profile_sha512",
    "d_descriptor_blob_oid",
    "d_descriptor_sha512",
    "e_manifest_blob_oid",
    "e_manifest_sha512",
    "campaign_id",
    "lane_order",
    "lanes_sha512",
    "evidence_inventory_sha512",
    "no_authority",
    "assurance_limits",
    "admission_state",
    "git_executable_sha512",
    "accepted_attempt_history_id",
    "accepted_attempt_history_sequence",
    "accepted_attempt_history_sha512",
    "result_sha512",
}
_OBJECT_BINDING_FIELDS = {
    "commit_oid",
    "commit_raw_sha512",
    "tree_oid",
    "tree_raw_sha512",
}


def _commit_binding(
    database: GitObjectDatabase, commit: CommitObject
) -> dict[str, Any]:
    tree = database.read_object(commit.tree_oid, expected_type="tree")
    return {
        "commit_oid": commit.oid,
        "commit_raw_sha512": commit.raw_sha512,
        "tree_oid": commit.tree_oid,
        "tree_raw_sha512": tree.raw_sha512,
    }


def _verify_policy_blob(
    database: GitObjectDatabase,
    p_tree: dict[str, TreeBlob],
) -> tuple[TreeBlob, dict[str, Any]]:
    if POLICY_PATH not in p_tree:
        raise reject("P_POLICY_BLOB_MISSING")
    record = p_tree[POLICY_PATH]
    blob = database.read_blob(record.blob_oid)
    if blob.content != policy_document_bytes():
        raise reject("P_POLICY_BLOB_NOT_FIXED_POLICY")
    policy = strict_json_document(blob.content, code="P_POLICY")
    validate_policy(policy)
    return record, policy


def _verify_e_delta(
    d_tree: dict[str, TreeBlob],
    e_tree: dict[str, TreeBlob],
    *,
    campaign: str,
) -> tuple[TreeBlob, dict[str, TreeBlob]]:
    parent_paths = set(d_tree)
    child_paths = set(e_tree)
    if parent_paths - child_paths:
        raise reject("E_DELETION_REJECTED")
    for path in parent_paths:
        if d_tree[path] != e_tree[path]:
            raise reject("E_MODIFICATION_OR_MODE_CHANGE_REJECTED")
    campaign_prefix = f"{EVIDENCE_ROOT}/{campaign}/"
    preexisting = [path for path in parent_paths if path.startswith(campaign_prefix)]
    if preexisting:
        raise reject("E_CAMPAIGN_SUBTREE_PREEXISTED")
    additions = {
        path: e_tree[path]
        for path in sorted(child_paths - parent_paths)
    }
    if not additions or any(not path.startswith(campaign_prefix) for path in additions):
        raise reject("E_ADDITION_OUTSIDE_CAMPAIGN_SUBTREE")
    manifest_path = f"{campaign_prefix}{E_MANIFEST_NAME}"
    if manifest_path not in additions:
        raise reject("E_MANIFEST_BLOB_MISSING")
    evidence = {path: record for path, record in additions.items() if path != manifest_path}
    if not evidence:
        raise reject("E_EVIDENCE_BLOBS_MISSING")
    return additions[manifest_path], evidence


def _build_result(
    *,
    database: GitObjectDatabase,
    commits: tuple[CommitObject, CommitObject, CommitObject, CommitObject],
    policy_blob: TreeBlob,
    t_profile_blob: TreeBlob,
    d_descriptor_blob: TreeBlob,
    e_manifest_blob: TreeBlob,
    d_descriptor: dict[str, Any],
    e_manifest: dict[str, Any],
    accepted_attempt_history: AcceptedAttemptHistory,
    expected_attempt_history_sha512: str,
    expected_git_executable_sha512: str,
) -> dict[str, Any]:
    p_commit, t_commit, d_commit, e_commit = commits
    unsigned = {
        "schema_id": RESULT_SCHEMA_ID,
        "result": SUCCESS_RESULT,
        "claim_text": SUCCESS_CLAIM_TEXT,
        "object_format": database.object_format,
        "object_bindings": {
            "P": _commit_binding(database, p_commit),
            "T": _commit_binding(database, t_commit),
            "D": _commit_binding(database, d_commit),
            "E": _commit_binding(database, e_commit),
        },
        "policy_blob_oid": policy_blob.blob_oid,
        "policy_sha512": policy_blob.blob_sha512,
        "t_profile_blob_oid": t_profile_blob.blob_oid,
        "t_profile_sha512": t_profile_blob.blob_sha512,
        "d_descriptor_blob_oid": d_descriptor_blob.blob_oid,
        "d_descriptor_sha512": d_descriptor_blob.blob_sha512,
        "e_manifest_blob_oid": e_manifest_blob.blob_oid,
        "e_manifest_sha512": e_manifest_blob.blob_sha512,
        "campaign_id": d_descriptor["campaign_id"],
        "lane_order": e_manifest["approved_lane_order"],
        "lanes_sha512": d_descriptor["lanes_sha512"],
        "evidence_inventory_sha512": e_manifest["evidence_inventory_sha512"],
        "no_authority": dict(NO_AUTHORITY),
        "assurance_limits": deepcopy(ASSURANCE_LIMITS),
        "admission_state": "NOT_ADMITTED",
        "git_executable_sha512": expected_git_executable_sha512,
        "accepted_attempt_history_id": accepted_attempt_history.history_id,
        "accepted_attempt_history_sequence": accepted_attempt_history.sequence,
        "accepted_attempt_history_sha512": expected_attempt_history_sha512,
    }
    return {**unsigned, "result_sha512": canonical_sha512(unsigned)}


def _verify_ptde_chain_impl(
    object_database: str | Path,
    *,
    p_oid: str,
    t_oid: str,
    d_oid: str,
    e_oid: str,
    expected_p_oid: str,
    expected_git_executable_sha512: str,
    accepted_attempt_history: AcceptedAttemptHistory,
    expected_attempt_history_sha512: str,
    git_executable: str = "git",
) -> dict[str, Any]:
    """Verify explicit immutable Git objects without consulting a checkout or ref.

    ``expected_p_oid`` is the out-of-band trust input. It is never derived from
    P/T/D/E, HEAD, a branch, a tag, a package, or another repository ref.
    """

    database = GitObjectDatabase(
        object_database,
        git_executable=git_executable,
        expected_git_executable_sha512=expected_git_executable_sha512,
    )
    history = validate_accepted_attempt_history(
        accepted_attempt_history,
        oid_hex_length=database.oid_hex_length,
        expected_sha512=expected_attempt_history_sha512,
    )
    supplied = tuple(
        database.require_oid(value, code=f"{stage}_OID_INVALID")
        for stage, value in zip(("P", "T", "D", "E"), (p_oid, t_oid, d_oid, e_oid))
    )
    pinned_p = database.require_oid(expected_p_oid, code="EXPECTED_P_OID_INVALID")
    if supplied[0] != pinned_p:
        raise reject("P_NOT_OUT_OF_BAND_PINNED_OBJECT")
    if len(set(supplied)) != 4:
        raise reject("PTDE_COMMIT_OIDS_NOT_DISTINCT")

    p_commit, t_commit, d_commit, e_commit = (
        database.read_commit(oid) for oid in supplied
    )
    if len(p_commit.parent_oids) > 1:
        raise reject("P_MERGE_COMMIT_REJECTED")
    require_direct_child(t_commit, p_commit.oid, stage="T")
    require_direct_child(d_commit, t_commit.oid, stage="D")
    require_direct_child(e_commit, d_commit.oid, stage="E")

    p_tree = database.flatten_tree(p_commit.tree_oid)
    t_tree = database.flatten_tree(t_commit.tree_oid)
    d_tree = database.flatten_tree(d_commit.tree_oid)
    e_tree = database.flatten_tree(e_commit.tree_oid)

    policy_blob, _ = _verify_policy_blob(database, p_tree)

    t_profile_blob = exact_added_blob_delta(
        p_tree,
        t_tree,
        added_path=T_PROFILE_PATH,
        stage="T",
    )
    t_profile_object = database.read_blob(t_profile_blob.blob_oid)
    t_profile = strict_json_document(t_profile_object.content, code="T_PROFILE")
    validate_t_profile(
        t_profile,
        database=database,
        p_commit=p_commit,
        p_tree=p_tree,
        policy_blob=policy_blob,
    )

    d_descriptor_blob = exact_added_blob_delta(
        t_tree,
        d_tree,
        added_path=D_DESCRIPTOR_PATH,
        stage="D",
    )
    d_descriptor_object = database.read_blob(d_descriptor_blob.blob_oid)
    d_descriptor = strict_json_document(
        d_descriptor_object.content, code="D_DESCRIPTOR"
    )
    validate_d_descriptor(
        d_descriptor,
        database=database,
        p_commit=p_commit,
        t_commit=t_commit,
        d_tree=d_tree,
        t_profile=t_profile,
        t_profile_blob=t_profile_blob,
    )

    e_manifest_blob, added_evidence = _verify_e_delta(
        d_tree,
        e_tree,
        campaign=d_descriptor["campaign_id"],
    )
    e_manifest_object = database.read_blob(e_manifest_blob.blob_oid)
    e_manifest = strict_json_document(e_manifest_object.content, code="E_MANIFEST")
    validate_e_manifest(
        e_manifest,
        database=database,
        p_commit=p_commit,
        t_commit=t_commit,
        d_commit=d_commit,
        d_descriptor=d_descriptor,
        d_descriptor_blob=d_descriptor_blob,
        added_evidence=added_evidence,
    )
    reject_attempt_reuse(
        history,
        campaign=d_descriptor["campaign_id"],
        lane_results=e_manifest["lane_results"],
    )

    return _build_result(
        database=database,
        commits=(p_commit, t_commit, d_commit, e_commit),
        policy_blob=policy_blob,
        t_profile_blob=t_profile_blob,
        d_descriptor_blob=d_descriptor_blob,
        e_manifest_blob=e_manifest_blob,
        d_descriptor=d_descriptor,
        e_manifest=e_manifest,
        accepted_attempt_history=history,
        expected_attempt_history_sha512=expected_attempt_history_sha512,
        expected_git_executable_sha512=expected_git_executable_sha512,
    )


def verify_ptde_chain(
    object_database: str | Path,
    *,
    p_oid: str,
    t_oid: str,
    d_oid: str,
    e_oid: str,
    expected_p_oid: str,
    expected_git_executable_sha512: str,
    accepted_attempt_history: AcceptedAttemptHistory,
    expected_attempt_history_sha512: str,
    git_executable: str = "git",
) -> dict[str, Any]:
    try:
        return _verify_ptde_chain_impl(
            object_database,
            p_oid=p_oid,
            t_oid=t_oid,
            d_oid=d_oid,
            e_oid=e_oid,
            expected_p_oid=expected_p_oid,
            expected_git_executable_sha512=expected_git_executable_sha512,
            accepted_attempt_history=accepted_attempt_history,
            expected_attempt_history_sha512=expected_attempt_history_sha512,
            git_executable=git_executable,
        )
    except PTDEVerificationError:
        raise
    except (Exception, MemoryError) as exc:
        raise reject(f"PTDE_INTERNAL_FAIL_CLOSED:{type(exc).__name__}") from exc


def _validate_verification_result_impl(value: Any) -> dict[str, Any]:
    result = exact_fields(value, _RESULT_FIELDS, code="PTDE_RESULT")
    if (
        result["schema_id"] != RESULT_SCHEMA_ID
        or result["result"] != SUCCESS_RESULT
        or result["claim_text"] != SUCCESS_CLAIM_TEXT
        or result["object_format"] not in {"sha1", "sha256"}
        or result["no_authority"] != NO_AUTHORITY
        or result["assurance_limits"] != ASSURANCE_LIMITS
        or result["admission_state"] != "NOT_ADMITTED"
    ):
        raise reject("PTDE_RESULT_CONTRACT_INVALID")
    bindings = exact_fields(
        result["object_bindings"], {"P", "T", "D", "E"}, code="PTDE_RESULT_BINDINGS"
    )
    oid_length = 40 if result["object_format"] == "sha1" else 64
    observed_commit_oids: set[str] = set()
    for binding in bindings.values():
        exact_fields(binding, _OBJECT_BINDING_FIELDS, code="PTDE_RESULT_OBJECT_BINDING")
        for field in ("commit_oid", "tree_oid"):
            oid = binding[field]
            if (
                type(oid) is not str
                or len(oid) != oid_length
                or any(char not in "0123456789abcdef" for char in oid)
            ):
                raise reject("PTDE_RESULT_OBJECT_OID_INVALID")
        observed_commit_oids.add(binding["commit_oid"])
        require_sha512(
            binding["commit_raw_sha512"], "PTDE_RESULT_COMMIT_RAW_DIGEST_INVALID"
        )
        require_sha512(
            binding["tree_raw_sha512"], "PTDE_RESULT_TREE_RAW_DIGEST_INVALID"
        )
    if len(observed_commit_oids) != 4:
        raise reject("PTDE_RESULT_COMMIT_OIDS_NOT_DISTINCT")
    for field in (
        "policy_sha512",
        "t_profile_sha512",
        "d_descriptor_sha512",
        "e_manifest_sha512",
        "lanes_sha512",
        "evidence_inventory_sha512",
        "result_sha512",
        "git_executable_sha512",
        "accepted_attempt_history_sha512",
    ):
        require_sha512(result[field], f"PTDE_RESULT_{field.upper()}_INVALID")
    identifier(
        result["accepted_attempt_history_id"],
        code="PTDE_RESULT_ATTEMPT_HISTORY_ID_INVALID",
    )
    nonnegative_int(
        result["accepted_attempt_history_sequence"],
        code="PTDE_RESULT_ATTEMPT_HISTORY_SEQUENCE_INVALID",
    )
    for field in (
        "policy_blob_oid",
        "t_profile_blob_oid",
        "d_descriptor_blob_oid",
        "e_manifest_blob_oid",
    ):
        oid = result[field]
        if (
            type(oid) is not str
            or len(oid) != oid_length
            or any(char not in "0123456789abcdef" for char in oid)
        ):
            raise reject("PTDE_RESULT_BLOB_OID_INVALID")
    campaign_id(result["campaign_id"])
    lane_order = result["lane_order"]
    resource_maxima = ASSURANCE_LIMITS.get("resource_maxima")
    maximum_lanes = (
        resource_maxima.get("lanes") if type(resource_maxima) is dict else None
    )
    if (
        type(lane_order) is not list
        or not lane_order
        or type(maximum_lanes) is not int
        or len(lane_order) > maximum_lanes
        or any(type(lane_id) is not str for lane_id in lane_order)
        or len(lane_order) != len(set(lane_order))
    ):
        raise reject("PTDE_RESULT_LANE_ORDER_INVALID")
    for lane_id in lane_order:
        identifier(lane_id, code="PTDE_RESULT_LANE_ID_INVALID")
    unsigned = {key: result[key] for key in result if key != "result_sha512"}
    if result["result_sha512"] != canonical_sha512(unsigned):
        raise reject("PTDE_RESULT_DIGEST_INVALID")
    return result


def validate_verification_result(value: Any) -> dict[str, Any]:
    try:
        return _validate_verification_result_impl(value)
    except PTDEVerificationError:
        raise
    except (Exception, MemoryError) as exc:
        raise reject(f"PTDE_RESULT_FAIL_CLOSED:{type(exc).__name__}") from exc


def verify_ptde_result(
    value: Any,
    object_database: str | Path,
    *,
    p_oid: str,
    t_oid: str,
    d_oid: str,
    e_oid: str,
    expected_p_oid: str,
    expected_git_executable_sha512: str,
    accepted_attempt_history: AcceptedAttemptHistory,
    expected_attempt_history_sha512: str,
    git_executable: str = "git",
) -> dict[str, Any]:
    observed = verify_ptde_chain(
        object_database,
        p_oid=p_oid,
        t_oid=t_oid,
        d_oid=d_oid,
        e_oid=e_oid,
        expected_p_oid=expected_p_oid,
        expected_git_executable_sha512=expected_git_executable_sha512,
        accepted_attempt_history=accepted_attempt_history,
        expected_attempt_history_sha512=expected_attempt_history_sha512,
        git_executable=git_executable,
    )
    validate_verification_result(value)
    if canonical_json_bytes(value) != canonical_json_bytes(observed):
        raise reject("PTDE_RESULT_DOES_NOT_MATCH_OBJECTS")
    return observed


__all__ = [
    "PTDEVerificationError",
    "validate_verification_result",
    "verify_ptde_chain",
    "verify_ptde_result",
]
