"""Exact T, D, and E document schemas and content bindings."""

from __future__ import annotations

import ast
import unicodedata
from typing import Any

from .canonical import (
    campaign_id,
    canonical_path,
    canonical_sha512,
    environment_name,
    exact_fields,
    identifier,
    nonnegative_int,
    positive_int,
    require_sha512,
    sha512_hex,
    strict_json_document,
)
from .constants import (
    CALLABLE_ALLOWED_SET,
    D_DESCRIPTOR_PATH,
    D_SCHEMA_ID,
    E_SCHEMA_ID,
    INVENTORY_CLASSES,
    MAX_ARGUMENT_UTF8_BYTES,
    MAX_ARGV_ITEMS,
    MAX_ARTIFACT_FILE_COUNT,
    MAX_ARTIFACT_TOTAL_BYTE_COUNT,
    MAX_ENVIRONMENT_NAMES,
    MAX_EVIDENCE_ENTRIES,
    MAX_INVENTORY_ENTRIES,
    MAX_LANE_TIMEOUT_SECONDS,
    MAX_LANES,
    MAX_STREAM_BYTE_COUNT,
    MAX_TRANSCRIPT_BYTE_COUNT,
    NO_AUTHORITY,
    POLICY_PATH,
    T_PROFILE_PATH,
    T_SCHEMA_ID,
    TIMEOUT_STATUS,
    TRANSCRIPT_SCHEMA_ID,
    assurance_limits_document,
)
from .errors import PTDEVerificationError, reject
from .git_objects import CommitObject, GitObjectDatabase, TreeBlob

_INVENTORY_ENTRY_FIELDS = frozenset({
    "path",
    "mode",
    "blob_oid",
    "blob_sha512",
    "blob_raw_sha512",
    "byte_count",
})
_INVENTORY_FIELDS = frozenset({"entries", "inventory_sha512"})
_T_FIELDS = frozenset({
    "schema_id",
    "policy_blob_oid",
    "policy_sha512",
    "policy_blob_raw_sha512",
    "p_commit_oid",
    "p_tree_oid",
    "p_commit_raw_sha512",
    "p_tree_raw_sha512",
    "inventories",
    "p_inventory_sha512",
    "test_profile_id",
    "lanes",
    "lanes_sha512",
    "no_authority",
    "runtime_attachment",
})
_LANE_FIELDS = frozenset({
    "lane_id",
    "order",
    "executable_id",
    "argv",
    "cwd_rule",
    "environment_name_allowlist",
    "environment_name_allowlist_sha512",
    "timeout_seconds",
    "expected_exit_codes",
    "stdout_contract",
    "stderr_contract",
    "produced_artifact_contract",
})
_STREAM_CONTRACT_FIELDS = frozenset(
    {"capture", "relative_path", "maximum_byte_count"}
)
_ARTIFACT_CONTRACT_FIELDS = frozenset({
    "required_relative_paths",
    "optional_relative_paths",
    "maximum_file_count",
    "maximum_total_byte_count",
})
_D_FIELDS = frozenset({
    "schema_id",
    "campaign_id",
    "p_commit_oid",
    "p_tree_oid",
    "p_commit_raw_sha512",
    "p_tree_raw_sha512",
    "t_commit_oid",
    "t_tree_oid",
    "t_commit_raw_sha512",
    "t_tree_raw_sha512",
    "t_profile_path",
    "t_profile_blob_oid",
    "t_profile_sha512",
    "t_profile_blob_raw_sha512",
    "policy_sha512",
    "p_inventory_sha512",
    "p_contract_inventory_sha512",
    "p_architecture_inventory_sha512",
    "p_configuration_inventory_sha512",
    "os_fingerprint_sha512",
    "build_fingerprint_sha512",
    "architecture_fingerprint_sha512",
    "runtime_fingerprint_sha512",
    "toolchain_fingerprint_sha512",
    "lanes",
    "lanes_sha512",
    "single_pipeline_callables",
    "no_authority",
    "assurance_limits",
})
_CALLABLE_FIELDS = frozenset({
    "qualified_name",
    "source_path",
    "source_blob_oid",
    "source_blob_sha512",
    "function_ast_sha512",
})
_E_FIELDS = frozenset({
    "schema_id",
    "campaign_id",
    "p_commit_oid",
    "p_tree_oid",
    "t_commit_oid",
    "t_tree_oid",
    "d_commit_oid",
    "d_tree_oid",
    "d_descriptor_path",
    "d_descriptor_blob_oid",
    "d_descriptor_sha512",
    "d_descriptor_blob_raw_sha512",
    "policy_sha512",
    "t_profile_sha512",
    "p_inventory_sha512",
    "lanes_sha512",
    "approved_lane_order",
    "lane_results",
    "evidence_inventory",
    "evidence_inventory_sha512",
    "limitations",
    "no_authority",
})
_LANE_RESULT_FIELDS = frozenset({
    "lane_id",
    "attempt_id",
    "status",
    "argv",
    "d_commit_oid",
    "d_descriptor_sha512",
    "exit_status",
    "started_at_unix_ms",
    "finished_at_unix_ms",
    "wall_clock_milliseconds",
    "timeout_seconds",
    "timed_out",
    "timeout_status",
    "cleanup_completed",
    "process_tree_terminated",
    "stdout_path",
    "stdout_byte_count",
    "stdout_sha512",
    "stderr_path",
    "stderr_byte_count",
    "stderr_sha512",
    "transcript_path",
    "transcript_byte_count",
    "transcript_sha512",
    "error",
    "produced_artifacts",
    "source_mutation_observed",
    "ledger_mutation_observed",
    "authority_mutation_observed",
})
_TRANSCRIPT_FIELDS = frozenset({
    "schema_id",
    "campaign_id",
    "lane_id",
    "attempt_id",
    "lane_contract_sha512",
    "d_commit_oid",
    "d_descriptor_sha512",
    "command_executed",
    "setup_completed",
    "status",
    "exit_status",
    "started_at_unix_ms",
    "finished_at_unix_ms",
    "wall_clock_milliseconds",
    "timeout_seconds",
    "timed_out",
    "timeout_status",
    "cleanup_completed",
    "process_tree_terminated",
    "stdout_path",
    "stdout_byte_count",
    "stdout_sha512",
    "stdout_full_bytes",
    "stderr_path",
    "stderr_byte_count",
    "stderr_sha512",
    "stderr_full_bytes",
    "output_truncated",
    "error",
    "produced_artifacts",
    "source_mutation_observed",
    "ledger_mutation_observed",
    "authority_mutation_observed",
    "no_authority",
})


def _text(value: Any, *, code: str) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or unicodedata.normalize("NFC", value) != value
    ):
        raise reject(code)
    return value


def _bounded_utf8(value: Any, *, code: str, maximum: int) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise reject(code)
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise reject(code) from exc
    if len(encoded) > maximum or unicodedata.normalize("NFC", value) != value:
        raise reject(code)
    return value


def _sorted_unique_paths(
    value: Any, *, code: str, maximum: int = MAX_ARTIFACT_FILE_COUNT
) -> list[str]:
    if type(value) is not list or len(value) > maximum:
        raise reject(code)
    paths = [canonical_path(item, code=code) for item in value]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise reject(code)
    if len({path.casefold() for path in paths}) != len(paths):
        raise reject(f"{code}_CASEFOLD_COLLISION")
    return paths


def _validate_stream_contract(value: Any, *, code: str) -> dict[str, Any]:
    contract = exact_fields(value, _STREAM_CONTRACT_FIELDS, code=code)
    if contract["capture"] != "FULL_BYTES":
        raise reject(f"{code}_CAPTURE_INVALID")
    canonical_path(contract["relative_path"], code=f"{code}_PATH_INVALID")
    positive_int(
        contract["maximum_byte_count"],
        code=f"{code}_MAXIMUM_INVALID",
        maximum=MAX_STREAM_BYTE_COUNT,
    )
    return contract


def _validate_artifact_contract(value: Any) -> dict[str, Any]:
    contract = exact_fields(value, _ARTIFACT_CONTRACT_FIELDS, code="LANE_ARTIFACT_CONTRACT")
    required = _sorted_unique_paths(
        contract["required_relative_paths"], code="LANE_REQUIRED_ARTIFACT_PATH_INVALID"
    )
    optional = _sorted_unique_paths(
        contract["optional_relative_paths"], code="LANE_OPTIONAL_ARTIFACT_PATH_INVALID"
    )
    if set(required) & set(optional):
        raise reject("LANE_ARTIFACT_CONTRACT_OVERLAP")
    maximum_count = nonnegative_int(
        contract["maximum_file_count"], code="LANE_ARTIFACT_MAXIMUM_COUNT_INVALID"
    )
    if (
        maximum_count > MAX_ARTIFACT_FILE_COUNT
        or maximum_count < len(required)
        or maximum_count > len(required) + len(optional)
    ):
        raise reject("LANE_ARTIFACT_MAXIMUM_COUNT_INVALID")
    positive_int(
        contract["maximum_total_byte_count"],
        code="LANE_ARTIFACT_MAXIMUM_BYTES_INVALID",
        maximum=MAX_ARTIFACT_TOTAL_BYTE_COUNT,
    )
    return contract


def validate_lanes(value: Any) -> list[dict[str, Any]]:
    if type(value) is not list or not value or len(value) > MAX_LANES:
        raise reject("LANES_NOT_NONEMPTY_ARRAY")
    lane_ids: set[str] = set()
    evidence_relative_paths: set[str] = set()
    result: list[dict[str, Any]] = []
    for expected_order, raw_lane in enumerate(value, start=1):
        lane = exact_fields(raw_lane, _LANE_FIELDS, code="LANE")
        lane_id = identifier(lane["lane_id"], code="LANE_ID_INVALID")
        if lane_id in lane_ids or lane["order"] != expected_order:
            raise reject("LANE_ID_OR_ORDER_INVALID")
        lane_ids.add(lane_id)
        executable_id = identifier(
            lane["executable_id"], code="LANE_EXECUTABLE_ID_INVALID"
        )
        argv = lane["argv"]
        if (
            type(argv) is not list
            or not argv
            or len(argv) > MAX_ARGV_ITEMS
            or argv[0] != executable_id
            or any(
                _bounded_utf8(
                    item, code="LANE_ARGV_INVALID", maximum=MAX_ARGUMENT_UTF8_BYTES
                )
                != item
                for item in argv
            )
        ):
            raise reject("LANE_ARGV_INVALID")
        _text(lane["cwd_rule"], code="LANE_CWD_RULE_INVALID")
        names = lane["environment_name_allowlist"]
        if type(names) is not list or len(names) > MAX_ENVIRONMENT_NAMES:
            raise reject("LANE_ENVIRONMENT_ALLOWLIST_INVALID")
        checked_names = [environment_name(item) for item in names]
        if checked_names != sorted(checked_names) or len(checked_names) != len(set(checked_names)):
            raise reject("LANE_ENVIRONMENT_ALLOWLIST_INVALID")
        if lane["environment_name_allowlist_sha512"] != canonical_sha512(checked_names):
            raise reject("LANE_ENVIRONMENT_ALLOWLIST_DIGEST_INVALID")
        positive_int(
            lane["timeout_seconds"],
            code="LANE_TIMEOUT_INVALID",
            maximum=MAX_LANE_TIMEOUT_SECONDS,
        )
        exit_codes = lane["expected_exit_codes"]
        if (
            type(exit_codes) is not list
            or not exit_codes
            or any(type(item) is not int or item < 0 or item > 255 for item in exit_codes)
            or exit_codes != sorted(set(exit_codes))
        ):
            raise reject("LANE_EXPECTED_EXIT_CODES_INVALID")
        stdout_contract = _validate_stream_contract(
            lane["stdout_contract"], code="LANE_STDOUT_CONTRACT"
        )
        stderr_contract = _validate_stream_contract(
            lane["stderr_contract"], code="LANE_STDERR_CONTRACT"
        )
        artifact_contract = _validate_artifact_contract(lane["produced_artifact_contract"])
        lane_paths = {
            stdout_contract["relative_path"],
            stderr_contract["relative_path"],
            *artifact_contract["required_relative_paths"],
            *artifact_contract["optional_relative_paths"],
        }
        if len(lane_paths) != (
            2
            + len(artifact_contract["required_relative_paths"])
            + len(artifact_contract["optional_relative_paths"])
        ):
            raise reject("LANE_EVIDENCE_PATH_OVERLAP")
        if evidence_relative_paths & lane_paths:
            raise reject("LANE_CROSS_LANE_EVIDENCE_PATH_OVERLAP")
        evidence_relative_paths.update(lane_paths)
        result.append(lane)
    return result


def validate_t_profile(
    value: Any,
    *,
    database: GitObjectDatabase,
    p_commit: CommitObject,
    p_tree: dict[str, TreeBlob],
    policy_blob: TreeBlob,
) -> dict[str, Any]:
    profile = exact_fields(value, _T_FIELDS, code="T_PROFILE")
    if (
        profile["schema_id"] != T_SCHEMA_ID
        or profile["policy_blob_oid"] != policy_blob.blob_oid
        or profile["policy_sha512"] != policy_blob.blob_sha512
        or profile["policy_blob_raw_sha512"] != policy_blob.blob_raw_sha512
        or profile["p_commit_oid"] != p_commit.oid
        or profile["p_tree_oid"] != p_commit.tree_oid
        or profile["p_commit_raw_sha512"] != p_commit.raw_sha512
        or profile["no_authority"] != NO_AUTHORITY
        or profile["runtime_attachment"] != "NONE"
    ):
        raise reject("T_PROFILE_BINDING_INVALID")
    p_tree_object = database.read_object(p_commit.tree_oid, expected_type="tree")
    if profile["p_tree_raw_sha512"] != p_tree_object.raw_sha512:
        raise reject("T_P_TREE_RAW_DIGEST_INVALID")
    identifier(profile["test_profile_id"], code="T_TEST_PROFILE_ID_INVALID")
    inventories = exact_fields(
        profile["inventories"], set(INVENTORY_CLASSES), code="T_INVENTORIES"
    )
    observed_paths: set[str] = set()
    for inventory_class in INVENTORY_CLASSES:
        inventory = exact_fields(
            inventories[inventory_class], _INVENTORY_FIELDS, code="T_INVENTORY"
        )
        entries = inventory["entries"]
        if type(entries) is not list or len(entries) > MAX_INVENTORY_ENTRIES:
            raise reject("T_INVENTORY_ENTRIES_INVALID")
        checked_entries: list[dict[str, Any]] = []
        last_path: str | None = None
        for entry in entries:
            exact_fields(entry, _INVENTORY_ENTRY_FIELDS, code="T_INVENTORY_ENTRY")
            path = canonical_path(entry["path"], code="T_INVENTORY_PATH_INVALID")
            if last_path is not None and path <= last_path:
                raise reject("T_INVENTORY_ORDER_OR_DUPLICATE_INVALID")
            last_path = path
            if path in observed_paths or path not in p_tree or entry != p_tree[path].record():
                raise reject("T_INVENTORY_ENTRY_NOT_P_TREE")
            observed_paths.add(path)
            checked_entries.append(entry)
        if inventory["inventory_sha512"] != canonical_sha512(checked_entries):
            raise reject("T_INVENTORY_DIGEST_INVALID")
    if observed_paths != set(p_tree):
        raise reject("T_INVENTORIES_NOT_EXHAUSTIVE")
    contract_paths = {
        item["path"] for item in inventories["contract"]["entries"]
    }
    if POLICY_PATH not in contract_paths:
        raise reject("T_POLICY_NOT_IN_CONTRACT_INVENTORY")
    source_paths = {item["path"] for item in inventories["source"]["entries"]}
    if any(item["source_path"] not in source_paths for item in CALLABLE_ALLOWED_SET):
        raise reject("T_CALLABLE_SOURCE_NOT_IN_SOURCE_INVENTORY")
    if profile["p_inventory_sha512"] != canonical_sha512(inventories):
        raise reject("T_P_INVENTORY_DIGEST_INVALID")
    lanes = validate_lanes(profile["lanes"])
    if profile["lanes_sha512"] != canonical_sha512(lanes):
        raise reject("T_LANES_DIGEST_INVALID")
    return profile


def _function_ast_sha512(source: bytes, qualified_name: str) -> str:
    try:
        text = source.decode("utf-8", errors="strict")
        if unicodedata.normalize("NFC", text) != text:
            raise reject("D_CALLABLE_SOURCE_NOT_NFC")
        module = ast.parse(text)
    except PTDEVerificationError:
        raise
    except (UnicodeError, SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        raise reject("D_CALLABLE_SOURCE_INVALID") from exc
    function_name = qualified_name.rsplit(".", 1)[-1]
    matches = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
    ]
    if len(matches) != 1:
        raise reject("D_CALLABLE_DEFINITION_NOT_EXACT")
    try:
        dumped = ast.dump(matches[0], annotate_fields=True, include_attributes=False)
        return sha512_hex(dumped.encode("utf-8"))
    except (UnicodeError, RecursionError, MemoryError, ValueError) as exc:
        raise reject("D_CALLABLE_AST_INVALID") from exc


def validate_d_descriptor(
    value: Any,
    *,
    database: GitObjectDatabase,
    p_commit: CommitObject,
    t_commit: CommitObject,
    d_tree: dict[str, TreeBlob],
    t_profile: dict[str, Any],
    t_profile_blob: TreeBlob,
) -> dict[str, Any]:
    descriptor = exact_fields(value, _D_FIELDS, code="D_DESCRIPTOR")
    fixed = {
        "schema_id": D_SCHEMA_ID,
        "p_commit_oid": p_commit.oid,
        "p_tree_oid": p_commit.tree_oid,
        "p_commit_raw_sha512": p_commit.raw_sha512,
        "t_commit_oid": t_commit.oid,
        "t_tree_oid": t_commit.tree_oid,
        "t_commit_raw_sha512": t_commit.raw_sha512,
        "t_profile_path": T_PROFILE_PATH,
        "t_profile_blob_oid": t_profile_blob.blob_oid,
        "t_profile_sha512": t_profile_blob.blob_sha512,
        "t_profile_blob_raw_sha512": t_profile_blob.blob_raw_sha512,
        "policy_sha512": t_profile["policy_sha512"],
        "p_inventory_sha512": t_profile["p_inventory_sha512"],
        "p_contract_inventory_sha512": t_profile["inventories"]["contract"]["inventory_sha512"],
        "p_architecture_inventory_sha512": t_profile["inventories"]["architecture"]["inventory_sha512"],
        "p_configuration_inventory_sha512": t_profile["inventories"]["configuration"]["inventory_sha512"],
        "lanes": t_profile["lanes"],
        "lanes_sha512": t_profile["lanes_sha512"],
        "no_authority": NO_AUTHORITY,
        "assurance_limits": assurance_limits_document(),
    }
    p_tree_object = database.read_object(p_commit.tree_oid, expected_type="tree")
    t_tree_object = database.read_object(t_commit.tree_oid, expected_type="tree")
    fixed["p_tree_raw_sha512"] = p_tree_object.raw_sha512
    fixed["t_tree_raw_sha512"] = t_tree_object.raw_sha512
    if any(descriptor[key] != expected for key, expected in fixed.items()):
        raise reject("D_DESCRIPTOR_BINDING_INVALID")
    campaign_id(descriptor["campaign_id"])
    for field in (
        "os_fingerprint_sha512",
        "build_fingerprint_sha512",
        "architecture_fingerprint_sha512",
        "runtime_fingerprint_sha512",
        "toolchain_fingerprint_sha512",
    ):
        require_sha512(descriptor[field], f"D_{field.upper()}_INVALID")
    callables = descriptor["single_pipeline_callables"]
    if type(callables) is not list or len(callables) != len(CALLABLE_ALLOWED_SET):
        raise reject("D_CALLABLE_SET_INVALID")
    for expected, record in zip(CALLABLE_ALLOWED_SET, callables):
        exact_fields(record, _CALLABLE_FIELDS, code="D_CALLABLE")
        path = expected["source_path"]
        if (
            record["qualified_name"] != expected["qualified_name"]
            or record["source_path"] != path
            or path not in d_tree
        ):
            raise reject("D_CALLABLE_POLICY_MISMATCH")
        blob_record = d_tree[path]
        blob = database.read_blob(blob_record.blob_oid)
        expected_record = {
            **expected,
            "source_blob_oid": blob_record.blob_oid,
            "source_blob_sha512": blob_record.blob_sha512,
            "function_ast_sha512": _function_ast_sha512(
                blob.content, expected["qualified_name"]
            ),
        }
        if record != expected_record:
            raise reject("D_CALLABLE_BINDING_INVALID")
    return descriptor


def _evidence_entry_map(
    value: Any, *, added: dict[str, TreeBlob]
) -> dict[str, dict[str, Any]]:
    if type(value) is not list or len(value) > MAX_EVIDENCE_ENTRIES:
        raise reject("E_EVIDENCE_INVENTORY_INVALID")
    records: dict[str, dict[str, Any]] = {}
    prior: str | None = None
    for record in value:
        exact_fields(record, _INVENTORY_ENTRY_FIELDS, code="E_EVIDENCE_ENTRY")
        path = canonical_path(record["path"], code="E_EVIDENCE_PATH_INVALID")
        if prior is not None and path <= prior:
            raise reject("E_EVIDENCE_INVENTORY_ORDER_INVALID")
        prior = path
        if path in records or path not in added or record != added[path].record():
            raise reject("E_EVIDENCE_ENTRY_NOT_ADDED_BLOB")
        records[path] = record
    if set(records) != set(added):
        raise reject("E_EVIDENCE_INVENTORY_NOT_EXHAUSTIVE")
    return records


def _campaign_path(campaign: str, relative: str) -> str:
    return canonical_path(f"evidence/ptde/{campaign}/{relative}")


def _validate_lane_transcript(
    value: Any,
    *,
    campaign: str,
    lane: dict[str, Any],
    result: dict[str, Any],
    produced_artifacts: list[str],
) -> dict[str, Any]:
    transcript = exact_fields(value, _TRANSCRIPT_FIELDS, code="E_LANE_TRANSCRIPT")
    exact_bindings = {
        "schema_id": TRANSCRIPT_SCHEMA_ID,
        "campaign_id": campaign,
        "lane_id": result["lane_id"],
        "attempt_id": result["attempt_id"],
        "lane_contract_sha512": canonical_sha512(lane),
        "d_commit_oid": result["d_commit_oid"],
        "d_descriptor_sha512": result["d_descriptor_sha512"],
        "status": result["status"],
        "exit_status": result["exit_status"],
        "started_at_unix_ms": result["started_at_unix_ms"],
        "finished_at_unix_ms": result["finished_at_unix_ms"],
        "wall_clock_milliseconds": result["wall_clock_milliseconds"],
        "timeout_seconds": result["timeout_seconds"],
        "timed_out": result["timed_out"],
        "timeout_status": result["timeout_status"],
        "cleanup_completed": result["cleanup_completed"],
        "process_tree_terminated": result["process_tree_terminated"],
        "stdout_path": result["stdout_path"],
        "stdout_byte_count": result["stdout_byte_count"],
        "stdout_sha512": result["stdout_sha512"],
        "stderr_path": result["stderr_path"],
        "stderr_byte_count": result["stderr_byte_count"],
        "stderr_sha512": result["stderr_sha512"],
        "error": result["error"],
        "produced_artifacts": produced_artifacts,
        "source_mutation_observed": result["source_mutation_observed"],
        "ledger_mutation_observed": result["ledger_mutation_observed"],
        "authority_mutation_observed": result["authority_mutation_observed"],
        "no_authority": NO_AUTHORITY,
    }
    if any(transcript[key] != expected for key, expected in exact_bindings.items()):
        raise reject("E_LANE_TRANSCRIPT_BINDING_INVALID")
    if (
        transcript["command_executed"] is not True
        or transcript["setup_completed"] is not True
        or transcript["stdout_full_bytes"] is not True
        or transcript["stderr_full_bytes"] is not True
        or transcript["output_truncated"] is not False
    ):
        raise reject("E_LANE_TRANSCRIPT_NOT_FULL_EXECUTION_RECORD")
    return transcript


def validate_e_manifest(
    value: Any,
    *,
    database: GitObjectDatabase,
    p_commit: CommitObject,
    t_commit: CommitObject,
    d_commit: CommitObject,
    d_descriptor: dict[str, Any],
    d_descriptor_blob: TreeBlob,
    added_evidence: dict[str, TreeBlob],
) -> dict[str, Any]:
    manifest = exact_fields(value, _E_FIELDS, code="E_MANIFEST")
    campaign = campaign_id(d_descriptor["campaign_id"])
    fixed = {
        "schema_id": E_SCHEMA_ID,
        "campaign_id": campaign,
        "p_commit_oid": p_commit.oid,
        "p_tree_oid": p_commit.tree_oid,
        "t_commit_oid": t_commit.oid,
        "t_tree_oid": t_commit.tree_oid,
        "d_commit_oid": d_commit.oid,
        "d_tree_oid": d_commit.tree_oid,
        "d_descriptor_path": D_DESCRIPTOR_PATH,
        "d_descriptor_blob_oid": d_descriptor_blob.blob_oid,
        "d_descriptor_sha512": d_descriptor_blob.blob_sha512,
        "d_descriptor_blob_raw_sha512": d_descriptor_blob.blob_raw_sha512,
        "policy_sha512": d_descriptor["policy_sha512"],
        "t_profile_sha512": d_descriptor["t_profile_sha512"],
        "p_inventory_sha512": d_descriptor["p_inventory_sha512"],
        "lanes_sha512": d_descriptor["lanes_sha512"],
        "approved_lane_order": [lane["lane_id"] for lane in d_descriptor["lanes"]],
        "limitations": assurance_limits_document(),
        "no_authority": NO_AUTHORITY,
    }
    if any(manifest[key] != expected for key, expected in fixed.items()):
        raise reject("E_MANIFEST_BINDING_INVALID")
    evidence_records = _evidence_entry_map(
        manifest["evidence_inventory"], added=added_evidence
    )
    if manifest["evidence_inventory_sha512"] != canonical_sha512(
        manifest["evidence_inventory"]
    ):
        raise reject("E_EVIDENCE_INVENTORY_DIGEST_INVALID")
    lane_results = manifest["lane_results"]
    lanes = d_descriptor["lanes"]
    if type(lane_results) is not list or len(lane_results) != len(lanes):
        raise reject("E_LANE_RESULTS_INVALID")
    attempts: set[str] = set()
    transcript_digests: set[str] = set()
    claimed_paths: set[str] = set()
    for lane, result in zip(lanes, lane_results):
        exact_fields(result, _LANE_RESULT_FIELDS, code="E_LANE_RESULT")
        attempt_id = identifier(result["attempt_id"], code="E_ATTEMPT_ID_INVALID")
        if attempt_id in attempts:
            raise reject("E_ATTEMPT_ID_DUPLICATE")
        attempts.add(attempt_id)
        if (
            result["lane_id"] != lane["lane_id"]
            or result["argv"] != lane["argv"]
            or result["d_commit_oid"] != d_commit.oid
            or result["d_descriptor_sha512"] != d_descriptor_blob.blob_sha512
            or result["timeout_seconds"] != lane["timeout_seconds"]
        ):
            raise reject("E_LANE_D_OR_T_BINDING_INVALID")
        start = nonnegative_int(
            result["started_at_unix_ms"], code="E_LANE_START_TIME_INVALID"
        )
        finish = nonnegative_int(
            result["finished_at_unix_ms"], code="E_LANE_FINISH_TIME_INVALID"
        )
        wall = nonnegative_int(
            result["wall_clock_milliseconds"], code="E_LANE_WALL_CLOCK_INVALID"
        )
        if finish < start or finish - start != wall:
            raise reject("E_LANE_WALL_CLOCK_INVALID")
        if wall >= lane["timeout_seconds"] * 1000:
            raise reject("E_LANE_WALL_CLOCK_LIMIT_EXCEEDED")
        if result["timed_out"] is True or result["timeout_status"] == TIMEOUT_STATUS:
            raise reject("E_TIMED_OUT_LANE_REJECTED")
        if (
            result["timed_out"] is not False
            or result["timeout_status"] != "NOT_TIMED_OUT"
            or result["status"] != "LANE_PASS"
            or type(result["exit_status"]) is not int
            or result["exit_status"] < 0
            or result["exit_status"] > 255
            or result["exit_status"] not in lane["expected_exit_codes"]
            or result["error"] is not None
            or result["cleanup_completed"] is not True
            or result["process_tree_terminated"] is not False
            or result["source_mutation_observed"] is not False
            or result["ledger_mutation_observed"] is not False
            or result["authority_mutation_observed"] is not False
        ):
            raise reject("E_LANE_NOT_SUCCESSFUL_OR_NONMUTATING")
        stream_specs = (
            (
                "stdout",
                lane["stdout_contract"],
                result["stdout_path"],
                result["stdout_byte_count"],
                result["stdout_sha512"],
            ),
            (
                "stderr",
                lane["stderr_contract"],
                result["stderr_path"],
                result["stderr_byte_count"],
                result["stderr_sha512"],
            ),
        )
        lane_claimed: set[str] = set()
        for name, contract, path_value, count, digest_value in stream_specs:
            expected_path = _campaign_path(campaign, contract["relative_path"])
            if path_value != expected_path or expected_path not in evidence_records:
                raise reject(f"E_LANE_{name.upper()}_PATH_INVALID")
            nonnegative_int(count, code=f"E_LANE_{name.upper()}_COUNT_INVALID")
            require_sha512(digest_value, f"E_LANE_{name.upper()}_DIGEST_INVALID")
            record = evidence_records[expected_path]
            if (
                count != record["byte_count"]
                or count > contract["maximum_byte_count"]
                or digest_value != record["blob_sha512"]
            ):
                raise reject(f"E_LANE_{name.upper()}_CONTENT_INVALID")
            lane_claimed.add(expected_path)
        transcript_path = canonical_path(
            result["transcript_path"], code="E_LANE_TRANSCRIPT_PATH_INVALID"
        )
        if transcript_path not in evidence_records:
            raise reject("E_LANE_TRANSCRIPT_NOT_IN_EVIDENCE")
        transcript_count = nonnegative_int(
            result["transcript_byte_count"], code="E_LANE_TRANSCRIPT_COUNT_INVALID"
        )
        require_sha512(result["transcript_sha512"], "E_LANE_TRANSCRIPT_DIGEST_INVALID")
        transcript_record = evidence_records[transcript_path]
        if (
            transcript_count != transcript_record["byte_count"]
            or transcript_count > MAX_TRANSCRIPT_BYTE_COUNT
            or result["transcript_sha512"] != transcript_record["blob_sha512"]
        ):
            raise reject("E_LANE_TRANSCRIPT_CONTENT_INVALID")
        if result["transcript_sha512"] in transcript_digests:
            raise reject("E_LANE_TRANSCRIPT_DIGEST_DUPLICATE")
        transcript_digests.add(result["transcript_sha512"])
        if transcript_path in lane_claimed:
            raise reject("E_LANE_TRANSCRIPT_PATH_OVERLAP")
        lane_claimed.add(transcript_path)
        produced = result["produced_artifacts"]
        if type(produced) is not list:
            raise reject("E_LANE_PRODUCED_ARTIFACTS_INVALID")
        checked_produced = [
            canonical_path(path, code="E_LANE_PRODUCED_ARTIFACT_PATH_INVALID")
            for path in produced
        ]
        if checked_produced != sorted(set(checked_produced)):
            raise reject("E_LANE_PRODUCED_ARTIFACTS_INVALID")
        relative_produced: list[str] = []
        prefix = f"evidence/ptde/{campaign}/"
        for path in checked_produced:
            if not path.startswith(prefix) or path not in evidence_records:
                raise reject("E_LANE_PRODUCED_ARTIFACT_NOT_EVIDENCE")
            relative_produced.append(path[len(prefix) :])
        if lane_claimed & set(checked_produced):
            raise reject("E_LANE_PRODUCED_ARTIFACT_PATH_OVERLAP")
        artifact_contract = lane["produced_artifact_contract"]
        allowed = set(artifact_contract["required_relative_paths"]) | set(
            artifact_contract["optional_relative_paths"]
        )
        if (
            not set(artifact_contract["required_relative_paths"]).issubset(relative_produced)
            or not set(relative_produced).issubset(allowed)
            or len(relative_produced) > artifact_contract["maximum_file_count"]
        ):
            raise reject("E_LANE_PRODUCED_ARTIFACT_CONTRACT_FAILED")
        total = sum(evidence_records[path]["byte_count"] for path in checked_produced)
        if total > artifact_contract["maximum_total_byte_count"]:
            raise reject("E_LANE_PRODUCED_ARTIFACT_BYTES_EXCEEDED")
        transcript_blob = database.read_blob(transcript_record["blob_oid"])
        transcript = strict_json_document(
            transcript_blob.content, code="E_LANE_TRANSCRIPT"
        )
        _validate_lane_transcript(
            transcript,
            campaign=campaign,
            lane=lane,
            result=result,
            produced_artifacts=checked_produced,
        )
        lane_claimed.update(checked_produced)
        if claimed_paths & lane_claimed:
            raise reject("E_EVIDENCE_PATH_CLAIMED_BY_MULTIPLE_LANES")
        claimed_paths.update(lane_claimed)
    if claimed_paths != set(evidence_records):
        raise reject("E_EVIDENCE_NOT_EXACTLY_LANE_BOUND")
    return manifest


__all__ = [
    "validate_d_descriptor",
    "validate_e_manifest",
    "validate_lanes",
    "validate_t_profile",
]
