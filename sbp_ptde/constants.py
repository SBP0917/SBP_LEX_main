"""Locked constants for the detached SBP-LEX V2 P/T/D/E verifier."""

from __future__ import annotations

from types import MappingProxyType

POLICY_SCHEMA_ID = "sbp.lex.v2.ptde.policy/1"
T_SCHEMA_ID = "sbp.lex.v2.ptde.test-subject/1"
D_SCHEMA_ID = "sbp.lex.v2.ptde.runtime-descriptor/1"
E_SCHEMA_ID = "sbp.lex.v2.ptde.evidence-commit/1"
RESULT_SCHEMA_ID = "sbp.lex.v2.ptde.verification-result/1"
TRANSCRIPT_SCHEMA_ID = "sbp.lex.v2.ptde.lane-transcript/1"

POLICY_PATH = "contracts/ptde/PTDE_POLICY_V1.json"
T_PROFILE_PATH = "ptde_subjects/T_TEST_BUILD_PROFILE.json"
D_DESCRIPTOR_PATH = "ptde_subjects/D_RUNTIME_DESCRIPTOR.json"
EVIDENCE_ROOT = "evidence/ptde"
E_MANIFEST_NAME = "E_EVIDENCE_MANIFEST.json"

INVENTORY_CLASSES = (
    "source",
    "contract",
    "architecture",
    "configuration",
    "test",
    "dependency_build",
    "detached_verifier",
)

CALLABLE_ALLOWED_SET = (
    MappingProxyType(
        {"qualified_name": "main.run_sbp_lex", "source_path": "main.py"}
    ),
    MappingProxyType({
        "qualified_name": "sbp_lex.pipeline.runner.run_v2",
        "source_path": "sbp_lex/pipeline/runner.py",
    }),
    MappingProxyType({
        "qualified_name": "sbp_lex.pipeline.runner.run_v2_pipeline",
        "source_path": "sbp_lex/pipeline/runner.py",
    }),
)

MAX_LANE_TIMEOUT_SECONDS = 7200
MAX_JSON_DOCUMENT_BYTES = 16_777_216
MAX_JSON_DEPTH = 64
MAX_JSON_OBJECT_FIELDS = 4_096
MAX_JSON_LIST_ITEMS = 100_000
MAX_JSON_TOTAL_NODES = 1_000_000
MAX_JSON_STRING_BYTES = 1_048_576
MAX_INTEGER_ABSOLUTE = 9_223_372_036_854_775_807
MAX_PATH_UTF8_BYTES = 4_096
MAX_PATH_SEGMENT_UTF8_BYTES = 255
MAX_GIT_OBJECT_BYTES = 134_217_728
MAX_TOTAL_GIT_OBJECT_BYTES = 1_073_741_824
MAX_GIT_SUBPROCESS_METADATA_BYTES = 1_048_576
MAX_GIT_EXECUTABLE_BYTES = 268_435_456
MAX_GIT_SUBPROCESS_SECONDS = 120
MAX_COMMIT_PARENT_COUNT = 16
MAX_TREE_DEPTH = 64
MAX_TREE_COUNT = 100_000
MAX_TREE_ENTRY_COUNT = 100_000
MAX_BLOB_COUNT = 100_000
MAX_LANES = 1_024
MAX_ARGV_ITEMS = 4_096
MAX_ARGUMENT_UTF8_BYTES = 32_768
MAX_ENVIRONMENT_NAMES = 4_096
MAX_INVENTORY_ENTRIES = 100_000
MAX_EVIDENCE_ENTRIES = 100_000
MAX_STREAM_BYTE_COUNT = 134_217_728
MAX_ARTIFACT_FILE_COUNT = 10_000
MAX_ARTIFACT_TOTAL_BYTE_COUNT = 134_217_728
MAX_TRANSCRIPT_BYTE_COUNT = 1_048_576
TIMEOUT_STATUS = "TIMEOUT_FAIL_CLOSED"
SUCCESS_RESULT = "PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED"
SUCCESS_CLAIM_TEXT = (
    "The supplied committed Git objects form the required P→T→D→E "
    "direct-child chain; T and D contain only their admitted descriptor "
    "additions; E adds only its declared campaign evidence subtree; and its "
    "committed blobs match the declared SHA-512 inventory and lane-result "
    "records."
)

NO_AUTHORITY = MappingProxyType({
    "audit_mutation": False,
    "authority": False,
    "decision": False,
    "effect": False,
    "execution": False,
    "governance": False,
    "ledger_mutation": False,
    "licence": False,
    "runtime_attachment": "NONE",
    "source_mutation": False,
    "token": False,
})

_RESOURCE_MAXIMA = MappingProxyType({
    "artifact_file_count": MAX_ARTIFACT_FILE_COUNT,
    "artifact_total_byte_count": MAX_ARTIFACT_TOTAL_BYTE_COUNT,
    "argument_utf8_bytes": MAX_ARGUMENT_UTF8_BYTES,
    "argv_items": MAX_ARGV_ITEMS,
    "blob_count": MAX_BLOB_COUNT,
    "commit_parent_count": MAX_COMMIT_PARENT_COUNT,
    "environment_names": MAX_ENVIRONMENT_NAMES,
    "evidence_entries": MAX_EVIDENCE_ENTRIES,
    "git_executable_bytes": MAX_GIT_EXECUTABLE_BYTES,
    "git_object_bytes": MAX_GIT_OBJECT_BYTES,
    "git_subprocess_metadata_bytes": MAX_GIT_SUBPROCESS_METADATA_BYTES,
    "git_subprocess_seconds": MAX_GIT_SUBPROCESS_SECONDS,
    "integer_absolute": MAX_INTEGER_ABSOLUTE,
    "inventory_entries": MAX_INVENTORY_ENTRIES,
    "json_depth": MAX_JSON_DEPTH,
    "json_document_bytes": MAX_JSON_DOCUMENT_BYTES,
    "json_list_items": MAX_JSON_LIST_ITEMS,
    "json_object_fields": MAX_JSON_OBJECT_FIELDS,
    "json_string_bytes": MAX_JSON_STRING_BYTES,
    "json_total_nodes": MAX_JSON_TOTAL_NODES,
    "lanes": MAX_LANES,
    "lane_timeout_seconds": MAX_LANE_TIMEOUT_SECONDS,
    "path_segment_utf8_bytes": MAX_PATH_SEGMENT_UTF8_BYTES,
    "path_utf8_bytes": MAX_PATH_UTF8_BYTES,
    "stream_byte_count": MAX_STREAM_BYTE_COUNT,
    "total_git_object_bytes": MAX_TOTAL_GIT_OBJECT_BYTES,
    "transcript_byte_count": MAX_TRANSCRIPT_BYTE_COUNT,
    "tree_count": MAX_TREE_COUNT,
    "tree_depth": MAX_TREE_DEPTH,
    "tree_entry_count": MAX_TREE_ENTRY_COUNT,
})

ASSURANCE_LIMITS = MappingProxyType({
    "production_admitted": False,
    "external_validation": False,
    "deployment_admitted": False,
    "external_trust_custody": "NOT_PROVEN",
    "durable_replay_or_rollback_head": "NOT_PROVEN",
    "effect_path_non_bypass": "NOT_PROVEN",
    "accepted_attempt_history_persistence": "EXTERNAL_DURABLE_DEPENDENCY",
    "git_executable_point_of_use_immutability": "WINDOWS_SAME_HANDLE_EXECUTION_NOT_PROVEN",
    "transcript_assertion_scope": "COMMITTED_BYTES_ONLY_NOT_EXTERNAL_COMMAND_ATTESTATION",
    "resource_maxima": _RESOURCE_MAXIMA,
})


def assurance_limits_document() -> dict[str, object]:
    """Return a detached JSON-safe copy of the immutable assurance policy."""

    return {
        "production_admitted": ASSURANCE_LIMITS["production_admitted"],
        "external_validation": ASSURANCE_LIMITS["external_validation"],
        "deployment_admitted": ASSURANCE_LIMITS["deployment_admitted"],
        "external_trust_custody": ASSURANCE_LIMITS[
            "external_trust_custody"
        ],
        "durable_replay_or_rollback_head": ASSURANCE_LIMITS[
            "durable_replay_or_rollback_head"
        ],
        "effect_path_non_bypass": ASSURANCE_LIMITS[
            "effect_path_non_bypass"
        ],
        "accepted_attempt_history_persistence": ASSURANCE_LIMITS[
            "accepted_attempt_history_persistence"
        ],
        "git_executable_point_of_use_immutability": ASSURANCE_LIMITS[
            "git_executable_point_of_use_immutability"
        ],
        "transcript_assertion_scope": ASSURANCE_LIMITS[
            "transcript_assertion_scope"
        ],
        "resource_maxima": dict(_RESOURCE_MAXIMA),
    }

REGULAR_BLOB_MODES = frozenset({"100644", "100755"})
TREE_MODE = "40000"
SYMLINK_MODE = "120000"
GITLINK_MODE = "160000"


__all__ = [
    "ASSURANCE_LIMITS",
    "CALLABLE_ALLOWED_SET",
    "D_DESCRIPTOR_PATH",
    "D_SCHEMA_ID",
    "EVIDENCE_ROOT",
    "E_MANIFEST_NAME",
    "E_SCHEMA_ID",
    "INVENTORY_CLASSES",
    "MAX_ARGUMENT_UTF8_BYTES",
    "MAX_ARGV_ITEMS",
    "MAX_ARTIFACT_FILE_COUNT",
    "MAX_ARTIFACT_TOTAL_BYTE_COUNT",
    "MAX_BLOB_COUNT",
    "MAX_COMMIT_PARENT_COUNT",
    "MAX_ENVIRONMENT_NAMES",
    "MAX_EVIDENCE_ENTRIES",
    "MAX_GIT_EXECUTABLE_BYTES",
    "MAX_GIT_OBJECT_BYTES",
    "MAX_GIT_SUBPROCESS_METADATA_BYTES",
    "MAX_GIT_SUBPROCESS_SECONDS",
    "MAX_INTEGER_ABSOLUTE",
    "MAX_INVENTORY_ENTRIES",
    "MAX_JSON_DEPTH",
    "MAX_JSON_DOCUMENT_BYTES",
    "MAX_JSON_LIST_ITEMS",
    "MAX_JSON_OBJECT_FIELDS",
    "MAX_JSON_STRING_BYTES",
    "MAX_JSON_TOTAL_NODES",
    "MAX_LANES",
    "MAX_LANE_TIMEOUT_SECONDS",
    "MAX_PATH_SEGMENT_UTF8_BYTES",
    "MAX_PATH_UTF8_BYTES",
    "MAX_STREAM_BYTE_COUNT",
    "MAX_TOTAL_GIT_OBJECT_BYTES",
    "MAX_TRANSCRIPT_BYTE_COUNT",
    "MAX_TREE_COUNT",
    "MAX_TREE_DEPTH",
    "MAX_TREE_ENTRY_COUNT",
    "NO_AUTHORITY",
    "POLICY_PATH",
    "POLICY_SCHEMA_ID",
    "RESULT_SCHEMA_ID",
    "SUCCESS_CLAIM_TEXT",
    "SUCCESS_RESULT",
    "TIMEOUT_STATUS",
    "TRANSCRIPT_SCHEMA_ID",
    "T_PROFILE_PATH",
    "T_SCHEMA_ID",
    "assurance_limits_document",
]
