"""The fixed invariant policy; campaign OIDs and lane commands never live here."""

from __future__ import annotations

from typing import Any

from .canonical import canonical_json_document_bytes, exact_fields, sha512_hex
from .constants import (
    ASSURANCE_LIMITS,
    CALLABLE_ALLOWED_SET,
    D_DESCRIPTOR_PATH,
    D_SCHEMA_ID,
    E_MANIFEST_NAME,
    E_SCHEMA_ID,
    INVENTORY_CLASSES,
    MAX_LANE_TIMEOUT_SECONDS,
    NO_AUTHORITY,
    POLICY_PATH,
    POLICY_SCHEMA_ID,
    RESULT_SCHEMA_ID,
    SUCCESS_CLAIM_TEXT,
    SUCCESS_RESULT,
    TIMEOUT_STATUS,
    T_PROFILE_PATH,
    T_SCHEMA_ID,
    TRANSCRIPT_SCHEMA_ID,
)
from .errors import reject


def expected_policy() -> dict[str, Any]:
    return {
        "callable_allowed_set": [dict(item) for item in CALLABLE_ALLOWED_SET],
        "canonical_json": {
            "duplicate_keys_rejected": True,
            "encoding": "UTF-8",
            "floats_rejected": True,
            "key_order": "UTF-16_CODE_UNIT",
            "nfc_required": True,
            "terminal_lf_required": True,
        },
        "evidence_digest": {
            "algorithm": "SHA-512",
            "hex_case": "lowercase",
            "hex_length": 128,
        },
        "inventory_classes": list(INVENTORY_CLASSES),
        "json_schemas": {
            "d": D_SCHEMA_ID,
            "e": E_SCHEMA_ID,
            "result": RESULT_SCHEMA_ID,
            "t": T_SCHEMA_ID,
            "transcript": TRANSCRIPT_SCHEMA_ID,
        },
        "lane_contract": {
            "argv_zero_equals_executable_id": True,
            "environment_names_only": True,
            "evidence_must_be_full_bytes": True,
            "maximum_timeout_seconds": MAX_LANE_TIMEOUT_SECONDS,
            "minimum_timeout_seconds": 1,
            "ordered_nonempty_unique_lane_ids": True,
            "pass_requires_command_executed": True,
            "pass_requires_untruncated_full_stream_bytes": True,
            "timeout_status": TIMEOUT_STATUS,
            "transcript_schema": TRANSCRIPT_SCHEMA_ID,
        },
        "no_authority": dict(NO_AUTHORITY),
        "object_database": {
            "abbreviated_oids_rejected": True,
            "bare_or_object_database_only": True,
            "grafts_rejected": True,
            "head_and_refs_rejected_as_inputs": True,
            "inherited_repository_and_config_redirection_rejected_or_sanitized": True,
            "object_hash_recomputed": True,
            "replace_objects_rejected": True,
            "shallow_and_commondir_rejected": True,
            "supplied_oids_full_length": True,
            "working_tree_not_consulted": True,
        },
        "paths": {
            "d_descriptor": D_DESCRIPTOR_PATH,
            "e_campaign_root": "evidence/ptde/<campaign_id>/",
            "e_manifest_name": E_MANIFEST_NAME,
            "policy": POLICY_PATH,
            "t_profile": T_PROFILE_PATH,
        },
        "policy_id": "SBP_LEX_V2_PTDE_POLICY",
        "resource_maxima": dict(ASSURANCE_LIMITS["resource_maxima"]),
        "schema_id": POLICY_SCHEMA_ID,
        "stage_chain": {
            "d": {"delta": "EXACTLY_ONE_ADDED_REGULAR_BLOB", "sole_parent": "T"},
            "e": {"delta": "ONLY_DECLARED_CAMPAIGN_EVIDENCE_BLOBS", "sole_parent": "D"},
            "p": {"trust": "OUT_OF_BAND_EXPECTED_FULL_OID"},
            "t": {"delta": "EXACTLY_ONE_ADDED_REGULAR_BLOB", "sole_parent": "P"},
        },
        "success": {
            "claim_text": SUCCESS_CLAIM_TEXT,
            "result": SUCCESS_RESULT,
        },
        "trust_inputs": {
            "accepted_attempt_history": "OUT_OF_BAND_PINNED_CANONICAL_SHA512",
            "accepted_attempt_history_persistence": "EXTERNAL_DURABLE_DEPENDENCY",
            "expected_p_oid": "OUT_OF_BAND_PINNED_FULL_OID",
            "git_executable": "OUT_OF_BAND_PINNED_RAW_FILE_SHA512",
            "windows_same_handle_execution": "NOT_PROVEN",
        },
        "version": 1,
    }


_POLICY_FIELDS = {
    "callable_allowed_set",
    "canonical_json",
    "evidence_digest",
    "inventory_classes",
    "json_schemas",
    "lane_contract",
    "no_authority",
    "object_database",
    "paths",
    "policy_id",
    "resource_maxima",
    "schema_id",
    "stage_chain",
    "success",
    "trust_inputs",
    "version",
}


def validate_policy(value: Any) -> dict[str, Any]:
    policy = exact_fields(value, _POLICY_FIELDS, code="POLICY")
    if policy != expected_policy():
        raise reject("POLICY_NOT_LOCKED_V1")
    return policy


def policy_document_bytes() -> bytes:
    return canonical_json_document_bytes(expected_policy())


def policy_sha512() -> str:
    return sha512_hex(policy_document_bytes())


__all__ = [
    "expected_policy",
    "policy_document_bytes",
    "policy_sha512",
    "validate_policy",
]
