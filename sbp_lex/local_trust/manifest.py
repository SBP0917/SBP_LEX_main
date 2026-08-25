"""V2 root repository-provenance manifest (stage 1)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .artifact import build_signed_artifact, validate_signed_artifact
from .constants import DIRTY, FAIL, GENESIS, PASS
from .digests import digest_equal
from .paths import LocalTrustPathError, measure_file, validated_root
from .repository import collect_repository_provenance, collect_v2_evidence_inventory
from .signing import HybridSigningContext, HybridVerificationContext

PAYLOAD_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_ROOT_MANIFEST_PAYLOAD_V1"
_PAYLOAD_FIELDS = {
    "schema_id",
    "status",
    "repository",
    "evidence_inventory",
    "runtime_attachment",
    "scope_statement",
    "repository_identity_digest",
    "accepted_history_digest",
    "accepted_history_sequence",
    "accepted_history_live_head_digest",
}


def build_manifest(
    repository_root: str | Path,
    *,
    signer: HybridSigningContext,
    time_evidence: Mapping[str, Any],
    repository_identity_digest: str,
    accepted_history: Mapping[str, Any],
) -> dict[str, Any]:
    repository = collect_repository_provenance(repository_root)
    inventory = collect_v2_evidence_inventory(repository_root)
    status = (
        PASS
        if repository["working_tree_clean"] and not inventory["required_missing_groups"]
        else DIRTY if not repository["working_tree_clean"] else FAIL
    )
    payload = {
        "schema_id": PAYLOAD_SCHEMA,
        "status": status,
        "repository": repository,
        "evidence_inventory": inventory,
        "runtime_attachment": "NONE",
        "scope_statement": "Local/offline repository evidence only; no runtime or authority effect.",
        "repository_identity_digest": repository_identity_digest,
        "accepted_history_digest": accepted_history.get("history_digest"),
        "accepted_history_sequence": accepted_history.get("sequence"),
        "accepted_history_live_head_digest": accepted_history.get("live_head_digest"),
    }
    return build_signed_artifact(
        stage="manifest",
        payload=payload,
        signer=signer,
        prior_artifact_digest=GENESIS,
        time_evidence=time_evidence,
    )


def validate_manifest(
    manifest: Any,
    repository_root: str | Path,
    *,
    trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    clock_trust_context: HybridVerificationContext,
    owner_pinned_clock_context_digest: str,
    expected_time_sequence: int,
    expected_prior_time_digest: str,
    expected_repository_identity_digest: str,
    expected_accepted_history_digest: str,
    expected_accepted_history_sequence: int,
    expected_accepted_history_live_head_digest: str,
    expected_time_digest: str | None = None,
) -> dict[str, Any]:
    base = validate_signed_artifact(
        manifest,
        expected_stage="manifest",
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        clock_trust_context=clock_trust_context,
        owner_pinned_clock_context_digest=owner_pinned_clock_context_digest,
        expected_prior_artifact_digest=GENESIS,
        expected_time_sequence=expected_time_sequence,
        expected_prior_time_digest=expected_prior_time_digest,
        expected_time_digest=expected_time_digest,
    )
    failures = list(base["validation_failures"])
    try:
        payload = manifest["payload"]
        if type(payload) is not dict or set(payload) != _PAYLOAD_FIELDS:
            failures.append("manifest_payload_shape_invalid")
        elif (
            payload.get("schema_id") != PAYLOAD_SCHEMA
            or payload.get("runtime_attachment") != "NONE"
            or payload.get("status") != PASS
            or payload.get("repository_identity_digest") != expected_repository_identity_digest
            or payload.get("accepted_history_digest") != expected_accepted_history_digest
            or payload.get("accepted_history_sequence") != expected_accepted_history_sequence
            or payload.get("accepted_history_live_head_digest") != expected_accepted_history_live_head_digest
        ):
            failures.append("manifest_not_admissible")
        else:
            current_repository = collect_repository_provenance(repository_root)
            if payload["repository"] != current_repository:
                failures.append("repository_provenance_changed")
            inventory = payload.get("evidence_inventory")
            if type(inventory) is not dict or inventory.get("required_missing_groups") != []:
                failures.append("required_evidence_missing")
            else:
                root = validated_root(repository_root)
                files = inventory.get("files")
                if type(files) is not list:
                    failures.append("evidence_inventory_invalid")
                else:
                    for expected in files:
                        if type(expected) is not dict:
                            failures.append("evidence_record_invalid")
                            break
                        expected_path = expected.get("path")
                        if type(expected_path) is not str:
                            failures.append("evidence_record_invalid")
                            break
                        try:
                            observed = measure_file(root, expected_path)
                        except LocalTrustPathError:
                            failures.append("evidence_file_unavailable")
                            break
                        if observed != expected:
                            failures.append("evidence_file_changed")
                            break
                    if not digest_equal(
                        inventory.get("inventory_digest"),
                        __import__("sbp_lex.local_trust.digests", fromlist=["digest"]).digest(
                            {"groups": inventory.get("groups"), "files": files}
                        ),
                    ):
                        failures.append("evidence_inventory_digest_invalid")
    except (KeyError, TypeError, ValueError):
        failures.append("manifest_malformed")
    return {
        **base,
        "status": PASS if not failures else FAIL,
        "validation_failures": sorted(set(failures)),
    }


build_local_trust_manifest = build_manifest
validate_local_trust_manifest = validate_manifest


__all__ = [
    "PAYLOAD_SCHEMA",
    "build_local_trust_manifest",
    "build_manifest",
    "validate_local_trust_manifest",
    "validate_manifest",
]
