from __future__ import annotations

import base64
import binascii
from copy import deepcopy
from typing import Dict, Any, List

from sbp_lex.baseline.foundational_baseline import (
    foundational_baseline_hash_payload,
    verify_foundational_baseline,
)
from sbp_lex.config.pipeline_config import FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    build_signed_object,
    verify_signed_object,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_ENVELOPE_SCHEMA_ID,
    HybridVerificationContext,
    hybrid_envelope_shape_exact,
    is_hybrid_provider,
)
from sbp_lex.security.integrity import (
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_AUTHORITY_ROLE,
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_SCHEMA_STATUS,
    FILED_LIFECYCLE_STAGES,
    LIFECYCLE_PASS,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE,
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_PASS,
)
from sbp_lex.governance.skg_authority import (
    SKG_AUTHORITY_ROLE,
    SKG_CONTENT_CLASSES,
    SKG_PASS,
    SKG_SATISFIED,
    SKG_SCHEMA_STATUS,
    SKG_V2_CONTRACT_ID,
    skg_authority_hash_payload,
)
from sbp_lex.governance.three_p_doctrine import verify_three_p_core
from sbp_lex.governance.authority_provenance import (
    AUTHORITY_PROVENANCE_PASS,
    AUTHORITY_PROVENANCE_STAGE,
    authority_provenance_hash_payload,
    authority_provenance_token_bindings,
)


# ─────────────────────────────────────────────
# LOCKED TOKEN NAMES
# ─────────────────────────────────────────────

REQUIRED_CORE_TOKENS: List[str] = [
    "foundational",
    "authority_provenance",
    "authority",
    "skg",
    "procedural_truth",
    "ptodf",
    "classification",
    "licensing",
    "aj_saaf",
    "gala",
    "abegf",
    *[
        FILED_LIFECYCLE_ENGINE_IDS[engine].lower()
        for engine in FILED_LIFECYCLE_ORDER
    ],
    *[
        FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ].lower()
        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
    ],
    "governance",
    "domain",
    "aurion",
    "execution_boundary",
    "execution_attestation",
]

CONDITIONAL_THRESHOLD_TOKENS: List[str] = [
    "consequentiality_threshold",
    "corroboration_threshold",
    "financial_threshold",
    "autonomy_boundary_threshold",
    "escalation_threshold",
]

_TOKEN_ISSUANCE_CONTRACTS: dict[str, tuple[str, str]] = {
    "foundational": (
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
        FOUNDATIONAL_BASELINE_AGGREGATE_STAGE,
    ),
    "authority_provenance": (
        "authority_provenance",
        AUTHORITY_PROVENANCE_STAGE,
    ),
    "authority": ("root_of_trust", "root_of_trust"),
    "skg": ("skg_authority", "skg_authority"),
    "procedural_truth": ("procedural_truth_engine", "procedural_truth"),
    "classification": ("classification_engine", "classification"),
    "licensing": ("licensing_engine", "licensing"),
    "governance": ("governance_engine", "governance"),
    "domain": ("domain_wrap", "domain_wrap"),
    "aurion": ("aurion15_runtime", "aurion_runtime"),
    "aj_saaf": ("AJ-SAAF", "filed_framework:aj_saaf"),
    "ptodf": ("PTODF", "filed_framework:ptodf"),
    "gala": ("GALA", "filed_framework:gala"),
    "abegf": ("ABEGF", "filed_framework:abegf"),
    "execution_boundary": ("execution_gate", "execution_prep"),
    "execution_attestation": ("execution_gate", "execution_prep"),
    "consequentiality_threshold": ("threshold_engine", "procedural_truth"),
    "corroboration_threshold": ("threshold_engine", "procedural_truth"),
    "financial_threshold": ("threshold_engine", "procedural_truth"),
    "autonomy_boundary_threshold": ("threshold_engine", "procedural_truth"),
    "escalation_threshold": ("threshold_engine", "procedural_truth"),
    **{
        FILED_LIFECYCLE_ENGINE_IDS[engine].lower(): (
            FILED_LIFECYCLE_ENGINE_IDS[engine],
            FILED_LIFECYCLE_STAGES[engine],
        )
        for engine in FILED_LIFECYCLE_ORDER
    },
    **{
        FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ].lower(): (
            FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                governance_function
            ],
            FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
        )
        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
    },
}

_APPLICATION_INTEGRITY_TOKEN_FIELDS = (
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
)
_FOUNDATIONAL_COMPONENT_TOKEN_FIELDS = (
    "digital_provenance_digest",
    "digital_provenance_verification_receipt_digest",
    "sovereign_identity_digest",
    "authority_boundary_digest",
    "authority_boundary_trace_digest",
    "impersonation_protection_digest",
    "australian_minor_access_record_digest",
)
_FOUNDATIONAL_AUTHORITY_FIELDS = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_authority_granted",
    "pipeline_bypass_permitted",
)
_FOUNDATIONAL_TOKEN_BODY_FIELDS = {
    "name",
    "request_fingerprint",
    "issued_state_hash",
    "issued_chain_index",
    "issued_chain_stage",
    "three_p_core_digest",
    "three_p_trace_hash",
    "three_p_evaluation_stage",
    "three_p_evaluation_sequence",
    "three_p_binding_chain_index",
    *_APPLICATION_INTEGRITY_TOKEN_FIELDS,
    *_FOUNDATIONAL_COMPONENT_TOKEN_FIELDS,
    "foundational_baseline_digest",
    "issuer",
    "issued_at_stage",
    "payload",
    *_FOUNDATIONAL_AUTHORITY_FIELDS,
}
_FOUNDATIONAL_TOKEN_FIELDS = _FOUNDATIONAL_TOKEN_BODY_FIELDS | {
    "digest",
    "signature",
    "verified",
}

_AUTHORITY_PROVENANCE_BINDING_FIELDS = (
    "authority_provenance_digest",
    "authority_provenance_trace_digest",
    "authority_provenance_trust_context_digest",
    "authority_provenance_clock_receipt_digest",
    "authority_provenance_registry_head_digest",
)
_AUTHORITY_PROVENANCE_TOKEN_BODY_FIELDS = (
    _FOUNDATIONAL_TOKEN_BODY_FIELDS
    | set(_AUTHORITY_PROVENANCE_BINDING_FIELDS)
)
_AUTHORITY_PROVENANCE_TOKEN_FIELDS = (
    _AUTHORITY_PROVENANCE_TOKEN_BODY_FIELDS
    | {"digest", "signature", "verified"}
)

_FRAMEWORK_TOKEN_BINDINGS = {
    "ptodf": ("PTODF", "filed_framework:ptodf"),
    "aj_saaf": ("AJ-SAAF", "filed_framework:aj_saaf"),
    "gala": ("GALA", "filed_framework:gala"),
    "abegf": ("ABEGF", "filed_framework:abegf"),
}

_LIFECYCLE_TOKEN_BINDINGS = {
    FILED_LIFECYCLE_ENGINE_IDS[engine].lower(): (
        engine,
        FILED_LIFECYCLE_ENGINE_IDS[engine],
        FILED_LIFECYCLE_STAGES[engine],
    )
    for engine in FILED_LIFECYCLE_ORDER
}

_GOVERNANCE_INTEGRITY_TOKEN_BINDINGS = {
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
        governance_function
    ].lower(): (
        governance_function,
        FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[governance_function],
        FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
    )
    for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
}

_SKG_RECORD_FIELDS = {
    "contract_id",
    "schema_status",
    "content_classes",
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "downstream_override_permitted",
}
_SKG_SNAPSHOT_FIELDS = {
    "contract_id",
    "schema_status",
    "content_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_skg_digest",
}
_SKG_SOURCE_FIELDS = {
    "contract_id",
    "schema_status",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_skg_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_SKG_DETERMINATION_FIELDS = {
    "result",
    "content_class_results",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "downstream_override_permitted",
}
_LIFECYCLE_RECORD_FIELDS = {
    "schema_status",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "authority_granted",
    "execution_authority_granted",
    "licence_granted",
    "governance_superseded",
}
_LIFECYCLE_SNAPSHOT_FIELDS = {
    "schema_status",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "implementation_order",
    "request_fingerprint",
    "state_hash",
    "evaluation_time",
    "prior_lifecycle_digest",
    "three_p_core_result",
    "three_p_core_digest",
    "three_p_trace_hash",
    "three_p_trace",
    "skg_result",
    "skg_digest",
    "skg_record",
    "governance_result",
}
_LIFECYCLE_SOURCE_FIELDS = {
    "schema_status",
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "lifecycle_engine",
    "lifecycle_engine_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_lifecycle_digest",
    "three_p_core_digest",
    "three_p_trace_hash",
    "skg_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
}
_LIFECYCLE_DETERMINATION_FIELDS = {
    "result",
    "transition_beyond_current_ai_paradigms_modelled",
    "full_lifecycle_governance_envelope_secured",
    "lawful_authority_continuity_preserved",
    "violent_or_coercive_interaction_prohibited",
    "bound_to_three_p",
    "bound_to_skg",
    "authority_granted",
    "execution_authority_granted",
    "licence_granted",
    "governance_superseded",
    "evidence_references",
}
_GOVERNANCE_INTEGRITY_RECORD_FIELDS = {
    "schema_status",
    "result_vocabulary_authority",
    "governance_integrity_function",
    "function_id",
    "stage",
    "evaluation_sequence",
    "implementation_order_authority",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "evidence_references",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
}
_GOVERNANCE_INTEGRITY_DETERMINATION_FIELDS = {
    "result",
    "evidence_references",
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
}
_GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS = (
    "authority_granted",
    "licence_granted",
    "execution_authority_granted",
    "effect_granted",
    "bypass_permitted",
)


def _safe_integrity_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _exact_text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _signature_envelope_exact(value: Any) -> bool:
    if (
        type(value) is dict
        and value.get("schema_id") == HYBRID_ENVELOPE_SCHEMA_ID
    ):
        return hybrid_envelope_shape_exact(value)
    if type(value) is not dict or set(value) != {
        "provider_id",
        "algorithm",
        "key_id",
        "custody_class",
        "effect_authority",
        "signature_b64",
    }:
        return False
    if not all(
        _exact_text(value.get(field))
        for field in ("provider_id", "algorithm", "key_id", "custody_class")
    ):
        return False
    # The unversioned Ed25519 envelope is retained only as a legacy,
    # explicitly non-effect representation.
    if value.get("algorithm") != "Ed25519" or value.get("effect_authority") is not False:
        return False
    encoded = value.get("signature_b64")
    if not _exact_text(encoded):
        return False
    try:
        return bool(base64.b64decode(encoded, validate=True))
    except (binascii.Error, ValueError):
        return False


def _signed_source_digest_exact(source: dict[str, Any]) -> bool:
    unsigned = {
        key: value
        for key, value in source.items()
        if key not in {"digest", "signature", "verified"}
    }
    return source.get("digest") == _safe_integrity_hash(unsigned)


def _skg_evidence_exact(value: Any) -> bool:
    if type(value) is not list or len(value) != len(SKG_CONTENT_CLASSES):
        return False
    if [
        item.get("content_class") if type(item) is dict else None
        for item in value
    ] != list(SKG_CONTENT_CLASSES):
        return False
    evidence_ids: set[str] = set()
    for item in value:
        if type(item) is not dict or set(item) != {
            "content_class",
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        evidence_id = item.get("evidence_id")
        if not _exact_text(evidence_id) or evidence_id in evidence_ids:
            return False
        evidence_ids.add(evidence_id)
        if not _exact_text(item.get("source")) or not is_sha512(
            item.get("digest")
        ):
            return False
    return True


def _expected_skg_token_payload(
    state: Dict[str, Any], issued_chain_index: int
) -> dict[str, Any] | None:
    try:
        trace = state.get("skg_authority_trace")
        record = state.get("skg_authority_record")
        chain = state.get("hash_chain")
        if (
            type(trace) is not list
            or not trace
            or type(record) is not dict
            or record != trace[-1]
            or set(record) != _SKG_RECORD_FIELDS
            or state.get("skg_authority_result") != SKG_PASS
            or state.get("skg_authority_reason")
            != "SKG_AUTHORITY_EVALUATION_COMPLETED"
            or state.get("skg_authority_granted") is not False
            or state.get("skg_execution_authority_granted") is not False
            or state.get("skg_downstream_override_permitted") is not False
            or state.get("skg_authority_digest")
            != _safe_integrity_hash(record)
            or state.get("skg_authority_trace_digest")
            != _safe_integrity_hash(trace)
            or type(chain) is not list
            or issued_chain_index < 2
            or issued_chain_index >= len(chain)
        ):
            return None
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if (
            record.get("contract_id") != SKG_V2_CONTRACT_ID
            or record.get("schema_status") != SKG_SCHEMA_STATUS
            or record.get("content_classes") != list(SKG_CONTENT_CLASSES)
            or record.get("stage") != "constitutional_authority_substrate"
            or record.get("evaluation_sequence") != len(trace)
            or record.get("result") != SKG_PASS
            or record.get("reason") != "SKG_AUTHORITY_EVALUATION_COMPLETED"
            or record.get("authority_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("downstream_override_permitted") is not False
            or type(snapshot) is not dict
            or set(snapshot) != _SKG_SNAPSHOT_FIELDS
            or type(source) is not dict
            or set(source) != _SKG_SOURCE_FIELDS
            or record.get("evaluation_snapshot_digest")
            != _safe_integrity_hash(snapshot)
            or record.get("evaluation_source_digest")
            != _safe_integrity_hash(source)
        ):
            return None
        determination = source.get("determination")
        class_results = (
            determination.get("content_class_results")
            if type(determination) is dict
            else None
        )
        evidence = (
            determination.get("evidence_references")
            if type(determination) is dict
            else None
        )
        if (
            snapshot.get("contract_id") != SKG_V2_CONTRACT_ID
            or snapshot.get("schema_status") != SKG_SCHEMA_STATUS
            or snapshot.get("content_classes") != list(SKG_CONTENT_CLASSES)
            or snapshot.get("stage") != record.get("stage")
            or snapshot.get("evaluation_sequence")
            != record.get("evaluation_sequence")
            or snapshot.get("request_fingerprint")
            != state.get("request_fingerprint")
            or snapshot.get("evaluation_time") != state.get("evaluation_time")
            or not is_sha512(snapshot.get("request_fingerprint"))
            or type(snapshot.get("evaluation_time")) is not int
            or snapshot.get("evaluation_time") < 0
            or (
                snapshot.get("prior_skg_digest") is not None
                and not is_sha512(snapshot.get("prior_skg_digest"))
            )
            or source.get("contract_id") != SKG_V2_CONTRACT_ID
            or source.get("schema_status") != SKG_SCHEMA_STATUS
            or not _exact_text(source.get("evaluator_id"))
            or not _exact_text(source.get("evaluator_version"))
            or source.get("authority_credential", {}).get("authority_role")
            != SKG_AUTHORITY_ROLE
            or not _exact_text(
                source.get("authority_credential", {}).get("credential_id")
            )
            or source.get("stage") != snapshot.get("stage")
            or source.get("evaluation_sequence")
            != snapshot.get("evaluation_sequence")
            or source.get("request_fingerprint")
            != snapshot.get("request_fingerprint")
            or source.get("pre_evaluation_state_hash")
            != snapshot.get("pre_evaluation_state_hash")
            or source.get("evaluation_time") != snapshot.get("evaluation_time")
            or source.get("prior_skg_digest")
            != snapshot.get("prior_skg_digest")
            or source.get("snapshot_digest")
            != _safe_integrity_hash(snapshot)
            or not _signed_source_digest_exact(source)
            or not _signature_envelope_exact(source.get("signature"))
            or type(determination) is not dict
            or set(determination) != _SKG_DETERMINATION_FIELDS
            or determination.get("result") != SKG_PASS
            or type(class_results) is not dict
            or tuple(class_results) != SKG_CONTENT_CLASSES
            or any(value != SKG_SATISFIED for value in class_results.values())
            or not _skg_evidence_exact(evidence)
            or determination.get("authority_granted") is not False
            or determination.get("execution_authority_granted") is not False
            or determination.get("downstream_override_permitted") is not False
            or record.get("evidence_references") != evidence
        ):
            return None
        expected_payload = skg_authority_hash_payload(state)
        pre_entry = chain[issued_chain_index - 2]
        entry = chain[issued_chain_index - 1]
        post_entry = chain[issued_chain_index]
        if (
            pre_entry.get("stage")
            != "three_p_core:skg_authority:constitutional_authority_substrate"
            or entry.get("stage")
            != "skg_authority:constitutional_authority_substrate"
            or entry.get("previous_hash")
            != snapshot.get("pre_evaluation_state_hash")
            or entry.get("payload_hash")
            != _safe_integrity_hash(expected_payload)
            or post_entry.get("stage")
            != (
                "three_p_core:skg_authority:"
                "constitutional_authority_substrate:post"
            )
        ):
            return None
        return expected_payload
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _lifecycle_evidence_exact(value: Any) -> bool:
    if type(value) is not list or not value:
        return False
    evidence_ids: set[str] = set()
    for item in value:
        if type(item) is not dict or set(item) != {
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        evidence_id = item.get("evidence_id")
        if not _exact_text(evidence_id) or evidence_id in evidence_ids:
            return False
        evidence_ids.add(evidence_id)
        if not _exact_text(item.get("source")) or not is_sha512(
            item.get("digest")
        ):
            return False
    return True


def _lifecycle_prefix_payload(
    state: Dict[str, Any], sequence: int
) -> dict[str, Any] | None:
    try:
        trace = state.get("filed_lifecycle_trace")
        results = state.get("filed_lifecycle_results")
        if (
            type(trace) is not list
            or len(trace) < sequence
            or type(results) is not dict
            or state.get("filed_lifecycle_digest")
            != _safe_integrity_hash(trace)
        ):
            return None
        prior_digest: str | None = None
        for index in range(sequence):
            record = trace[index]
            engine = FILED_LIFECYCLE_ORDER[index]
            engine_id = FILED_LIFECYCLE_ENGINE_IDS[engine]
            stage = FILED_LIFECYCLE_STAGES[engine]
            if type(record) is not dict or set(record) != _LIFECYCLE_RECORD_FIELDS:
                return None
            snapshot = record.get("evaluation_snapshot")
            source = record.get("evaluation_source")
            if (
                record.get("schema_status") != FILED_LIFECYCLE_SCHEMA_STATUS
                or record.get("lifecycle_engine") != engine
                or record.get("lifecycle_engine_id") != engine_id
                or record.get("stage") != stage
                or record.get("evaluation_sequence") != index + 1
                or record.get("implementation_order_authority")
                != FILED_LIFECYCLE_ORDER_AUTHORITY
                or record.get("result") != LIFECYCLE_PASS
                or record.get("authority_granted") is not False
                or record.get("execution_authority_granted") is not False
                or record.get("licence_granted") is not False
                or record.get("governance_superseded") is not False
                or results.get(engine) != LIFECYCLE_PASS
                or type(snapshot) is not dict
                or set(snapshot) != _LIFECYCLE_SNAPSHOT_FIELDS
                or type(source) is not dict
                or set(source) != _LIFECYCLE_SOURCE_FIELDS
                or record.get("evaluation_snapshot_digest")
                != _safe_integrity_hash(snapshot)
                or record.get("evaluation_source_digest")
                != _safe_integrity_hash(source)
            ):
                return None
            determination = source.get("determination")
            evidence = (
                determination.get("evidence_references")
                if type(determination) is dict
                else None
            )
            three_p_trace = snapshot.get("three_p_trace")
            if (
                snapshot.get("schema_status")
                != FILED_LIFECYCLE_SCHEMA_STATUS
                or snapshot.get("lifecycle_engine") != engine
                or snapshot.get("lifecycle_engine_id") != engine_id
                or snapshot.get("stage") != stage
                or snapshot.get("evaluation_sequence") != index + 1
                or snapshot.get("implementation_order_authority")
                != FILED_LIFECYCLE_ORDER_AUTHORITY
                or snapshot.get("implementation_order")
                != list(FILED_LIFECYCLE_ORDER)
                or snapshot.get("request_fingerprint")
                != state.get("request_fingerprint")
                or not is_sha512(snapshot.get("request_fingerprint"))
                or not is_sha512(snapshot.get("state_hash"))
                or type(snapshot.get("evaluation_time")) is not int
                or snapshot.get("evaluation_time") != state.get("evaluation_time")
                or snapshot.get("prior_lifecycle_digest") != prior_digest
                or snapshot.get("three_p_core_result") != "PASS"
                or not is_sha512(snapshot.get("three_p_core_digest"))
                or not is_sha512(snapshot.get("three_p_trace_hash"))
                or type(three_p_trace) is not list
                or not three_p_trace
                or type(three_p_trace[-1]) is not dict
                or three_p_trace[-1].get("three_p_core_digest")
                != snapshot.get("three_p_core_digest")
                or three_p_trace[-1].get("trace_hash")
                != snapshot.get("three_p_trace_hash")
                or snapshot.get("skg_result") != SKG_PASS
                or snapshot.get("skg_digest")
                != state.get("skg_authority_digest")
                or snapshot.get("skg_record")
                != state.get("skg_authority_record")
                or _safe_integrity_hash(snapshot.get("skg_record"))
                != snapshot.get("skg_digest")
                or snapshot.get("governance_result") != "ALLOW"
                or source.get("schema_status")
                != FILED_LIFECYCLE_SCHEMA_STATUS
                or source.get("lifecycle_engine") != engine
                or source.get("lifecycle_engine_id") != engine_id
                or source.get("stage") != stage
                or source.get("evaluation_sequence") != index + 1
                or source.get("implementation_order_authority")
                != FILED_LIFECYCLE_ORDER_AUTHORITY
                or source.get("request_fingerprint")
                != snapshot.get("request_fingerprint")
                or source.get("pre_evaluation_state_hash")
                != snapshot.get("state_hash")
                or source.get("evaluation_time") != snapshot.get("evaluation_time")
                or source.get("prior_lifecycle_digest") != prior_digest
                or source.get("three_p_core_digest")
                != snapshot.get("three_p_core_digest")
                or source.get("three_p_trace_hash")
                != snapshot.get("three_p_trace_hash")
                or source.get("skg_digest") != snapshot.get("skg_digest")
                or source.get("snapshot_digest")
                != _safe_integrity_hash(snapshot)
                or not _exact_text(source.get("evaluator_id"))
                or not _exact_text(source.get("evaluator_version"))
                or not _exact_text(
                    source.get("authority_credential", {}).get("credential_id")
                )
                or source.get("authority_credential", {}).get("authority_role")
                != FILED_LIFECYCLE_AUTHORITY_ROLE
                or not _signed_source_digest_exact(source)
                or not _signature_envelope_exact(source.get("signature"))
                or type(determination) is not dict
                or set(determination) != _LIFECYCLE_DETERMINATION_FIELDS
                or determination.get("result") != LIFECYCLE_PASS
                or determination.get(
                    "transition_beyond_current_ai_paradigms_modelled"
                )
                is not True
                or determination.get(
                    "full_lifecycle_governance_envelope_secured"
                )
                is not True
                or determination.get("lawful_authority_continuity_preserved")
                is not True
                or determination.get("violent_or_coercive_interaction_prohibited")
                is not True
                or determination.get("bound_to_three_p") is not True
                or determination.get("bound_to_skg") is not True
                or determination.get("authority_granted") is not False
                or determination.get("execution_authority_granted") is not False
                or determination.get("licence_granted") is not False
                or determination.get("governance_superseded") is not False
                or not _lifecycle_evidence_exact(evidence)
                or record.get("evidence_references") != evidence
            ):
                return None
            prior_digest = _safe_integrity_hash(trace[: index + 1])
            if prior_digest is None:
                return None
        record = trace[sequence - 1]
        return {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "lifecycle_engine": record.get("lifecycle_engine"),
            "lifecycle_engine_id": record.get("lifecycle_engine_id"),
            "stage": record.get("stage"),
            "evaluation_sequence": record.get("evaluation_sequence"),
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "result": LIFECYCLE_PASS,
            "reason": record.get("reason"),
            "record_digest": _safe_integrity_hash(record),
            "trace_digest": _safe_integrity_hash(trace[:sequence]),
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _expected_lifecycle_token_payload(
    state: Dict[str, Any], token_name: str, issued_chain_index: int
) -> dict[str, Any] | None:
    binding = _LIFECYCLE_TOKEN_BINDINGS.get(token_name)
    if binding is None:
        return None
    engine, _, stage = binding
    sequence = FILED_LIFECYCLE_ORDER.index(engine) + 1
    expected_payload = _lifecycle_prefix_payload(state, sequence)
    chain = state.get("hash_chain")
    if (
        expected_payload is None
        or type(chain) is not list
        or issued_chain_index < 2
        or issued_chain_index >= len(chain)
        or chain[issued_chain_index - 2].get("stage")
        != f"three_p_core:{stage}"
        or chain[issued_chain_index - 1].get("stage") != stage
        or chain[issued_chain_index].get("stage")
        != f"three_p_core:{stage}:post"
        or chain[issued_chain_index - 1].get("payload_hash")
        != _safe_integrity_hash(expected_payload)
    ):
        return None
    snapshot = state["filed_lifecycle_trace"][sequence - 1][
        "evaluation_snapshot"
    ]
    if chain[issued_chain_index - 1].get("previous_hash") != snapshot.get(
        "state_hash"
    ):
        return None
    return expected_payload


def _governance_integrity_prefix_payload(
    state: Dict[str, Any], sequence: int
) -> dict[str, Any] | None:
    try:
        trace = state.get("filed_governance_integrity_trace")
        results = state.get("filed_governance_integrity_results")
        if (
            type(trace) is not list
            or len(trace) < sequence
            or type(results) is not dict
            or state.get("filed_governance_integrity_digest")
            != _safe_integrity_hash(trace)
        ):
            return None
        prior_digest: str | None = None
        prior_revocation_sequence: int | None = None
        for index in range(sequence):
            record = trace[index]
            governance_function = FILED_GOVERNANCE_INTEGRITY_ORDER[index]
            function_id = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                governance_function
            ]
            stage = FILED_GOVERNANCE_INTEGRITY_STAGES[
                governance_function
            ]
            if (
                type(record) is not dict
                or set(record) != _GOVERNANCE_INTEGRITY_RECORD_FIELDS
                or record.get("schema_status")
                != FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS
                or record.get("result_vocabulary_authority")
                != FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
                or record.get("governance_integrity_function")
                != governance_function
                or record.get("function_id") != function_id
                or record.get("stage") != stage
                or record.get("evaluation_sequence") != index + 1
                or record.get("implementation_order_authority")
                != FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                or record.get("result") != GOVERNANCE_INTEGRITY_PASS
                or results.get(governance_function)
                != GOVERNANCE_INTEGRITY_PASS
                or any(
                    record.get(field) is not False
                    for field in _GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS
                )
            ):
                return None
            snapshot = record.get("evaluation_snapshot")
            source = record.get("evaluation_source")
            determination = (
                source.get("determination")
                if type(source) is dict
                else None
            )
            revocation = (
                snapshot.get("revocation_binding")
                if type(snapshot) is dict
                else None
            )
            three_p_trace = (
                snapshot.get("three_p_trace")
                if type(snapshot) is dict
                else None
            )
            if (
                type(snapshot) is not dict
                or type(source) is not dict
                or type(determination) is not dict
                or set(determination)
                != _GOVERNANCE_INTEGRITY_DETERMINATION_FIELDS
                or determination.get("result")
                != GOVERNANCE_INTEGRITY_PASS
                or any(
                    determination.get(field) is not False
                    for field in _GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS
                )
                or record.get("evaluation_snapshot_digest")
                != _safe_integrity_hash(snapshot)
                or record.get("evaluation_source_digest")
                != _safe_integrity_hash(source)
                or not _signed_source_digest_exact(source)
                or not _signature_envelope_exact(source.get("signature"))
                or source.get("authority_credential", {}).get(
                    "authority_role"
                )
                != FILED_GOVERNANCE_INTEGRITY_AUTHORITY_ROLE
                or snapshot.get("governance_integrity_function")
                != governance_function
                or snapshot.get("function_id") != function_id
                or snapshot.get("stage") != stage
                or snapshot.get("evaluation_sequence") != index + 1
                or snapshot.get("implementation_order_authority")
                != FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
                or snapshot.get("implementation_order")
                != list(FILED_GOVERNANCE_INTEGRITY_ORDER)
                or snapshot.get("request_fingerprint")
                != state.get("request_fingerprint")
                or snapshot.get("evaluation_time")
                != state.get("evaluation_time")
                or snapshot.get("prior_governance_integrity_digest")
                != prior_digest
                or snapshot.get("three_p_core_result") != "PASS"
                or type(three_p_trace) is not list
                or not three_p_trace
                or three_p_trace[-1].get("three_p_core_digest")
                != snapshot.get("three_p_core_digest")
                or three_p_trace[-1].get("trace_hash")
                != snapshot.get("three_p_trace_hash")
                or snapshot.get("skg_result") != SKG_PASS
                or snapshot.get("skg_digest")
                != state.get("skg_authority_digest")
                or snapshot.get("skg_record")
                != state.get("skg_authority_record")
                or type(revocation) is not dict
                or set(revocation) != {"status", "sequence", "digest"}
                or revocation.get("status") != "ACTIVE"
                or type(revocation.get("sequence")) is not int
                or revocation.get("sequence") < 0
                or revocation.get("digest")
                != _safe_integrity_hash(
                    {
                        "status": "ACTIVE",
                        "sequence": revocation.get("sequence"),
                    }
                )
                or (
                    prior_revocation_sequence is not None
                    and revocation.get("sequence")
                    < prior_revocation_sequence
                )
                or source.get("governance_integrity_function")
                != governance_function
                or source.get("function_id") != function_id
                or source.get("stage") != stage
                or source.get("evaluation_sequence") != index + 1
                or source.get("request_fingerprint")
                != snapshot.get("request_fingerprint")
                or source.get("pre_evaluation_state_hash")
                != snapshot.get("state_hash")
                or source.get("prior_governance_integrity_digest")
                != prior_digest
                or source.get("revocation_status") != "ACTIVE"
                or source.get("revocation_sequence")
                != revocation.get("sequence")
                or source.get("revocation_digest")
                != revocation.get("digest")
                or source.get("snapshot_digest")
                != _safe_integrity_hash(snapshot)
                or not _lifecycle_evidence_exact(
                    determination.get("evidence_references")
                )
                or record.get("evidence_references")
                != determination.get("evidence_references")
            ):
                return None
            prior_digest = _safe_integrity_hash(trace[: index + 1])
            prior_revocation_sequence = revocation.get("sequence")
            if prior_digest is None:
                return None
        record = trace[sequence - 1]
        return {
            "schema_status": FILED_GOVERNANCE_INTEGRITY_SCHEMA_STATUS,
            "result_vocabulary_authority": (
                FILED_GOVERNANCE_INTEGRITY_RESULT_VOCABULARY_AUTHORITY
            ),
            "governance_integrity_function": record.get(
                "governance_integrity_function"
            ),
            "function_id": record.get("function_id"),
            "stage": record.get("stage"),
            "evaluation_sequence": record.get("evaluation_sequence"),
            "implementation_order_authority": (
                FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
            ),
            "result": GOVERNANCE_INTEGRITY_PASS,
            "reason": record.get("reason"),
            "record_digest": _safe_integrity_hash(record),
            "trace_digest": _safe_integrity_hash(trace[:sequence]),
            **{
                field: False
                for field in _GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS
            },
        }
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _expected_governance_integrity_token_payload(
    state: Dict[str, Any], token_name: str, issued_chain_index: int
) -> dict[str, Any] | None:
    binding = _GOVERNANCE_INTEGRITY_TOKEN_BINDINGS.get(token_name)
    if binding is None:
        return None
    governance_function, _, stage = binding
    sequence = FILED_GOVERNANCE_INTEGRITY_ORDER.index(
        governance_function
    ) + 1
    expected_payload = _governance_integrity_prefix_payload(
        state, sequence
    )
    chain = state.get("hash_chain")
    if (
        expected_payload is None
        or type(chain) is not list
        or issued_chain_index < 2
        or issued_chain_index >= len(chain)
        or chain[issued_chain_index - 2].get("stage")
        != f"three_p_core:{stage}"
        or chain[issued_chain_index - 1].get("stage") != stage
        or chain[issued_chain_index].get("stage")
        != f"three_p_core:{stage}:post"
        or chain[issued_chain_index - 1].get("payload_hash")
        != _safe_integrity_hash(expected_payload)
    ):
        return None
    snapshot = state["filed_governance_integrity_trace"][sequence - 1][
        "evaluation_snapshot"
    ]
    if chain[issued_chain_index - 1].get("previous_hash") != snapshot.get(
        "state_hash"
    ):
        return None
    return expected_payload


def _expected_governance_token_payload(
    state: Dict[str, Any],
) -> dict[str, Any] | None:
    if len(FILED_LIFECYCLE_ORDER) != 3:
        return None
    if _lifecycle_prefix_payload(state, len(FILED_LIFECYCLE_ORDER)) is None:
        return None
    if _governance_integrity_prefix_payload(
        state, len(FILED_GOVERNANCE_INTEGRITY_ORDER)
    ) is None:
        return None
    results = state.get("filed_framework_results")
    lifecycle_results = state.get("filed_lifecycle_results")
    integrity_results = state.get("filed_governance_integrity_results")
    lifecycle_trace = state.get("filed_lifecycle_trace")
    revocation = state.get(
        "filed_governance_integrity_revocation_binding"
    )
    if (
        type(results) is not dict
        or type(lifecycle_results) is not dict
        or lifecycle_results
        != {engine: LIFECYCLE_PASS for engine in FILED_LIFECYCLE_ORDER}
        or state.get("filed_lifecycle_digest")
        != _safe_integrity_hash(lifecycle_trace)
        or type(integrity_results) is not dict
        or integrity_results
        != {
            governance_function: GOVERNANCE_INTEGRITY_PASS
            for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
        }
        or state.get("filed_governance_integrity_result")
        != GOVERNANCE_INTEGRITY_PASS
        or type(revocation) is not dict
        or revocation.get("status") != "ACTIVE"
        or any(
            state.get(f"filed_governance_integrity_{field}") is not False
            for field in _GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS
        )
    ):
        return None
    return {
        "governance_result": state.get("governance_result"),
        "governance_reason": state.get("governance_reason"),
        "governance_framework_results": {
            framework: results.get(framework)
            for framework in ("AJ-SAAF", "GALA", "ABEGF")
        },
        "filed_framework_digest": state.get("filed_framework_digest"),
        "filed_lifecycle_results": {
            engine: lifecycle_results.get(engine)
            for engine in FILED_LIFECYCLE_ORDER
        },
        "filed_lifecycle_digest": state.get("filed_lifecycle_digest"),
        "lifecycle_implementation_order_authority": (
            FILED_LIFECYCLE_ORDER_AUTHORITY
        ),
        "filed_governance_integrity_result": GOVERNANCE_INTEGRITY_PASS,
        "filed_governance_integrity_results": {
            governance_function: integrity_results.get(
                governance_function
            )
            for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
        },
        "filed_governance_integrity_digest": state.get(
            "filed_governance_integrity_digest"
        ),
        "governance_integrity_implementation_order_authority": (
            FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY
        ),
        "filed_governance_integrity_revocation_status": revocation.get(
            "status"
        ),
        "filed_governance_integrity_revocation_sequence": revocation.get(
            "sequence"
        ),
        "filed_governance_integrity_revocation_digest": revocation.get(
            "digest"
        ),
        **{
            f"filed_governance_integrity_{field}": False
            for field in _GOVERNANCE_INTEGRITY_NO_GRANT_FIELDS
        },
    }


def _foundational_bindings_valid(state: Dict[str, Any]) -> bool:
    try:
        return (
            all(
                is_sha512(state.get(field))
                for field in _APPLICATION_INTEGRITY_TOKEN_FIELDS
            )
            and type(state.get("foundational_baseline_record")) is dict
            and all(
                is_sha512(
                    state["foundational_baseline_record"].get(field)
                )
                for field in _FOUNDATIONAL_COMPONENT_TOKEN_FIELDS
            )
            and is_sha512(state.get("foundational_baseline_digest"))
            and all(
                state.get(f"foundational_baseline_{field}") is False
                for field in _FOUNDATIONAL_AUTHORITY_FIELDS
            )
            and verify_foundational_baseline(
                state,
                require_hash_binding=True,
            )
        )
    except Exception:
        return False


def _foundational_token_bindings(state: Dict[str, Any]) -> dict[str, Any]:
    record = state.get("foundational_baseline_record")
    record = record if type(record) is dict else {}
    return {
        **{
            field: state.get(field)
            for field in _APPLICATION_INTEGRITY_TOKEN_FIELDS
        },
        **{
            field: record.get(field)
            for field in _FOUNDATIONAL_COMPONENT_TOKEN_FIELDS
        },
        "foundational_baseline_digest": state.get(
            "foundational_baseline_digest"
        ),
    }


def _authority_provenance_bindings_valid(state: Dict[str, Any]) -> bool:
    try:
        bindings = authority_provenance_token_bindings(state)
        record = state.get("authority_provenance_record")
        trace = state.get("authority_provenance_trace")
        chain = state.get("hash_chain")
        return (
            bindings is not None
            and type(record) is dict
            and type(trace) is list
            and len(trace) == 1
            and record == trace[0]
            and state.get("authority_provenance_result")
            == AUTHORITY_PROVENANCE_PASS
            and record.get("result") == AUTHORITY_PROVENANCE_PASS
            and verify_hash_chain_entries(chain, state.get("state_hash"))
            and sum(
                1
                for entry in chain
                if type(entry) is dict
                and entry.get("stage") == AUTHORITY_PROVENANCE_STAGE
                and entry.get("payload_hash")
                == canonical_integrity_hash(
                    authority_provenance_hash_payload(state)
                )
            )
            == 1
        )
    except Exception:
        return False


def _three_p_token_bindings(
    state: Dict[str, Any],
    chain: list[dict[str, Any]],
) -> dict[str, Any] | None:
    try:
        record = state.get("three_p_core_record")
        if type(record) is not dict:
            return None
        stage = record.get("evaluation_stage")
        sequence = record.get("evaluation_sequence")
        digest = state.get("three_p_core_digest")
        trace_hash = state.get("three_p_trace_hash")
        if (
            not _exact_text(stage)
            or type(sequence) is not int
            or sequence < 1
            or not is_sha512(digest)
            or not is_sha512(trace_hash)
        ):
            return None
        binding_index = max(
            index
            for index, entry in enumerate(chain)
            if type(entry) is dict
            and type(entry.get("stage")) is str
            and entry["stage"].startswith("three_p_core:")
        )
        entry = chain[binding_index]
        expected_payload_hash = canonical_integrity_hash(
            {
                "evaluation_stage": stage,
                "three_p_core_digest": digest,
                "three_p_core_result": "PASS",
                "three_p_trace_hash": trace_hash,
            }
        )
        if (
            entry.get("stage") != f"three_p_core:{stage}"
            or entry.get("payload_hash") != expected_payload_hash
        ):
            return None
        return {
            "three_p_core_digest": digest,
            "three_p_trace_hash": trace_hash,
            "three_p_evaluation_stage": stage,
            "three_p_evaluation_sequence": sequence,
            "three_p_binding_chain_index": binding_index,
        }
    except (IntegrityContractError, KeyError, TypeError, ValueError):
        return None


def _token_three_p_binding_valid(
    token: dict[str, Any],
    chain: list[dict[str, Any]],
    issued_chain_index: int,
) -> bool:
    try:
        three_p_digest = token.get("three_p_core_digest")
        three_p_trace_hash = token.get("three_p_trace_hash")
        three_p_stage = token.get("three_p_evaluation_stage")
        three_p_sequence = token.get("three_p_evaluation_sequence")
        three_p_index = token.get("three_p_binding_chain_index")
        if (
            not is_sha512(three_p_digest)
            or not is_sha512(three_p_trace_hash)
            or not _exact_text(three_p_stage)
            or type(three_p_sequence) is not int
            or three_p_sequence < 1
            or type(three_p_index) is not int
            or three_p_index < 0
            or three_p_index > issued_chain_index
        ):
            return False
        three_p_entry = chain[three_p_index]
        expected_payload_hash = canonical_integrity_hash(
            {
                "evaluation_stage": three_p_stage,
                "three_p_core_digest": three_p_digest,
                "three_p_core_result": "PASS",
                "three_p_trace_hash": three_p_trace_hash,
            }
        )
        return (
            three_p_entry.get("stage") == f"three_p_core:{three_p_stage}"
            and three_p_entry.get("payload_hash") == expected_payload_hash
        )
    except (IntegrityContractError, IndexError, KeyError, TypeError, ValueError):
        return False


def _three_p_preceded_authority_provenance(
    state: Dict[str, Any],
    *,
    attestation_provider: SignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    """Verify the exact 3P state immediately preceding P0 projection.

    P0 authenticates authority projections and therefore intentionally changes
    fields in the 3P stable-state snapshot.  Its non-authorising token may bind
    that immediately preceding 3P evaluation; every later authority-bearing
    stage still requires a fresh current 3P evaluation.
    """

    try:
        provenance = state.get("authority_provenance_record")
        three_p = state.get("three_p_core_record")
        snapshot = three_p.get("evaluation_snapshot")
        chain = state.get("hash_chain")
        if (
            type(provenance) is not dict
            or type(three_p) is not dict
            or type(snapshot) is not dict
            or type(chain) is not list
        ):
            return False
        binding_index = max(
            index
            for index, entry in enumerate(chain)
            if type(entry) is dict
            and entry.get("stage")
            == f"three_p_core:{three_p.get('evaluation_stage')}"
        )
        if binding_index != len(chain) - 2:
            return False
        binding = chain[binding_index]
        provenance_snapshot = provenance.get("evaluation_snapshot")
        if (
            type(provenance_snapshot) is not dict
            or provenance_snapshot.get("pre_evaluation_state_hash")
            != binding.get("hash")
        ):
            return False
        historical = deepcopy(state)
        for field in (
            "request_fingerprint",
            "action",
            "payload",
            "context",
            "resolved_authority",
            "jurisdiction",
            "ap_acf_class",
            "ap_acf_subclass",
            "requested_autonomy_level",
            "requested_system_mode",
            "autonomy_ceiling",
            "operational_environment",
            "public_exposure",
            "operational_scope",
            "environment_modifiers",
            "deployment_restrictions",
            "deployment_scope",
            "license_profile",
            "evaluation_time",
            "current_candidate",
            "candidate_attempt_count",
        ):
            historical[field] = deepcopy(snapshot.get(field))
        for field, value in snapshot.get("active_results", {}).items():
            historical[field] = deepcopy(value)
        return verify_three_p_core(
            historical,
            attestation_provider=attestation_provider,
            require_hash_binding=True,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
    except (IntegrityContractError, KeyError, StopIteration, TypeError, ValueError):
        return False


# ─────────────────────────────────────────────
# STATE INITIALISATION
# ─────────────────────────────────────────────

def ensure_token_state(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("tokens", {})
    state.setdefault("token_stack_valid", False)
    state.setdefault("token_verification_failures", [])
    state.setdefault("token_trace", [])
    return state


# ─────────────────────────────────────────────
# TOKEN BUILD / ISSUE
# ─────────────────────────────────────────────

def build_token(
    *,
    token_name: str,
    state: Dict[str, Any],
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
    provider: SignatureProvider | None,
    three_p_attestation_provider: SignatureProvider | None,
    three_p_trust_context: HybridVerificationContext | None = None,
    three_p_owner_pinned_context_digest: str | None = None,
) -> Dict[str, Any]:
    if not is_hybrid_provider(provider):
        raise ValueError("TOKEN_ISSUANCE_HYBRID_SIGNATURE_REQUIRED")
    expected_contract = _TOKEN_ISSUANCE_CONTRACTS.get(token_name)
    if expected_contract is None:
        raise ValueError("TOKEN_NAME_NOT_ADMITTED")
    if (issuer, issued_at_stage) != expected_contract:
        raise ValueError("TOKEN_ISSUANCE_CONTRACT_MISMATCH")
    chain = state.get("hash_chain")
    state_hash = state.get("state_hash")
    if not verify_hash_chain_entries(chain, state_hash):
        raise ValueError("TOKEN_ISSUANCE_HASH_CHAIN_INVALID")
    three_p_current = (
        _three_p_preceded_authority_provenance(
            state,
            attestation_provider=three_p_attestation_provider,
            trust_context=three_p_trust_context,
            owner_pinned_context_digest=(
                three_p_owner_pinned_context_digest
            ),
        )
        if token_name == "authority_provenance"
        else verify_three_p_core(
            state,
                attestation_provider=three_p_attestation_provider,
                require_hash_binding=True,
                trust_context=three_p_trust_context,
                owner_pinned_context_digest=(
                    three_p_owner_pinned_context_digest
                ),
        )
    )
    if not three_p_current:
        raise ValueError("TOKEN_ISSUANCE_THREE_P_CORE_INVALID")
    issued_chain_index = len(chain) - 1
    issued_chain_stage = chain[issued_chain_index]["stage"]
    three_p_bindings = _three_p_token_bindings(state, chain)
    if three_p_bindings is None:
        raise ValueError("TOKEN_ISSUANCE_THREE_P_BINDING_INVALID")
    if not _foundational_bindings_valid(state):
        raise ValueError("TOKEN_ISSUANCE_FOUNDATIONAL_BASELINE_INVALID")
    foundational_bindings = _foundational_token_bindings(state)
    if token_name == "foundational":
        expected_payload = foundational_baseline_hash_payload(state)
        if (
            issued_chain_stage != FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
            or payload != expected_payload
        ):
            raise ValueError("TOKEN_ISSUANCE_FOUNDATIONAL_BINDING_INVALID")
        token_body = {
            "name": token_name,
            "request_fingerprint": state.get("request_fingerprint"),
            "issued_state_hash": state_hash,
            "issued_chain_index": issued_chain_index,
            "issued_chain_stage": issued_chain_stage,
            **three_p_bindings,
            **foundational_bindings,
            "issuer": issuer,
            "issued_at_stage": issued_at_stage,
            "payload": payload,
            **{field: False for field in _FOUNDATIONAL_AUTHORITY_FIELDS},
        }
        if set(token_body) != _FOUNDATIONAL_TOKEN_BODY_FIELDS:
            raise ValueError("TOKEN_ISSUANCE_FOUNDATIONAL_SCHEMA_INVALID")
        return build_signed_object(token_body, provider=provider)
    if not _authority_provenance_bindings_valid(state):
        raise ValueError("TOKEN_ISSUANCE_AUTHORITY_PROVENANCE_INVALID")
    provenance_bindings = authority_provenance_token_bindings(state)
    if token_name == "authority_provenance":
        expected_payload = authority_provenance_hash_payload(state)
        if (
            issued_chain_stage != AUTHORITY_PROVENANCE_STAGE
            or payload != expected_payload
        ):
            raise ValueError(
                "TOKEN_ISSUANCE_AUTHORITY_PROVENANCE_BINDING_INVALID"
            )
        token_body = {
            "name": token_name,
            "request_fingerprint": state.get("request_fingerprint"),
            "issued_state_hash": state_hash,
            "issued_chain_index": issued_chain_index,
            "issued_chain_stage": issued_chain_stage,
            **three_p_bindings,
            **foundational_bindings,
            **provenance_bindings,
            "issuer": issuer,
            "issued_at_stage": issued_at_stage,
            "payload": payload,
            **{field: False for field in _FOUNDATIONAL_AUTHORITY_FIELDS},
        }
        if set(token_body) != _AUTHORITY_PROVENANCE_TOKEN_BODY_FIELDS:
            raise ValueError(
                "TOKEN_ISSUANCE_AUTHORITY_PROVENANCE_SCHEMA_INVALID"
            )
        return build_signed_object(token_body, provider=provider)
    if token_name == "skg":
        expected_payload = _expected_skg_token_payload(
            state, issued_chain_index
        )
        if expected_payload is None or payload != expected_payload:
            raise ValueError("TOKEN_ISSUANCE_SKG_BINDING_INVALID")
    lifecycle_binding = _LIFECYCLE_TOKEN_BINDINGS.get(token_name)
    if lifecycle_binding is not None:
        expected_payload = _expected_lifecycle_token_payload(
            state, token_name, issued_chain_index
        )
        if expected_payload is None or payload != expected_payload:
            raise ValueError(
                "TOKEN_ISSUANCE_FILED_LIFECYCLE_BINDING_INVALID"
            )
    governance_integrity_binding = (
        _GOVERNANCE_INTEGRITY_TOKEN_BINDINGS.get(token_name)
    )
    if governance_integrity_binding is not None:
        expected_payload = _expected_governance_integrity_token_payload(
            state, token_name, issued_chain_index
        )
        if expected_payload is None or payload != expected_payload:
            raise ValueError(
                "TOKEN_ISSUANCE_FILED_GOVERNANCE_INTEGRITY_BINDING_INVALID"
            )
    if token_name == "governance":
        expected_payload = _expected_governance_token_payload(state)
        if expected_payload is None or payload != expected_payload:
            raise ValueError(
                "TOKEN_ISSUANCE_GOVERNANCE_LIFECYCLE_BINDING_INVALID"
            )
    filed_licence_trace = state.get("filed_licence_trace")
    if type(filed_licence_trace) is not list or not filed_licence_trace:
        raise ValueError("TOKEN_ISSUANCE_FILED_LICENCE_BINDING_MISSING")
    licence_record = filed_licence_trace[-1]
    licence_source = licence_record.get("evaluation_source")
    licence_snapshot = licence_record.get("evaluation_snapshot")
    if type(licence_source) is not dict or type(licence_snapshot) is not dict:
        raise ValueError("TOKEN_ISSUANCE_FILED_LICENCE_BINDING_INVALID")
    licence_determination = licence_source.get("determination")
    licence_bindings = licence_snapshot.get("bindings")
    if (
        type(licence_determination) is not dict
        or type(licence_bindings) is not dict
        or licence_record.get("result") != "ALLOW"
        or licence_determination.get("invalidation_status") != "VALID"
        or licence_determination.get("revocation_status") != "ACTIVE"
        or state.get("licence_invalidation_status") != "VALID"
        or state.get("licence_revocation_status") != "ACTIVE"
    ):
        raise ValueError("TOKEN_ISSUANCE_FILED_LICENCE_NOT_ACTIVE")

    token_body = {
        "name": token_name,
        "request_fingerprint": state.get("request_fingerprint"),
        "issued_state_hash": state_hash,
        "issued_chain_index": issued_chain_index,
        "issued_chain_stage": issued_chain_stage,
        **three_p_bindings,
        **foundational_bindings,
        **provenance_bindings,
        "tier": state.get("safety_profile", {}).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "licence_binding_stage": licence_record.get("stage"),
        "licence_evaluation_sequence": licence_record.get(
            "evaluation_sequence"
        ),
        "filed_licence_digest": canonical_integrity_hash(
            filed_licence_trace
        ),
        "licence_id": licence_determination.get("licence_id"),
        "license_tier": licence_determination.get("tier"),
        "licence_bindings_digest": canonical_integrity_hash(
            licence_bindings
        ),
        "licence_invalidation_status": licence_determination.get(
            "invalidation_status"
        ),
        "licence_revocation_status": licence_determination.get(
            "revocation_status"
        ),
        "licence_revocation_sequence": licence_determination.get(
            "revocation_sequence"
        ),
        "issuer": issuer,
        "issued_at_stage": issued_at_stage,
        "payload": payload,
    }

    signed = build_signed_object(token_body, provider=provider)
    return signed


def issue_token(
    state: Dict[str, Any],
    *,
    token_name: str,
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
    provider: SignatureProvider | None,
    three_p_attestation_provider: SignatureProvider | None = None,
    three_p_trust_context: HybridVerificationContext | None = None,
    three_p_owner_pinned_context_digest: str | None = None,
) -> Dict[str, Any]:
    state = ensure_token_state(state)
    if token_name in state["tokens"]:
        raise ValueError("TOKEN_ALREADY_ISSUED")

    token = build_token(
        token_name=token_name,
        state=state,
        issuer=issuer,
        issued_at_stage=issued_at_stage,
        payload=payload,
        provider=provider,
        three_p_attestation_provider=three_p_attestation_provider,
        three_p_trust_context=three_p_trust_context,
        three_p_owner_pinned_context_digest=(
            three_p_owner_pinned_context_digest
        ),
    )

    state["tokens"][token_name] = token
    state["token_trace"].append(
        {
            "event": "issued",
            "token": token_name,
            "issuer": issuer,
            "stage": issued_at_stage,
            "issued_chain_index": token["issued_chain_index"],
            "issued_chain_stage": token["issued_chain_stage"],
            "issued_state_hash": token["issued_state_hash"],
        }
    )
    return state


# ─────────────────────────────────────────────
# TOKEN VERIFICATION
# ─────────────────────────────────────────────

def verify_token(
    state: Dict[str, Any],
    token_name: str,
    *,
    provider: SignatureProvider | None,
    require_effect_authority: bool = False,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> bool:
    token = state.get("tokens", {}).get(token_name)
    if not token:
        return False

    if not verify_signed_object(
        token,
        provider=provider,
        require_effect_authority=require_effect_authority,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        allow_legacy_non_effect=False,
    ):
        return False

    if token.get("request_fingerprint") != state.get("request_fingerprint"):
        return False

    contract = _TOKEN_ISSUANCE_CONTRACTS.get(token_name)
    if contract is None or (
        token.get("issuer"),
        token.get("issued_at_stage"),
    ) != contract:
        return False

    chain = state.get("hash_chain")
    if not verify_hash_chain_entries(chain, state.get("state_hash")):
        return False
    issued_chain_index = token.get("issued_chain_index")
    if (
        type(issued_chain_index) is not int
        or issued_chain_index < 0
        or issued_chain_index >= len(chain)
    ):
        return False
    issued_entry = chain[issued_chain_index]
    issued_state_hash = token.get("issued_state_hash")
    if not is_sha512(issued_state_hash) or issued_entry["hash"] != issued_state_hash:
        return False
    if token.get("issued_chain_stage") != issued_entry["stage"]:
        return False

    if not _token_three_p_binding_valid(token, chain, issued_chain_index):
        return False
    if not _foundational_bindings_valid(state):
        return False
    foundational_bindings = _foundational_token_bindings(state)
    if any(
        token.get(field) != value
        for field, value in foundational_bindings.items()
    ):
        return False
    if token_name == "foundational":
        return (
            set(token) == _FOUNDATIONAL_TOKEN_FIELDS
            and token.get("name") == "foundational"
            and issued_entry["stage"] == FOUNDATIONAL_BASELINE_AGGREGATE_STAGE
            and token.get("payload")
            == foundational_baseline_hash_payload(state)
            and all(
                token.get(field) is False
                for field in _FOUNDATIONAL_AUTHORITY_FIELDS
            )
        )

    if not _authority_provenance_bindings_valid(state):
        return False
    provenance_bindings = authority_provenance_token_bindings(state)
    if any(
        token.get(field) != value
        for field, value in provenance_bindings.items()
    ):
        return False
    if token_name == "authority_provenance":
        return (
            set(token) == _AUTHORITY_PROVENANCE_TOKEN_FIELDS
            and token.get("name") == "authority_provenance"
            and issued_entry["stage"] == AUTHORITY_PROVENANCE_STAGE
            and token.get("payload")
            == authority_provenance_hash_payload(state)
            and all(
                token.get(field) is False
                for field in _FOUNDATIONAL_AUTHORITY_FIELDS
            )
        )

    if token_name == "skg":
        expected_payload = _expected_skg_token_payload(
            state, issued_chain_index
        )
        if expected_payload is None or token.get("payload") != expected_payload:
            return False
    if token_name in _LIFECYCLE_TOKEN_BINDINGS:
        expected_payload = _expected_lifecycle_token_payload(
            state, token_name, issued_chain_index
        )
        if expected_payload is None or token.get("payload") != expected_payload:
            return False
    if token_name in _GOVERNANCE_INTEGRITY_TOKEN_BINDINGS:
        expected_payload = _expected_governance_integrity_token_payload(
            state, token_name, issued_chain_index
        )
        if expected_payload is None or token.get("payload") != expected_payload:
            return False

    # Authority and SKG are issued before the procedural-truth threshold
    # calculation. Their signed issuance snapshots therefore cannot be
    # compared to the later, intentionally populated threshold fields.
    if token_name not in {"authority", "skg"}:
        if token.get("tier") != state.get(
            "safety_profile", {}
        ).get("computed_tier"):
            return False

        if token.get("corroboration_required") != state.get(
            "corroboration_required"
        ):
            return False

    trace = state.get("filed_licence_trace")
    licence_sequence = token.get("licence_evaluation_sequence")
    if (
        type(trace) is not list
        or type(licence_sequence) is not int
        or licence_sequence < 1
        or licence_sequence > len(trace)
        or state.get("licence_invalidation_status") != "VALID"
        or state.get("licence_revocation_status") != "ACTIVE"
    ):
        return False
    licence_record = trace[licence_sequence - 1]
    licence_source = licence_record.get("evaluation_source")
    licence_snapshot = licence_record.get("evaluation_snapshot")
    if type(licence_source) is not dict or type(licence_snapshot) is not dict:
        return False
    licence_determination = licence_source.get("determination")
    licence_bindings = licence_snapshot.get("bindings")
    if type(licence_determination) is not dict or type(licence_bindings) is not dict:
        return False
    try:
        licence_trace_digest = canonical_integrity_hash(
            trace[:licence_sequence]
        )
        licence_bindings_digest = canonical_integrity_hash(licence_bindings)
    except (IntegrityContractError, TypeError, ValueError):
        return False
    if (
        token.get("licence_binding_stage") != licence_record.get("stage")
        or token.get("filed_licence_digest") != licence_trace_digest
        or token.get("licence_id") != licence_determination.get("licence_id")
        or token.get("license_tier") != licence_determination.get("tier")
        or token.get("licence_bindings_digest") != licence_bindings_digest
        or token.get("licence_invalidation_status") != "VALID"
        or token.get("licence_revocation_status") != "ACTIVE"
        or token.get("licence_revocation_sequence")
        != licence_determination.get("revocation_sequence")
    ):
        return False

    if token_name in {"authority", "licensing"}:
        required_length = 1 if token_name == "authority" else 2
        if type(trace) is not list or len(trace) < required_length:
            return False
        licence_record = trace[required_length - 1]
        source = licence_record.get("evaluation_source")
        snapshot = licence_record.get("evaluation_snapshot")
        if type(source) is not dict or type(snapshot) is not dict:
            return False
        determination = source.get("determination")
        bindings = snapshot.get("bindings")
        if type(determination) is not dict or type(bindings) is not dict:
            return False
        common_payload = {
            "licence_id": determination.get("licence_id"),
            "license_tier": determination.get("tier"),
            "filed_licence_digest": canonical_integrity_hash(
                trace[:required_length]
            ),
            "licence_bindings_digest": canonical_integrity_hash(bindings),
        }
        expected_payload = {
            **(
                {
                    "authority_first_result": state.get(
                        "authority_first_result"
                    ),
                    "authority_first_reason": state.get(
                        "authority_first_reason"
                    ),
                }
                if token_name == "authority"
                else {
                    "licensing_result": "ALLOW",
                    "licensing_reason": "license_valid",
                    "licence_revocation_status": determination.get(
                        "revocation_status"
                    ),
                    "licence_revocation_sequence": determination.get(
                        "revocation_sequence"
                    ),
                }
            ),
            **common_payload,
        }
        if token.get("payload") != expected_payload:
            return False

    framework_binding = _FRAMEWORK_TOKEN_BINDINGS.get(token_name)
    if framework_binding is not None:
        framework, framework_stage = framework_binding
        records = [
            record
            for record in state.get("filed_framework_trace", [])
            if type(record) is dict and record.get("framework") == framework
        ]
        if len(records) != 1:
            return False
        record = records[0]
        try:
            record_digest = canonical_integrity_hash(record)
        except (IntegrityContractError, TypeError, ValueError):
            return False
        if token.get("payload") != {
            "framework_result": record.get("result"),
            "framework_record_digest": record_digest,
            "evaluation_source_digest": record.get(
                "evaluation_source_digest"
            ),
            "execution_authority_granted": False,
        }:
            return False
        if (
            issued_chain_index < 2
            or chain[issued_chain_index - 2].get("stage")
            != f"three_p_core:{framework_stage}"
            or chain[issued_chain_index - 1].get("stage") != framework_stage
            or chain[issued_chain_index].get("stage")
            != f"three_p_core:{framework_stage}:post"
        ):
            return False

    if token_name == "governance":
        expected_payload = _expected_governance_token_payload(state)
        if expected_payload is None or token.get("payload") != expected_payload:
            return False

    return True


def verify_required_tokens(
    state: Dict[str, Any],
    *,
    required_threshold_tokens: List[str] | None = None,
    provider: SignatureProvider | None,
    require_effect_authority: bool = True,
    trust_context: HybridVerificationContext | None = None,
    owner_pinned_context_digest: str | None = None,
) -> Dict[str, Any]:
    state = ensure_token_state(state)

    failures: List[str] = []
    token_names = list(REQUIRED_CORE_TOKENS)

    if required_threshold_tokens:
        token_names.extend(required_threshold_tokens)

    for token_name in token_names:
        passed = verify_token(
            state,
            token_name,
            provider=provider,
            require_effect_authority=require_effect_authority,
            trust_context=trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        )
        state["token_trace"].append(
            {
                "event": "verified",
                "token": token_name,
                "passed": passed,
            }
        )
        if not passed:
            failures.append(token_name)

    core_indexes = [
        state.get("tokens", {}).get(token_name, {}).get(
            "issued_chain_index"
        )
        for token_name in REQUIRED_CORE_TOKENS
    ]
    if (
        all(type(index) is int for index in core_indexes)
        and (
            core_indexes[0] >= core_indexes[1]
            or core_indexes[1:] != sorted(core_indexes[1:])
        )
    ):
        failures.append("core_token_chronology")

    state["token_verification_failures"] = failures
    state["token_stack_valid"] = len(failures) == 0
    return state


# ─────────────────────────────────────────────
# THRESHOLD TOKEN HELPERS
# ─────────────────────────────────────────────

def get_required_threshold_tokens(state: Dict[str, Any]) -> List[str]:
    required: List[str] = []

    if state.get("safety_profile", {}).get("computed_tier"):
        required.append("consequentiality_threshold")

    if state.get("corroboration_required") is not None:
        required.append("corroboration_threshold")

    if state.get("financial_amount") is not None:
        required.append("financial_threshold")

    if state.get("autonomy_boundary_required") is True:
        required.append("autonomy_boundary_threshold")

    if state.get("escalation_threshold_required") is True:
        required.append("escalation_threshold")

    return required
