use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, is_sha512},
    evidence::{evidence_references, exact_keys},
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const SCHEMA_STATUS: &str = "IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_SCHEMA";
pub const ORDER_AUTHORITY: &str = "V2_IMPLEMENTATION_DEFINED_ORDER_NOT_FILED_ORDER";
pub const ORDER: [(&str, &str, &str); 3] = [
    (
        "AI Obsolescence Lifecycle & Supersession Engine",
        "AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION",
        "filed_lifecycle:ai_obsolescence_lifecycle_supersession",
    ),
    (
        "Civilisational Successor Intelligence Transition Engine",
        "CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION",
        "filed_lifecycle:civilisational_successor_intelligence_transition",
    ),
    (
        "Structured Post-AI Era Continuity Engine",
        "STRUCTURED_POST_AI_ERA_CONTINUITY",
        "filed_lifecycle:structured_post_ai_era_continuity",
    ),
];

const RECORD_FIELDS: &[&str] = &[
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
];

pub fn verify_filed_lifecycle(
    trace: &Value,
    trace_digest: &str,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    let records = trace
        .as_array()
        .ok_or(BoundaryError::Malformed("filed_lifecycle_trace"))?;
    if records.len() != ORDER.len() {
        return Err(BoundaryError::WrongOrder("filed_lifecycle_count"));
    }
    if !is_sha512(trace_digest) || canonical_digest(trace)? != trace_digest {
        return Err(BoundaryError::DigestMismatch("filed_lifecycle_trace"));
    }
    for (index, (record, (engine, engine_id, stage))) in records.iter().zip(ORDER).enumerate() {
        exact_keys(record, RECORD_FIELDS, "filed_lifecycle_record")?;
        let object = record
            .as_object()
            .ok_or(BoundaryError::Malformed("filed_lifecycle_record"))?;
        if object.get("schema_status").and_then(Value::as_str) != Some(SCHEMA_STATUS)
            || object
                .get("implementation_order_authority")
                .and_then(Value::as_str)
                != Some(ORDER_AUTHORITY)
            || object.get("lifecycle_engine").and_then(Value::as_str) != Some(engine)
            || object.get("lifecycle_engine_id").and_then(Value::as_str) != Some(engine_id)
            || object.get("stage").and_then(Value::as_str) != Some(stage)
            || object.get("evaluation_sequence").and_then(Value::as_u64) != Some(index as u64 + 1)
            || object.get("result").and_then(Value::as_str) != Some("PASS")
            || [
                "authority_granted",
                "execution_authority_granted",
                "licence_granted",
                "governance_superseded",
            ]
            .iter()
            .any(|field| object.get(*field).and_then(Value::as_bool) != Some(false))
        {
            return Err(BoundaryError::FailedPrerequisite("filed_lifecycle"));
        }
        let snapshot = &object["evaluation_snapshot"];
        if object
            .get("evaluation_snapshot_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(snapshot)?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("filed_lifecycle_snapshot"));
        }
        let source = &object["evaluation_source"];
        verify_signed_object(source, signer, false)?;
        if object
            .get("evaluation_source_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(source)?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("filed_lifecycle_source"));
        }
        evidence_references(&object["evidence_references"])?;
    }
    Proof::new(Component::FiledLifecycle, request_fingerprint)
}
