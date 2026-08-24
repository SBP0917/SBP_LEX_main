use std::collections::HashSet;

use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, is_sha512},
    evidence::{exact_keys, nonempty_text, sha512_field},
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const CONTRACT_ID: &str = "SBP_LEX_SKG_AUTHORITY_V2";
pub const SCHEMA_STATUS: &str = "IMPLEMENTATION_DEFINED_V2_MECHANICS";
pub const CONTENT_CLASSES: [&str; 7] = [
    "Authority hierarchies",
    "Jurisdictional legitimacy",
    "Statutory and constitutional precedence",
    "Procedural obligations",
    "Evidentiary sufficiency",
    "Conflict resolution precedence",
    "Treaty and delegated mandates",
];
pub const AUTHORITY_ROLE: &str = "SKG_CONSTITUTIONAL_AUTHORITY_EVALUATOR";

const RECORD_FIELDS: &[&str] = &[
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
];
const SNAPSHOT_FIELDS: &[&str] = &[
    "contract_id",
    "schema_status",
    "content_classes",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_skg_digest",
];
const SOURCE_FIELDS: &[&str] = &[
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
];

fn content_classes_exact(value: &Value) -> bool {
    value.as_array().is_some_and(|classes| {
        classes.len() == CONTENT_CLASSES.len()
            && classes
                .iter()
                .zip(CONTENT_CLASSES)
                .all(|(observed, expected)| observed.as_str() == Some(expected))
    })
}

fn skg_evidence_references(value: &Value) -> Result<(), BoundaryError> {
    let references = value
        .as_array()
        .filter(|references| references.len() == CONTENT_CLASSES.len())
        .ok_or(BoundaryError::Malformed("skg_evidence_references"))?;
    let mut identifiers = HashSet::new();
    for (reference, content_class) in references.iter().zip(CONTENT_CLASSES) {
        exact_keys(
            reference,
            &["content_class", "evidence_id", "source", "digest"],
            "skg_evidence_reference",
        )?;
        let object = reference
            .as_object()
            .ok_or(BoundaryError::Malformed("skg_evidence_reference"))?;
        if object.get("content_class").and_then(Value::as_str) != Some(content_class)
            || !identifiers.insert(nonempty_text(object, "evidence_id")?)
        {
            return Err(BoundaryError::Substitution("skg_evidence_reference"));
        }
        nonempty_text(object, "source")?;
        sha512_field(object, "digest")?;
    }
    Ok(())
}

pub fn verify_skg_evidence(
    trace: &Value,
    expected_trace_digest: &str,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    let records = trace
        .as_array()
        .filter(|records| !records.is_empty())
        .ok_or(BoundaryError::Missing("skg_trace"))?;
    if !is_sha512(expected_trace_digest) || canonical_digest(trace)? != expected_trace_digest {
        return Err(BoundaryError::DigestMismatch("skg_trace"));
    }
    let mut prior_digest: Option<String> = None;
    for (index, record) in records.iter().enumerate() {
        exact_keys(record, RECORD_FIELDS, "skg_record")?;
        let object = record
            .as_object()
            .ok_or(BoundaryError::Malformed("skg_record"))?;
        if object.get("contract_id").and_then(Value::as_str) != Some(CONTRACT_ID)
            || object.get("schema_status").and_then(Value::as_str) != Some(SCHEMA_STATUS)
            || !content_classes_exact(&object["content_classes"])
            || object.get("evaluation_sequence").and_then(Value::as_u64) != Some(index as u64 + 1)
            || object.get("result").and_then(Value::as_str) != Some("PASS")
            || object.get("reason").and_then(Value::as_str)
                != Some("SKG_AUTHORITY_EVALUATION_COMPLETED")
            || object.get("authority_granted").and_then(Value::as_bool) != Some(false)
            || object
                .get("execution_authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
            || object
                .get("downstream_override_permitted")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(BoundaryError::FailedPrerequisite("skg"));
        }
        skg_evidence_references(&object["evidence_references"])?;
        let snapshot = object
            .get("evaluation_snapshot")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("skg_snapshot"))?;
        exact_keys(
            &Value::Object(snapshot.clone()),
            SNAPSHOT_FIELDS,
            "skg_snapshot",
        )?;
        if snapshot.get("contract_id").and_then(Value::as_str) != Some(CONTRACT_ID)
            || snapshot.get("schema_status").and_then(Value::as_str) != Some(SCHEMA_STATUS)
            || !content_classes_exact(&snapshot["content_classes"])
            || snapshot.get("stage") != object.get("stage")
            || snapshot.get("evaluation_sequence") != object.get("evaluation_sequence")
            || snapshot.get("request_fingerprint").and_then(Value::as_str)
                != Some(request_fingerprint)
            || snapshot
                .get("evaluation_time")
                .and_then(Value::as_u64)
                .is_none()
        {
            return Err(BoundaryError::Substitution("skg_snapshot_binding"));
        }
        let pre_state = snapshot
            .get("pre_evaluation_state_hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("pre_evaluation_state_hash"))?;
        if pre_state != "GENESIS" && !is_sha512(pre_state) {
            return Err(BoundaryError::Malformed("pre_evaluation_state_hash"));
        }
        if snapshot.get("prior_skg_digest").and_then(Value::as_str) != prior_digest.as_deref()
            && !(prior_digest.is_none() && snapshot.get("prior_skg_digest") == Some(&Value::Null))
        {
            return Err(BoundaryError::WrongOrder("skg_trace"));
        }
        if object
            .get("evaluation_snapshot_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(&Value::Object(snapshot.clone()))?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("skg_snapshot"));
        }
        let source = object
            .get("evaluation_source")
            .ok_or(BoundaryError::Missing("skg_source"))?;
        exact_keys(source, SOURCE_FIELDS, "skg_source")?;
        verify_signed_object(source, signer, false)?;
        let source_object = source
            .as_object()
            .ok_or(BoundaryError::Malformed("skg_source"))?;
        let credential = source_object
            .get("authority_credential")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("skg_authority_credential"))?;
        if credential.len() != 2
            || credential.get("authority_role").and_then(Value::as_str) != Some(AUTHORITY_ROLE)
            || nonempty_text(credential, "credential_id").is_err()
            || source_object.get("contract_id") != object.get("contract_id")
            || source_object.get("schema_status") != object.get("schema_status")
            || source_object.get("stage") != snapshot.get("stage")
            || source_object.get("evaluation_sequence") != snapshot.get("evaluation_sequence")
            || source_object.get("request_fingerprint") != snapshot.get("request_fingerprint")
            || source_object.get("pre_evaluation_state_hash")
                != snapshot.get("pre_evaluation_state_hash")
            || source_object.get("evaluation_time") != snapshot.get("evaluation_time")
            || source_object.get("prior_skg_digest") != snapshot.get("prior_skg_digest")
            || source_object.get("snapshot_digest") != object.get("evaluation_snapshot_digest")
        {
            return Err(BoundaryError::Substitution("skg_source_binding"));
        }
        nonempty_text(source_object, "evaluator_id")?;
        nonempty_text(source_object, "evaluator_version")?;
        let determination = source_object
            .get("determination")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("skg_determination"))?;
        if determination.len() != 6
            || determination.get("result").and_then(Value::as_str) != Some("PASS")
            || determination
                .get("authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
            || determination
                .get("execution_authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
            || determination
                .get("downstream_override_permitted")
                .and_then(Value::as_bool)
                != Some(false)
            || determination.get("evidence_references") != object.get("evidence_references")
        {
            return Err(BoundaryError::FailedPrerequisite("skg_determination"));
        }
        let class_results = determination
            .get("content_class_results")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("skg_content_class_results"))?;
        if class_results.len() != CONTENT_CLASSES.len()
            || CONTENT_CLASSES.iter().any(|content_class| {
                class_results.get(*content_class).and_then(Value::as_str) != Some("SATISFIED")
            })
        {
            return Err(BoundaryError::FailedPrerequisite("skg_content_classes"));
        }
        let source_digest = object
            .get("evaluation_source_digest")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Missing("evaluation_source_digest"))?;
        if canonical_digest(source)? != source_digest {
            return Err(BoundaryError::DigestMismatch("skg_source"));
        }
        prior_digest = Some(canonical_digest(record)?);
    }
    Proof::new(Component::Skg, request_fingerprint)
}
