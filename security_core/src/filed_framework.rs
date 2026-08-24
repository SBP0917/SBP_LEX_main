use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, is_sha512},
    evidence::{evidence_references, exact_keys, nonempty_text},
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const ORDER: [(&str, &str); 4] = [
    ("PTODF", "filed_framework:ptodf"),
    ("AJ-SAAF", "filed_framework:aj_saaf"),
    ("GALA", "filed_framework:gala"),
    ("ABEGF", "filed_framework:abegf"),
];

const RECORD_FIELDS: &[&str] = &[
    "framework",
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
];
const SOURCE_FIELDS: &[&str] = &[
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "framework",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_framework_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
];

pub fn verify_filed_frameworks(
    trace: &Value,
    trace_digest: &str,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    let records = trace
        .as_array()
        .ok_or(BoundaryError::Malformed("filed_framework_trace"))?;
    if records.len() != ORDER.len() {
        return Err(BoundaryError::WrongOrder("filed_framework_count"));
    }
    if !is_sha512(trace_digest) || canonical_digest(trace)? != trace_digest {
        return Err(BoundaryError::DigestMismatch("filed_framework_trace"));
    }
    for (index, (record, (framework, stage))) in records.iter().zip(ORDER).enumerate() {
        exact_keys(record, RECORD_FIELDS, "filed_framework_record")?;
        let object = record
            .as_object()
            .ok_or(BoundaryError::Malformed("filed_framework_record"))?;
        if object.get("framework").and_then(Value::as_str) != Some(framework)
            || object.get("stage").and_then(Value::as_str) != Some(stage)
            || object.get("evaluation_sequence").and_then(Value::as_u64) != Some(index as u64 + 1)
            || object.get("result").and_then(Value::as_str) != Some("PASS")
            || object.get("authority_granted").and_then(Value::as_bool) != Some(false)
            || object
                .get("execution_authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(BoundaryError::FailedPrerequisite("filed_framework"));
        }
        let snapshot = &object["evaluation_snapshot"];
        if object
            .get("evaluation_snapshot_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(snapshot)?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("filed_framework_snapshot"));
        }
        let source = &object["evaluation_source"];
        exact_keys(source, SOURCE_FIELDS, "filed_framework_source")?;
        verify_signed_object(source, signer, false)?;
        if object
            .get("evaluation_source_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(source)?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("filed_framework_source"));
        }
        let source = source
            .as_object()
            .ok_or(BoundaryError::Malformed("filed_framework_source"))?;
        nonempty_text(source, "evaluator_id")?;
        nonempty_text(source, "evaluator_version")?;
        let credential = source
            .get("authority_credential")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("framework_authority_credential"))?;
        if credential.len() != 2
            || credential.get("authority_role").and_then(Value::as_str)
                != Some("FILED_GOVERNANCE_FRAMEWORK_EVALUATOR")
            || nonempty_text(credential, "credential_id").is_err()
            || source.get("framework") != object.get("framework")
            || source.get("stage") != object.get("stage")
            || source.get("evaluation_sequence") != object.get("evaluation_sequence")
            || source.get("request_fingerprint").and_then(Value::as_str)
                != Some(request_fingerprint)
            || source.get("pre_evaluation_state_hash") != snapshot.get("state_hash")
            || source.get("evaluation_time") != snapshot.get("evaluation_time")
            || source.get("prior_framework_digest") != snapshot.get("prior_framework_digest")
            || source.get("snapshot_digest") != object.get("evaluation_snapshot_digest")
        {
            return Err(BoundaryError::Substitution(
                "filed_framework_source_binding",
            ));
        }
        let determination = source
            .get("determination")
            .and_then(Value::as_object)
            .ok_or(BoundaryError::Malformed("filed_framework_determination"))?;
        if determination.get("result").and_then(Value::as_str) != Some("PASS")
            || determination.get("evidence_references") != object.get("evidence_references")
        {
            return Err(BoundaryError::FailedPrerequisite(
                "filed_framework_determination",
            ));
        }
        evidence_references(&object["evidence_references"])?;
    }
    Proof::new(Component::FiledFramework, request_fingerprint)
}
