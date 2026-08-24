use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, constant_time_hex_equal, is_sha512},
    evidence::{evidence_references, exact_keys, nonempty_text},
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const DOCTRINE_ID: &str = "SBP_LEX_3P_CORE_FINAL_MASTER_SPEC_4_3_26";
pub const AUTHORITY_ROLE: &str = "CONSTITUTIONAL_3P_EVALUATOR";

const SOURCE_FIELDS: &[&str] = &[
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_three_p_digest",
    "snapshot_digest",
    "determinations",
    "digest",
    "signature",
    "verified",
];
const RECORD_FIELDS: &[&str] = &[
    "doctrine",
    "constitutional_layer",
    "evaluation_stage",
    "evaluator_id",
    "evaluator_version",
    "authority_role",
    "authority_credential_id",
    "evaluation_sequence",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "primitive_order",
    "primitives",
    "mechanically_constrained_processes",
    "result",
    "reason",
    "authority_granted",
];

pub fn verify_three_p_evidence(
    record: &Value,
    expected_digest: &str,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    if !is_sha512(expected_digest) || canonical_digest(record)? != expected_digest {
        return Err(BoundaryError::DigestMismatch("three_p_record"));
    }
    let object = record
        .as_object()
        .ok_or(BoundaryError::Malformed("three_p_record"))?;
    exact_keys(record, RECORD_FIELDS, "three_p_record")?;
    if object.get("doctrine").and_then(Value::as_str) != Some(DOCTRINE_ID)
        || object.get("constitutional_layer").and_then(Value::as_bool) != Some(true)
        || object.get("authority_role").and_then(Value::as_str) != Some(AUTHORITY_ROLE)
        || object.get("result").and_then(Value::as_str) != Some("PASS")
        || object.get("reason").and_then(Value::as_str) != Some("3P_CORE_SATISFIED")
        || object.get("authority_granted").and_then(Value::as_bool) != Some(false)
    {
        return Err(BoundaryError::FailedPrerequisite("three_p"));
    }
    let source = object
        .get("evaluation_source")
        .ok_or(BoundaryError::Missing("three_p_source"))?;
    exact_keys(source, SOURCE_FIELDS, "three_p_source")?;
    verify_signed_object(source, signer, false)?;
    let source_object = source
        .as_object()
        .ok_or(BoundaryError::Malformed("three_p_source"))?;
    nonempty_text(source_object, "evaluator_id")?;
    nonempty_text(source_object, "evaluator_version")?;
    if source_object
        .get("request_fingerprint")
        .and_then(Value::as_str)
        != Some(request_fingerprint)
    {
        return Err(BoundaryError::Substitution("three_p_request"));
    }
    let source_digest = canonical_digest(source)?;
    if object
        .get("evaluation_source_digest")
        .and_then(Value::as_str)
        != Some(source_digest.as_str())
        || object.get("evaluation_stage") != source_object.get("stage")
        || object.get("evaluation_sequence") != source_object.get("evaluation_sequence")
        || object.get("evaluator_id") != source_object.get("evaluator_id")
        || object.get("evaluator_version") != source_object.get("evaluator_version")
    {
        return Err(BoundaryError::Substitution("three_p_source_binding"));
    }
    let credential = source_object
        .get("authority_credential")
        .and_then(Value::as_object)
        .ok_or(BoundaryError::Malformed("three_p_authority_credential"))?;
    if credential.len() != 2
        || credential.get("credential_id") != object.get("authority_credential_id")
        || credential.get("authority_role") != object.get("authority_role")
    {
        return Err(BoundaryError::Substitution("three_p_authority_credential"));
    }
    let determinations = source_object
        .get("determinations")
        .and_then(Value::as_object)
        .ok_or(BoundaryError::Malformed("three_p_determinations"))?;
    if determinations.len() != 3
        || ["P1", "P2", "P3"]
            .iter()
            .any(|key| !determinations.contains_key(*key))
    {
        return Err(BoundaryError::Malformed("three_p_determinations"));
    }
    for primitive in ["P1", "P2", "P3"] {
        let determination = &determinations[primitive];
        exact_keys(
            determination,
            &["result", "evidence_references"],
            "three_p_determination",
        )?;
        if determination.get("result").and_then(Value::as_str) != Some("SATISFIED") {
            return Err(BoundaryError::FailedPrerequisite("three_p_primitive"));
        }
        evidence_references(&determination["evidence_references"])?;
    }
    let snapshot = object
        .get("evaluation_snapshot")
        .ok_or(BoundaryError::Missing("three_p_snapshot"))?;
    let snapshot_digest = object
        .get("evaluation_snapshot_digest")
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Missing("evaluation_snapshot_digest"))?;
    if !constant_time_hex_equal(snapshot_digest, &canonical_digest(snapshot)?) {
        return Err(BoundaryError::DigestMismatch("three_p_snapshot"));
    }
    if source_object.get("snapshot_digest").and_then(Value::as_str) != Some(snapshot_digest) {
        return Err(BoundaryError::Substitution("three_p_snapshot"));
    }
    if snapshot.get("request_fingerprint") != source_object.get("request_fingerprint")
        || snapshot.get("state_hash") != source_object.get("pre_evaluation_state_hash")
        || snapshot.get("evaluation_time") != source_object.get("evaluation_time")
        || snapshot.get("prior_three_p_digest") != source_object.get("prior_three_p_digest")
    {
        return Err(BoundaryError::Substitution("three_p_snapshot_binding"));
    }
    let primitive_order = object
        .get("primitive_order")
        .and_then(Value::as_array)
        .ok_or(BoundaryError::Malformed("three_p_primitive_order"))?;
    if primitive_order.len() != 3
        || primitive_order
            .iter()
            .zip(["P1", "P2", "P3"])
            .any(|(observed, expected)| observed.as_str() != Some(expected))
    {
        return Err(BoundaryError::WrongOrder("three_p_primitives"));
    }
    let primitives = object
        .get("primitives")
        .and_then(Value::as_array)
        .ok_or(BoundaryError::Malformed("three_p_primitives"))?;
    if primitives.len() != 3 {
        return Err(BoundaryError::Malformed("three_p_primitives"));
    }
    for (primitive, primitive_record) in ["P1", "P2", "P3"].into_iter().zip(primitives) {
        exact_keys(
            primitive_record,
            &[
                "primitive",
                "name",
                "definition",
                "result",
                "reason",
                "evidence_references",
                "evidence_digest",
                "authority_granted",
            ],
            "three_p_primitive_record",
        )?;
        let primitive_record = primitive_record
            .as_object()
            .ok_or(BoundaryError::Malformed("three_p_primitive_record"))?;
        let expected_reason = format!("{primitive}_EVALUATOR_PASS");
        if primitive_record.get("primitive").and_then(Value::as_str) != Some(primitive)
            || primitive_record.get("result").and_then(Value::as_str) != Some("PASS")
            || primitive_record.get("reason").and_then(Value::as_str)
                != Some(expected_reason.as_str())
            || primitive_record
                .get("authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
            || primitive_record.get("evidence_references")
                != determinations
                    .get(primitive)
                    .and_then(|value| value.get("evidence_references"))
        {
            return Err(BoundaryError::Substitution("three_p_primitive_record"));
        }
        let references = primitive_record
            .get("evidence_references")
            .ok_or(BoundaryError::Missing("evidence_references"))?;
        if primitive_record
            .get("evidence_digest")
            .and_then(Value::as_str)
            != Some(canonical_digest(references)?.as_str())
        {
            return Err(BoundaryError::DigestMismatch("three_p_primitive_evidence"));
        }
    }
    let processes = object
        .get("mechanically_constrained_processes")
        .and_then(Value::as_array)
        .ok_or(BoundaryError::Malformed(
            "mechanically_constrained_processes",
        ))?;
    let expected_processes = [
        "optimisation",
        "modelling",
        "routing",
        "attestation",
        "licensing",
        "escalation",
        "execution",
        "lifecycle_governance",
        "obsolescence_modelling",
        "supersession",
    ];
    if processes.len() != expected_processes.len()
        || processes
            .iter()
            .zip(expected_processes)
            .any(|(observed, expected)| observed.as_str() != Some(expected))
    {
        return Err(BoundaryError::Substitution(
            "mechanically_constrained_processes",
        ));
    }
    Proof::new(Component::ThreeP, request_fingerprint)
}
