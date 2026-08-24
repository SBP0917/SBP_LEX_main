use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, is_sha512},
    evidence::{evidence_references, exact_keys, nonempty_text},
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const STAGES: [&str; 3] = [
    "filed_licence:root_binding",
    "filed_licence:validation",
    "filed_licence:revalidation",
];
pub const TIERS: [&str; 4] = [
    "TIER_1_PERSONAL",
    "TIER_2_COMMERCIAL",
    "TIER_3_INSTITUTIONAL",
    "TIER_4_EXTRA_TERRITORIAL",
];
pub const BINDING_FIELDS: [&str; 5] = [
    "identity",
    "jurisdiction",
    "authority_state",
    "execution_rights",
    "autonomy_level",
];

const RECORD_FIELDS: &[&str] = &[
    "stage",
    "evaluation_sequence",
    "result",
    "reason",
    "evaluation_snapshot",
    "evaluation_snapshot_digest",
    "evaluation_source",
    "evaluation_source_digest",
    "authority_granted",
    "execution_authority_granted",
];
const DETERMINATION_FIELDS: &[&str] = &[
    "result",
    "licence_id",
    "tier",
    "bindings",
    "invalidation_status",
    "revocation_status",
    "revocation_sequence",
    "evidence_references",
];

pub fn verify_licence(
    trace: &Value,
    trace_digest: &str,
    expected_bindings: &Value,
    expected_action: &str,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    let records = trace
        .as_array()
        .ok_or(BoundaryError::Malformed("licence_trace"))?;
    if records.len() != STAGES.len() {
        return Err(BoundaryError::WrongOrder("licence_stage_count"));
    }
    if !is_sha512(trace_digest) || canonical_digest(trace)? != trace_digest {
        return Err(BoundaryError::DigestMismatch("licence_trace"));
    }
    exact_keys(expected_bindings, &BINDING_FIELDS, "licence_bindings")?;
    let mut licence_id: Option<&str> = None;
    let mut revocation_sequence = 0_u64;
    for (index, (record, stage)) in records.iter().zip(STAGES).enumerate() {
        exact_keys(record, RECORD_FIELDS, "licence_record")?;
        let object = record
            .as_object()
            .ok_or(BoundaryError::Malformed("licence_record"))?;
        if object.get("stage").and_then(Value::as_str) != Some(stage)
            || object.get("evaluation_sequence").and_then(Value::as_u64) != Some(index as u64 + 1)
            || object.get("result").and_then(Value::as_str) != Some("ALLOW")
            || object.get("authority_granted").and_then(Value::as_bool) != Some(false)
            || object
                .get("execution_authority_granted")
                .and_then(Value::as_bool)
                != Some(false)
        {
            return Err(BoundaryError::FailedPrerequisite("licence"));
        }
        let snapshot = &object["evaluation_snapshot"];
        let snapshot_digest = canonical_digest(snapshot)?;
        if object
            .get("evaluation_snapshot_digest")
            .and_then(Value::as_str)
            != Some(snapshot_digest.as_str())
        {
            return Err(BoundaryError::DigestMismatch("licence_snapshot"));
        }
        let source = &object["evaluation_source"];
        verify_signed_object(source, signer, false)?;
        let source_digest = canonical_digest(source)?;
        if object
            .get("evaluation_source_digest")
            .and_then(Value::as_str)
            != Some(source_digest.as_str())
        {
            return Err(BoundaryError::DigestMismatch("licence_source"));
        }
        let determination = source
            .get("determination")
            .ok_or(BoundaryError::Missing("licence_determination"))?;
        exact_keys(determination, DETERMINATION_FIELDS, "licence_determination")?;
        let determination = determination
            .as_object()
            .ok_or(BoundaryError::Malformed("licence_determination"))?;
        let observed_id = nonempty_text(determination, "licence_id")?;
        if licence_id.is_some_and(|expected| expected != observed_id) {
            return Err(BoundaryError::Substitution("licence_id"));
        }
        licence_id = Some(observed_id);
        if determination.get("result").and_then(Value::as_str) != Some("ALLOW")
            || !TIERS.contains(
                &determination
                    .get("tier")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
            || determination.get("bindings") != Some(expected_bindings)
            || determination
                .get("invalidation_status")
                .and_then(Value::as_str)
                != Some("VALID")
            || determination
                .get("revocation_status")
                .and_then(Value::as_str)
                != Some("ACTIVE")
        {
            return Err(BoundaryError::FailedPrerequisite(
                "licence_status_or_binding",
            ));
        }
        let sequence = determination
            .get("revocation_sequence")
            .and_then(Value::as_u64)
            .ok_or(BoundaryError::Malformed("revocation_sequence"))?;
        if sequence < revocation_sequence {
            return Err(BoundaryError::Rollback);
        }
        revocation_sequence = sequence;
        evidence_references(&determination["evidence_references"])?;
        let allowed = determination["bindings"]["execution_rights"]["allowed_actions"]
            .as_array()
            .ok_or(BoundaryError::Malformed("allowed_actions"))?;
        if !allowed
            .iter()
            .any(|action| action.as_str() == Some(expected_action))
        {
            return Err(BoundaryError::FailedPrerequisite("execution_right"));
        }
    }
    Proof::new(Component::Licence, request_fingerprint)
}
