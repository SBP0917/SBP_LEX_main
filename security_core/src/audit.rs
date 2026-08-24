use serde_json::{json, Value};

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, is_sha512},
    hash_chain::verify_hash_chain,
    BoundaryError,
};

pub fn verify_terminal_audit(
    audit_record: &Value,
    audit_hash: &str,
    audit_ledger: &Value,
    live_state: &Value,
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    if !is_sha512(audit_hash) || canonical_digest(audit_record)? != audit_hash {
        return Err(BoundaryError::DigestMismatch("audit_record"));
    }
    let record = audit_record
        .as_object()
        .ok_or(BoundaryError::Malformed("audit_record"))?;
    let live = live_state
        .as_object()
        .ok_or(BoundaryError::Malformed("live_state"))?;
    for field in [
        "request_fingerprint",
        "decision",
        "execution_result",
        "execution_reason",
        "governance_result",
        "governance_reason",
        "governance_feedback",
        "three_p_core_digest",
        "three_p_trace_hash",
        "skg_authority_digest",
        "filed_framework_digest",
        "filed_lifecycle_digest",
        "filed_licence_digest",
        "licence_id",
        "license_tier",
        "licence_revocation_status",
        "licence_revocation_sequence",
        "effect_id",
        "effect_result",
        "state_hash",
    ] {
        if record.get(field) != live.get(field) {
            return Err(BoundaryError::Substitution("audit_live_binding"));
        }
    }
    if record.get("request_fingerprint").and_then(Value::as_str) != Some(request_fingerprint) {
        return Err(BoundaryError::Substitution("audit_request"));
    }
    let audited_chain = record
        .get("hash_chain")
        .ok_or(BoundaryError::Missing("audited_hash_chain"))?;
    let audited_state_hash = record
        .get("state_hash")
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Missing("audited_state_hash"))?;
    verify_hash_chain(audited_chain, audited_state_hash, request_fingerprint)?;
    let live_chain = live
        .get("hash_chain")
        .and_then(Value::as_array)
        .ok_or(BoundaryError::Missing("live_hash_chain"))?;
    let audited_entries = audited_chain
        .as_array()
        .ok_or(BoundaryError::Malformed("audited_hash_chain"))?;
    if live_chain != audited_entries {
        return Err(BoundaryError::Substitution("audit_chain_suffix"));
    }
    let ledger = audit_ledger
        .as_array()
        .filter(|ledger| !ledger.is_empty())
        .ok_or(BoundaryError::Missing("audit_ledger"))?;
    let mut previous = "GENESIS".to_owned();
    for entry in ledger {
        let object = entry
            .as_object()
            .ok_or(BoundaryError::Malformed("audit_ledger_entry"))?;
        if object.len() != 3
            || object.get("previous_ledger_hash").and_then(Value::as_str) != Some(previous.as_str())
        {
            return Err(BoundaryError::Malformed("audit_ledger_entry"));
        }
        let entry_audit_hash = object
            .get("audit_hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("audit_hash"))?;
        let ledger_hash = object
            .get("ledger_hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("ledger_hash"))?;
        let unsigned = json!({"previous_ledger_hash": previous, "audit_hash": entry_audit_hash});
        if canonical_digest(&unsigned)? != ledger_hash {
            return Err(BoundaryError::DigestMismatch("audit_ledger"));
        }
        previous = ledger_hash.to_owned();
    }
    if ledger
        .last()
        .and_then(|entry| entry.get("audit_hash"))
        .and_then(Value::as_str)
        != Some(audit_hash)
    {
        return Err(BoundaryError::Substitution("terminal_audit"));
    }
    Proof::new(Component::Audit, request_fingerprint)
}
