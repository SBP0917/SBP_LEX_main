use serde_json::{json, Value};

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, constant_time_hex_equal, is_sha512},
    BoundaryError,
};

pub const GENESIS: &str = "GENESIS";

pub fn verify_hash_chain(
    chain: &Value,
    state_hash: &str,
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    verify_hash_chain_inner(chain, state_hash, None)?;
    Proof::new(Component::HashChain, request_fingerprint)
}

pub fn verify_exact_hash_chain(
    chain: &Value,
    state_hash: &str,
    exact_stages: &[&str],
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    verify_hash_chain_inner(chain, state_hash, Some(exact_stages))?;
    Proof::new(Component::HashChain, request_fingerprint)
}

fn verify_hash_chain_inner(
    chain: &Value,
    state_hash: &str,
    exact_stages: Option<&[&str]>,
) -> Result<(), BoundaryError> {
    let entries = chain
        .as_array()
        .filter(|entries| !entries.is_empty())
        .ok_or(BoundaryError::Missing("hash_chain"))?;
    if let Some(stages) = exact_stages {
        if entries.len() != stages.len() {
            return Err(BoundaryError::WrongOrder("hash_chain_stage_count"));
        }
    }
    let mut previous = GENESIS.to_owned();
    for (index, entry) in entries.iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or(BoundaryError::Malformed("hash_chain_entry"))?;
        let exact_fields = ["stage", "previous_hash", "payload_hash", "hash"];
        if object.len() != exact_fields.len()
            || exact_fields.iter().any(|key| !object.contains_key(*key))
        {
            return Err(BoundaryError::Malformed("hash_chain_entry"));
        }
        let stage = object
            .get("stage")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(BoundaryError::Malformed("hash_chain_stage"))?;
        if exact_stages.is_some_and(|stages| stages[index] != stage) {
            return Err(BoundaryError::WrongOrder("hash_chain_stage"));
        }
        if object.get("previous_hash").and_then(Value::as_str) != Some(previous.as_str()) {
            return Err(BoundaryError::DigestMismatch("hash_chain_link"));
        }
        let payload_hash = object
            .get("payload_hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("payload_hash"))?;
        let observed = object
            .get("hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("hash"))?;
        if !is_sha512(payload_hash) || !is_sha512(observed) {
            return Err(BoundaryError::Malformed("hash_chain_digest"));
        }
        let unsigned = json!({
            "stage": stage,
            "previous_hash": previous,
            "payload_hash": payload_hash,
        });
        let expected = canonical_digest(&unsigned)?;
        if !constant_time_hex_equal(observed, &expected) {
            return Err(BoundaryError::DigestMismatch("hash_chain_entry"));
        }
        previous = observed.to_owned();
    }
    if !constant_time_hex_equal(state_hash, &previous) {
        return Err(BoundaryError::DigestMismatch("state_hash"));
    }
    Ok(())
}

pub fn build_entry(
    previous_hash: &str,
    stage: &str,
    payload: &Value,
) -> Result<Value, BoundaryError> {
    if (previous_hash != GENESIS && !is_sha512(previous_hash)) || stage.is_empty() {
        return Err(BoundaryError::Malformed("hash_chain_entry_input"));
    }
    let mut entry = json!({
        "stage": stage,
        "previous_hash": previous_hash,
        "payload_hash": canonical_digest(payload)?,
    });
    let hash = canonical_digest(&entry)?;
    entry
        .as_object_mut()
        .ok_or(BoundaryError::Malformed("hash_chain_entry"))?
        .insert("hash".to_owned(), Value::String(hash));
    Ok(entry)
}
