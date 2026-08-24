use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::is_sha512,
    evidence::exact_keys,
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const PERMIT_SCHEMA: &str = "SBP_LEX_LOCAL_EFFECT_PERMIT_V1";

const PERMIT_FIELDS: &[&str] = &[
    "schema",
    "permit_id",
    "request_fingerprint",
    "issued_state_hash",
    "action",
    "payload_digest",
    "candidate_digest",
    "authority_digest",
    "jurisdiction_digest",
    "three_p_core_digest",
    "three_p_trace_hash",
    "skg_authority_digest",
    "skg_authority_trace_digest",
    "filed_lifecycle_digest",
    "filed_licence_digest",
    "license_tier",
    "licence_id",
    "licence_bindings_digest",
    "licence_revocation_status",
    "licence_revocation_sequence",
    "licence_point_of_use_evidence_digest",
    "licence_point_of_use_revocation_sequence",
    "filed_framework_digest",
    "token_stack_digest",
    "adapter_id",
    "handler_id",
    "effect_id",
    "issued_chain_index",
    "issued_chain_stage",
    "issued_at_ms",
    "expires_at_ms",
    "digest",
    "signature",
    "verified",
];

const EXPECTED_BINDING_FIELDS: &[&str] = &[
    "request_fingerprint",
    "issued_state_hash",
    "action",
    "payload_digest",
    "candidate_digest",
    "authority_digest",
    "jurisdiction_digest",
    "three_p_core_digest",
    "three_p_trace_hash",
    "skg_authority_digest",
    "skg_authority_trace_digest",
    "filed_lifecycle_digest",
    "filed_licence_digest",
    "license_tier",
    "licence_id",
    "licence_bindings_digest",
    "licence_revocation_status",
    "licence_revocation_sequence",
    "licence_point_of_use_evidence_digest",
    "licence_point_of_use_revocation_sequence",
    "filed_framework_digest",
    "token_stack_digest",
    "adapter_id",
    "handler_id",
    "effect_id",
];

pub fn verify_effect_permit(
    permit: &Value,
    expected_binding: &Value,
    hash_chain: &Value,
    now_ms: u64,
    maximum_ttl_ms: u64,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
) -> Result<Proof, BoundaryError> {
    exact_keys(permit, PERMIT_FIELDS, "effect_permit")?;
    verify_signed_object(permit, signer, true)?;
    let object = permit
        .as_object()
        .ok_or(BoundaryError::Malformed("effect_permit"))?;
    if object.get("schema").and_then(Value::as_str) != Some(PERMIT_SCHEMA)
        || object.get("request_fingerprint").and_then(Value::as_str) != Some(request_fingerprint)
    {
        return Err(BoundaryError::Substitution("effect_permit"));
    }
    let permit_id = object
        .get("permit_id")
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Malformed("permit_id"))?;
    if permit_id.len() != 32
        || !permit_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BoundaryError::Malformed("permit_id"));
    }
    let issued_at = object
        .get("issued_at_ms")
        .and_then(Value::as_u64)
        .ok_or(BoundaryError::Malformed("issued_at_ms"))?;
    let expires_at = object
        .get("expires_at_ms")
        .and_then(Value::as_u64)
        .ok_or(BoundaryError::Malformed("expires_at_ms"))?;
    if expires_at <= issued_at || expires_at - issued_at > maximum_ttl_ms {
        return Err(BoundaryError::Malformed("permit_time_window"));
    }
    if now_ms < issued_at {
        return Err(BoundaryError::NotYetValid);
    }
    if now_ms >= expires_at {
        return Err(BoundaryError::Expired);
    }
    exact_keys(
        expected_binding,
        EXPECTED_BINDING_FIELDS,
        "expected_effect_binding",
    )?;
    let expected = expected_binding
        .as_object()
        .ok_or(BoundaryError::Malformed("expected_effect_binding"))?;
    for (field, value) in expected {
        if object.get(field) != Some(value) {
            return Err(BoundaryError::Substitution("effect_permit_binding"));
        }
    }
    let chain = hash_chain
        .as_array()
        .ok_or(BoundaryError::Malformed("hash_chain"))?;
    let index = usize::try_from(
        object
            .get("issued_chain_index")
            .and_then(Value::as_u64)
            .ok_or(BoundaryError::Malformed("issued_chain_index"))?,
    )
    .map_err(|_| BoundaryError::Malformed("issued_chain_index"))?;
    let entry = chain
        .get(index)
        .ok_or(BoundaryError::Substitution("permit_chain_index"))?;
    let issued_state_hash = object
        .get("issued_state_hash")
        .and_then(Value::as_str)
        .ok_or(BoundaryError::Malformed("issued_state_hash"))?;
    if !is_sha512(issued_state_hash)
        || entry.get("hash").and_then(Value::as_str) != Some(issued_state_hash)
        || entry.get("stage") != object.get("issued_chain_stage")
    {
        return Err(BoundaryError::Substitution("permit_chain_binding"));
    }
    Proof::new(Component::EffectPermit, request_fingerprint)
}
