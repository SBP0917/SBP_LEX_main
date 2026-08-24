use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, constant_time_hex_equal, is_sha512},
    BoundaryError,
};

pub fn verify_authority_binding(
    authority_state: &Value,
    expected_digest: &str,
    request_fingerprint: &str,
    bound_request_fingerprint: &str,
    result: &str,
) -> Result<Proof, BoundaryError> {
    if result != "ALLOW" {
        return Err(BoundaryError::FailedPrerequisite("authority_state"));
    }
    if request_fingerprint != bound_request_fingerprint {
        return Err(BoundaryError::Substitution("authority_request"));
    }
    if !is_sha512(expected_digest)
        || !constant_time_hex_equal(&canonical_digest(authority_state)?, expected_digest)
    {
        return Err(BoundaryError::DigestMismatch("authority_state"));
    }
    Proof::new(Component::Authority, request_fingerprint)
}
