use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::{canonical_digest, constant_time_hex_equal, is_sha512},
    BoundaryError,
};

pub fn verify_request_fingerprint(
    request: &Value,
    fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    if !is_sha512(fingerprint) {
        return Err(BoundaryError::Malformed("request_fingerprint"));
    }
    if !constant_time_hex_equal(&canonical_digest(request)?, fingerprint) {
        return Err(BoundaryError::DigestMismatch("request_fingerprint"));
    }
    Proof::new(Component::Request, fingerprint)
}
