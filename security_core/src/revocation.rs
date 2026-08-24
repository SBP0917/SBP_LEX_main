use crate::{
    decision::{Component, Proof},
    BoundaryError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationState {
    pub status: String,
    pub sequence: u64,
}

pub fn verify_monotonic_revocation(
    prior: &RevocationState,
    current: &RevocationState,
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    if current.sequence < prior.sequence {
        return Err(BoundaryError::Rollback);
    }
    match (prior.status.as_str(), current.status.as_str()) {
        ("ACTIVE", "ACTIVE") => Proof::new(Component::Revocation, request_fingerprint),
        ("ACTIVE" | "REVOKED", "REVOKED") => Err(BoundaryError::Revoked),
        ("REVOKED", "ACTIVE") => Err(BoundaryError::Rollback),
        _ => Err(BoundaryError::UnknownValue("revocation_status")),
    }
}
