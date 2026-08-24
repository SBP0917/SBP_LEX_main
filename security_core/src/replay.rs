use crate::{
    decision::{Component, Proof},
    BoundaryError,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ClaimResult {
    Claimed,
    AlreadyClaimed,
}

pub trait DurableReplayStore {
    fn claim_once(
        &mut self,
        namespace: &str,
        identifier: &str,
    ) -> Result<ClaimResult, BoundaryError>;
}

pub fn claim_replay_slot(
    store: Option<&mut dyn DurableReplayStore>,
    namespace: &str,
    identifier: &str,
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    if namespace.is_empty() || identifier.is_empty() {
        return Err(BoundaryError::Malformed("replay_key"));
    }
    let store = store.ok_or(BoundaryError::Missing("durable_replay_store"))?;
    match store.claim_once(namespace, identifier)? {
        ClaimResult::Claimed => Proof::new(Component::Replay, request_fingerprint),
        ClaimResult::AlreadyClaimed => Err(BoundaryError::Replay),
    }
}
