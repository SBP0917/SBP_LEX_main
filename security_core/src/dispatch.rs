use crate::{
    decision::{Component, Proof},
    BoundaryError, ClosedDecision,
};

pub trait EffectHandler {
    fn dispatch(&mut self) -> Result<(), BoundaryError>;
}

pub fn dispatch_existing_authorization(
    pre_effect: Option<&Proof>,
    replay: Option<&Proof>,
    request_fingerprint: &str,
    handler: &mut dyn EffectHandler,
) -> ClosedDecision {
    let pre_effect = match pre_effect {
        Some(proof)
            if proof.component() == Component::PreEffect
                && proof.request_fingerprint() == request_fingerprint =>
        {
            proof
        }
        _ => return ClosedDecision::Deny(BoundaryError::Missing("pre_effect_proof")),
    };
    let replay = match replay {
        Some(proof)
            if proof.component() == Component::Replay
                && proof.request_fingerprint() == request_fingerprint =>
        {
            proof
        }
        _ => return ClosedDecision::Deny(BoundaryError::Missing("replay_proof")),
    };
    let _ = (pre_effect, replay);
    match handler.dispatch() {
        Ok(()) => ClosedDecision::PermitExistingAuthorization,
        Err(error) => ClosedDecision::Deny(error),
    }
}
