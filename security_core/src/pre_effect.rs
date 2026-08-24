use std::collections::HashSet;

use crate::{
    decision::{Component, Proof},
    BoundaryError,
};

const REQUIRED: [Component; 11] = [
    Component::Request,
    Component::ThreeP,
    Component::Skg,
    Component::Authority,
    Component::FiledFramework,
    Component::FiledLifecycle,
    Component::Licence,
    Component::TokenStack,
    Component::HashChain,
    Component::EffectPermit,
    Component::Revocation,
];

pub fn immediate_pre_effect_revalidation(
    proofs: &[Proof],
    request_fingerprint: &str,
) -> Result<Proof, BoundaryError> {
    let mut components = HashSet::new();
    for proof in proofs {
        if proof.request_fingerprint() != request_fingerprint {
            return Err(BoundaryError::Substitution("proof_request"));
        }
        if !components.insert(proof.component()) {
            return Err(BoundaryError::Duplicate("proof_component"));
        }
    }
    if REQUIRED
        .iter()
        .any(|component| !components.contains(component))
    {
        return Err(BoundaryError::Missing("pre_effect_prerequisite"));
    }
    Proof::new(Component::PreEffect, request_fingerprint)
}
