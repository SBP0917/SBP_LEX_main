use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::{
    decision::{Component, Proof},
    digest::is_sha512,
    signature::{verify_signed_object, SignerExpectation},
    BoundaryError,
};

pub const REQUIRED_CORE_TOKENS: [&str; 17] = [
    "authority",
    "skg",
    "procedural_truth",
    "ptodf",
    "classification",
    "licensing",
    "aj_saaf",
    "gala",
    "abegf",
    "ai_obsolescence_lifecycle_supersession",
    "civilisational_successor_intelligence_transition",
    "structured_post_ai_era_continuity",
    "governance",
    "domain",
    "aurion",
    "execution_boundary",
    "execution_attestation",
];

pub const REQUIRED_THRESHOLD_TOKENS: [&str; 3] = [
    "consequentiality_threshold",
    "corroboration_threshold",
    "financial_threshold",
];

pub const CONDITIONAL_TOKENS: [&str; 2] = ["autonomy_boundary_threshold", "escalation_threshold"];

fn contracts() -> HashMap<&'static str, (&'static str, &'static str)> {
    HashMap::from([
        ("authority", ("root_of_trust", "root_of_trust")),
        ("skg", ("skg_authority", "skg_authority")),
        (
            "procedural_truth",
            ("procedural_truth_engine", "procedural_truth"),
        ),
        ("ptodf", ("PTODF", "filed_framework:ptodf")),
        (
            "classification",
            ("classification_engine", "classification"),
        ),
        ("licensing", ("licensing_engine", "licensing")),
        ("aj_saaf", ("AJ-SAAF", "filed_framework:aj_saaf")),
        ("gala", ("GALA", "filed_framework:gala")),
        ("abegf", ("ABEGF", "filed_framework:abegf")),
        (
            "ai_obsolescence_lifecycle_supersession",
            (
                "AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION",
                "filed_lifecycle:ai_obsolescence_lifecycle_supersession",
            ),
        ),
        (
            "civilisational_successor_intelligence_transition",
            (
                "CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION",
                "filed_lifecycle:civilisational_successor_intelligence_transition",
            ),
        ),
        (
            "structured_post_ai_era_continuity",
            (
                "STRUCTURED_POST_AI_ERA_CONTINUITY",
                "filed_lifecycle:structured_post_ai_era_continuity",
            ),
        ),
        ("governance", ("governance_engine", "governance")),
        ("domain", ("domain_wrap", "domain_wrap")),
        ("aurion", ("aurion15_runtime", "aurion_runtime")),
        ("execution_boundary", ("execution_gate", "execution_prep")),
        (
            "execution_attestation",
            ("execution_gate", "execution_prep"),
        ),
        (
            "consequentiality_threshold",
            ("threshold_engine", "procedural_truth"),
        ),
        (
            "corroboration_threshold",
            ("threshold_engine", "procedural_truth"),
        ),
        (
            "financial_threshold",
            ("threshold_engine", "procedural_truth"),
        ),
        (
            "autonomy_boundary_threshold",
            ("threshold_engine", "procedural_truth"),
        ),
        (
            "escalation_threshold",
            ("threshold_engine", "procedural_truth"),
        ),
    ])
}

fn verify_required_order(required_order: &[&str]) -> Result<(), BoundaryError> {
    let mandatory_len = REQUIRED_CORE_TOKENS.len() + REQUIRED_THRESHOLD_TOKENS.len();
    if required_order.len() < mandatory_len
        || required_order[..REQUIRED_CORE_TOKENS.len()] != REQUIRED_CORE_TOKENS
        || required_order[REQUIRED_CORE_TOKENS.len()..mandatory_len] != REQUIRED_THRESHOLD_TOKENS
    {
        return Err(BoundaryError::Missing("required_token_order"));
    }
    let conditional = &required_order[mandatory_len..];
    let mut prior_position = None;
    for name in conditional {
        let position = CONDITIONAL_TOKENS
            .iter()
            .position(|candidate| candidate == name)
            .ok_or(BoundaryError::UnknownValue("conditional_token_name"))?;
        if prior_position.is_some_and(|prior| position <= prior) {
            return Err(BoundaryError::WrongOrder("conditional_token_order"));
        }
        prior_position = Some(position);
    }
    Ok(())
}

fn same_stage_rank(name: &str) -> u8 {
    match name {
        "corroboration_threshold" | "execution_attestation" => 1,
        "financial_threshold" => 2,
        _ => 0,
    }
}

pub fn verify_token_stack(
    tokens: &Value,
    token_trace: &Value,
    required_order: &[&str],
    hash_chain: &Value,
    request_fingerprint: &str,
    signer: Option<&SignerExpectation>,
    require_effect_authority: bool,
) -> Result<Proof, BoundaryError> {
    verify_required_order(required_order)?;
    let tokens = tokens
        .as_object()
        .ok_or(BoundaryError::Malformed("tokens"))?;
    let trace = token_trace
        .as_array()
        .ok_or(BoundaryError::Malformed("token_trace"))?;
    if tokens.len() != required_order.len() || trace.len() != required_order.len() {
        return Err(BoundaryError::Missing("required_token"));
    }
    let mut trace_by_token = HashMap::new();
    let mut prior_trace_chain_index = 0_u64;
    let mut prior_same_stage_rank = 0_u8;
    for (position, event) in trace.iter().enumerate() {
        let event = event
            .as_object()
            .ok_or(BoundaryError::Malformed("token_trace_event"))?;
        let name = event
            .get("token")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("token_trace_token"))?;
        if !required_order.contains(&name) || trace_by_token.insert(name, event).is_some() {
            return Err(BoundaryError::Duplicate("token_trace_token"));
        }
        let chain_index = event
            .get("issued_chain_index")
            .and_then(Value::as_u64)
            .ok_or(BoundaryError::Malformed("issued_chain_index"))?;
        let rank = same_stage_rank(name);
        if position > 0
            && (chain_index < prior_trace_chain_index
                || (chain_index == prior_trace_chain_index && rank <= prior_same_stage_rank))
        {
            return Err(BoundaryError::WrongOrder("token_chronology"));
        }
        prior_trace_chain_index = chain_index;
        prior_same_stage_rank = rank;
    }
    let mut unique = HashSet::new();
    let chain = hash_chain
        .as_array()
        .ok_or(BoundaryError::Malformed("hash_chain"))?;
    let issuance_contracts = contracts();
    for name in required_order {
        if !unique.insert(*name) {
            return Err(BoundaryError::Duplicate("token_name"));
        }
        let token = tokens
            .get(*name)
            .ok_or(BoundaryError::Missing("required_token"))?;
        verify_signed_object(token, signer, require_effect_authority)?;
        let object = token.as_object().ok_or(BoundaryError::Malformed("token"))?;
        if object.get("name").and_then(Value::as_str) != Some(*name)
            || object.get("request_fingerprint").and_then(Value::as_str)
                != Some(request_fingerprint)
        {
            return Err(BoundaryError::Substitution("token"));
        }
        let contract = issuance_contracts
            .get(name)
            .ok_or(BoundaryError::UnknownValue("token_name"))?;
        if object.get("issuer").and_then(Value::as_str) != Some(contract.0)
            || object.get("issued_at_stage").and_then(Value::as_str) != Some(contract.1)
        {
            return Err(BoundaryError::Substitution("token_issuance_contract"));
        }
        let issued_index = object
            .get("issued_chain_index")
            .and_then(Value::as_u64)
            .ok_or(BoundaryError::Malformed("issued_chain_index"))?;
        let chain_index = usize::try_from(issued_index)
            .map_err(|_| BoundaryError::Malformed("issued_chain_index"))?;
        let chain_entry = chain
            .get(chain_index)
            .ok_or(BoundaryError::Substitution("issued_chain_index"))?;
        let issued_hash = object
            .get("issued_state_hash")
            .and_then(Value::as_str)
            .ok_or(BoundaryError::Malformed("issued_state_hash"))?;
        if !is_sha512(issued_hash)
            || chain_entry.get("hash").and_then(Value::as_str) != Some(issued_hash)
            || chain_entry.get("stage") != object.get("issued_chain_stage")
        {
            return Err(BoundaryError::Substitution("token_chain_binding"));
        }
        let event = trace_by_token
            .get(name)
            .ok_or(BoundaryError::Missing("token_trace_event"))?;
        if event.get("event").and_then(Value::as_str) != Some("issued")
            || event.get("token").and_then(Value::as_str) != Some(*name)
            || event.get("issuer") != object.get("issuer")
            || event.get("stage") != object.get("issued_at_stage")
            || event.get("issued_chain_index") != object.get("issued_chain_index")
            || event.get("issued_chain_stage") != object.get("issued_chain_stage")
            || event.get("issued_state_hash") != object.get("issued_state_hash")
        {
            return Err(BoundaryError::WrongOrder("token_trace"));
        }
    }
    if tokens.keys().any(|name| !unique.contains(name.as_str())) {
        return Err(BoundaryError::Substitution("token_set"));
    }
    Proof::new(Component::TokenStack, request_fingerprint)
}
