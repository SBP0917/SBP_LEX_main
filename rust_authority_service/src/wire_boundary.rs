//! Non-authorizing admission boundary for the pinned SBP-LEX-WIRE/1 codec.
//!
//! A parsed convergence request is still only a caller assertion. The v1 wire
//! carries projection, snapshot and provenance digests, but no independently
//! authenticated branch statements or canonical snapshot bodies from which
//! this process can derive them. Consequently this module may inspect and bind
//! a request, but it deliberately cannot construct `ConvergenceEvidence` or
//! enter the trusted core's `Candidate::converge` transition.

use core::fmt;

use sbp_lex_wire_contract::{decode_frame, encode_message, Message, Value};
use trusted_authority_core::{AuthorityClass, Digest};

use crate::profile::WIRE_CONTRACT_SHA256;
use crate::sha256::{decode_lower_hex_32, digest};
use crate::sha512::digest as sha512_digest;

const WIRE_CODEC_SHA256: &str = "5c29dffb26b859e32d71d3ef3abdcc3b97f2c0b1524f0ea428256d57863ed8eb";
const WIRE_CODEC_MANIFEST_SHA256: &str =
    "394fec6a7dcb1909f9b6e02dcb1652e6dc07dd84bb7827eaaeaf66fef79b09c0";
const WIRE_GOLDEN_SHA256: &str = "2c91bffb4eab4890f36d27bc63cb926b37a1f24d4f7bfff6846723424ec420e0";
const WIRE_ADVERSARIAL_SHA256: &str =
    "946f45cc9f7f95e19e90b76056a2a09a260b27095d1a589231fb4ba32a7c9132";
const ZERO_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const SPEC_BYTES: &[u8] = include_bytes!("../../wire_protocol/SPEC.md");
const CODEC_BYTES: &[u8] = include_bytes!("../../wire_protocol/rust/src/lib.rs");
const CODEC_MANIFEST_BYTES: &[u8] = include_bytes!("../../wire_protocol/rust/Cargo.toml");
const GOLDEN_BYTES: &[u8] = include_bytes!("../../wire_protocol/vectors/golden_transcript.jsonl");
const ADVERSARIAL_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/vectors/adversarial_cases.txt");

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WireBoundaryError {
    ContractHashMismatch,
    CodecHashMismatch,
    DecodeRejected,
    NotConvergenceRequest,
    InvalidSequence,
    InvalidInitialChain,
    NotFresh,
    FutureMessage,
    SoftwareAuthorityNotAdmitted,
    InvalidDigest,
    IndependentConvergenceEvidenceRequired,
}

impl fmt::Display for WireBoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ContractHashMismatch => "WIRE_CONTRACT_HASH_MISMATCH",
            Self::CodecHashMismatch => "WIRE_CODEC_HASH_MISMATCH",
            Self::DecodeRejected => "WIRE_FRAME_REJECTED",
            Self::NotConvergenceRequest => "WIRE_NOT_CONVERGENCE_REQUEST",
            Self::InvalidSequence => "WIRE_INITIAL_SEQUENCE_INVALID",
            Self::InvalidInitialChain => "WIRE_INITIAL_CHAIN_INVALID",
            Self::NotFresh => "WIRE_TRUSTED_TIME_OUTSIDE_VALIDITY",
            Self::FutureMessage => "WIRE_MESSAGE_FROM_FUTURE",
            Self::SoftwareAuthorityNotAdmitted => "WIRE_SOFTWARE_AUTHORITY_NOT_ADMITTED",
            Self::InvalidDigest => "WIRE_DIGEST_INVALID",
            Self::IndependentConvergenceEvidenceRequired => {
                "INDEPENDENT_CONVERGENCE_EVIDENCE_REQUIRED"
            }
        })
    }
}

impl std::error::Error for WireBoundaryError {}

/// A non-authorizing summary derived by Rust from one canonical frame.
///
/// `wire_binding_digest` binds every byte of the canonical request.
/// `stable_effect_intent_digest` intentionally excludes traversal, operation,
/// challenge, nonce, time and artifact identifiers: changing ephemeral
/// metadata cannot make the same effect intent consumable again.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NonAuthorizingWireInspection {
    authority_class: AuthorityClass,
    wire_binding_digest: Digest,
    stable_effect_intent_digest: Digest,
    durable_consumption_digest: Digest,
    projection_a_digest: Digest,
    projection_b_digest: Digest,
    policy_projection_digest: Digest,
    branch_a_provenance_digest: Digest,
    branch_b_provenance_digest: Digest,
}

impl NonAuthorizingWireInspection {
    pub const fn authority_class(&self) -> AuthorityClass {
        self.authority_class
    }

    pub const fn wire_binding_digest(&self) -> Digest {
        self.wire_binding_digest
    }

    pub const fn stable_effect_intent_digest(&self) -> Digest {
        self.stable_effect_intent_digest
    }

    pub const fn durable_consumption_digest(&self) -> Digest {
        self.durable_consumption_digest
    }

    pub const fn projection_a_digest(&self) -> Digest {
        self.projection_a_digest
    }

    pub const fn projection_b_digest(&self) -> Digest {
        self.projection_b_digest
    }

    pub const fn policy_projection_digest(&self) -> Digest {
        self.policy_projection_digest
    }

    pub const fn branch_a_provenance_digest(&self) -> Digest {
        self.branch_a_provenance_digest
    }

    pub const fn branch_b_provenance_digest(&self) -> Digest {
        self.branch_b_provenance_digest
    }

    /// Structural equality is not independent architectural evidence. This
    /// transition stays unavailable until Rust can verify admitted A/B (and,
    /// for Mode 2, validator) statements against canonical projection inputs.
    pub const fn require_independently_authenticated_convergence(
        &self,
    ) -> Result<(), WireBoundaryError> {
        Err(WireBoundaryError::IndependentConvergenceEvidenceRequired)
    }
}

pub fn verify_embedded_wire_contract() -> Result<(), WireBoundaryError> {
    let expected_spec =
        decode_lower_hex_32(WIRE_CONTRACT_SHA256).ok_or(WireBoundaryError::ContractHashMismatch)?;
    if digest(SPEC_BYTES) != expected_spec {
        return Err(WireBoundaryError::ContractHashMismatch);
    }
    let expected_codec =
        decode_lower_hex_32(WIRE_CODEC_SHA256).ok_or(WireBoundaryError::CodecHashMismatch)?;
    if digest(CODEC_BYTES) != expected_codec {
        return Err(WireBoundaryError::CodecHashMismatch);
    }
    let expected_manifest = decode_lower_hex_32(WIRE_CODEC_MANIFEST_SHA256)
        .ok_or(WireBoundaryError::CodecHashMismatch)?;
    if digest(CODEC_MANIFEST_BYTES) != expected_manifest {
        return Err(WireBoundaryError::CodecHashMismatch);
    }
    let expected_golden =
        decode_lower_hex_32(WIRE_GOLDEN_SHA256).ok_or(WireBoundaryError::ContractHashMismatch)?;
    let expected_adversarial = decode_lower_hex_32(WIRE_ADVERSARIAL_SHA256)
        .ok_or(WireBoundaryError::ContractHashMismatch)?;
    if digest(GOLDEN_BYTES) != expected_golden || digest(ADVERSARIAL_BYTES) != expected_adversarial
    {
        return Err(WireBoundaryError::ContractHashMismatch);
    }
    Ok(())
}

/// Parse, structurally validate, freshness-check and hash-bind a convergence
/// request. This function never authorizes, signs, prepares or commits.
pub fn inspect_convergence_frame(
    frame: &[u8],
    trusted_now_ms: u64,
) -> Result<NonAuthorizingWireInspection, WireBoundaryError> {
    verify_embedded_wire_contract()?;
    let message = decode_frame(frame).map_err(|_| WireBoundaryError::DecodeRejected)?;
    if text(&message, "kind")? != "convergence_request" {
        return Err(WireBoundaryError::NotConvergenceRequest);
    }
    if number(&message, "sequence")? != 0 {
        return Err(WireBoundaryError::InvalidSequence);
    }
    if text(&message, "prior_transcript_digest")? != ZERO_DIGEST {
        return Err(WireBoundaryError::InvalidInitialChain);
    }
    let not_before = number(&message, "not_before_ms")?;
    let expires_at = number(&message, "expires_at_ms")?;
    if trusted_now_ms < not_before || trusted_now_ms >= expires_at {
        return Err(WireBoundaryError::NotFresh);
    }
    if number(&message, "message_time_ms")? > trusted_now_ms {
        return Err(WireBoundaryError::FutureMessage);
    }
    let authority_class = match text(&message, "authority_class")? {
        "TEST_ONLY" => AuthorityClass::NonproductionEvidenceOnly,
        "HSM" => AuthorityClass::ProductionHsm,
        "TPM" => AuthorityClass::ProductionTpm,
        "SOFTWARE" => return Err(WireBoundaryError::SoftwareAuthorityNotAdmitted),
        _ => return Err(WireBoundaryError::DecodeRejected),
    };
    let encoded = encode_message(&message).map_err(|_| WireBoundaryError::DecodeRejected)?;
    let stable_effect_intent_digest = digest_named_fields(
        b"SBP-LEX-RUST-AUTHORITY/1\0STABLE-EFFECT-INTENT\0",
        &message,
        &[
            "oracle_sha256",
            "authority_class",
            "authority_key_class",
            "authority_key_id",
            "replay_namespace",
            "effect_digest",
            "effect_intent_digest",
            "adapter_digest",
            "adapter_boundary_digest",
            "adapter_key_class",
            "adapter_key_id",
        ],
    )?;
    Ok(NonAuthorizingWireInspection {
        authority_class,
        wire_binding_digest: legacy_to_v2_digest(&digest(
            &[
                b"SBP-LEX-RUST-AUTHORITY/1\0WIRE-BINDING\0".as_slice(),
                encoded.as_slice(),
            ]
            .concat(),
        )),
        stable_effect_intent_digest: legacy_to_v2_digest(&stable_effect_intent_digest),
        durable_consumption_digest: wire_digest(&message, "durable_consumption_digest")?,
        projection_a_digest: wire_digest(&message, "projection_a_digest")?,
        projection_b_digest: wire_digest(&message, "projection_b_digest")?,
        policy_projection_digest: wire_digest(&message, "policy_projection_digest")?,
        branch_a_provenance_digest: wire_digest(&message, "branch_a_provenance_digest")?,
        branch_b_provenance_digest: wire_digest(&message, "branch_b_provenance_digest")?,
    })
}

fn text<'a>(message: &'a Message, field: &str) -> Result<&'a str, WireBoundaryError> {
    match message.get(field) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(WireBoundaryError::DecodeRejected),
    }
}

fn number(message: &Message, field: &str) -> Result<u64, WireBoundaryError> {
    match message.get(field) {
        Some(Value::Number(value)) => Ok(*value),
        _ => Err(WireBoundaryError::DecodeRejected),
    }
}

fn wire_digest(message: &Message, field: &str) -> Result<Digest, WireBoundaryError> {
    decode_lower_hex_32(text(message, field)?)
        .map(|legacy| legacy_to_v2_digest(&legacy))
        .ok_or(WireBoundaryError::InvalidDigest)
}

/// Wire v1 remains transport-only historical provenance.  Its 32-byte values
/// are domain-separated before entering the 64-byte V2 trusted-core type, so
/// they cannot be mistaken for native V2 SHA-512 identities.
fn legacy_to_v2_digest(legacy: &[u8; 32]) -> Digest {
    let mut material = b"SBP-LEX-RUST-AUTHORITY/2\0LEGACY-WIRE-V1\0".to_vec();
    material.extend_from_slice(legacy);
    Digest::new(sha512_digest(&material))
}

fn digest_named_fields(
    domain: &[u8],
    message: &Message,
    fields: &[&str],
) -> Result<[u8; 32], WireBoundaryError> {
    let mut material = Vec::from(domain);
    for field in fields {
        let name = field.as_bytes();
        let value = text(message, field)?.as_bytes();
        material.extend_from_slice(&(name.len() as u16).to_be_bytes());
        material.extend_from_slice(name);
        material.extend_from_slice(&(value.len() as u32).to_be_bytes());
        material.extend_from_slice(value);
    }
    Ok(digest(&material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbp_lex_wire_contract::{encode_frame, parse_message, seal_message};

    const GOLDEN: &str = include_str!("../../wire_protocol/vectors/golden_transcript.jsonl");
    const TRUSTED_NOW: u64 = 1_900_000_000_100;

    fn first_message() -> Message {
        parse_message(
            GOLDEN
                .lines()
                .next()
                .expect("golden convergence request")
                .as_bytes(),
        )
        .expect("valid golden request")
    }

    fn inspect(message: &Message) -> Result<NonAuthorizingWireInspection, WireBoundaryError> {
        let frame = encode_frame(message).expect("valid frame");
        inspect_convergence_frame(&frame, TRUSTED_NOW)
    }

    #[test]
    fn embedded_spec_and_codec_are_exactly_pinned() {
        verify_embedded_wire_contract().expect("fixed contract hashes");
    }

    #[test]
    fn canonical_request_is_bound_but_remains_non_authorizing() {
        let inspected = inspect(&first_message()).expect("structural inspection");
        assert_eq!(
            inspected.authority_class(),
            AuthorityClass::NonproductionEvidenceOnly
        );
        assert_eq!(
            inspected.projection_a_digest(),
            inspected.projection_b_digest()
        );
        assert_eq!(
            inspected.projection_a_digest(),
            inspected.policy_projection_digest()
        );
        assert_ne!(
            inspected.branch_a_provenance_digest(),
            inspected.branch_b_provenance_digest()
        );
        assert_eq!(
            inspected.require_independently_authenticated_convergence(),
            Err(WireBoundaryError::IndependentConvergenceEvidenceRequired)
        );
    }

    #[test]
    fn production_labels_cannot_upgrade_opaque_convergence_assertions() {
        let mut labelled = first_message();
        labelled.insert("authority_class".into(), Value::Text("HSM".into()));
        labelled.insert(
            "authority_key_class".into(),
            Value::Text("PRODUCTION_HSM".into()),
        );
        let labelled = seal_message(&labelled).expect("structurally valid HSM label");
        let inspected = inspect(&labelled).expect("non-authorizing inspection");
        assert_eq!(inspected.authority_class(), AuthorityClass::ProductionHsm);
        assert_eq!(
            inspected.require_independently_authenticated_convergence(),
            Err(WireBoundaryError::IndependentConvergenceEvidenceRequired)
        );
    }

    #[test]
    fn fresh_ephemeral_ids_cannot_change_stable_effect_intent() {
        let original = inspect(&first_message()).expect("original");
        let mut changed = first_message();
        changed.insert("traversal_id".into(), Value::Text("a".repeat(32)));
        changed.insert("operation_id".into(), Value::Text("b".repeat(32)));
        changed.insert("challenge".into(), Value::Text("c".repeat(64)));
        changed.insert("nonce".into(), Value::Text("d".repeat(64)));
        let changed = seal_message(&changed).expect("resealed request");
        let inspected = inspect(&changed).expect("changed inspection");
        assert_eq!(
            inspected.stable_effect_intent_digest(),
            original.stable_effect_intent_digest()
        );
        assert_ne!(
            inspected.wire_binding_digest(),
            original.wire_binding_digest()
        );
    }

    #[test]
    fn changing_effect_intent_changes_durable_identity() {
        let original = inspect(&first_message()).expect("original");
        let mut changed = first_message();
        changed.insert("effect_intent_digest".into(), Value::Text("e".repeat(64)));
        let changed = seal_message(&changed).expect("resealed request");
        let inspected = inspect(&changed).expect("changed inspection");
        assert_ne!(
            inspected.stable_effect_intent_digest(),
            original.stable_effect_intent_digest()
        );

        for (field, replacement) in [
            ("replay_namespace", "1"),
            ("effect_digest", "2"),
            ("adapter_boundary_digest", "3"),
            ("adapter_key_id", "4"),
        ] {
            let mut changed = first_message();
            changed.insert(field.into(), Value::Text(replacement.repeat(64)));
            let changed = seal_message(&changed).expect("resealed stable binding mutation");
            let inspected = inspect(&changed).expect("changed inspection");
            assert_ne!(
                inspected.stable_effect_intent_digest(),
                original.stable_effect_intent_digest(),
                "{field} must be part of durable effect identity"
            );
        }
    }

    #[test]
    fn software_authority_and_future_message_fail_closed() {
        let mut software = first_message();
        software.insert("authority_class".into(), Value::Text("SOFTWARE".into()));
        let software = seal_message(&software).expect("structurally valid software wire");
        assert_eq!(
            inspect(&software),
            Err(WireBoundaryError::SoftwareAuthorityNotAdmitted)
        );
        let frame = encode_frame(&first_message()).expect("valid frame");
        assert_eq!(
            inspect_convergence_frame(&frame, 1_899_999_999_999),
            Err(WireBoundaryError::FutureMessage)
        );
    }
}
