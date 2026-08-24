//! Independent Rust implementation of SBP-LEX-AUTH-WIRE/2.
//! No Python parser, executable object, dynamic loading, or live authority route is used.

#![forbid(unsafe_code)]

pub mod hybrid;

use sha2::{Digest as _, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const PROTOCOL: &str = "SBP-LEX-AUTH-WIRE/2";
pub const ORACLE_SHA512: &str = "4953fa1136348279509933ddb91102591015af3e7d45f1d6b1ca39ccb9e44190b5880c9f1a0ec054add824dd31d74feefc2922aa652833b16252cac159921f82";
pub const MAX_FRAME_BYTES: usize = 32_768;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const FAIL_CLOSE_RESULT_MAX_DELAY_MS: u64 = 1_000;
pub const ZERO: &str = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_ID: &str = "00000000000000000000000000000000";
const TDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0TRANSCRIPT\0";
const SDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0SIGNATURE\0";
const PDOM: &[u8] = b"SBP-LEX-EXEC-PROJECTION/2\0";
pub const EXTENSION_ADMISSION_MODE: &str = "EXTENSIONS_DISABLED";
pub const EXTENSION_SCHEMA: &str = "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED";
const RDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0REGISTRY\0";
const SETDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0SET\0";
const CDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0CONVERGENCE\0";
const TESTDOM: &[u8] = b"SBP-LEX-TEST-SIGNATURE/1\0";
const STABLEREQUESTDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0STABLE-REQUEST\0";
const STABLEDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0STABLE-EFFECT-INTENT\0";
const DURABLEDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0DURABLE-CONSUMPTION\0";
const POUDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0POINT-OF-USE\0";
const ARTIFACTIDDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0ARTIFACT-ID\0";
const PREPAREDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0PREPARE-PROOF\0";
const CAPABILITYDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0EXECUTION-CAPABILITY\0";
const LEASEDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0EXECUTION-LEASE\0";
const WATCHDOGDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0WATCHDOG-ARM\0";
const PERMITDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0EFFECT-PERMIT\0";
const CHECKPOINTDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-CHECKPOINT\0";
const RELEASEDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-RELEASE\0";
const ACKDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0RENDEZVOUS-ACK\0";
const STATESEALDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0MODE3-STATE-SEAL\0";
const SINGLEPROOFDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0MODE3-PROOF\0";
const CONSUMEDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0ATOMIC-CONSUMPTION\0";
const RECEIPTDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0EFFECT-RECEIPT\0";
const ADMISSIONDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0ADMISSION-POLICY\0";
const AUTHCONVDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0AUTHENTICATED-CONVERGENCE\0";
const STAGECTXDOM: &[u8] = b"SBP-LEX-AUTH-WIRE/2\0VERIFIED-STAGE-CONTEXT\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Text(String),
    Number(u64),
}
pub type Message = BTreeMap<String, Value>;
type ModeEvidenceRefs = (String, String, String, String);
type DerivedModeRequest = (ModeEvidenceRefs, String);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WireError(pub String);
impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for WireError {}
fn fail(text: &str) -> WireError {
    WireError(text.to_owned())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    pub role: String,
    pub key_class: String,
    pub public_key_hex: String,
}
impl KeyRecord {
    pub fn key_id(&self) -> Result<String, WireError> {
        Ok(hex(&sha512(&hex_bytes(&self.public_key_hex)?)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustRegistry {
    pub root_digest: String,
    pub entries: BTreeMap<String, KeyRecord>,
}
impl TrustRegistry {
    pub fn digest(&self) -> Result<String, WireError> {
        let mut body = Vec::new();
        for (role, entry) in &self.entries {
            if entry.role != *role || !even_lower_hex(&entry.public_key_hex) {
                return Err(fail("invalid registry entry"));
            }
            body.extend_from_slice(
                format!(
                    "{}|{}|{}|{}\n",
                    role,
                    entry.key_class,
                    entry.key_id()?,
                    entry.public_key_hex
                )
                .as_bytes(),
            );
        }
        let mut input = RDOM.to_vec();
        input.extend_from_slice(&body);
        Ok(hex(&sha512(&input)))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionPolicy {
    pub trust_root_digest: String,
    pub registry_digest: String,
    pub runtime_subject: String,
    pub runtime_tree: String,
    pub authority_class: String,
    pub authority_epoch: u64,
    pub authority_profile: String,
    pub authority_build_id: String,
    pub mode: String,
    pub traversal_id: String,
    pub operation_id: String,
    pub challenge: String,
    pub replay_namespace: String,
    pub stable_request_digest: String,
    pub request_digest: String,
    pub state_digest: String,
    pub effect_digest: String,
    pub effect_intent_digest: String,
    pub adapter_digest: String,
    pub adapter_boundary_digest: String,
    pub inhibit_binding_digest: String,
    pub interlock_digest: String,
    pub audit_anchor_digest: String,
    pub domain_digest: String,
    pub subject_digest: String,
    pub extension_admission_mode: String,
    pub extension_schema: String,
    pub extension_configuration_digest: String,
    pub extension_admission_binding_digest: String,
    pub branch_a_callable_digest: String,
    pub branch_a_code_provenance_digest: String,
    pub branch_b_callable_digest: String,
    pub branch_b_code_provenance_digest: String,
    pub validator_code_digest: String,
    pub validator_provenance_digest: String,
    pub single_state_callable_digest: String,
    pub single_state_provenance_digest: String,
}

/// Opaque, language-local proof that one complete request prefix was verified.
/// It is not serializable authority and has no public constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStageContext {
    stage_kind: String,
    expected_result_kind: String,
    request_transcript_digest: String,
    chain_tip_digest: String,
    admission_policy_digest: String,
    authenticated_convergence_binding_digest: String,
    context_digest: String,
    values: BTreeMap<String, Value>,
}

/// Opaque final point-of-use permit evidence. It is intentionally not a wire
/// message and cannot be transported as a reusable capability.
#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedEffectPermitContext {
    stage_context_digest: String,
    admission_policy_digest: String,
    authenticated_convergence_binding_digest: String,
    values: BTreeMap<String, Value>,
}

impl VerifiedEffectPermitContext {
    pub fn stage_context_digest(&self) -> &str {
        &self.stage_context_digest
    }
    pub fn admission_policy_digest(&self) -> &str {
        &self.admission_policy_digest
    }
    pub fn authenticated_convergence_binding_digest(&self) -> &str {
        &self.authenticated_convergence_binding_digest
    }
    pub fn derived(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }
    pub fn derived_text(&self, name: &str) -> Result<&str, WireError> {
        text(&self.values, name)
    }
    pub fn derived_number(&self, name: &str) -> Result<u64, WireError> {
        number(&self.values, name)
    }
}

impl VerifiedStageContext {
    pub fn stage_kind(&self) -> &str {
        &self.stage_kind
    }
    pub fn expected_result_kind(&self) -> &str {
        &self.expected_result_kind
    }
    pub fn request_transcript_digest(&self) -> &str {
        &self.request_transcript_digest
    }
    pub fn chain_tip_digest(&self) -> &str {
        &self.chain_tip_digest
    }
    pub fn admission_policy_digest(&self) -> &str {
        &self.admission_policy_digest
    }
    pub fn authenticated_convergence_binding_digest(&self) -> &str {
        &self.authenticated_convergence_binding_digest
    }
    pub fn context_digest(&self) -> &str {
        &self.context_digest
    }
    pub fn derived(&self, name: &str) -> Option<&Value> {
        self.values.get(name)
    }
    pub fn derived_text(&self, name: &str) -> Result<&str, WireError> {
        text(&self.values, name)
    }
    pub fn derived_number(&self, name: &str) -> Result<u64, WireError> {
        number(&self.values, name)
    }
}

pub trait SignatureVerifier {
    fn verify(&self, algorithm: &str, public_key: &[u8], preimage: &[u8], signature: &[u8])
        -> bool;
}
pub struct FixtureVerifier;
impl SignatureVerifier for FixtureVerifier {
    fn verify(
        &self,
        algorithm: &str,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> bool {
        if algorithm != "TEST-SHA512" {
            return false;
        }
        let mut input = TESTDOM.to_vec();
        input.extend_from_slice(public_key);
        input.extend_from_slice(preimage);
        signature == sha512(&input)
    }
}

fn text<'a>(m: &'a Message, key: &str) -> Result<&'a str, WireError> {
    match m.get(key) {
        Some(Value::Text(v)) => Ok(v),
        _ => Err(fail("missing or non-string field")),
    }
}
fn number(m: &Message, key: &str) -> Result<u64, WireError> {
    match m.get(key) {
        Some(Value::Number(v)) => Ok(*v),
        _ => Err(fail("missing or non-integer field")),
    }
}
fn ascii_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}
fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn even_lower_hex(value: &str) -> bool {
    value.len() >= 2
        && value.len().is_multiple_of(2)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest128(value: &str) -> bool {
    lower_hex(value, 128)
}
fn token(value: &str) -> bool {
    value.len() <= 64
        && value.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

const COMMON: &[&str] = &[
    "adapter_boundary_digest",
    "adapter_digest",
    "audit_anchor_digest",
    "authority_build_id",
    "authority_class",
    "authority_epoch",
    "authority_profile",
    "challenge",
    "domain_digest",
    "durable_consumption_digest",
    "effect_digest",
    "effect_intent_digest",
    "extension_admission_binding_digest",
    "extension_admission_mode",
    "extension_configuration_digest",
    "extension_schema",
    "error_code",
    "expires_at_ms",
    "inhibit_binding_digest",
    "interlock_digest",
    "issued_at_ms",
    "kind",
    "message_time_ms",
    "mode",
    "nonce",
    "not_before_ms",
    "operation_id",
    "oracle_sha512",
    "prior_transcript_digest",
    "protocol",
    "replay_namespace",
    "request_digest",
    "runtime_subject",
    "runtime_tree",
    "sequence",
    "signature_algorithm",
    "signature_hex",
    "signer_key_class",
    "signer_key_id",
    "signer_role",
    "signing_public_key_hex",
    "stable_effect_intent_digest",
    "stable_request_digest",
    "state_digest",
    "subject_digest",
    "transcript_digest",
    "traversal_id",
    "trust_registry_digest",
    "trust_root_digest",
];
const PROJECTION: &[&str] = &[
    "projection_adapter_digest",
    "projection_audit_context_digest",
    "projection_aurion_digest",
    "projection_candidate_digest",
    "projection_constraints_digest",
    "projection_digest",
    "projection_domain_digest",
    "projection_effect_digest",
    "projection_mode_freeze_digest",
    "projection_outcome_digest",
    "projection_pathway_digest",
    "projection_policy_digest",
    "projection_provider_linkage_digest",
    "projection_request_digest",
    "projection_schema",
    "projection_state_digest",
    "projection_token_stack_digest",
    "extension_admission_binding_digest",
    "extension_admission_mode",
    "extension_configuration_digest",
    "extension_schema",
];

fn extras(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        "branch_a_statement" | "branch_b_statement" => &[
            "callable_digest",
            "code_provenance_digest",
            "process_digest",
            "release_checkpoint_digest",
            "snapshot_digest",
            "substantive_end_ms",
            "substantive_start_ms",
            "worker_id",
        ],
        "mode1_release_request" => &[
            "a_checkpoint_digest",
            "a_process_digest",
            "b_checkpoint_digest",
            "b_process_digest",
            "rendezvous_opened_at_ms",
            "worker_a_id",
            "worker_b_id",
        ],
        "mode1_release_result" => &[
            "a_checkpoint_digest",
            "b_checkpoint_digest",
            "decision",
            "release_request_digest",
            "rendezvous_opened_at_ms",
            "rendezvous_release_digest",
            "rendezvous_released_at_ms",
        ],
        "mode1_overlap_witness" => &[
            "a_ack_digest",
            "a_checkpoint_digest",
            "a_end_ms",
            "a_process_digest",
            "a_start_ms",
            "b_ack_digest",
            "b_checkpoint_digest",
            "b_end_ms",
            "b_process_digest",
            "b_start_ms",
            "projection_digest",
            "rendezvous_opened_at_ms",
            "rendezvous_release_digest",
            "rendezvous_released_at_ms",
            "release_result_digest",
            "statement_a_digest",
            "statement_b_digest",
            "worker_a_id",
            "worker_b_id",
        ],
        "mode2_validator_certificate" => &[
            "candidate_input_set",
            "candidate_output_set",
            "candidate_rejections",
            "pathway_input_set",
            "pathway_output_set",
            "pathway_rejections",
            "primary_statement_digest",
            "validator_code_digest",
            "validator_provenance_digest",
        ],
        "mode3_single_state_proof" => &[
            "single_state_callable_digest",
            "single_state_proof_digest",
            "single_state_provenance_digest",
            "state_seal_digest",
        ],
        "convergence_request" => &[
            "convergence_digest",
            "evidence_a_digest",
            "evidence_b_digest",
            "mode_evidence_digest",
            "projection_digest",
        ],
        "convergence_result" => &[
            "convergence_digest",
            "decision",
            "evidence_a_digest",
            "evidence_b_digest",
            "mode_evidence_digest",
            "projection_digest",
        ],
        "prepare_request" => &["convergence_digest"],
        "prepare_result" => &["decision", "prepare_id", "prepare_proof_digest"],
        "commit_request" => &["prepare_id", "prepare_proof_digest"],
        "commit_result" => &["capability_digest", "capability_id", "decision"],
        "lease_redeem_request" => &["capability_digest", "capability_id", "lease_deadline_ms"],
        "lease_redeem_result" => &["decision", "lease_deadline_ms", "lease_digest", "lease_id"],
        "watchdog_arm_request" => &["lease_digest", "lease_id", "watchdog_deadline_ms"],
        "watchdog_arm_result" => &["decision", "watchdog_deadline_ms", "watchdog_digest"],
        "effect_permit_request" => &[
            "lease_deadline_ms",
            "lease_digest",
            "lease_id",
            "point_of_use_digest",
            "watchdog_deadline_ms",
            "watchdog_digest",
        ],
        "effect_permit_result" => &[
            "decision",
            "permit_deadline_ms",
            "permit_digest",
            "permit_id",
            "watchdog_digest",
        ],
        "effect_receipt" => &[
            "adapter_consumed_at_ms",
            "adapter_consumption_digest",
            "effect_outcome",
            "permit_digest",
            "permit_id",
            "receipt_digest",
            "watchdog_digest",
        ],
        "receipt_ack" => &[
            "decision",
            "permit_digest",
            "permit_id",
            "receipt_digest",
            "receipt_status",
            "watchdog_digest",
        ],
        "watchdog_terminal" => &[
            "permit_digest",
            "permit_id",
            "receipt_digest",
            "watchdog_digest",
            "watchdog_status",
        ],
        "watchdog_result" => &[
            "decision",
            "permit_digest",
            "permit_id",
            "receipt_digest",
            "watchdog_digest",
        ],
        _ => return None,
    })
}
fn projection_kind(kind: &str) -> bool {
    matches!(
        kind,
        "branch_a_statement"
            | "branch_b_statement"
            | "mode2_validator_certificate"
            | "mode3_single_state_proof"
    )
}
fn expected_role(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "branch_a_statement" => "BRANCH_A",
        "branch_b_statement" => "BRANCH_B",
        "mode1_release_request" => "COORDINATOR",
        "mode1_release_result" => "AUTHORITY",
        "mode1_overlap_witness" => "WITNESS",
        "mode2_validator_certificate" => "VALIDATOR",
        "mode3_single_state_proof" => "SINGLE_STATE",
        "convergence_request" | "prepare_request" | "commit_request" | "watchdog_arm_request" => {
            "COORDINATOR"
        }
        "convergence_result"
        | "prepare_result"
        | "commit_result"
        | "lease_redeem_result"
        | "effect_permit_result"
        | "receipt_ack"
        | "watchdog_result" => "AUTHORITY",
        "lease_redeem_request" | "effect_permit_request" | "effect_receipt" => "ADAPTER",
        "watchdog_arm_result" | "watchdog_terminal" => "WATCHDOG",
        _ => return None,
    })
}

fn expected_fields(kind: &str) -> Option<BTreeSet<&'static str>> {
    let mut fields: BTreeSet<_> = COMMON.iter().copied().collect();
    if projection_kind(kind) {
        fields.extend(PROJECTION.iter().copied());
    }
    fields.extend(extras(kind)?.iter().copied());
    Some(fields)
}

fn push_quoted(out: &mut Vec<u8>, value: &str) -> Result<(), WireError> {
    if !ascii_token(value) {
        return Err(fail("noncanonical string"));
    }
    out.push(b'"');
    out.extend_from_slice(value.as_bytes());
    out.push(b'"');
    Ok(())
}
fn encode_raw(message: &Message) -> Result<Vec<u8>, WireError> {
    let mut out = vec![b'{'];
    for (i, (key, value)) in message.iter().enumerate() {
        if i > 0 {
            out.push(b',');
        }
        push_quoted(&mut out, key)?;
        out.push(b':');
        match value {
            Value::Text(v) => push_quoted(&mut out, v)?,
            Value::Number(v) if *v <= MAX_SAFE_INTEGER => {
                out.extend_from_slice(v.to_string().as_bytes())
            }
            _ => return Err(fail("integer range")),
        }
    }
    out.push(b'}');
    Ok(out)
}

pub fn parse_message(input: &[u8]) -> Result<Message, WireError> {
    if input.is_empty() || input.len() > MAX_FRAME_BYTES || input.iter().any(|b| *b > 0x7f) {
        return Err(fail("payload bounds or encoding"));
    }
    let mut parser = Parser { input, pos: 0 };
    let result = parser.object()?;
    if parser.pos != input.len() {
        return Err(fail("trailing bytes"));
    }
    validate_structure(&result, true)?;
    if encode_raw(&result)? != input {
        return Err(fail("noncanonical bytes"));
    }
    Ok(result)
}
pub fn encode_message(message: &Message) -> Result<Vec<u8>, WireError> {
    validate_structure(message, true)?;
    let out = encode_raw(message)?;
    if out.is_empty() || out.len() > MAX_FRAME_BYTES {
        return Err(fail("payload bounds"));
    }
    Ok(out)
}
pub fn encode_frame(message: &Message) -> Result<Vec<u8>, WireError> {
    let payload = encode_message(message)?;
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend(payload);
    Ok(out)
}
pub fn decode_frame(frame: &[u8]) -> Result<Message, WireError> {
    if frame.len() < 4 {
        return Err(fail("truncated frame"));
    }
    let size = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if size == 0 || size > MAX_FRAME_BYTES || frame.len() != size + 4 {
        return Err(fail("frame length"));
    }
    parse_message(&frame[4..])
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}
impl<'a> Parser<'a> {
    fn take(&mut self, b: u8) -> Result<(), WireError> {
        if self.input.get(self.pos) != Some(&b) {
            return Err(fail("malformed JSON"));
        }
        self.pos += 1;
        Ok(())
    }
    fn quoted(&mut self) -> Result<String, WireError> {
        self.take(b'"')?;
        let start = self.pos;
        while let Some(byte) = self.input.get(self.pos) {
            if *byte == b'"' {
                break;
            }
            if !(0x20..=0x7e).contains(byte) || *byte == b'\\' {
                return Err(fail("escaped/non-ASCII string"));
            }
            self.pos += 1;
        }
        if start == self.pos {
            return Err(fail("empty string"));
        }
        let value = std::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| fail("UTF-8"))?
            .to_owned();
        self.take(b'"')?;
        Ok(value)
    }
    fn object(&mut self) -> Result<Message, WireError> {
        self.take(b'{')?;
        let mut out = Message::new();
        let mut prior: Option<String> = None;
        loop {
            let key = self.quoted()?;
            if prior.as_ref().is_some_and(|p| p >= &key) {
                return Err(fail("duplicate or unsorted field"));
            }
            self.take(b':')?;
            let value = if self.input.get(self.pos) == Some(&b'"') {
                Value::Text(self.quoted()?)
            } else {
                let start = self.pos;
                while self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                    self.pos += 1;
                }
                if start == self.pos {
                    return Err(fail("forbidden JSON type"));
                }
                let digits = std::str::from_utf8(&self.input[start..self.pos])
                    .map_err(|_| fail("integer"))?;
                if digits.len() > 1 && digits.starts_with('0') {
                    return Err(fail("noncanonical integer"));
                }
                Value::Number(digits.parse().map_err(|_| fail("integer range"))?)
            };
            prior = Some(key.clone());
            if out.insert(key, value).is_some() {
                return Err(fail("duplicate field"));
            }
            match self.input.get(self.pos) {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err(fail("malformed object")),
            }
        }
        Ok(out)
    }
}

pub fn transcript_digest(message: &Message) -> Result<String, WireError> {
    let mut unsigned = message.clone();
    unsigned.remove("transcript_digest");
    unsigned.remove("signature_hex");
    let kind = text(&unsigned, "kind")?;
    if extras(kind).is_none() {
        return Err(fail("unknown kind"));
    }
    let mut input = TDOM.to_vec();
    input.extend_from_slice(kind.as_bytes());
    input.push(0);
    input.extend_from_slice(&encode_raw(&unsigned)?);
    Ok(hex(&sha512(&input)))
}
pub fn signature_preimage(message: &Message) -> Result<Vec<u8>, WireError> {
    let kind = text(message, "kind")?;
    let digest = text(message, "transcript_digest")?;
    if extras(kind).is_none() || !digest128(digest) {
        return Err(fail("signature preimage"));
    }
    let mut out = SDOM.to_vec();
    out.extend_from_slice(kind.as_bytes());
    out.push(0);
    out.extend_from_slice(&hex_bytes(digest)?);
    Ok(out)
}
pub fn projection_digest(message: &Message) -> Result<String, WireError> {
    let mut projected = Message::new();
    for key in PROJECTION {
        if *key != "projection_digest" {
            projected.insert(
                (*key).to_owned(),
                message
                    .get(*key)
                    .ok_or_else(|| fail("projection field"))?
                    .clone(),
            );
        }
    }
    let mut input = PDOM.to_vec();
    input.extend_from_slice(&encode_raw(&projected)?);
    Ok(hex(&sha512(&input)))
}
pub fn set_digest(value: &str) -> Result<String, WireError> {
    parse_set(value)?;
    let mut input = SETDOM.to_vec();
    input.extend_from_slice(value.as_bytes());
    Ok(hex(&sha512(&input)))
}
pub fn convergence_digest(
    a: &str,
    b: &str,
    evidence: &str,
    projection: &str,
) -> Result<String, WireError> {
    let mut input = CDOM.to_vec();
    for value in [a, b, evidence, projection] {
        if !digest128(value) {
            return Err(fail("convergence reference"));
        }
        input.extend_from_slice(&hex_bytes(value)?);
    }
    Ok(hex(&sha512(&input)))
}
pub fn stable_request_digest(request: &str) -> Result<String, WireError> {
    if !digest128(request) {
        return Err(fail("stable request binding"));
    }
    let mut input = STABLEREQUESTDOM.to_vec();
    input.extend_from_slice(&hex_bytes(request)?);
    Ok(hex(&sha512(&input)))
}
pub fn stable_effect_intent_digest(
    stable_request: &str,
    effect_intent: &str,
    effect: &str,
    adapter: &str,
    boundary: &str,
) -> Result<String, WireError> {
    let mut input = STABLEDOM.to_vec();
    for value in [stable_request, effect_intent, effect, adapter, boundary] {
        if !digest128(value) {
            return Err(fail("stable effect binding"));
        }
        input.extend_from_slice(&hex_bytes(value)?);
    }
    Ok(hex(&sha512(&input)))
}
pub fn durable_consumption_digest(namespace: &str, stable: &str) -> Result<String, WireError> {
    if !digest128(namespace) || !digest128(stable) {
        return Err(fail("durable binding"));
    }
    let mut input = DURABLEDOM.to_vec();
    input.extend_from_slice(&hex_bytes(namespace)?);
    input.extend_from_slice(&hex_bytes(stable)?);
    Ok(hex(&sha512(&input)))
}

const POINT_OF_USE_TEXT_FIELDS: &[&str] = &[
    "adapter_boundary_digest",
    "adapter_digest",
    "audit_anchor_digest",
    "authority_build_id",
    "authority_class",
    "authority_profile",
    "domain_digest",
    "durable_consumption_digest",
    "effect_digest",
    "effect_intent_digest",
    "inhibit_binding_digest",
    "interlock_digest",
    "lease_digest",
    "lease_id",
    "operation_id",
    "replay_namespace",
    "request_digest",
    "stable_effect_intent_digest",
    "stable_request_digest",
    "state_digest",
    "subject_digest",
    "traversal_id",
    "watchdog_digest",
];

pub fn point_of_use_digest(message: &Message) -> Result<String, WireError> {
    let mut values = Message::new();
    for key in POINT_OF_USE_TEXT_FIELDS {
        let value = text(message, key)?;
        if value.is_empty() {
            return Err(fail("point-of-use binding text"));
        }
        values.insert((*key).into(), Value::Text(value.into()));
    }
    for key in [
        "authority_epoch",
        "lease_deadline_ms",
        "watchdog_deadline_ms",
    ] {
        values.insert(key.into(), Value::Number(number(message, key)?));
    }
    if number(message, "authority_epoch")? == 0 {
        return Err(fail("point-of-use epoch"));
    }
    let mut input = POUDOM.to_vec();
    input.extend_from_slice(&encode_raw(&values)?);
    Ok(hex(&sha512(&input)))
}

pub fn authority_artifact_digest(
    stage: &str,
    context: &VerifiedStageContext,
    request: &Message,
    result: &Message,
) -> Result<String, WireError> {
    if context.stage_kind != stage {
        return Err(fail("authority artifact stage"));
    }
    let (domain, request_fields): (&[u8], &[&str]) = match stage {
        "prepare_request" => (PREPAREDOM, &["convergence_digest"]),
        "commit_request" => (CAPABILITYDOM, &["prepare_id", "prepare_proof_digest"]),
        "lease_redeem_request" => (
            LEASEDOM,
            &["capability_digest", "capability_id", "lease_deadline_ms"],
        ),
        "watchdog_arm_request" => (
            WATCHDOGDOM,
            &["lease_digest", "lease_id", "watchdog_deadline_ms"],
        ),
        "effect_permit_request" => (
            PERMITDOM,
            &[
                "lease_deadline_ms",
                "lease_digest",
                "lease_id",
                "point_of_use_digest",
                "watchdog_deadline_ms",
                "watchdog_digest",
            ],
        ),
        _ => return Err(fail("authority artifact stage")),
    };
    let mut values = Message::from([
        (
            "admission_policy_digest".into(),
            Value::Text(context.admission_policy_digest.clone()),
        ),
        (
            "authenticated_convergence_binding_digest".into(),
            Value::Text(context.authenticated_convergence_binding_digest.clone()),
        ),
        (
            "authority_build_id".into(),
            Value::Text(text(result, "authority_build_id")?.into()),
        ),
        (
            "authority_class".into(),
            Value::Text(text(result, "authority_class")?.into()),
        ),
        (
            "authority_epoch".into(),
            Value::Number(number(result, "authority_epoch")?),
        ),
        (
            "authority_profile".into(),
            Value::Text(text(result, "authority_profile")?.into()),
        ),
        (
            "context_digest".into(),
            Value::Text(context.context_digest.clone()),
        ),
        (
            "message_time_ms".into(),
            Value::Number(number(result, "message_time_ms")?),
        ),
        ("nonce".into(), Value::Text(text(result, "nonce")?.into())),
        (
            "request_transcript_digest".into(),
            Value::Text(text(request, "transcript_digest")?.into()),
        ),
        (
            "signer_key_id".into(),
            Value::Text(text(result, "signer_key_id")?.into()),
        ),
        ("stage".into(), Value::Text(stage.into())),
    ]);
    for key in request_fields {
        values.insert(
            format!("request_{}", key),
            request
                .get(*key)
                .cloned()
                .ok_or_else(|| fail("authority artifact request field"))?,
        );
    }
    if stage == "effect_permit_request" {
        values.insert(
            "result_permit_deadline_ms".into(),
            Value::Number(number(result, "permit_deadline_ms")?),
        );
    }
    let mut input = domain.to_vec();
    input.extend_from_slice(&encode_raw(&values)?);
    Ok(hex(&sha512(&input)))
}

pub fn authority_artifact_id(stage: &str, artifact_digest: &str) -> Result<String, WireError> {
    if !matches!(
        stage,
        "prepare_request"
            | "commit_request"
            | "lease_redeem_request"
            | "watchdog_arm_request"
            | "effect_permit_request"
    ) || !digest128(artifact_digest)
    {
        return Err(fail("authority artifact ID"));
    }
    let mut input = ARTIFACTIDDOM.to_vec();
    input.extend_from_slice(stage.as_bytes());
    input.push(0);
    input.extend_from_slice(&hex_bytes(artifact_digest)?);
    Ok(hex(&sha512(&input)[..16]))
}
pub fn rendezvous_checkpoint_digest(
    branch: &str,
    traversal: &str,
    challenge: &str,
    worker: &str,
    process: &str,
) -> Result<String, WireError> {
    if !matches!(branch, "A" | "B")
        || !lower_hex(traversal, 32)
        || !digest128(challenge)
        || !token(worker)
        || !digest128(process)
    {
        return Err(fail("checkpoint binding"));
    }
    let mut input = CHECKPOINTDOM.to_vec();
    input.extend_from_slice(branch.as_bytes());
    input.push(0);
    input.extend_from_slice(&hex_bytes(traversal)?);
    input.extend_from_slice(&hex_bytes(challenge)?);
    input.extend_from_slice(&hex_bytes(process)?);
    input.push(0);
    input.extend_from_slice(worker.as_bytes());
    Ok(hex(&sha512(&input)))
}
pub fn rendezvous_release_digest(
    a: &str,
    b: &str,
    opened: u64,
    released: u64,
) -> Result<String, WireError> {
    if !digest128(a) || !digest128(b) || opened > released {
        return Err(fail("release binding"));
    }
    let mut input = RELEASEDOM.to_vec();
    input.extend_from_slice(&hex_bytes(a)?);
    input.extend_from_slice(&hex_bytes(b)?);
    input.extend_from_slice(&opened.to_be_bytes());
    input.extend_from_slice(&released.to_be_bytes());
    Ok(hex(&sha512(&input)))
}
pub fn rendezvous_ack_digest(
    branch: &str,
    release: &str,
    statement: &str,
) -> Result<String, WireError> {
    if !matches!(branch, "A" | "B") || !digest128(release) || !digest128(statement) {
        return Err(fail("ACK binding"));
    }
    let mut input = ACKDOM.to_vec();
    input.extend_from_slice(branch.as_bytes());
    input.push(0);
    input.extend_from_slice(&hex_bytes(release)?);
    input.extend_from_slice(&hex_bytes(statement)?);
    Ok(hex(&sha512(&input)))
}

pub fn mode3_state_seal_digest(
    state: &str,
    mode_freeze: &str,
    projection: &str,
    traversal: &str,
    challenge: &str,
) -> Result<String, WireError> {
    if !digest128(state)
        || !digest128(mode_freeze)
        || !digest128(projection)
        || !lower_hex(traversal, 32)
        || !digest128(challenge)
    {
        return Err(fail("Mode 3 seal binding"));
    }
    let mut input = STATESEALDOM.to_vec();
    for value in [state, mode_freeze, projection] {
        input.extend_from_slice(&hex_bytes(value)?);
    }
    input.extend_from_slice(&hex_bytes(traversal)?);
    input.extend_from_slice(&hex_bytes(challenge)?);
    Ok(hex(&sha512(&input)))
}
pub fn mode3_single_state_proof_digest(
    seal: &str,
    callable: &str,
    provenance: &str,
) -> Result<String, WireError> {
    if !digest128(seal) || !digest128(callable) || !digest128(provenance) {
        return Err(fail("Mode 3 proof binding"));
    }
    let mut input = SINGLEPROOFDOM.to_vec();
    for value in [seal, callable, provenance] {
        input.extend_from_slice(&hex_bytes(value)?);
    }
    Ok(hex(&sha512(&input)))
}
pub fn adapter_consumption_digest(
    durable: &str,
    permit: &str,
    effect: &str,
    adapter: &str,
    consumed: u64,
    outcome: &str,
) -> Result<String, WireError> {
    if !digest128(durable)
        || !digest128(permit)
        || !digest128(effect)
        || !digest128(adapter)
        || !matches!(outcome, "SUCCEEDED" | "FAILED" | "UNKNOWN")
    {
        return Err(fail("atomic consumption binding"));
    }
    let mut input = CONSUMEDOM.to_vec();
    for value in [durable, permit, effect, adapter] {
        input.extend_from_slice(&hex_bytes(value)?);
    }
    input.extend_from_slice(&consumed.to_be_bytes());
    input.push(0);
    input.extend_from_slice(outcome.as_bytes());
    Ok(hex(&sha512(&input)))
}

const RECEIPT_TEXT_FIELDS: &[&str] = &[
    "adapter_boundary_digest",
    "adapter_consumption_digest",
    "adapter_digest",
    "audit_anchor_digest",
    "domain_digest",
    "durable_consumption_digest",
    "effect_digest",
    "effect_intent_digest",
    "effect_outcome",
    "inhibit_binding_digest",
    "interlock_digest",
    "operation_id",
    "permit_digest",
    "permit_id",
    "request_digest",
    "stable_effect_intent_digest",
    "stable_request_digest",
    "state_digest",
    "subject_digest",
    "watchdog_digest",
];

pub fn effect_receipt_digest(fields: &Message) -> Result<String, WireError> {
    let mut values = Message::new();
    for key in RECEIPT_TEXT_FIELDS {
        let value = text(fields, key)?;
        if value.is_empty() {
            return Err(fail("effect receipt binding text"));
        }
        values.insert((*key).into(), Value::Text(value.into()));
    }
    let outcome = text(fields, "effect_outcome")?;
    if !matches!(outcome, "SUCCEEDED" | "FAILED" | "UNKNOWN")
        || !lower_hex(text(fields, "operation_id")?, 32)
        || !lower_hex(text(fields, "permit_id")?, 32)
    {
        return Err(fail("effect receipt identifier/outcome"));
    }
    for key in RECEIPT_TEXT_FIELDS {
        if matches!(*key, "effect_outcome" | "operation_id" | "permit_id") {
            continue;
        }
        if !digest128(text(fields, key)?) {
            return Err(fail("effect receipt digest field"));
        }
    }
    let consumed = number(fields, "adapter_consumed_at_ms")?;
    let epoch = number(fields, "authority_epoch")?;
    if epoch == 0 {
        return Err(fail("effect receipt epoch"));
    }
    values.insert("adapter_consumed_at_ms".into(), Value::Number(consumed));
    values.insert("authority_epoch".into(), Value::Number(epoch));
    let mut input = RECEIPTDOM.to_vec();
    input.extend_from_slice(&encode_raw(&values)?);
    let derived = hex(&sha512(&input));
    if derived == ZERO {
        return Err(fail("zero effect receipt derivation"));
    }
    Ok(derived)
}

pub fn admission_policy_digest(admission: &AdmissionPolicy) -> Result<String, WireError> {
    if admission.stable_request_digest != stable_request_digest(&admission.request_digest)? {
        return Err(fail("admission stable request derivation"));
    }
    if !digest128(&admission.extension_configuration_digest)
        || admission.extension_configuration_digest == ZERO
        || !digest128(&admission.extension_admission_binding_digest)
        || admission.extension_admission_binding_digest == ZERO
    {
        return Err(fail("zero extension admission digest"));
    }
    let mut values = Message::new();
    for (key, value) in [
        (
            "adapter_boundary_digest",
            &admission.adapter_boundary_digest,
        ),
        ("adapter_digest", &admission.adapter_digest),
        ("audit_anchor_digest", &admission.audit_anchor_digest),
        ("authority_build_id", &admission.authority_build_id),
        ("authority_class", &admission.authority_class),
        ("authority_profile", &admission.authority_profile),
        (
            "branch_a_callable_digest",
            &admission.branch_a_callable_digest,
        ),
        (
            "branch_a_code_provenance_digest",
            &admission.branch_a_code_provenance_digest,
        ),
        (
            "branch_b_callable_digest",
            &admission.branch_b_callable_digest,
        ),
        (
            "branch_b_code_provenance_digest",
            &admission.branch_b_code_provenance_digest,
        ),
        ("challenge", &admission.challenge),
        ("domain_digest", &admission.domain_digest),
        ("effect_digest", &admission.effect_digest),
        ("effect_intent_digest", &admission.effect_intent_digest),
        (
            "extension_admission_binding_digest",
            &admission.extension_admission_binding_digest,
        ),
        (
            "extension_admission_mode",
            &admission.extension_admission_mode,
        ),
        (
            "extension_configuration_digest",
            &admission.extension_configuration_digest,
        ),
        ("extension_schema", &admission.extension_schema),
        ("inhibit_binding_digest", &admission.inhibit_binding_digest),
        ("interlock_digest", &admission.interlock_digest),
        ("mode", &admission.mode),
        ("operation_id", &admission.operation_id),
        ("registry_digest", &admission.registry_digest),
        ("replay_namespace", &admission.replay_namespace),
        ("request_digest", &admission.request_digest),
        ("runtime_subject", &admission.runtime_subject),
        ("runtime_tree", &admission.runtime_tree),
        (
            "single_state_callable_digest",
            &admission.single_state_callable_digest,
        ),
        (
            "single_state_provenance_digest",
            &admission.single_state_provenance_digest,
        ),
        ("stable_request_digest", &admission.stable_request_digest),
        ("state_digest", &admission.state_digest),
        ("subject_digest", &admission.subject_digest),
        ("traversal_id", &admission.traversal_id),
        ("trust_root_digest", &admission.trust_root_digest),
        ("validator_code_digest", &admission.validator_code_digest),
        (
            "validator_provenance_digest",
            &admission.validator_provenance_digest,
        ),
    ] {
        if value.is_empty() {
            return Err(fail("invalid admission policy"));
        }
        values.insert(key.into(), Value::Text(value.clone()));
    }
    if admission.authority_epoch == 0 || admission.authority_epoch > MAX_SAFE_INTEGER {
        return Err(fail("invalid admission policy epoch"));
    }
    values.insert(
        "authority_epoch".into(),
        Value::Number(admission.authority_epoch),
    );
    let mut input = ADMISSIONDOM.to_vec();
    input.extend_from_slice(&encode_raw(&values)?);
    Ok(hex(&sha512(&input)))
}

pub fn authenticated_convergence_binding_digest(
    admission: &AdmissionPolicy,
    registry: &TrustRegistry,
    prefix: &[Message],
    convergence: &str,
    projection: &str,
) -> Result<String, WireError> {
    if prefix.is_empty() || !digest128(convergence) || !digest128(projection) {
        return Err(fail("invalid authenticated convergence derivation"));
    }
    let mut input = AUTHCONVDOM.to_vec();
    input.extend_from_slice(PROTOCOL.as_bytes());
    input.push(0);
    input.extend_from_slice(ORACLE_SHA512.as_bytes());
    input.extend_from_slice(b"\0SBP-LEX-EXEC-PROJECTION/2\0");
    input.extend_from_slice(&hex_bytes(&admission_policy_digest(admission)?)?);
    input.extend_from_slice(&hex_bytes(&registry.root_digest)?);
    input.extend_from_slice(&hex_bytes(&registry.digest()?)?);
    input.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
    for item in prefix {
        input.extend_from_slice(&hex_bytes(text(item, "transcript_digest")?)?);
    }
    input.extend_from_slice(&hex_bytes(convergence)?);
    input.extend_from_slice(&hex_bytes(projection)?);
    Ok(hex(&sha512(&input)))
}

pub fn seal_fixture_message(message: &Message, key: &KeyRecord) -> Result<Message, WireError> {
    let mut sealed = message.clone();
    sealed.insert(
        "signer_key_class".into(),
        Value::Text(key.key_class.clone()),
    );
    sealed.insert("signer_key_id".into(), Value::Text(key.key_id()?));
    sealed.insert("signer_role".into(), Value::Text(key.role.clone()));
    sealed.insert(
        "signature_algorithm".into(),
        Value::Text("TEST-SHA512".into()),
    );
    sealed.insert(
        "signing_public_key_hex".into(),
        Value::Text(key.public_key_hex.clone()),
    );
    sealed.insert("signature_hex".into(), Value::Text("00".into()));
    sealed.insert("transcript_digest".into(), Value::Text(ZERO.into()));
    validate_structure(&sealed, false)?;
    let digest = transcript_digest(&sealed)?;
    sealed.insert("transcript_digest".into(), Value::Text(digest));
    let preimage = signature_preimage(&sealed)?;
    let mut input = TESTDOM.to_vec();
    input.extend_from_slice(&hex_bytes(&key.public_key_hex)?);
    input.extend_from_slice(&preimage);
    sealed.insert("signature_hex".into(), Value::Text(hex(&sha512(&input))));
    validate_structure(&sealed, true)?;
    Ok(sealed)
}

fn validate_structure(message: &Message, check_digest: bool) -> Result<(), WireError> {
    let kind = text(message, "kind")?;
    let expected = expected_fields(kind).ok_or_else(|| fail("kind or exact field set"))?;
    let actual: BTreeSet<&str> = message.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(fail("kind or exact field set"));
    }
    const TIMES: &[&str] = &[
        "message_time_ms",
        "issued_at_ms",
        "not_before_ms",
        "expires_at_ms",
        "substantive_start_ms",
        "substantive_end_ms",
        "a_start_ms",
        "a_end_ms",
        "b_start_ms",
        "b_end_ms",
        "rendezvous_opened_at_ms",
        "rendezvous_released_at_ms",
        "lease_deadline_ms",
        "watchdog_deadline_ms",
        "permit_deadline_ms",
        "adapter_consumed_at_ms",
    ];
    for (key, value) in message {
        match value {
            Value::Number(v)
                if (matches!(key.as_str(), "sequence" | "authority_epoch")
                    || TIMES.contains(&key.as_str()))
                    && *v <= MAX_SAFE_INTEGER => {}
            Value::Text(v) if ascii_token(v) => {}
            _ => return Err(fail("exact field type")),
        }
    }
    for (key, value) in message {
        if ((key.ends_with("_digest") && key != "projection_schema")
            || matches!(
                key.as_str(),
                "challenge"
                    | "nonce"
                    | "signer_key_id"
                    | "trust_root_digest"
                    | "trust_registry_digest"
            ))
            && !digest128(match value {
                Value::Text(v) => v,
                _ => return Err(fail("digest field")),
            })
        {
            return Err(fail("digest field"));
        }
    }
    if !(matches!(text(message, "runtime_subject")?.len(), 128)
        && text(message, "runtime_subject")?
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        || !(matches!(text(message, "runtime_tree")?.len(), 128)
            && text(message, "runtime_tree")?
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(fail("runtime identity"));
    }
    if !lower_hex(text(message, "traversal_id")?, 32)
        || !lower_hex(text(message, "operation_id")?, 32)
    {
        return Err(fail("operation identity"));
    }
    for key in ["prepare_id", "capability_id", "lease_id", "permit_id"] {
        if message.contains_key(key) && !lower_hex(text(message, key)?, 32) {
            return Err(fail("artifact identity"));
        }
    }
    if text(message, "protocol")? != PROTOCOL
        || text(message, "oracle_sha512")? != ORACLE_SHA512
        || !matches!(text(message, "mode")?, "MODE_1" | "MODE_2" | "MODE_3")
    {
        return Err(fail("protocol/oracle/mode"));
    }
    if !matches!(
        text(message, "authority_class")?,
        "TEST_ONLY" | "PRODUCTION_HSM" | "PRODUCTION_TPM"
    ) {
        return Err(fail("authority class"));
    }
    if number(message, "authority_epoch")? == 0 {
        return Err(fail("authority epoch"));
    }
    let nbf = number(message, "not_before_ms")?;
    let issued = number(message, "issued_at_ms")?;
    let time = number(message, "message_time_ms")?;
    let expiry = number(message, "expires_at_ms")?;
    if !(nbf <= issued && issued <= time && time < expiry) {
        return Err(fail("message validity"));
    }
    if text(message, "signer_role")? != expected_role(kind).ok_or_else(|| fail("role"))? {
        return Err(fail("kind/signer role"));
    }
    if !matches!(
        text(message, "signer_key_class")?,
        "TEST_FIXTURE" | "PRODUCTION_HSM" | "PRODUCTION_TPM"
    ) || !matches!(
        text(message, "signature_algorithm")?,
        "TEST-SHA512" | "ML-DSA-65" | "ML-DSA-87"
    ) || !even_lower_hex(text(message, "signing_public_key_hex")?)
        || !even_lower_hex(text(message, "signature_hex")?)
    {
        return Err(fail("signature structure"));
    }
    if hex(&sha512(&hex_bytes(text(
        message,
        "signing_public_key_hex",
    )?)?))
        != text(message, "signer_key_id")?
    {
        return Err(fail("key ID derivation"));
    }
    if matches!(kind, "branch_a_statement" | "branch_b_statement")
        && !(nbf <= number(message, "substantive_start_ms")?
            && number(message, "substantive_start_ms")? < number(message, "substantive_end_ms")?
            && number(message, "substantive_end_ms")? <= time)
    {
        return Err(fail("branch substantive time"));
    }
    if projection_kind(kind) {
        if text(message, "projection_schema")? != "SBP-LEX-EXEC-PROJECTION/2"
            || text(message, "projection_digest")? != projection_digest(message)?
        {
            return Err(fail("projection derivation"));
        }
        if (
            text(message, "projection_request_digest")?,
            text(message, "projection_state_digest")?,
            text(message, "projection_effect_digest")?,
            text(message, "projection_adapter_digest")?,
        ) != (
            text(message, "request_digest")?,
            text(message, "state_digest")?,
            text(message, "effect_digest")?,
            text(message, "adapter_digest")?,
        ) {
            return Err(fail("projection execution binding"));
        }
    }
    if text(message, "extension_admission_mode")? != EXTENSION_ADMISSION_MODE
        || text(message, "extension_schema")? != EXTENSION_SCHEMA
        || text(message, "extension_configuration_digest")? == ZERO
        || text(message, "extension_admission_binding_digest")? == ZERO
    {
        return Err(fail("unsupported extension admission mode/schema"));
    }
    if let Some(Value::Text(decision)) = message.get("decision") {
        let allowed = match kind {
            "receipt_ack" => matches!(decision.as_str(), "ACK" | "FAILURE_ACK"),
            "watchdog_result" => matches!(decision.as_str(), "ACK" | "BLOCK"),
            _ => matches!(decision.as_str(), "ALLOW" | "DENY"),
        };
        if !allowed
            || matches!(decision.as_str(), "ALLOW" | "ACK")
                != (text(message, "error_code")? == "NONE")
        {
            return Err(fail("decision/error semantics"));
        }
    } else if text(message, "error_code")? != "NONE" {
        return Err(fail("non-result error"));
    }
    if check_digest && text(message, "transcript_digest")? != transcript_digest(message)? {
        return Err(fail("transcript digest"));
    }
    Ok(())
}

fn parse_set(value: &str) -> Result<BTreeSet<String>, WireError> {
    if value.is_empty() || value == "NONE" {
        return Err(fail("digest set"));
    }
    let parts: Vec<_> = value.split(',').collect();
    if parts.iter().any(|p| !digest128(p)) || !parts.windows(2).all(|w| w[0] < w[1]) {
        return Err(fail("noncanonical digest set"));
    }
    Ok(parts.into_iter().map(str::to_owned).collect())
}
fn check_rejections(removed: &BTreeSet<String>, value: &str) -> Result<(), WireError> {
    let entries: Vec<_> = if value == "NONE" {
        vec![]
    } else {
        value.split(',').collect()
    };
    if !entries.windows(2).all(|w| w[0] < w[1]) {
        return Err(fail("rejection order"));
    }
    let mut found = BTreeSet::new();
    for entry in entries {
        let (digest, reason) = entry
            .split_once('=')
            .ok_or_else(|| fail("rejection syntax"))?;
        if !digest128(digest) || !token(reason) || !found.insert(digest.to_owned()) {
            return Err(fail("rejection entry"));
        }
    }
    if &found != removed {
        return Err(fail("rejection coverage"));
    }
    Ok(())
}

const POST_KINDS: &[&str] = &[
    "prepare_request",
    "prepare_result",
    "commit_request",
    "commit_result",
    "lease_redeem_request",
    "lease_redeem_result",
    "watchdog_arm_request",
    "watchdog_arm_result",
    "effect_permit_request",
    "effect_permit_result",
];

const IMMUTABLE_FIELDS: &[&str] = &[
    "adapter_boundary_digest",
    "adapter_digest",
    "audit_anchor_digest",
    "authority_build_id",
    "authority_class",
    "authority_epoch",
    "authority_profile",
    "challenge",
    "domain_digest",
    "durable_consumption_digest",
    "effect_digest",
    "effect_intent_digest",
    "extension_admission_binding_digest",
    "extension_admission_mode",
    "extension_configuration_digest",
    "extension_schema",
    "expires_at_ms",
    "inhibit_binding_digest",
    "interlock_digest",
    "issued_at_ms",
    "mode",
    "not_before_ms",
    "operation_id",
    "oracle_sha512",
    "protocol",
    "replay_namespace",
    "request_digest",
    "runtime_subject",
    "runtime_tree",
    "stable_effect_intent_digest",
    "stable_request_digest",
    "state_digest",
    "subject_digest",
    "traversal_id",
    "trust_registry_digest",
    "trust_root_digest",
];

fn mode_prefix(mode: &str) -> Result<&'static [&'static str], WireError> {
    match mode {
        "MODE_1" => Ok(&[
            "mode1_release_request",
            "mode1_release_result",
            "branch_a_statement",
            "branch_b_statement",
            "mode1_overlap_witness",
            "convergence_request",
            "convergence_result",
        ]),
        "MODE_2" => Ok(&[
            "branch_a_statement",
            "mode2_validator_certificate",
            "convergence_request",
            "convergence_result",
        ]),
        "MODE_3" => Ok(&[
            "mode3_single_state_proof",
            "convergence_request",
            "convergence_result",
        ]),
        _ => Err(fail("unknown mode")),
    }
}

fn result_for_request(kind: &str) -> Option<&'static str> {
    match kind {
        "mode1_release_request" => Some("mode1_release_result"),
        "convergence_request" => Some("convergence_result"),
        "prepare_request" => Some("prepare_result"),
        "commit_request" => Some("commit_result"),
        "lease_redeem_request" => Some("lease_redeem_result"),
        "watchdog_arm_request" => Some("watchdog_arm_result"),
        "effect_permit_request" => Some("effect_permit_result"),
        "effect_receipt" => Some("receipt_ack"),
        "watchdog_terminal" => Some("watchdog_result"),
        _ => None,
    }
}

fn request_for_result(kind: &str) -> Option<&'static str> {
    [
        "mode1_release_request",
        "convergence_request",
        "prepare_request",
        "commit_request",
        "lease_redeem_request",
        "watchdog_arm_request",
        "effect_permit_request",
        "effect_receipt",
        "watchdog_terminal",
    ]
    .into_iter()
    .find(|request| result_for_request(request) == Some(kind))
}

fn authenticate_messages(
    messages: &[Message],
    expected: &[&str],
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<bool, WireError> {
    if messages.is_empty() || messages.len() != expected.len() {
        return Err(fail("empty/mismatched authenticated prefix"));
    }
    for message in messages {
        validate_structure(message, true)?;
    }
    if admission.trust_root_digest != registry.root_digest
        || text(&messages[0], "trust_root_digest")? != admission.trust_root_digest
    {
        return Err(fail("trust root mismatch"));
    }
    if admission.registry_digest != registry.digest()?
        || text(&messages[0], "trust_registry_digest")? != admission.registry_digest
    {
        return Err(fail("registry mismatch"));
    }
    if text(&messages[0], "runtime_subject")? != admission.runtime_subject
        || text(&messages[0], "runtime_tree")? != admission.runtime_tree
        || text(&messages[0], "authority_class")? != admission.authority_class
        || number(&messages[0], "authority_epoch")? != admission.authority_epoch
        || text(&messages[0], "authority_profile")? != admission.authority_profile
        || text(&messages[0], "authority_build_id")? != admission.authority_build_id
    {
        return Err(fail("admission policy mismatch"));
    }
    for (key, value) in [
        ("mode", admission.mode.as_str()),
        ("traversal_id", admission.traversal_id.as_str()),
        ("operation_id", admission.operation_id.as_str()),
        ("challenge", admission.challenge.as_str()),
        ("replay_namespace", admission.replay_namespace.as_str()),
        ("domain_digest", admission.domain_digest.as_str()),
        ("subject_digest", admission.subject_digest.as_str()),
        (
            "stable_request_digest",
            admission.stable_request_digest.as_str(),
        ),
        ("request_digest", admission.request_digest.as_str()),
        ("state_digest", admission.state_digest.as_str()),
        ("effect_digest", admission.effect_digest.as_str()),
        (
            "effect_intent_digest",
            admission.effect_intent_digest.as_str(),
        ),
        ("adapter_digest", admission.adapter_digest.as_str()),
        (
            "adapter_boundary_digest",
            admission.adapter_boundary_digest.as_str(),
        ),
        (
            "inhibit_binding_digest",
            admission.inhibit_binding_digest.as_str(),
        ),
        ("interlock_digest", admission.interlock_digest.as_str()),
        (
            "audit_anchor_digest",
            admission.audit_anchor_digest.as_str(),
        ),
        (
            "extension_admission_mode",
            admission.extension_admission_mode.as_str(),
        ),
        ("extension_schema", admission.extension_schema.as_str()),
        (
            "extension_configuration_digest",
            admission.extension_configuration_digest.as_str(),
        ),
        (
            "extension_admission_binding_digest",
            admission.extension_admission_binding_digest.as_str(),
        ),
    ] {
        if text(&messages[0], key)? != value {
            return Err(fail("expected execution context mismatch"));
        }
    }
    if text(&messages[0], "stable_request_digest")?
        != stable_request_digest(text(&messages[0], "request_digest")?)?
    {
        return Err(fail("stable request derivation"));
    }
    let stable = stable_effect_intent_digest(
        text(&messages[0], "stable_request_digest")?,
        text(&messages[0], "effect_intent_digest")?,
        text(&messages[0], "effect_digest")?,
        text(&messages[0], "adapter_digest")?,
        text(&messages[0], "adapter_boundary_digest")?,
    )?;
    if text(&messages[0], "stable_effect_intent_digest")? != stable
        || text(&messages[0], "durable_consumption_digest")?
            != durable_consumption_digest(text(&messages[0], "replay_namespace")?, &stable)?
    {
        return Err(fail("stable/durable effect binding"));
    }
    let required_roles: BTreeSet<&str> = [
        "BRANCH_A",
        "BRANCH_B",
        "VALIDATOR",
        "SINGLE_STATE",
        "WITNESS",
        "COORDINATOR",
        "AUTHORITY",
        "ADAPTER",
        "WATCHDOG",
    ]
    .into_iter()
    .collect();
    if registry
        .entries
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != required_roles
    {
        return Err(fail("registry role set mismatch"));
    }
    let mut key_ids = BTreeSet::new();
    let expected_registry_class = match admission.authority_class.as_str() {
        "TEST_ONLY" => "TEST_FIXTURE",
        "PRODUCTION_HSM" => "PRODUCTION_HSM",
        "PRODUCTION_TPM" => "PRODUCTION_TPM",
        _ => return Err(fail("authority class")),
    };
    for key in registry.entries.values() {
        if key.key_class != expected_registry_class {
            return Err(fail("registry authority class mismatch"));
        }
        if !key_ids.insert(key.key_id()?) {
            return Err(fail("role keys not distinct"));
        }
    }
    let binding: Vec<Value> = IMMUTABLE_FIELDS
        .iter()
        .map(|key| messages[0].get(*key).unwrap().clone())
        .collect();
    let mut prior = ZERO.to_owned();
    let mut prior_time = None;
    let mut nonces = BTreeSet::new();
    let mut terminal = false;
    for (index, (message, kind)) in messages.iter().zip(expected.iter()).enumerate() {
        if text(message, "kind")? != *kind || number(message, "sequence")? != index as u64 {
            return Err(fail("order mismatch"));
        }
        if IMMUTABLE_FIELDS
            .iter()
            .map(|key| message.get(*key).unwrap().clone())
            .collect::<Vec<_>>()
            != binding
        {
            return Err(fail("execution binding mutation"));
        }
        if text(message, "prior_transcript_digest")? != prior
            || !nonces.insert(text(message, "nonce")?.to_owned())
        {
            return Err(fail("chain or nonce replay"));
        }
        let time = number(message, "message_time_ms")?;
        if prior_time.is_some_and(|value| time < value)
            || !(number(message, "not_before_ms")? <= time
                && time <= trusted_now_ms
                && trusted_now_ms < number(message, "expires_at_ms")?)
        {
            return Err(fail("trusted-time freshness/order"));
        }
        prior_time = Some(time);
        prior = text(message, "transcript_digest")?.to_owned();
        let role = expected_role(kind).ok_or_else(|| fail("role"))?;
        let admitted = registry
            .entries
            .get(role)
            .ok_or_else(|| fail("unadmitted role"))?;
        if text(message, "signer_role")? != role
            || text(message, "signer_key_class")? != admitted.key_class
            || text(message, "signer_key_id")? != admitted.key_id()?
            || text(message, "signing_public_key_hex")? != admitted.public_key_hex
        {
            return Err(fail("signer registry mismatch"));
        }
        let algorithm = text(message, "signature_algorithm")?;
        let matrix = match text(message, "authority_class")? {
            "TEST_ONLY" => ("TEST_FIXTURE", &["TEST-SHA512"][..]),
            "PRODUCTION_HSM" => ("PRODUCTION_HSM", &["ML-DSA-65", "ML-DSA-87"][..]),
            "PRODUCTION_TPM" => ("PRODUCTION_TPM", &["ML-DSA-65", "ML-DSA-87"][..]),
            _ => return Err(fail("authority class")),
        };
        if admitted.key_class != matrix.0 || !matrix.1.contains(&algorithm) {
            return Err(fail("authority/key/algorithm matrix"));
        }
        if !verifier.verify(
            algorithm,
            &hex_bytes(&admitted.public_key_hex)?,
            &signature_preimage(message)?,
            &hex_bytes(text(message, "signature_hex")?)?,
        ) {
            return Err(fail("signature verification failed"));
        }
        if *kind == "effect_permit_request"
            && text(message, "point_of_use_digest")? != point_of_use_digest(message)?
        {
            return Err(fail("point-of-use derivation"));
        }
        if matches!(message.get("decision"), Some(Value::Text(value)) if matches!(value.as_str(), "DENY" | "BLOCK"))
        {
            if index != messages.len() - 1 {
                return Err(fail("continued after denial"));
            }
            terminal = true;
        }
    }
    Ok(terminal)
}

fn expected_stage_prefix(
    mode: &str,
    stage: &str,
    actual: &[&str],
) -> Result<Vec<&'static str>, WireError> {
    let prefix = mode_prefix(mode)?;
    if stage == "mode1_release_request" {
        return if mode == "MODE_1" {
            Ok(vec!["mode1_release_request"])
        } else {
            Err(fail("release stage outside Mode 1"))
        };
    }
    if stage == "convergence_request" {
        return Ok(prefix[..prefix.len() - 1].to_vec());
    }
    let offset = match stage {
        "prepare_request" => Some(1),
        "commit_request" => Some(3),
        "lease_redeem_request" => Some(5),
        "watchdog_arm_request" => Some(7),
        "effect_permit_request" => Some(9),
        _ => None,
    };
    let mut base = prefix.to_vec();
    base.extend_from_slice(POST_KINDS);
    if let Some(count) = offset {
        let mut result = prefix.to_vec();
        result.extend_from_slice(&POST_KINDS[..count]);
        return Ok(result);
    }
    if stage == "effect_receipt" {
        base.push("effect_receipt");
        return Ok(base);
    }
    if stage == "watchdog_terminal" {
        let mut timeout = base.clone();
        timeout.push("watchdog_terminal");
        let mut receipt = base;
        receipt.extend_from_slice(&["effect_receipt", "receipt_ack", "watchdog_terminal"]);
        return if actual == receipt {
            Ok(receipt)
        } else {
            Ok(timeout)
        };
    }
    Err(fail("unsupported staged request"))
}

fn release_request_values(request: &Message) -> Result<Message, WireError> {
    let ca = rendezvous_checkpoint_digest(
        "A",
        text(request, "traversal_id")?,
        text(request, "challenge")?,
        text(request, "worker_a_id")?,
        text(request, "a_process_digest")?,
    )?;
    let cb = rendezvous_checkpoint_digest(
        "B",
        text(request, "traversal_id")?,
        text(request, "challenge")?,
        text(request, "worker_b_id")?,
        text(request, "b_process_digest")?,
    )?;
    if text(request, "a_checkpoint_digest")? != ca
        || text(request, "b_checkpoint_digest")? != cb
        || text(request, "worker_a_id")? == text(request, "worker_b_id")?
        || text(request, "a_process_digest")? == text(request, "b_process_digest")?
        || !(number(request, "not_before_ms")? <= number(request, "rendezvous_opened_at_ms")?
            && number(request, "rendezvous_opened_at_ms")? <= number(request, "message_time_ms")?)
    {
        return Err(fail("Mode 1 release request evidence"));
    }
    Ok(BTreeMap::from([
        ("a_checkpoint_digest".into(), Value::Text(ca)),
        ("b_checkpoint_digest".into(), Value::Text(cb)),
        (
            "rendezvous_opened_at_ms".into(),
            Value::Number(number(request, "rendezvous_opened_at_ms")?),
        ),
        (
            "release_request_digest".into(),
            Value::Text(text(request, "transcript_digest")?.into()),
        ),
    ]))
}

fn validate_release_pair(request: &Message, result: &Message) -> Result<String, WireError> {
    let values = release_request_values(request)?;
    let common_mismatch = text(result, "a_checkpoint_digest")?
        != text(&values, "a_checkpoint_digest")?
        || text(result, "b_checkpoint_digest")? != text(&values, "b_checkpoint_digest")?
        || text(result, "release_request_digest")? != text(&values, "release_request_digest")?
        || number(result, "rendezvous_opened_at_ms")?
            != number(&values, "rendezvous_opened_at_ms")?;
    if text(result, "decision")? == "DENY" {
        if common_mismatch
            || text(result, "rendezvous_release_digest")? != ZERO
            || number(result, "rendezvous_released_at_ms")? != 0
        {
            return Err(fail("Mode 1 denied release evidence"));
        }
        return Ok(ZERO.into());
    }
    let release = rendezvous_release_digest(
        text(&values, "a_checkpoint_digest")?,
        text(&values, "b_checkpoint_digest")?,
        number(&values, "rendezvous_opened_at_ms")?,
        number(result, "rendezvous_released_at_ms")?,
    )?;
    if common_mismatch
        || text(result, "rendezvous_release_digest")? != release
        || !(number(request, "message_time_ms")? <= number(result, "rendezvous_released_at_ms")?
            && number(result, "rendezvous_released_at_ms")? <= number(result, "message_time_ms")?)
    {
        return Err(fail("Mode 1 release result evidence"));
    }
    Ok(release)
}

fn receipt_request_values(
    messages: &[Message],
    start: usize,
    base: usize,
) -> Result<Message, WireError> {
    if messages.len() != base + 1 || text(&messages[base], "kind")? != "effect_receipt" {
        return Err(fail("receipt request prefix"));
    }
    let permit = &messages[start + 9];
    let lease = &messages[start + 5];
    let armed = &messages[start + 7];
    let receipt = &messages[base];
    if text(permit, "decision")? != "ALLOW"
        || text(armed, "decision")? != "ALLOW"
        || text(receipt, "permit_digest")? != text(permit, "permit_digest")?
        || text(receipt, "permit_id")? != text(permit, "permit_id")?
        || text(receipt, "watchdog_digest")? != text(permit, "watchdog_digest")?
    {
        return Err(fail("receipt permit/watchdog binding"));
    }
    let deadline = number(lease, "lease_deadline_ms")?
        .min(number(permit, "permit_deadline_ms")?)
        .min(number(armed, "watchdog_deadline_ms")?);
    let consumed = number(receipt, "adapter_consumed_at_ms")?;
    if consumed < number(permit, "message_time_ms")?
        || consumed >= deadline
        || consumed > number(receipt, "message_time_ms")?
        || number(receipt, "message_time_ms")? >= deadline
    {
        return Err(fail("adapter atomic consumption freshness"));
    }
    let derived_consumption = adapter_consumption_digest(
        text(receipt, "durable_consumption_digest")?,
        text(receipt, "permit_digest")?,
        text(receipt, "effect_digest")?,
        text(receipt, "adapter_digest")?,
        consumed,
        text(receipt, "effect_outcome")?,
    )?;
    if text(receipt, "adapter_consumption_digest")? != derived_consumption {
        return Err(fail("adapter consumption derivation"));
    }
    let derived_receipt = effect_receipt_digest(receipt)?;
    if text(receipt, "receipt_digest")? != derived_receipt || derived_receipt == ZERO {
        return Err(fail("effect receipt derivation"));
    }
    let (status, ack_decision, watchdog_status, watchdog_decision) =
        match text(receipt, "effect_outcome")? {
            "SUCCEEDED" => ("SUCCESS_RECORDED", "ACK", "HEALTHY", "ACK"),
            "FAILED" => ("FAILURE_RECORDED", "FAILURE_ACK", "STOP", "BLOCK"),
            "UNKNOWN" => ("UNKNOWN_BLOCKED", "FAILURE_ACK", "STOP", "BLOCK"),
            _ => return Err(fail("effect outcome")),
        };
    Ok(BTreeMap::from([
        (
            "adapter_consumption_digest".into(),
            Value::Text(derived_consumption),
        ),
        ("completion_deadline_ms".into(), Value::Number(deadline)),
        (
            "permit_digest".into(),
            Value::Text(text(receipt, "permit_digest")?.into()),
        ),
        (
            "permit_id".into(),
            Value::Text(text(receipt, "permit_id")?.into()),
        ),
        ("receipt_digest".into(), Value::Text(derived_receipt)),
        ("receipt_status".into(), Value::Text(status.into())),
        (
            "required_ack_decision".into(),
            Value::Text(ack_decision.into()),
        ),
        (
            "required_watchdog_decision".into(),
            Value::Text(watchdog_decision.into()),
        ),
        (
            "required_watchdog_status".into(),
            Value::Text(watchdog_status.into()),
        ),
        (
            "watchdog_digest".into(),
            Value::Text(text(receipt, "watchdog_digest")?.into()),
        ),
    ]))
}

fn watchdog_terminal_values(
    messages: &[Message],
    start: usize,
    base: usize,
) -> Result<Message, WireError> {
    let lease = &messages[start + 5];
    let permit = &messages[start + 9];
    let armed = &messages[start + 7];
    let tail = &messages[base..];
    if tail.len() == 1 {
        let terminal = &tail[0];
        let fail_close_deadline = number(lease, "lease_deadline_ms")?
            .min(number(permit, "permit_deadline_ms")?)
            .min(number(armed, "watchdog_deadline_ms")?);
        let terminal_time = number(terminal, "message_time_ms")?;
        let result_deadline_exclusive = terminal_time
            .saturating_add(FAIL_CLOSE_RESULT_MAX_DELAY_MS + 1)
            .min(MAX_SAFE_INTEGER + 1);
        let valid_trip_time = if text(terminal, "watchdog_status")? == "TIMEOUT" {
            terminal_time == fail_close_deadline
        } else {
            number(permit, "message_time_ms")? <= terminal_time
                && terminal_time <= fail_close_deadline
        };
        if !matches!(text(terminal, "watchdog_status")?, "STOP" | "TIMEOUT")
            || text(terminal, "receipt_digest")? != ZERO
            || text(terminal, "permit_digest")? != text(permit, "permit_digest")?
            || text(terminal, "permit_id")? != text(permit, "permit_id")?
            || text(terminal, "watchdog_digest")? != text(permit, "watchdog_digest")?
            || !valid_trip_time
        {
            return Err(fail("invalid no-receipt watchdog request"));
        }
        return Ok(BTreeMap::from([
            (
                "completion_deadline_ms".into(),
                Value::Number(result_deadline_exclusive),
            ),
            (
                "fail_close_deadline_ms".into(),
                Value::Number(fail_close_deadline),
            ),
            (
                "permit_digest".into(),
                Value::Text(text(terminal, "permit_digest")?.into()),
            ),
            (
                "permit_id".into(),
                Value::Text(text(terminal, "permit_id")?.into()),
            ),
            ("receipt_digest".into(), Value::Text(ZERO.into())),
            (
                "required_watchdog_decision".into(),
                Value::Text("BLOCK".into()),
            ),
            (
                "watchdog_digest".into(),
                Value::Text(text(terminal, "watchdog_digest")?.into()),
            ),
        ]));
    }
    if tail.len() != 3
        || text(&tail[0], "kind")? != "effect_receipt"
        || text(&tail[1], "kind")? != "receipt_ack"
    {
        return Err(fail("watchdog request prefix"));
    }
    let receipt_values = receipt_request_values(&messages[..base + 1], start, base)?;
    let receipt = &tail[0];
    let ack = &tail[1];
    let terminal = &tail[2];
    if text(ack, "receipt_digest")? != text(&receipt_values, "receipt_digest")?
        || text(ack, "permit_digest")? != text(&receipt_values, "permit_digest")?
        || text(ack, "permit_id")? != text(&receipt_values, "permit_id")?
        || text(ack, "watchdog_digest")? != text(&receipt_values, "watchdog_digest")?
        || text(ack, "receipt_status")? != text(&receipt_values, "receipt_status")?
        || text(ack, "decision")? != text(&receipt_values, "required_ack_decision")?
        || text(terminal, "receipt_digest")? != text(&receipt_values, "receipt_digest")?
        || text(terminal, "permit_digest")? != text(&receipt_values, "permit_digest")?
        || text(terminal, "permit_id")? != text(&receipt_values, "permit_id")?
        || text(terminal, "watchdog_digest")? != text(&receipt_values, "watchdog_digest")?
        || text(terminal, "watchdog_status")? != text(&receipt_values, "required_watchdog_status")?
        || number(ack, "message_time_ms")? >= number(&receipt_values, "completion_deadline_ms")?
        || number(terminal, "message_time_ms")?
            >= number(&receipt_values, "completion_deadline_ms")?
        || text(receipt, "receipt_digest")? != text(&receipt_values, "receipt_digest")?
    {
        return Err(fail("receipt/watchdog staged semantics"));
    }
    Ok(BTreeMap::from([
        (
            "completion_deadline_ms".into(),
            receipt_values
                .get("completion_deadline_ms")
                .cloned()
                .ok_or_else(|| fail("completion deadline"))?,
        ),
        (
            "permit_digest".into(),
            Value::Text(text(&receipt_values, "permit_digest")?.into()),
        ),
        (
            "permit_id".into(),
            Value::Text(text(&receipt_values, "permit_id")?.into()),
        ),
        (
            "receipt_digest".into(),
            Value::Text(text(&receipt_values, "receipt_digest")?.into()),
        ),
        (
            "required_watchdog_decision".into(),
            Value::Text(text(&receipt_values, "required_watchdog_decision")?.into()),
        ),
        (
            "watchdog_digest".into(),
            Value::Text(text(&receipt_values, "watchdog_digest")?.into()),
        ),
    ]))
}

pub fn validate_request_prefix(
    messages: &[Message],
    expected_request_kind: &str,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<VerifiedStageContext, WireError> {
    if messages.is_empty() {
        return Err(fail("empty staged request"));
    }
    let mode = text(&messages[0], "mode")?;
    let actual: Vec<&str> = messages
        .iter()
        .map(|message| text(message, "kind"))
        .collect::<Result<_, _>>()?;
    let expected = expected_stage_prefix(mode, expected_request_kind, &actual)?;
    if actual != expected || actual.last().copied() != Some(expected_request_kind) {
        return Err(fail("staged request shape/order"));
    }
    if authenticate_messages(
        messages,
        &expected,
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )? {
        return Err(fail("terminal denial is not a new request"));
    }
    let prefix = mode_prefix(mode)?;
    if !matches!(
        expected_request_kind,
        "mode1_release_request" | "convergence_request"
    ) {
        validate_completed_lifecycle(messages, prefix.len(), registry, admission)?;
    }
    stage_context_from_authenticated(messages, expected_request_kind, registry, admission)
}

fn stage_context_from_authenticated(
    messages: &[Message],
    expected_request_kind: &str,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
) -> Result<VerifiedStageContext, WireError> {
    let mode = text(&messages[0], "mode")?;
    let prefix = mode_prefix(mode)?;
    let mut convergence_binding = ZERO.to_owned();
    let values = if expected_request_kind == "mode1_release_request" {
        release_request_values(&messages[0])?
    } else if expected_request_kind == "convergence_request" {
        let (refs, convergence) =
            derive_mode_request(messages, mode, messages.len() - 1, admission)?;
        convergence_binding = authenticated_convergence_binding_digest(
            admission,
            registry,
            messages,
            &convergence,
            &refs.3,
        )?;
        BTreeMap::from([
            ("convergence_digest".into(), Value::Text(convergence)),
            ("evidence_a_digest".into(), Value::Text(refs.0)),
            ("evidence_b_digest".into(), Value::Text(refs.1)),
            ("mode_evidence_digest".into(), Value::Text(refs.2)),
            ("projection_digest".into(), Value::Text(refs.3)),
        ])
    } else {
        let result_index = prefix.len() - 1;
        validate_mode_prefix(messages, mode, result_index, admission)?;
        if text(&messages[result_index], "decision")? != "ALLOW" {
            return Err(fail("request after refused convergence"));
        }
        let (refs, convergence) = derive_mode_request(messages, mode, result_index - 1, admission)?;
        convergence_binding = authenticated_convergence_binding_digest(
            admission,
            registry,
            &messages[..result_index],
            &convergence,
            &refs.3,
        )?;
        let start = prefix.len();
        let base = start + POST_KINDS.len();
        let request = messages.last().unwrap();
        match expected_request_kind {
            "prepare_request" => BTreeMap::from([(
                "convergence_digest".into(),
                Value::Text(text(request, "convergence_digest")?.into()),
            )]),
            "commit_request" => BTreeMap::from([
                (
                    "prepare_id".into(),
                    Value::Text(text(request, "prepare_id")?.into()),
                ),
                (
                    "prepare_proof_digest".into(),
                    Value::Text(text(request, "prepare_proof_digest")?.into()),
                ),
            ]),
            "lease_redeem_request" => BTreeMap::from([
                (
                    "capability_digest".into(),
                    Value::Text(text(request, "capability_digest")?.into()),
                ),
                (
                    "capability_id".into(),
                    Value::Text(text(request, "capability_id")?.into()),
                ),
                (
                    "lease_deadline_ms".into(),
                    Value::Number(number(request, "lease_deadline_ms")?),
                ),
            ]),
            "watchdog_arm_request" => BTreeMap::from([
                (
                    "lease_digest".into(),
                    Value::Text(text(request, "lease_digest")?.into()),
                ),
                (
                    "lease_id".into(),
                    Value::Text(text(request, "lease_id")?.into()),
                ),
                (
                    "watchdog_deadline_ms".into(),
                    Value::Number(number(request, "watchdog_deadline_ms")?),
                ),
            ]),
            "effect_permit_request" => BTreeMap::from([
                (
                    "lease_deadline_ms".into(),
                    Value::Number(number(request, "lease_deadline_ms")?),
                ),
                (
                    "lease_digest".into(),
                    Value::Text(text(request, "lease_digest")?.into()),
                ),
                (
                    "lease_id".into(),
                    Value::Text(text(request, "lease_id")?.into()),
                ),
                (
                    "point_of_use_digest".into(),
                    Value::Text(text(request, "point_of_use_digest")?.into()),
                ),
                (
                    "watchdog_deadline_ms".into(),
                    Value::Number(number(request, "watchdog_deadline_ms")?),
                ),
                (
                    "watchdog_digest".into(),
                    Value::Text(text(request, "watchdog_digest")?.into()),
                ),
            ]),
            "effect_receipt" => receipt_request_values(messages, start, base)?,
            "watchdog_terminal" => watchdog_terminal_values(messages, start, base)?,
            _ => return Err(fail("unsupported staged request semantics")),
        }
    };
    let result_kind = result_for_request(expected_request_kind)
        .ok_or_else(|| fail("missing staged result kind"))?;
    let policy_digest = admission_policy_digest(admission)?;
    let mut body = Vec::new();
    body.extend_from_slice(&hex_bytes(&policy_digest)?);
    body.extend_from_slice(&hex_bytes(&registry.digest()?)?);
    body.extend_from_slice(&hex_bytes(&convergence_binding)?);
    body.extend_from_slice(&(messages.len() as u32).to_be_bytes());
    for message in messages {
        body.extend_from_slice(&hex_bytes(text(message, "transcript_digest")?)?);
    }
    body.extend_from_slice(expected_request_kind.as_bytes());
    body.push(0);
    body.extend_from_slice(result_kind.as_bytes());
    body.push(0);
    body.extend_from_slice(&encode_raw(&values)?);
    let mut context_input = STAGECTXDOM.to_vec();
    context_input.extend_from_slice(&body);
    Ok(VerifiedStageContext {
        stage_kind: expected_request_kind.into(),
        expected_result_kind: result_kind.into(),
        request_transcript_digest: text(messages.last().unwrap(), "transcript_digest")?.into(),
        chain_tip_digest: text(messages.last().unwrap(), "transcript_digest")?.into(),
        admission_policy_digest: policy_digest,
        authenticated_convergence_binding_digest: convergence_binding,
        context_digest: hex(&sha512(&context_input)),
        values,
    })
}

pub fn validate_and_append_result(
    request_prefix: &[Message],
    result: &Message,
    context: &VerifiedStageContext,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<Vec<Message>, WireError> {
    let fresh = validate_request_prefix(
        request_prefix,
        context.stage_kind(),
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )?;
    if fresh.context_digest() != context.context_digest() {
        return Err(fail("stale or foreign stage context"));
    }
    let actual: Vec<&str> = request_prefix
        .iter()
        .map(|message| text(message, "kind"))
        .collect::<Result<_, _>>()?;
    let mut expected = expected_stage_prefix(&admission.mode, context.stage_kind(), &actual)?;
    expected.push(context.expected_result_kind());
    let mut appended = request_prefix.to_vec();
    appended.push(result.clone());
    authenticate_messages(
        &appended,
        &expected,
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )?;
    validate_stage_result(result, &fresh, request_prefix)?;
    Ok(appended)
}

pub fn validate_effect_permit_for_atomic_consumption(
    messages_through_permit: &[Message],
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<VerifiedEffectPermitContext, WireError> {
    if messages_through_permit.len() < 2
        || text(messages_through_permit.last().unwrap(), "kind")? != "effect_permit_result"
    {
        return Err(fail("atomic permit prefix"));
    }
    let request_prefix = &messages_through_permit[..messages_through_permit.len() - 1];
    let stage = validate_request_prefix(
        request_prefix,
        "effect_permit_request",
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )?;
    let appended = validate_and_append_result(
        request_prefix,
        messages_through_permit.last().unwrap(),
        &stage,
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )?;
    let permit = appended.last().unwrap();
    if text(permit, "decision")? != "ALLOW" {
        return Err(fail("non-authorizing permit result"));
    }
    let deadline = stage
        .derived_number("lease_deadline_ms")?
        .min(stage.derived_number("watchdog_deadline_ms")?)
        .min(number(permit, "permit_deadline_ms")?);
    if trusted_now_ms >= deadline {
        return Err(fail("permit expired at point of use"));
    }
    let values = BTreeMap::from([
        (
            "adapter_boundary_digest".into(),
            Value::Text(text(permit, "adapter_boundary_digest")?.into()),
        ),
        (
            "adapter_digest".into(),
            Value::Text(text(permit, "adapter_digest")?.into()),
        ),
        (
            "authority_epoch".into(),
            Value::Number(number(permit, "authority_epoch")?),
        ),
        (
            "domain_digest".into(),
            Value::Text(text(permit, "domain_digest")?.into()),
        ),
        (
            "durable_consumption_digest".into(),
            Value::Text(text(permit, "durable_consumption_digest")?.into()),
        ),
        (
            "effect_digest".into(),
            Value::Text(text(permit, "effect_digest")?.into()),
        ),
        (
            "operation_id".into(),
            Value::Text(text(permit, "operation_id")?.into()),
        ),
        (
            "permit_deadline_ms".into(),
            Value::Number(number(permit, "permit_deadline_ms")?),
        ),
        (
            "permit_digest".into(),
            Value::Text(text(permit, "permit_digest")?.into()),
        ),
        (
            "permit_id".into(),
            Value::Text(text(permit, "permit_id")?.into()),
        ),
        (
            "lease_id".into(),
            Value::Text(stage.derived_text("lease_id")?.into()),
        ),
        (
            "point_of_use_digest".into(),
            Value::Text(stage.derived_text("point_of_use_digest")?.into()),
        ),
        (
            "stable_effect_intent_digest".into(),
            Value::Text(text(permit, "stable_effect_intent_digest")?.into()),
        ),
        (
            "subject_digest".into(),
            Value::Text(text(permit, "subject_digest")?.into()),
        ),
        (
            "traversal_id".into(),
            Value::Text(text(permit, "traversal_id")?.into()),
        ),
        (
            "watchdog_deadline_ms".into(),
            Value::Number(stage.derived_number("watchdog_deadline_ms")?),
        ),
        (
            "watchdog_digest".into(),
            Value::Text(text(permit, "watchdog_digest")?.into()),
        ),
    ]);
    Ok(VerifiedEffectPermitContext {
        stage_context_digest: stage.context_digest().into(),
        admission_policy_digest: stage.admission_policy_digest().into(),
        authenticated_convergence_binding_digest: stage
            .authenticated_convergence_binding_digest()
            .into(),
        values,
    })
}

fn validate_stage_result(
    result: &Message,
    context: &VerifiedStageContext,
    request_prefix: &[Message],
) -> Result<(), WireError> {
    if text(result, "kind")? != context.expected_result_kind() {
        return Err(fail("staged result kind"));
    }
    if number(result, "sequence")? != request_prefix.len() as u64
        || text(result, "prior_transcript_digest")? != context.chain_tip_digest()
    {
        return Err(fail("staged result chain"));
    }
    if number(result, "message_time_ms")?
        < number(request_prefix.last().unwrap(), "message_time_ms")?
    {
        return Err(fail("staged result chronology"));
    }
    validate_completed_result_semantics(
        context.stage_kind(),
        request_prefix.last().unwrap(),
        result,
        context,
    )?;
    match context.stage_kind() {
        "mode1_release_request" => {
            validate_release_pair(request_prefix.last().unwrap(), result)?;
        }
        "convergence_request" => {
            for key in [
                "convergence_digest",
                "evidence_a_digest",
                "evidence_b_digest",
                "mode_evidence_digest",
                "projection_digest",
            ] {
                if result.get(key) != context.derived(key) {
                    return Err(fail("convergence result derivation"));
                }
            }
        }
        "lease_redeem_request" => {
            if result.get("lease_deadline_ms") != context.derived("lease_deadline_ms") {
                return Err(fail("authority lifecycle handoff: lease result"));
            }
            if text(result, "decision")? == "ALLOW"
                && number(result, "message_time_ms")? >= number(result, "lease_deadline_ms")?
            {
                return Err(fail("lease result deadline"));
            }
        }
        "watchdog_arm_request" => {
            if result.get("watchdog_deadline_ms") != context.derived("watchdog_deadline_ms") {
                return Err(fail("watchdog result derivation"));
            }
            if text(result, "decision")? == "ALLOW"
                && number(result, "message_time_ms")? >= number(result, "watchdog_deadline_ms")?
            {
                return Err(fail("watchdog arm result deadline"));
            }
        }
        "effect_permit_request" => {
            if result.get("watchdog_digest") != context.derived("watchdog_digest") {
                return Err(fail("permit result derivation"));
            }
            if text(result, "decision")? == "ALLOW"
                && (number(result, "permit_deadline_ms")?
                    > context
                        .derived_number("lease_deadline_ms")?
                        .min(context.derived_number("watchdog_deadline_ms")?)
                    || number(result, "message_time_ms")? >= number(result, "permit_deadline_ms")?)
            {
                return Err(fail("permit result deadline"));
            }
        }
        "effect_receipt" => {
            for key in [
                "permit_digest",
                "permit_id",
                "receipt_digest",
                "receipt_status",
                "watchdog_digest",
            ] {
                if result.get(key) != context.derived(key) {
                    return Err(fail("receipt ACK derivation"));
                }
            }
            if text(result, "decision")? != context.derived_text("required_ack_decision")?
                || number(result, "message_time_ms")?
                    >= context.derived_number("completion_deadline_ms")?
            {
                return Err(fail("receipt ACK decision/deadline"));
            }
        }
        "watchdog_terminal" => {
            if result.get("permit_digest") != context.derived("permit_digest")
                || result.get("permit_id") != context.derived("permit_id")
                || result.get("receipt_digest") != context.derived("receipt_digest")
                || result.get("watchdog_digest") != context.derived("watchdog_digest")
                || text(result, "decision")?
                    != context.derived_text("required_watchdog_decision")?
            {
                return Err(fail("watchdog final result derivation"));
            }
            let deadline = context.derived_number("completion_deadline_ms")?;
            if deadline != 0 && number(result, "message_time_ms")? >= deadline {
                return Err(fail("watchdog final result deadline"));
            }
        }
        _ => {}
    }
    if matches!(text(result, "decision")?, "ALLOW" | "ACK") {
        let artifact = match context.stage_kind() {
            "prepare_request" => Some("prepare_proof_digest"),
            "commit_request" => Some("capability_digest"),
            "lease_redeem_request" => Some("lease_digest"),
            "watchdog_arm_request" => Some("watchdog_digest"),
            "effect_permit_request" => Some("permit_digest"),
            _ => None,
        };
        if artifact.is_some_and(|key| text(result, key).is_ok_and(|value| value == ZERO)) {
            return Err(fail("zero authority artifact"));
        }
    }
    Ok(())
}

pub fn validate_transcript(
    messages: &[Message],
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<(), WireError> {
    if messages.is_empty() {
        return Err(fail("empty transcript"));
    }
    for message in messages {
        validate_structure(message, true)?;
    }
    let mode = text(&messages[0], "mode")?;
    let prefix: &[&str] = match mode {
        "MODE_1" => &[
            "mode1_release_request",
            "mode1_release_result",
            "branch_a_statement",
            "branch_b_statement",
            "mode1_overlap_witness",
            "convergence_request",
            "convergence_result",
        ],
        "MODE_2" => &[
            "branch_a_statement",
            "mode2_validator_certificate",
            "convergence_request",
            "convergence_result",
        ],
        "MODE_3" => &[
            "mode3_single_state_proof",
            "convergence_request",
            "convergence_result",
        ],
        _ => return Err(fail("unknown mode")),
    };
    let post = &[
        "prepare_request",
        "prepare_result",
        "commit_request",
        "commit_result",
        "lease_redeem_request",
        "lease_redeem_result",
        "watchdog_arm_request",
        "watchdog_arm_result",
        "effect_permit_request",
        "effect_permit_result",
    ];
    let mut base = prefix.to_vec();
    base.extend_from_slice(post);
    let mut expected = base.clone();
    if messages.len() > base.len() {
        match text(&messages[base.len()], "kind")? {
            "effect_receipt" => expected.extend_from_slice(&[
                "effect_receipt",
                "receipt_ack",
                "watchdog_terminal",
                "watchdog_result",
            ]),
            "watchdog_terminal" => {
                expected.extend_from_slice(&["watchdog_terminal", "watchdog_result"])
            }
            _ => return Err(fail("invalid lifecycle tail")),
        }
    }
    if messages.len() > expected.len() {
        return Err(fail("lifecycle length"));
    }
    expected.truncate(messages.len());
    // Full-transcript audit deliberately reuses the same authentication primitive as
    // staged request validation.  Untrusted audit bytes must not have a weaker or
    // divergent admission, binding, signature, nonce, ordering, or trusted-time path.
    let terminal_denial = authenticate_messages(
        messages,
        &expected,
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )?;
    if terminal_denial {
        let result_kind = text(messages.last().unwrap(), "kind")?;
        let request_kind =
            request_for_result(result_kind).ok_or_else(|| fail("denial without staged request"))?;
        let context = validate_request_prefix(
            &messages[..messages.len() - 1],
            request_kind,
            registry,
            admission,
            verifier,
            trusted_now_ms,
        )?;
        validate_stage_result(
            messages.last().unwrap(),
            &context,
            &messages[..messages.len() - 1],
        )?;
        return Ok(());
    }
    let cidx = prefix.len() - 1;
    if messages.len() <= cidx {
        return Err(fail("incomplete convergence prefix"));
    }
    validate_mode_prefix(messages, mode, cidx, admission)?;
    validate_completed_lifecycle(messages, prefix.len(), registry, admission)?;
    if messages.len() <= base.len() {
        return Err(fail("successful lifecycle incomplete"));
    }
    validate_lifecycle(messages, prefix.len(), base.len(), terminal_denial)
}

fn validate_completed_lifecycle(
    messages: &[Message],
    start: usize,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
) -> Result<(), WireError> {
    let checks = [
        (0isize, -1isize, "convergence_digest", "convergence_digest"),
        (2, 1, "prepare_proof_digest", "prepare_proof_digest"),
        (2, 1, "prepare_id", "prepare_id"),
        (4, 3, "capability_digest", "capability_digest"),
        (4, 3, "capability_id", "capability_id"),
        (5, 4, "lease_deadline_ms", "lease_deadline_ms"),
        (6, 5, "lease_digest", "lease_digest"),
        (6, 5, "lease_id", "lease_id"),
        (7, 6, "watchdog_deadline_ms", "watchdog_deadline_ms"),
        (8, 5, "lease_digest", "lease_digest"),
        (8, 5, "lease_id", "lease_id"),
        (8, 5, "lease_deadline_ms", "lease_deadline_ms"),
        (8, 7, "watchdog_digest", "watchdog_digest"),
        (8, 7, "watchdog_deadline_ms", "watchdog_deadline_ms"),
        (9, 8, "watchdog_digest", "watchdog_digest"),
    ];
    let present = messages.len().saturating_sub(start);
    for (right, left, lk, rk) in checks {
        if right as usize >= present {
            continue;
        }
        let left_index = if left < 0 {
            start - 1
        } else {
            start + left as usize
        };
        same(
            &messages[left_index],
            lk,
            &messages[start + right as usize],
            rk,
        )?;
    }
    let deadline_fields: &[(usize, &[&str])] = &[
        (4, &["lease_deadline_ms"]),
        (5, &["lease_deadline_ms"]),
        (6, &["watchdog_deadline_ms"]),
        (7, &["watchdog_deadline_ms"]),
        (8, &["lease_deadline_ms", "watchdog_deadline_ms"]),
        (9, &["permit_deadline_ms"]),
    ];
    for (offset, fields) in deadline_fields {
        if *offset >= present {
            continue;
        }
        let item = &messages[start + *offset];
        if item.get("decision") == Some(&Value::Text("DENY".into())) {
            continue;
        }
        for field in *fields {
            if number(item, "message_time_ms")? >= number(item, field)? {
                return Err(fail("expired authority lifecycle deadline"));
            }
        }
    }
    if present > 9 {
        let request = &messages[start + 8];
        let result = &messages[start + 9];
        if text(result, "decision")? == "ALLOW"
            && number(result, "permit_deadline_ms")?
                > number(request, "lease_deadline_ms")?
                    .min(number(request, "watchdog_deadline_ms")?)
        {
            return Err(fail("permit deadline widening"));
        }
    }
    for (stage, request_offset, result_offset) in [
        ("prepare_request", 0usize, 1usize),
        ("commit_request", 2, 3),
        ("lease_redeem_request", 4, 5),
        ("watchdog_arm_request", 6, 7),
        ("effect_permit_request", 8, 9),
    ] {
        if result_offset < present {
            let context = stage_context_from_authenticated(
                &messages[..start + request_offset + 1],
                stage,
                registry,
                admission,
            )?;
            validate_completed_result_semantics(
                stage,
                &messages[start + request_offset],
                &messages[start + result_offset],
                &context,
            )?;
        }
    }
    Ok(())
}

fn validate_completed_result_semantics(
    stage: &str,
    request: &Message,
    result: &Message,
    context: &VerifiedStageContext,
) -> Result<(), WireError> {
    let artifact = match stage {
        "prepare_request" => Some("prepare_proof_digest"),
        "commit_request" => Some("capability_digest"),
        "lease_redeem_request" => Some("lease_digest"),
        "watchdog_arm_request" => Some("watchdog_digest"),
        "effect_permit_request" => Some("permit_digest"),
        _ => None,
    };
    let identity = match stage {
        "prepare_request" => Some("prepare_id"),
        "commit_request" => Some("capability_id"),
        "lease_redeem_request" => Some("lease_id"),
        "effect_permit_request" => Some("permit_id"),
        _ => None,
    };
    if text(result, "decision")? != "ALLOW" {
        if artifact.is_some_and(|field| text(result, field).is_ok_and(|value| value != ZERO)) {
            return Err(fail("denied authority artifact must be zero"));
        }
        if identity.is_some_and(|field| text(result, field).is_ok_and(|value| value != ZERO_ID)) {
            return Err(fail("denied authority artifact ID must be zero"));
        }
        return Ok(());
    }
    if let Some(field) = artifact {
        let expected = authority_artifact_digest(stage, context, request, result)?;
        if text(result, field)? != expected {
            return Err(fail("authority artifact derivation"));
        }
        if let Some(id_field) = identity {
            if text(result, id_field)? != authority_artifact_id(stage, text(result, field)?)? {
                return Err(fail("authority artifact ID derivation"));
            }
        }
    }
    match stage {
        "prepare_request" if text(result, "prepare_proof_digest")? == ZERO => {
            return Err(fail("zero authority artifact: prepare proof"));
        }
        "commit_request" if text(result, "capability_digest")? == ZERO => {
            return Err(fail("zero authority artifact: capability"));
        }
        "lease_redeem_request" => {
            if text(result, "lease_digest")? == ZERO {
                return Err(fail("zero authority artifact: lease"));
            }
            if number(result, "lease_deadline_ms")? != number(request, "lease_deadline_ms")? {
                return Err(fail("authority lifecycle handoff: lease result"));
            }
        }
        "watchdog_arm_request" => {
            if text(result, "watchdog_digest")? == ZERO {
                return Err(fail("zero authority artifact: watchdog"));
            }
            if number(result, "watchdog_deadline_ms")? != number(request, "watchdog_deadline_ms")? {
                return Err(fail("watchdog result derivation"));
            }
        }
        "effect_permit_request" => {
            if text(result, "permit_digest")? == ZERO {
                return Err(fail("zero authority artifact: permit"));
            }
            if text(result, "watchdog_digest")? != text(request, "watchdog_digest")? {
                return Err(fail("permit result derivation"));
            }
            if number(result, "permit_deadline_ms")?
                > number(request, "lease_deadline_ms")?
                    .min(number(request, "watchdog_deadline_ms")?)
            {
                return Err(fail("permit deadline widening"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn derive_mode_request(
    messages: &[Message],
    mode: &str,
    request_index: usize,
    admission: &AdmissionPolicy,
) -> Result<DerivedModeRequest, WireError> {
    let request = &messages[request_index];
    let refs: (String, String, String, String);
    if mode == "MODE_1" {
        let (release_request, release_result, a, b, w) = (
            &messages[0],
            &messages[1],
            &messages[2],
            &messages[3],
            &messages[4],
        );
        let ca = rendezvous_checkpoint_digest(
            "A",
            text(release_request, "traversal_id")?,
            text(release_request, "challenge")?,
            text(release_request, "worker_a_id")?,
            text(release_request, "a_process_digest")?,
        )?;
        let cb = rendezvous_checkpoint_digest(
            "B",
            text(release_request, "traversal_id")?,
            text(release_request, "challenge")?,
            text(release_request, "worker_b_id")?,
            text(release_request, "b_process_digest")?,
        )?;
        let release = rendezvous_release_digest(
            &ca,
            &cb,
            number(release_request, "rendezvous_opened_at_ms")?,
            number(release_result, "rendezvous_released_at_ms")?,
        )?;
        if text(release_request, "a_checkpoint_digest")? != ca
            || text(release_request, "b_checkpoint_digest")? != cb
            || text(release_result, "release_request_digest")?
                != text(release_request, "transcript_digest")?
            || text(release_result, "a_checkpoint_digest")? != ca
            || text(release_result, "b_checkpoint_digest")? != cb
            || number(release_result, "rendezvous_opened_at_ms")?
                != number(release_request, "rendezvous_opened_at_ms")?
            || text(release_result, "rendezvous_release_digest")? != release
            || text(release_result, "decision")? != "ALLOW"
            || !(number(release_request, "not_before_ms")?
                <= number(release_request, "rendezvous_opened_at_ms")?
                && number(release_request, "rendezvous_opened_at_ms")?
                    <= number(release_request, "message_time_ms")?
                && number(release_request, "message_time_ms")?
                    <= number(release_result, "rendezvous_released_at_ms")?
                && number(release_result, "rendezvous_released_at_ms")?
                    <= number(release_result, "message_time_ms")?)
        {
            return Err(fail("Mode 1 admitted causal release evidence"));
        }
        if text(a, "projection_digest")? != text(b, "projection_digest")? {
            return Err(fail("Mode 1 projection divergence"));
        }
        if text(a, "callable_digest")? != admission.branch_a_callable_digest
            || text(a, "code_provenance_digest")? != admission.branch_a_code_provenance_digest
            || text(b, "callable_digest")? != admission.branch_b_callable_digest
            || text(b, "code_provenance_digest")? != admission.branch_b_code_provenance_digest
        {
            return Err(fail("Mode 1 semantic provenance not admitted"));
        }
        if text(a, "callable_digest")? == text(b, "callable_digest")?
            || text(a, "code_provenance_digest")? == text(b, "code_provenance_digest")?
            || text(a, "signer_key_id")? == text(b, "signer_key_id")?
            || text(a, "worker_id")? == text(b, "worker_id")?
        {
            return Err(fail("Mode 1 independence"));
        }
        if text(a, "worker_id")? != text(release_request, "worker_a_id")?
            || text(b, "worker_id")? != text(release_request, "worker_b_id")?
            || text(a, "process_digest")? != text(release_request, "a_process_digest")?
            || text(b, "process_digest")? != text(release_request, "b_process_digest")?
            || text(a, "release_checkpoint_digest")? != ca
            || text(b, "release_checkpoint_digest")? != cb
            || text(w, "worker_a_id")? != text(release_request, "worker_a_id")?
            || text(w, "worker_b_id")? != text(release_request, "worker_b_id")?
            || text(w, "a_process_digest")? != text(release_request, "a_process_digest")?
            || text(w, "b_process_digest")? != text(release_request, "b_process_digest")?
        {
            return Err(fail("Mode 1 release identity transplant"));
        }
        for (side, statement) in [("a", a), ("b", b)] {
            if text(w, &format!("statement_{}_digest", side))?
                != text(statement, "transcript_digest")?
                || text(w, &format!("worker_{}_id", side))? != text(statement, "worker_id")?
                || number(w, &format!("{}_start_ms", side))?
                    != number(statement, "substantive_start_ms")?
                || number(w, &format!("{}_end_ms", side))?
                    != number(statement, "substantive_end_ms")?
            {
                return Err(fail("Mode 1 witness mismatch"));
            }
        }
        let astart = number(w, "a_start_ms")?;
        let aend = number(w, "a_end_ms")?;
        let bstart = number(w, "b_start_ms")?;
        let bend = number(w, "b_end_ms")?;
        if number(w, "message_time_ms")? < aend.max(bend)
            || astart.max(bstart) >= aend.min(bend)
            || text(w, "a_process_digest")? == text(w, "b_process_digest")?
            || !(number(w, "not_before_ms")? <= number(w, "rendezvous_opened_at_ms")?
                && number(w, "rendezvous_opened_at_ms")? <= number(w, "rendezvous_released_at_ms")?
                && number(w, "rendezvous_released_at_ms")? <= number(w, "message_time_ms")?)
        {
            return Err(fail("Mode 1 overlap evidence"));
        }
        if text(w, "a_checkpoint_digest")? != ca
            || text(w, "b_checkpoint_digest")? != cb
            || text(w, "rendezvous_release_digest")? != release
            || text(w, "release_result_digest")? != text(release_result, "transcript_digest")?
            || number(w, "rendezvous_opened_at_ms")?
                != number(release_request, "rendezvous_opened_at_ms")?
            || number(w, "rendezvous_released_at_ms")?
                != number(release_result, "rendezvous_released_at_ms")?
            || text(w, "a_ack_digest")?
                != rendezvous_ack_digest("A", &release, text(a, "transcript_digest")?)?
            || text(w, "b_ack_digest")?
                != rendezvous_ack_digest("B", &release, text(b, "transcript_digest")?)?
            || number(w, "rendezvous_released_at_ms")? > astart.min(bstart)
            || number(release_result, "rendezvous_released_at_ms")?
                > number(a, "substantive_start_ms")?.min(number(b, "substantive_start_ms")?)
        {
            return Err(fail("Mode 1 causal rendezvous"));
        }
        refs = (
            text(a, "transcript_digest")?.into(),
            text(b, "transcript_digest")?.into(),
            text(w, "transcript_digest")?.into(),
            text(a, "projection_digest")?.into(),
        );
    } else if mode == "MODE_2" {
        let (primary, cert) = (&messages[0], &messages[1]);
        if text(primary, "callable_digest")? != admission.branch_a_callable_digest
            || text(primary, "code_provenance_digest")? != admission.branch_a_code_provenance_digest
            || text(cert, "validator_code_digest")? != admission.validator_code_digest
            || text(cert, "validator_provenance_digest")? != admission.validator_provenance_digest
        {
            return Err(fail("Mode 2 semantic provenance not admitted"));
        }
        if text(cert, "primary_statement_digest")? != text(primary, "transcript_digest")? {
            return Err(fail("Mode 2 primary reference"));
        }
        let ci = parse_set(text(cert, "candidate_input_set")?)?;
        let co = parse_set(text(cert, "candidate_output_set")?)?;
        let pi = parse_set(text(cert, "pathway_input_set")?)?;
        let po = parse_set(text(cert, "pathway_output_set")?)?;
        if co.is_empty() || po.is_empty() || !co.is_subset(&ci) || !po.is_subset(&pi) {
            return Err(fail("Mode 2 no-widening/reduction"));
        }
        check_rejections(
            &ci.difference(&co).cloned().collect(),
            text(cert, "candidate_rejections")?,
        )?;
        check_rejections(
            &pi.difference(&po).cloned().collect(),
            text(cert, "pathway_rejections")?,
        )?;
        if text(primary, "projection_candidate_digest")?
            != set_digest(text(cert, "candidate_input_set")?)?
            || text(primary, "projection_pathway_digest")?
                != set_digest(text(cert, "pathway_input_set")?)?
            || text(cert, "projection_candidate_digest")?
                != set_digest(text(cert, "candidate_output_set")?)?
            || text(cert, "projection_pathway_digest")?
                != set_digest(text(cert, "pathway_output_set")?)?
        {
            return Err(fail("Mode 2 set/projection mismatch"));
        }
        for key in PROJECTION {
            if !matches!(
                *key,
                "projection_digest" | "projection_candidate_digest" | "projection_pathway_digest"
            ) && primary.get(*key) != cert.get(*key)
            {
                return Err(fail("Mode 2 non-set projection widening"));
            }
        }
        refs = (
            text(primary, "transcript_digest")?.into(),
            text(cert, "transcript_digest")?.into(),
            text(cert, "transcript_digest")?.into(),
            text(cert, "projection_digest")?.into(),
        );
    } else {
        let proof = &messages[0];
        if text(proof, "single_state_callable_digest")? != admission.single_state_callable_digest
            || text(proof, "single_state_provenance_digest")?
                != admission.single_state_provenance_digest
        {
            return Err(fail("Mode 3 semantic provenance not admitted"));
        }
        let seal = mode3_state_seal_digest(
            text(proof, "state_digest")?,
            text(proof, "projection_mode_freeze_digest")?,
            text(proof, "projection_digest")?,
            text(proof, "traversal_id")?,
            text(proof, "challenge")?,
        )?;
        let derived = mode3_single_state_proof_digest(
            &seal,
            text(proof, "single_state_callable_digest")?,
            text(proof, "single_state_provenance_digest")?,
        )?;
        if text(proof, "state_seal_digest")? != seal
            || text(proof, "single_state_proof_digest")? != derived
        {
            return Err(fail("Mode 3 proof derivation"));
        }
        refs = (
            text(proof, "transcript_digest")?.into(),
            ZERO.into(),
            text(proof, "transcript_digest")?.into(),
            text(proof, "projection_digest")?.into(),
        );
    }
    let convergence = convergence_digest(&refs.0, &refs.1, &refs.2, &refs.3)?;
    if (
        text(request, "evidence_a_digest")?,
        text(request, "evidence_b_digest")?,
        text(request, "mode_evidence_digest")?,
        text(request, "projection_digest")?,
    ) != (&refs.0, &refs.1, &refs.2, &refs.3)
        || text(request, "convergence_digest")? != convergence
    {
        return Err(fail("invented or mismatched convergence evidence"));
    }
    Ok((refs, convergence))
}

fn validate_mode_prefix(
    messages: &[Message],
    mode: &str,
    result_index: usize,
    admission: &AdmissionPolicy,
) -> Result<(), WireError> {
    let result = &messages[result_index];
    let (refs, convergence) = derive_mode_request(messages, mode, result_index - 1, admission)?;
    if (
        text(result, "evidence_a_digest")?,
        text(result, "evidence_b_digest")?,
        text(result, "mode_evidence_digest")?,
        text(result, "projection_digest")?,
    ) != (&refs.0, &refs.1, &refs.2, &refs.3)
        || text(result, "convergence_digest")? != convergence
    {
        return Err(fail("invented or mismatched convergence result"));
    }
    Ok(())
}

fn same(a: &Message, ak: &str, b: &Message, bk: &str) -> Result<(), WireError> {
    if a.get(ak) != b.get(bk) {
        Err(fail("authority lifecycle handoff"))
    } else {
        Ok(())
    }
}
fn validate_lifecycle(
    messages: &[Message],
    start: usize,
    base: usize,
    denied: bool,
) -> Result<(), WireError> {
    let p_req = &messages[start];
    let p_res = &messages[start + 1];
    let c_req = &messages[start + 2];
    let c_res = &messages[start + 3];
    let l_req = &messages[start + 4];
    let l_res = &messages[start + 5];
    let a_req = &messages[start + 6];
    let a_res = &messages[start + 7];
    let e_req = &messages[start + 8];
    let e_res = &messages[start + 9];
    for (a, ak, b, bk) in [
        (
            &messages[start - 1],
            "convergence_digest",
            p_req,
            "convergence_digest",
        ),
        (p_res, "prepare_proof_digest", c_req, "prepare_proof_digest"),
        (p_res, "prepare_id", c_req, "prepare_id"),
        (c_res, "capability_digest", l_req, "capability_digest"),
        (c_res, "capability_id", l_req, "capability_id"),
        (l_req, "lease_deadline_ms", l_res, "lease_deadline_ms"),
        (l_res, "lease_digest", a_req, "lease_digest"),
        (l_res, "lease_id", a_req, "lease_id"),
        (a_req, "watchdog_deadline_ms", a_res, "watchdog_deadline_ms"),
        (l_res, "lease_digest", e_req, "lease_digest"),
        (l_res, "lease_id", e_req, "lease_id"),
        (l_res, "lease_deadline_ms", e_req, "lease_deadline_ms"),
        (a_res, "watchdog_digest", e_req, "watchdog_digest"),
        (a_res, "watchdog_deadline_ms", e_req, "watchdog_deadline_ms"),
        (e_req, "watchdog_digest", e_res, "watchdog_digest"),
    ] {
        same(a, ak, b, bk)?;
    }
    for (m, deadline) in [
        (l_req, "lease_deadline_ms"),
        (l_res, "lease_deadline_ms"),
        (a_req, "watchdog_deadline_ms"),
        (a_res, "watchdog_deadline_ms"),
        (e_req, "lease_deadline_ms"),
        (e_req, "watchdog_deadline_ms"),
        (e_res, "permit_deadline_ms"),
    ] {
        if number(m, "message_time_ms")? >= number(m, deadline)? {
            return Err(fail("expired authority lifecycle deadline"));
        }
    }
    if number(e_res, "permit_deadline_ms")?
        > number(e_req, "lease_deadline_ms")?.min(number(e_req, "watchdog_deadline_ms")?)
    {
        return Err(fail("permit deadline widening"));
    }
    let tail = &messages[base..];
    if text(&tail[0], "kind")? == "watchdog_terminal" {
        let fail_close_deadline = number(l_res, "lease_deadline_ms")?
            .min(number(e_res, "permit_deadline_ms")?)
            .min(number(a_res, "watchdog_deadline_ms")?);
        if tail.len() != 2
            || !matches!(text(&tail[0], "watchdog_status")?, "STOP" | "TIMEOUT")
            || text(&tail[0], "receipt_digest")? != ZERO
            || text(&tail[0], "permit_digest")? != text(e_res, "permit_digest")?
            || text(&tail[0], "permit_id")? != text(e_res, "permit_id")?
            || text(&tail[0], "watchdog_digest")? != text(e_res, "watchdog_digest")?
            || text(&tail[1], "permit_digest")? != text(e_res, "permit_digest")?
            || text(&tail[1], "permit_id")? != text(e_res, "permit_id")?
            || text(&tail[1], "receipt_digest")? != ZERO
            || text(&tail[1], "watchdog_digest")? != text(&tail[0], "watchdog_digest")?
            || text(&tail[1], "decision")? != "BLOCK"
            || !denied
            || if text(&tail[0], "watchdog_status")? == "TIMEOUT" {
                number(&tail[0], "message_time_ms")? != fail_close_deadline
            } else {
                number(e_res, "message_time_ms")? > number(&tail[0], "message_time_ms")?
                    || number(&tail[0], "message_time_ms")? > fail_close_deadline
            }
            || number(&tail[1], "message_time_ms")? < number(&tail[0], "message_time_ms")?
            || number(&tail[1], "message_time_ms")?
                > number(&tail[0], "message_time_ms")? + FAIL_CLOSE_RESULT_MAX_DELAY_MS
        {
            return Err(fail("invalid no-receipt fail-closed tail"));
        }
        return Ok(());
    }
    if tail.len() != 4 {
        return Err(fail("receipt tail incomplete"));
    }
    let receipt = &tail[0];
    let ack = &tail[1];
    let terminal = &tail[2];
    let result = &tail[3];
    for (a, ak, b, bk) in [
        (receipt, "permit_digest", e_res, "permit_digest"),
        (receipt, "permit_id", e_res, "permit_id"),
        (receipt, "watchdog_digest", e_res, "watchdog_digest"),
        (ack, "permit_digest", e_res, "permit_digest"),
        (ack, "permit_id", e_res, "permit_id"),
        (ack, "receipt_digest", receipt, "receipt_digest"),
        (ack, "watchdog_digest", receipt, "watchdog_digest"),
        (terminal, "receipt_digest", receipt, "receipt_digest"),
        (terminal, "permit_digest", e_res, "permit_digest"),
        (terminal, "permit_id", e_res, "permit_id"),
        (terminal, "watchdog_digest", receipt, "watchdog_digest"),
        (result, "permit_digest", e_res, "permit_digest"),
        (result, "permit_id", e_res, "permit_id"),
        (result, "receipt_digest", receipt, "receipt_digest"),
        (result, "watchdog_digest", terminal, "watchdog_digest"),
    ] {
        same(a, ak, b, bk)?;
    }
    let consumed = number(receipt, "adapter_consumed_at_ms")?;
    let completion_deadline = number(l_res, "lease_deadline_ms")?
        .min(number(e_res, "permit_deadline_ms")?)
        .min(number(a_res, "watchdog_deadline_ms")?);
    if consumed < number(e_res, "message_time_ms")?
        || consumed >= completion_deadline
        || consumed > number(receipt, "message_time_ms")?
        || number(receipt, "message_time_ms")? >= completion_deadline
    {
        return Err(fail("adapter atomic consumption freshness"));
    }
    if [ack, terminal, result].iter().any(|item| {
        number(item, "message_time_ms").is_err()
            || number(item, "message_time_ms").unwrap() >= completion_deadline
    }) {
        return Err(fail("success/failure tail completion deadline"));
    }
    let expected_consumption = adapter_consumption_digest(
        text(receipt, "durable_consumption_digest")?,
        text(receipt, "permit_digest")?,
        text(receipt, "effect_digest")?,
        text(receipt, "adapter_digest")?,
        consumed,
        text(receipt, "effect_outcome")?,
    )?;
    if text(receipt, "adapter_consumption_digest")? != expected_consumption {
        return Err(fail("adapter consumption derivation"));
    }
    let expected_receipt = effect_receipt_digest(receipt)?;
    if text(receipt, "receipt_digest")? != expected_receipt || expected_receipt == ZERO {
        return Err(fail("effect receipt derivation"));
    }
    let expected = match text(receipt, "effect_outcome")? {
        "SUCCEEDED" => ("SUCCESS_RECORDED", "ACK", "HEALTHY", "ACK", false),
        "FAILED" => ("FAILURE_RECORDED", "FAILURE_ACK", "STOP", "BLOCK", true),
        "UNKNOWN" => ("UNKNOWN_BLOCKED", "FAILURE_ACK", "STOP", "BLOCK", true),
        _ => return Err(fail("effect outcome")),
    };
    if (
        text(ack, "receipt_status")?,
        text(ack, "decision")?,
        text(terminal, "watchdog_status")?,
        text(result, "decision")?,
        denied,
    ) != expected
    {
        return Err(fail("effect/watchdog fail-closed semantics"));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}
fn hex_bytes(value: &str) -> Result<Vec<u8>, WireError> {
    if !even_lower_hex(value) {
        return Err(fail("hex"));
    }
    fn d(b: u8) -> u8 {
        if b <= b'9' {
            b - b'0'
        } else {
            b - b'a' + 10
        }
    }
    Ok(value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| (d(p[0]) << 4) | d(p[1]))
        .collect())
}

fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}
