//! Independent Rust implementation of SBP-LEX-WIRE/1.
//!
//! This crate deliberately contains no application-object decoding, dynamic
//! loading or authorization decisions.  Cryptographic fields are parsed and
//! structurally bound; a caller must perform verification with admitted keys.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

pub const PROTOCOL: &str = "SBP-LEX-WIRE/1";
pub const ORACLE_SHA256: &str = "94578afd81a13aab31904f1fb3c8733addd8718658602f638ad4086d2e9d4df0";
pub const MAX_FRAME_BYTES: usize = 16_384;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Value {
    Text(String),
    Number(u64),
}

pub type Message = BTreeMap<String, Value>;

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

fn text<'a>(m: &'a Message, key: &str) -> Result<&'a str, WireError> {
    match m.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(fail("missing or non-string field")),
    }
}

fn number(m: &Message, key: &str) -> Result<u64, WireError> {
    match m.get(key) {
        Some(Value::Number(value)) => Ok(*value),
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

fn expected_fields(kind: &str) -> Option<BTreeSet<&'static str>> {
    let common = [
        "adapter_boundary_digest",
        "adapter_digest",
        "adapter_key_class",
        "adapter_key_id",
        "audit_anchor_digest",
        "authority_build_id",
        "authority_class",
        "authority_key_class",
        "authority_key_id",
        "authority_profile",
        "challenge",
        "crypto_evidence_digest",
        "crypto_key_class",
        "crypto_result",
        "durable_consumption_digest",
        "effect_digest",
        "effect_intent_digest",
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
        "oracle_sha256",
        "prior_transcript_digest",
        "protocol",
        "replay_namespace",
        "request_digest",
        "runtime_subject",
        "runtime_tree",
        "sequence",
        "signature_algorithm",
        "signature_hex",
        "signer_key_id",
        "signer_role",
        "signing_public_key_hex",
        "state_digest",
        "transcript_digest",
        "traversal_id",
        "watchdog_key_class",
        "watchdog_key_id",
    ];
    let extra: &[&str] = match kind {
        "convergence_request" => &[
            "branch_a_provenance_digest",
            "branch_b_provenance_digest",
            "candidate_input_set",
            "candidate_output_set",
            "mode_evidence_digest",
            "mode_evidence_type",
            "no_widening_proof_digest",
            "pathway_input_set",
            "pathway_output_set",
            "policy_projection_digest",
            "projection_a_digest",
            "projection_b_digest",
            "snapshot_a_digest",
            "snapshot_b_digest",
            "validator_certificate_digest",
        ],
        "convergence_result" => &["convergence_digest", "decision"],
        "prepare_request" => &["convergence_digest"],
        "prepare_result" => &["decision", "prepare_proof_digest"],
        "commit_request" => &["prepare_proof_digest"],
        "commit_result" => &["capability_digest", "decision"],
        "lease_redeem_request" => &["capability_digest", "lease_deadline_ms", "lease_digest"],
        "lease_redeem_result" => &["decision", "lease_deadline_ms", "lease_digest"],
        "watchdog_arm_request" => &["lease_digest", "watchdog_deadline_ms"],
        "watchdog_arm_result" => &["decision", "watchdog_deadline_ms", "watchdog_digest"],
        "effect_permit_request" => &[
            "lease_deadline_ms",
            "lease_digest",
            "point_of_use_digest",
            "watchdog_deadline_ms",
            "watchdog_digest",
        ],
        "effect_permit_result" => &[
            "decision",
            "permit_deadline_ms",
            "permit_digest",
            "watchdog_digest",
        ],
        "effect_receipt" => &[
            "adapter_consumed_at_ms",
            "adapter_consumption_digest",
            "effect_outcome",
            "permit_digest",
            "receipt_digest",
            "watchdog_digest",
        ],
        "receipt_ack" => &[
            "decision",
            "receipt_digest",
            "receipt_status",
            "watchdog_digest",
        ],
        "watchdog_terminal" => &[
            "permit_digest",
            "receipt_digest",
            "watchdog_digest",
            "watchdog_status",
        ],
        "watchdog_result" => &["decision", "watchdog_digest"],
        _ => return None,
    };
    Some(common.into_iter().chain(extra.iter().copied()).collect())
}

fn lifecycle() -> [&'static str; 16] {
    [
        "convergence_request",
        "convergence_result",
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
        "effect_receipt",
        "receipt_ack",
        "watchdog_terminal",
        "watchdog_result",
    ]
}

pub fn encode_message(message: &Message) -> Result<Vec<u8>, WireError> {
    validate_message(message, true)?;
    let encoded = encode_raw(message)?;
    if encoded.is_empty() || encoded.len() > MAX_FRAME_BYTES {
        return Err(fail("payload size"));
    }
    Ok(encoded)
}

fn encode_raw(message: &Message) -> Result<Vec<u8>, WireError> {
    let mut out = Vec::new();
    out.push(b'{');
    for (index, (key, value)) in message.iter().enumerate() {
        if index != 0 {
            out.push(b',');
        }
        push_quoted(&mut out, key)?;
        out.push(b':');
        match value {
            Value::Text(value) => push_quoted(&mut out, value)?,
            Value::Number(value) if *value <= MAX_SAFE_INTEGER => {
                out.extend_from_slice(value.to_string().as_bytes())
            }
            Value::Number(_) => return Err(fail("integer range")),
        }
    }
    out.push(b'}');
    Ok(out)
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

pub fn parse_message(input: &[u8]) -> Result<Message, WireError> {
    if input.is_empty() || input.len() > MAX_FRAME_BYTES || input.iter().any(|b| *b > 0x7f) {
        return Err(fail("payload size or encoding"));
    }
    let mut p = Parser { input, pos: 0 };
    let parsed = p.object()?;
    if p.pos != input.len() {
        return Err(fail("trailing bytes"));
    }
    validate_message(&parsed, true)?;
    if encode_raw(&parsed)? != input {
        return Err(fail("noncanonical JSON"));
    }
    Ok(parsed)
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn take(&mut self, expected: u8) -> Result<(), WireError> {
        if self.input.get(self.pos) != Some(&expected) {
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
        if self.pos == start {
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
        let mut result = Message::new();
        let mut prior: Option<String> = None;
        loop {
            let key = self.quoted()?;
            if prior.as_ref().is_some_and(|p| p >= &key) {
                return Err(fail("duplicate or unsorted key"));
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
            if result.insert(key, value).is_some() {
                return Err(fail("duplicate key"));
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
        Ok(result)
    }
}

fn validate_message(message: &Message, digest_check: bool) -> Result<(), WireError> {
    let kind = text(message, "kind")?;
    let expected = expected_fields(kind).ok_or_else(|| fail("unknown kind"))?;
    let actual: BTreeSet<&str> = message.keys().map(String::as_str).collect();
    if expected != actual {
        return Err(fail("field set"));
    }
    for (key, value) in message {
        match value {
            Value::Text(v) if ascii_token(v) => {}
            Value::Number(v)
                if (key == "sequence" || key.ends_with("_ms")) && *v <= MAX_SAFE_INTEGER => {}
            _ => return Err(fail("field type")),
        }
    }
    for (key, value) in message {
        if (key.ends_with("_digest")
            || key.ends_with("_key_id")
            || matches!(
                key.as_str(),
                "challenge" | "nonce" | "authority_build_id" | "replay_namespace"
            ))
            && !lower_hex(
                match value {
                    Value::Text(v) => v,
                    _ => return Err(fail("digest type")),
                },
                64,
            )
        {
            return Err(fail("digest format"));
        }
    }
    if !matches!(text(message, "runtime_subject")?.len(), 40 | 64)
        || !text(message, "runtime_subject")?
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !matches!(text(message, "runtime_tree")?.len(), 40 | 64)
        || !text(message, "runtime_tree")?
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(fail("runtime identity"));
    }
    if !lower_hex(text(message, "traversal_id")?, 32)
        || !lower_hex(text(message, "operation_id")?, 32)
    {
        return Err(fail("operation identity"));
    }
    if text(message, "protocol")? != PROTOCOL || text(message, "oracle_sha256")? != ORACLE_SHA256 {
        return Err(fail("protocol/oracle"));
    }
    if !matches!(text(message, "mode")?, "MODE_1" | "MODE_2" | "MODE_3") {
        return Err(fail("mode"));
    }
    if !matches!(
        text(message, "authority_class")?,
        "TEST_ONLY" | "SOFTWARE" | "HSM" | "TPM"
    ) {
        return Err(fail("authority class"));
    }
    let nbf = number(message, "not_before_ms")?;
    let issued = number(message, "issued_at_ms")?;
    let expires = number(message, "expires_at_ms")?;
    if !(nbf <= issued && issued < expires) {
        return Err(fail("validity"));
    }
    for name in [
        "message_time_ms",
        "adapter_consumed_at_ms",
        "lease_deadline_ms",
        "permit_deadline_ms",
        "watchdog_deadline_ms",
    ] {
        if message.contains_key(name) {
            let deadline = number(message, name)?;
            if deadline < issued || deadline > expires {
                return Err(fail("deadline"));
            }
        }
    }
    validate_crypto(message)?;
    if let Ok(decision) = text(message, "decision") {
        let allowed = match kind {
            "receipt_ack" => decision == "ACK",
            "watchdog_result" => matches!(decision, "ACK" | "BLOCK"),
            _ => matches!(decision, "ALLOW" | "DENY"),
        };
        if !allowed {
            return Err(fail("decision/kind"));
        }
        let error = text(message, "error_code")?;
        if (matches!(decision, "ALLOW" | "ACK") && error != "NONE")
            || (matches!(decision, "DENY" | "BLOCK") && error == "NONE")
        {
            return Err(fail("decision/error"));
        }
    } else if text(message, "error_code")? != "NONE" {
        return Err(fail("request error"));
    }
    if kind == "convergence_request" {
        let a = text(message, "projection_a_digest")?;
        if a != text(message, "projection_b_digest")?
            || a != text(message, "policy_projection_digest")?
        {
            return Err(fail("nonconvergence"));
        }
        let sets = [
            "candidate_input_set",
            "candidate_output_set",
            "pathway_input_set",
            "pathway_output_set",
        ];
        match text(message, "mode")? {
            "MODE_1" => {
                if text(message, "mode_evidence_type")? != "DUAL_EXECUTION_PROOF"
                    || sets
                        .iter()
                        .any(|key| text(message, key).ok() != Some("NONE"))
                    || text(message, "branch_a_provenance_digest")?
                        == text(message, "branch_b_provenance_digest")?
                    || text(message, "validator_certificate_digest")? != ZERO
                    || text(message, "no_widening_proof_digest")? != ZERO
                {
                    return Err(fail("Mode 1 evidence"));
                }
            }
            "MODE_2" => {
                if text(message, "mode_evidence_type")? != "VALIDATOR_REDUCTION_PROOF"
                    || text(message, "validator_certificate_digest")? == ZERO
                    || text(message, "no_widening_proof_digest")? == ZERO
                    || text(message, "branch_a_provenance_digest")?
                        == text(message, "branch_b_provenance_digest")?
                {
                    return Err(fail("Mode 2 certificate"));
                }
                let ci = digest_set(text(message, "candidate_input_set")?)?;
                let co = digest_set(text(message, "candidate_output_set")?)?;
                let pi = digest_set(text(message, "pathway_input_set")?)?;
                let po = digest_set(text(message, "pathway_output_set")?)?;
                if co.is_empty()
                    || po.is_empty()
                    || !co.is_subset(&ci)
                    || co == ci
                    || !po.is_subset(&pi)
                    || po == pi
                {
                    return Err(fail("Mode 2 reduction"));
                }
            }
            "MODE_3" => {
                if text(message, "mode_evidence_type")? != "SINGLE_STATE_PROOF"
                    || sets
                        .iter()
                        .any(|key| text(message, key).ok() != Some("NONE"))
                    || text(message, "branch_b_provenance_digest")? != ZERO
                    || text(message, "validator_certificate_digest")? != ZERO
                    || text(message, "no_widening_proof_digest")? != ZERO
                {
                    return Err(fail("Mode 3 evidence"));
                }
            }
            _ => unreachable!(),
        }
    }
    if let Ok(status) = text(message, "watchdog_status") {
        if !matches!(status, "HEALTHY" | "STOP" | "TIMEOUT") {
            return Err(fail("watchdog status"));
        }
    }
    if let Ok(outcome) = text(message, "effect_outcome") {
        if !matches!(outcome, "SUCCEEDED" | "FAILED" | "UNKNOWN") {
            return Err(fail("effect outcome"));
        }
    }
    if kind == "receipt_ack"
        && !matches!(
            text(message, "receipt_status")?,
            "SUCCESS_RECORDED" | "FAILURE_RECORDED" | "UNKNOWN_BLOCKED"
        )
    {
        return Err(fail("receipt status"));
    }
    if digest_check && text(message, "transcript_digest")? != transcript_digest(message)? {
        return Err(fail("transcript digest"));
    }
    Ok(())
}

fn validate_crypto(message: &Message) -> Result<(), WireError> {
    let class = text(message, "crypto_key_class")?;
    let result = text(message, "crypto_result")?;
    let evidence = text(message, "crypto_evidence_digest")?;
    let algorithm = text(message, "signature_algorithm")?;
    let key = text(message, "signing_public_key_hex")?;
    let signature = text(message, "signature_hex")?;
    let role = text(message, "signer_role")?;
    let signer_key_id = text(message, "signer_key_id")?;
    for name in [
        "adapter_key_class",
        "authority_key_class",
        "watchdog_key_class",
    ] {
        if !matches!(
            text(message, name)?,
            "TEST_FIXTURE" | "PRODUCTION_HSM" | "PRODUCTION_TPM"
        ) {
            return Err(fail("bound key class"));
        }
    }
    let authority = text(message, "authority_class")?;
    let authority_key_class = text(message, "authority_key_class")?;
    if (authority == "TEST_ONLY" && authority_key_class != "TEST_FIXTURE")
        || (authority == "SOFTWARE" && authority_key_class != "TEST_FIXTURE")
        || (authority == "HSM" && authority_key_class != "PRODUCTION_HSM")
        || (authority == "TPM" && authority_key_class != "PRODUCTION_TPM")
    {
        return Err(fail("authority/key class"));
    }
    let expected_role = match text(message, "kind")? {
        "convergence_request"
        | "prepare_request"
        | "commit_request"
        | "lease_redeem_request"
        | "watchdog_arm_request"
        | "effect_permit_request" => "NONE",
        "effect_receipt" => "ADAPTER",
        "watchdog_terminal" => "WATCHDOG",
        _ => "AUTHORITY",
    };
    if role != expected_role {
        return Err(fail("signer role"));
    }
    if class == "NONE"
        && result == "NOT_CHECKED"
        && evidence == ZERO
        && algorithm == "NONE"
        && key == "NONE"
        && signature == "NONE"
        && role == "NONE"
        && signer_key_id == ZERO
    {
        return Ok(());
    }
    if !matches!(class, "TEST_FIXTURE" | "PRODUCTION_HSM" | "PRODUCTION_TPM")
        || result != "SIGNATURE_PRESENT"
        || evidence == ZERO
        || !matches!(algorithm, "ML-DSA-65" | "ML-DSA-87")
        || !even_lower_hex(key)
        || !even_lower_hex(signature)
    {
        return Err(fail("crypto structure"));
    }
    let expected_id = hex(&sha256(&decode_hex(key)?));
    let (bound_class, bound_id) = match role {
        "AUTHORITY" => (
            text(message, "authority_key_class")?,
            text(message, "authority_key_id")?,
        ),
        "ADAPTER" => (
            text(message, "adapter_key_class")?,
            text(message, "adapter_key_id")?,
        ),
        "WATCHDOG" => (
            text(message, "watchdog_key_class")?,
            text(message, "watchdog_key_id")?,
        ),
        _ => return Err(fail("signed NONE role")),
    };
    if class != bound_class || signer_key_id != bound_id || signer_key_id != expected_id {
        return Err(fail("signer key identity/class"));
    }
    Ok(())
}

fn digest_set(value: &str) -> Result<BTreeSet<String>, WireError> {
    if value == "NONE" {
        return Err(fail("missing digest set"));
    }
    let items: Vec<&str> = value.split(',').collect();
    if items.iter().any(|item| !lower_hex(item, 64))
        || items.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(fail("digest set"));
    }
    Ok(items.into_iter().map(str::to_owned).collect())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, WireError> {
    if !even_lower_hex(value) {
        return Err(fail("hex"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| -> Result<u8, WireError> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    _ => Err(fail("hex")),
                }
            };
            Ok((digit(pair[0])? << 4) | digit(pair[1])?)
        })
        .collect()
}

pub fn transcript_digest(message: &Message) -> Result<String, WireError> {
    let kind = text(message, "kind")?.to_owned();
    expected_fields(&kind).ok_or_else(|| fail("kind"))?;
    let mut unsigned = message.clone();
    unsigned.remove("transcript_digest");
    unsigned.remove("signature_hex");
    let canonical = encode_raw(&unsigned)?;
    let mut material = Vec::from(b"SBP-LEX-WIRE/1\0TRANSCRIPT\0".as_slice());
    material.extend_from_slice(kind.as_bytes());
    material.push(0);
    material.extend_from_slice(&canonical);
    Ok(hex(&sha256(&material)))
}

pub fn signature_preimage(message: &Message) -> Result<Vec<u8>, WireError> {
    let kind = text(message, "kind")?;
    expected_fields(kind).ok_or_else(|| fail("kind"))?;
    let digest = text(message, "transcript_digest")?;
    if !lower_hex(digest, 64) {
        return Err(fail("transcript digest"));
    }
    let mut out = Vec::from(b"SBP-LEX-WIRE/1\0SIGNATURE\0".as_slice());
    out.extend_from_slice(kind.as_bytes());
    out.push(0);
    out.extend_from_slice(&decode_hex(digest)?);
    Ok(out)
}

pub fn seal_message(message: &Message) -> Result<Message, WireError> {
    let mut sealed = message.clone();
    sealed.insert("transcript_digest".into(), Value::Text(ZERO.into()));
    validate_message(&sealed, false)?;
    let digest = transcript_digest(&sealed)?;
    sealed.insert("transcript_digest".into(), Value::Text(digest));
    validate_message(&sealed, true)?;
    Ok(sealed)
}

pub fn encode_frame(message: &Message) -> Result<Vec<u8>, WireError> {
    let payload = encode_message(message)?;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_frame(frame: &[u8]) -> Result<Message, WireError> {
    if frame.len() < 4 {
        return Err(fail("frame prefix"));
    }
    let size = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    if size == 0 || size > MAX_FRAME_BYTES || frame.len() != size + 4 {
        return Err(fail("frame size"));
    }
    parse_message(&frame[4..])
}

pub fn validate_transcript(
    messages: &[Message],
    trusted_now_ms: Option<u64>,
) -> Result<(), WireError> {
    let receipt_order = lifecycle();
    if messages.is_empty() || messages.len() > 16 {
        return Err(fail("lifecycle length"));
    }
    let order: Vec<&str> =
        if messages.len() <= 12 || text(&messages[12], "kind")? == "effect_receipt" {
            receipt_order[..messages.len()].to_vec()
        } else if text(&messages[12], "kind")? == "watchdog_terminal" && messages.len() <= 14 {
            receipt_order[..12]
                .iter()
                .copied()
                .chain(
                    ["watchdog_terminal", "watchdog_result"][..messages.len() - 12]
                        .iter()
                        .copied(),
                )
                .collect()
        } else {
            return Err(fail("receipt-or-timeout tail"));
        };
    let bindings = [
        "adapter_boundary_digest",
        "adapter_digest",
        "adapter_key_class",
        "adapter_key_id",
        "audit_anchor_digest",
        "authority_build_id",
        "authority_class",
        "authority_key_class",
        "authority_key_id",
        "authority_profile",
        "challenge",
        "durable_consumption_digest",
        "effect_digest",
        "effect_intent_digest",
        "expires_at_ms",
        "inhibit_binding_digest",
        "interlock_digest",
        "issued_at_ms",
        "mode",
        "not_before_ms",
        "operation_id",
        "oracle_sha256",
        "protocol",
        "replay_namespace",
        "request_digest",
        "runtime_subject",
        "runtime_tree",
        "state_digest",
        "traversal_id",
        "watchdog_key_class",
        "watchdog_key_id",
    ];
    let first: Vec<&Value> = bindings
        .iter()
        .map(|k| messages[0].get(*k).unwrap())
        .collect();
    if let Some(now) = trusted_now_ms {
        if now > MAX_SAFE_INTEGER
            || now < number(&messages[0], "not_before_ms")?
            || now >= number(&messages[0], "expires_at_ms")?
        {
            return Err(fail("trusted freshness"));
        }
    }
    let mut prior = ZERO.to_owned();
    let mut nonces = BTreeSet::new();
    let mut prior_time = None;
    let mut terminal_denial = false;
    for (index, message) in messages.iter().enumerate() {
        validate_message(message, true)?;
        if text(message, "kind")? != order[index] || number(message, "sequence")? != index as u64 {
            return Err(fail("order"));
        }
        if text(message, "prior_transcript_digest")? != prior {
            return Err(fail("chain"));
        }
        let current: Vec<&Value> = bindings.iter().map(|k| message.get(*k).unwrap()).collect();
        if current != first {
            return Err(fail("binding mutation"));
        }
        if !nonces.insert(text(message, "nonce")?) {
            return Err(fail("nonce replay"));
        }
        let time = number(message, "message_time_ms")?;
        if time < number(message, "not_before_ms")?
            || time >= number(message, "expires_at_ms")?
            || prior_time.is_some_and(|prior| time < prior)
        {
            return Err(fail("message time"));
        }
        prior_time = Some(time);
        prior = text(message, "transcript_digest")?.to_owned();
        if matches!(message.get("decision"), Some(Value::Text(v)) if matches!(v.as_str(), "DENY" | "BLOCK"))
        {
            if index + 1 != messages.len() {
                return Err(fail("continued after denial"));
            }
            terminal_denial = true;
        }
    }
    let common_links = [
        (1, "convergence_digest", 2, "convergence_digest"),
        (3, "prepare_proof_digest", 4, "prepare_proof_digest"),
        (5, "capability_digest", 6, "capability_digest"),
        (6, "lease_digest", 7, "lease_digest"),
        (6, "lease_deadline_ms", 7, "lease_deadline_ms"),
        (7, "lease_digest", 8, "lease_digest"),
        (8, "watchdog_deadline_ms", 9, "watchdog_deadline_ms"),
        (9, "watchdog_digest", 10, "watchdog_digest"),
        (9, "watchdog_deadline_ms", 10, "watchdog_deadline_ms"),
        (7, "lease_digest", 10, "lease_digest"),
        (7, "lease_deadline_ms", 10, "lease_deadline_ms"),
        (10, "watchdog_digest", 11, "watchdog_digest"),
    ];
    for (li, lk, ri, rk) in common_links {
        if ri < messages.len() && messages[li].get(lk) != messages[ri].get(rk) {
            return Err(fail("handoff"));
        }
    }
    if messages.len() > 6
        && number(&messages[6], "message_time_ms")? > number(&messages[6], "lease_deadline_ms")?
    {
        return Err(fail("late lease"));
    }
    if messages.len() > 8
        && number(&messages[8], "message_time_ms")? > number(&messages[8], "watchdog_deadline_ms")?
    {
        return Err(fail("late watchdog arm"));
    }
    if messages.len() > 10
        && number(&messages[10], "message_time_ms")?
            > number(&messages[10], "lease_deadline_ms")?
                .min(number(&messages[10], "watchdog_deadline_ms")?)
    {
        return Err(fail("late point of use"));
    }
    if messages.len() > 11
        && (number(&messages[11], "permit_deadline_ms")?
            > number(&messages[10], "lease_deadline_ms")?
            || number(&messages[11], "permit_deadline_ms")?
                > number(&messages[10], "watchdog_deadline_ms")?
            || number(&messages[11], "message_time_ms")?
                > number(&messages[11], "permit_deadline_ms")?)
    {
        return Err(fail("permit deadline"));
    }
    if terminal_denial && messages.len() <= 12 {
        return Ok(());
    }
    if messages.len() <= 12 {
        return Err(fail("incomplete success"));
    }

    if text(&messages[12], "kind")? == "watchdog_terminal" {
        if messages.len() != 14 || !terminal_denial {
            return Err(fail("incomplete timeout tail"));
        }
        let terminal = &messages[12];
        let result = &messages[13];
        if !matches!(text(terminal, "watchdog_status")?, "STOP" | "TIMEOUT")
            || text(terminal, "receipt_digest")? != ZERO
            || terminal.get("permit_digest") != messages[11].get("permit_digest")
            || terminal.get("watchdog_digest") != messages[11].get("watchdog_digest")
            || result.get("watchdog_digest") != terminal.get("watchdog_digest")
            || text(result, "decision")? != "BLOCK"
        {
            return Err(fail("timeout tail"));
        }
        if text(terminal, "watchdog_status")? == "TIMEOUT"
            && number(terminal, "message_time_ms")? < number(&messages[10], "watchdog_deadline_ms")?
        {
            return Err(fail("early timeout"));
        }
        return Ok(());
    }
    if messages.len() != 16 {
        return Err(fail("incomplete receipt tail"));
    }
    let receipt = &messages[12];
    let ack = &messages[13];
    let terminal = &messages[14];
    let result = &messages[15];
    let receipt_links = [
        (&messages[11], "permit_digest", receipt, "permit_digest"),
        (&messages[11], "watchdog_digest", receipt, "watchdog_digest"),
        (receipt, "receipt_digest", ack, "receipt_digest"),
        (receipt, "watchdog_digest", ack, "watchdog_digest"),
        (&messages[11], "permit_digest", terminal, "permit_digest"),
        (receipt, "receipt_digest", terminal, "receipt_digest"),
        (receipt, "watchdog_digest", terminal, "watchdog_digest"),
        (terminal, "watchdog_digest", result, "watchdog_digest"),
    ];
    for (left, lk, right, rk) in receipt_links {
        if left.get(lk) != right.get(rk) {
            return Err(fail("receipt handoff"));
        }
    }
    let consumed = number(receipt, "adapter_consumed_at_ms")?;
    if consumed < number(&messages[11], "message_time_ms")?
        || consumed > number(&messages[11], "permit_deadline_ms")?
        || consumed > number(receipt, "message_time_ms")?
        || number(receipt, "message_time_ms")? > number(&messages[10], "watchdog_deadline_ms")?
    {
        return Err(fail("adapter consumption"));
    }
    match text(receipt, "effect_outcome")? {
        "SUCCEEDED"
            if text(ack, "receipt_status")? == "SUCCESS_RECORDED"
                && text(terminal, "watchdog_status")? == "HEALTHY"
                && text(result, "decision")? == "ACK"
                && !terminal_denial => {}
        "FAILED"
            if text(ack, "receipt_status")? == "FAILURE_RECORDED"
                && text(terminal, "watchdog_status")? == "STOP"
                && text(result, "decision")? == "BLOCK"
                && terminal_denial => {}
        "UNKNOWN"
            if text(ack, "receipt_status")? == "UNKNOWN_BLOCKED"
                && text(terminal, "watchdog_status")? == "STOP"
                && text(result, "decision")? == "BLOCK"
                && terminal_denial => {}
        _ => return Err(fail("receipt/watchdog semantics")),
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 15) as usize] as char);
    }
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut bytes = data.to_vec();
    let bits = (bytes.len() as u64) * 8;
    bytes.push(0x80);
    while bytes.len() % 64 != 56 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bits.to_be_bytes());
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    for c in bytes.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(c[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c0, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c0) ^ (b & c0);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c0;
            c0 = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, v) in h.iter_mut().zip([a, b, c0, d, e, f, g, hh]) {
            *x = x.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
