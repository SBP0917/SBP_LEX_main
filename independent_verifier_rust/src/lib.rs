#![forbid(unsafe_code)]

//! Independently authored, standard-library-only verifier for the strict
//! SBP-LEX high-risk evidence profile.

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

const HEADER: &str = "SBP-LEX-INDEPENDENT-EVIDENCE-V2";
const CHAIN_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-CHAIN-V1";
const PROOF_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-PROOF-V1";
const LEASE_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-LEASE-V1";
const RECEIPT_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-RECEIPT-V1";
const WATCHDOG_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-WATCHDOG-V1";
pub const SIGNATURE_SUITE_ID: &str = sbp_lex_v2_hybrid_signature::SUITE_ID;
pub const HYBRID_SIGNATURE_BYTES: usize = sbp_lex_v2_hybrid_signature::HYBRID_SIGNATURE_BYTES;

/// Absolute lease ceiling for this high-risk profile.
pub const MAX_LEASE_LIFETIME_MS: u64 = 30_000;
/// Proofs in this profile cannot remain usable for more than five minutes.
pub const MAX_PROOF_LIFETIME_MS: u64 = 300_000;
/// Receipt generation must promptly follow the commit decision.
pub const MAX_RECEIPT_DELAY_MS: u64 = 5_000;
/// Watchdog evidence must promptly follow the signed receipt.
pub const MAX_WATCHDOG_DELAY_MS: u64 = 30_000;

const MAX_INPUT_BYTES: usize = 65_536;
const MAX_LINES: usize = 32;
const MAX_LINE_BYTES: usize = 12_288;

/// A deliberately small boundary around independently reviewed cryptography.
///
/// Implementations must produce a 256-bit cryptographic digest and verify the
/// exact 4,741-byte raw `ML-DSA-87 || Ed448` composite for
/// [`SIGNATURE_SUITE_ID`]. The provider must bind its pinned authority epoch and
/// public context when constructing the shared hybrid preimage. Returning `Err`, or returning
/// `Ok(false)` from signature verification, always rejects the trace.
pub trait VerificationProvider {
    fn hash256(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], ProviderFailure>;

    fn verify_signature(
        &self,
        key_id: &str,
        domain: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ProviderFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    Unavailable,
    Internal,
    Unsupported,
}

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Unavailable => "provider unavailable",
            Self::Internal => "provider internal failure",
            Self::Unsupported => "provider operation unsupported",
        };
        formatter.write_str(text)
    }
}

impl Error for ProviderFailure {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InputTooLarge,
    NonCanonicalTransport,
    UnexpectedRecord,
    MissingOrExtraField,
    InvalidInteger,
    InvalidHex,
    InvalidToken,
    ProviderRequired,
    ProviderFailure,
    BrokenHashChain,
    NonMonotonicSequence,
    DuplicateSequence,
    DuplicateEventId,
    BindingMismatch,
    EnvelopeBroadened,
    InvalidLifetime,
    InvalidUseCount,
    InvalidOrdering,
    InvalidPointOfUse,
    InvalidReference,
    SignatureRejected,
    WatchdogRejected,
    EndMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationError {
    pub kind: ErrorKind,
    pub line: Option<usize>,
    detail: String,
}

impl VerificationError {
    fn new(kind: ErrorKind, line: Option<usize>, detail: impl Into<String>) -> Self {
        Self {
            kind,
            line,
            detail: detail.into(),
        }
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(formatter, "line {line}: {}", self.detail)
        } else {
            formatter.write_str(&self.detail)
        }
    }
}

impl Error for VerificationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTrace {
    pub decision: Decision,
    pub committed: bool,
    pub event_count: u64,
    pub request_id: [u8; 32],
    pub receipt_id: [u8; 32],
    pub head: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Bindings {
    request: [u8; 32],
    state: [u8; 32],
    convergence: [u8; 32],
    effect: [u8; 32],
    adapter: [u8; 32],
    extension_admission_binding: [u8; 32],
    capability: String,
}

struct Cursor<'a> {
    lines: &'a [&'a str],
    index: usize,
}

impl<'a> Cursor<'a> {
    fn new(lines: &'a [&'a str]) -> Self {
        Self { lines, index: 0 }
    }

    fn take_exact(
        &mut self,
        tag: &str,
        keys: &[&str],
    ) -> Result<(usize, &'a str, Vec<&'a str>), VerificationError> {
        let line_number = self.index + 2;
        let line = self.lines.get(self.index).copied().ok_or_else(|| {
            VerificationError::new(
                ErrorKind::UnexpectedRecord,
                Some(line_number),
                format!("missing required {tag} record"),
            )
        })?;
        self.index += 1;

        let mut parts = line.split(' ');
        if parts.next() != Some(tag) {
            return Err(VerificationError::new(
                ErrorKind::UnexpectedRecord,
                Some(line_number),
                format!("expected {tag} record"),
            ));
        }

        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            let part = parts.next().ok_or_else(|| {
                VerificationError::new(
                    ErrorKind::MissingOrExtraField,
                    Some(line_number),
                    format!("{tag} is missing field {key}"),
                )
            })?;
            let expected_prefix = format!("{key}=");
            let value = part.strip_prefix(&expected_prefix).ok_or_else(|| {
                VerificationError::new(
                    ErrorKind::MissingOrExtraField,
                    Some(line_number),
                    format!("{tag} fields are missing, unknown, or out of order at {key}"),
                )
            })?;
            if value.is_empty() {
                return Err(VerificationError::new(
                    ErrorKind::MissingOrExtraField,
                    Some(line_number),
                    format!("{tag}.{key} is empty"),
                ));
            }
            values.push(value);
        }
        if parts.next().is_some() {
            return Err(VerificationError::new(
                ErrorKind::MissingOrExtraField,
                Some(line_number),
                format!("{tag} has an unknown or extra field"),
            ));
        }
        Ok((line_number, line, values))
    }

    fn is_finished(&self) -> bool {
        self.index == self.lines.len()
    }
}

struct Chain<'a, 'p> {
    provider: &'p dyn VerificationProvider,
    previous_line: Option<&'a str>,
    next_sequence: u64,
    event_ids: HashSet<[u8; 32]>,
    sequences: HashSet<u64>,
}

impl<'a, 'p> Chain<'a, 'p> {
    fn new(provider: &'p dyn VerificationProvider) -> Self {
        Self {
            provider,
            previous_line: None,
            next_sequence: 1,
            event_ids: HashSet::new(),
            sequences: HashSet::new(),
        }
    }

    fn accept(
        &mut self,
        line_number: usize,
        line: &'a str,
        values: &[&str],
    ) -> Result<[u8; 32], VerificationError> {
        let event_id = parse_nonzero_hex(values[0], line_number, "event_id")?;
        let sequence = parse_u64(values[1], line_number, "seq")?;
        let provided_previous = parse_hex(values[2], line_number, "prev")?;

        if !self.event_ids.insert(event_id) {
            return Err(VerificationError::new(
                ErrorKind::DuplicateEventId,
                Some(line_number),
                "event_id is not unique",
            ));
        }
        if !self.sequences.insert(sequence) {
            return Err(VerificationError::new(
                ErrorKind::DuplicateSequence,
                Some(line_number),
                "sequence number is not unique",
            ));
        }
        if sequence != self.next_sequence {
            return Err(VerificationError::new(
                ErrorKind::NonMonotonicSequence,
                Some(line_number),
                format!("expected sequence {}", self.next_sequence),
            ));
        }

        let expected_previous = match self.previous_line {
            Some(previous) => provider_hash(
                self.provider,
                CHAIN_DOMAIN,
                previous.as_bytes(),
                line_number,
            )?,
            None => [0_u8; 32],
        };
        if provided_previous != expected_previous {
            return Err(VerificationError::new(
                ErrorKind::BrokenHashChain,
                Some(line_number),
                "prev does not hash the complete preceding event line",
            ));
        }

        self.previous_line = Some(line);
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            VerificationError::new(
                ErrorKind::InvalidInteger,
                Some(line_number),
                "sequence overflow",
            )
        })?;
        Ok(event_id)
    }

    fn event_count(&self) -> u64 {
        self.next_sequence - 1
    }

    fn expected_head(&self, line_number: usize) -> Result<[u8; 32], VerificationError> {
        let last = self.previous_line.ok_or_else(|| {
            VerificationError::new(
                ErrorKind::EndMismatch,
                Some(line_number),
                "trace has no events",
            )
        })?;
        provider_hash(self.provider, CHAIN_DOMAIN, last.as_bytes(), line_number)
    }
}

struct EventRecord<'a> {
    line_number: usize,
    line: &'a str,
    values: Vec<&'a str>,
    event_id: [u8; 32],
    extension_admission_binding: [u8; 32],
}

fn take_event<'a, 'p>(
    cursor: &mut Cursor<'a>,
    chain: &mut Chain<'a, 'p>,
    tag: &str,
    keys: &[&str],
) -> Result<EventRecord<'a>, VerificationError> {
    let (line_number, line, mut values) = cursor.take_exact(tag, keys)?;
    let event_id = chain.accept(line_number, line, &values)?;
    let extension_admission_binding =
        parse_nonzero_hex(values[8], line_number, "extension_admission_binding_digest")?;
    values.remove(8);
    Ok(EventRecord {
        line_number,
        line,
        values,
        event_id,
        extension_admission_binding,
    })
}

fn provider_hash(
    provider: &dyn VerificationProvider,
    domain: &[u8],
    message: &[u8],
    line_number: usize,
) -> Result<[u8; 32], VerificationError> {
    provider.hash256(domain, message).map_err(|failure| {
        VerificationError::new(
            ErrorKind::ProviderFailure,
            Some(line_number),
            format!("cryptographic hash provider failed: {failure}"),
        )
    })
}

fn parse_hex(text: &str, line_number: usize, field: &str) -> Result<[u8; 32], VerificationError> {
    if text.len() != 64
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidHex,
            Some(line_number),
            format!("{field} must be exactly 64 lowercase hexadecimal characters"),
        ));
    }

    let mut output = [0_u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

fn parse_hybrid_signature(text: &str, line_number: usize) -> Result<Vec<u8>, VerificationError> {
    if text.len() != HYBRID_SIGNATURE_BYTES * 2
        || !text
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidHex,
            Some(line_number),
            format!(
                "signature must be exactly {} lowercase hexadecimal characters for {SIGNATURE_SUITE_ID}",
                HYBRID_SIGNATURE_BYTES * 2
            ),
        ));
    }
    let mut output = vec![0u8; HYBRID_SIGNATURE_BYTES];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    sbp_lex_v2_hybrid_signature::HybridSignature::from_combined(&output).map_err(|_| {
        VerificationError::new(
            ErrorKind::SignatureRejected,
            Some(line_number),
            "signature contains a non-canonical hybrid lane encoding",
        )
    })?;
    Ok(output)
}

fn parse_nonzero_hex(
    text: &str,
    line_number: usize,
    field: &str,
) -> Result<[u8; 32], VerificationError> {
    let value = parse_hex(text, line_number, field)?;
    if value == [0_u8; 32] {
        return Err(VerificationError::new(
            ErrorKind::InvalidHex,
            Some(line_number),
            format!("{field} must not be the all-zero value"),
        ));
    }
    Ok(value)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0,
    }
}

fn parse_u64(text: &str, line_number: usize, field: &str) -> Result<u64, VerificationError> {
    if text.is_empty()
        || !text.as_bytes().iter().all(u8::is_ascii_digit)
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidInteger,
            Some(line_number),
            format!("{field} is not a canonical unsigned decimal integer"),
        ));
    }

    let mut result = 0_u64;
    for digit in text.bytes() {
        result = result
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit - b'0')))
            .ok_or_else(|| {
                VerificationError::new(
                    ErrorKind::InvalidInteger,
                    Some(line_number),
                    format!("{field} overflows u64"),
                )
            })?;
    }
    Ok(result)
}

fn validate_token(text: &str, line_number: usize, field: &str) -> Result<(), VerificationError> {
    let bytes = text.as_bytes();
    let valid_first = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    let valid_rest = bytes.iter().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'.' | b'_' | b':' | b'-')
    });
    if bytes.len() > 64 || !valid_first || !valid_rest {
        return Err(VerificationError::new(
            ErrorKind::InvalidToken,
            Some(line_number),
            format!("{field} is not a canonical lowercase token"),
        ));
    }
    Ok(())
}

fn bindings_from(
    values: &[&str],
    line_number: usize,
    extension_admission_binding: [u8; 32],
) -> Result<Bindings, VerificationError> {
    let capability = values[8];
    validate_token(capability, line_number, "capability")?;
    Ok(Bindings {
        request: parse_nonzero_hex(values[3], line_number, "request")?,
        state: parse_nonzero_hex(values[4], line_number, "state")?,
        convergence: parse_nonzero_hex(values[5], line_number, "convergence")?,
        effect: parse_nonzero_hex(values[6], line_number, "effect")?,
        adapter: parse_nonzero_hex(values[7], line_number, "adapter")?,
        extension_admission_binding,
        capability: capability.to_owned(),
    })
}

fn require_bindings(
    record: &EventRecord<'_>,
    expected: &Bindings,
) -> Result<(), VerificationError> {
    let actual = bindings_from(
        &record.values,
        record.line_number,
        record.extension_admission_binding,
    )?;
    if &actual != expected {
        return Err(VerificationError::new(
            ErrorKind::BindingMismatch,
            Some(record.line_number),
            "request/state/convergence/effect/adapter/extension/capability binding mismatch",
        ));
    }
    Ok(())
}

fn checked_span(
    start: u64,
    end: u64,
    line_number: usize,
    field: &str,
) -> Result<u64, VerificationError> {
    end.checked_sub(start).ok_or_else(|| {
        VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(line_number),
            format!("{field} ends before it starts"),
        )
    })
}

fn verify_signed_record(
    provider: &dyn VerificationProvider,
    record: &EventRecord<'_>,
    signer_index: usize,
    signature_index: usize,
    domain: &[u8],
    watchdog: bool,
) -> Result<(), VerificationError> {
    let signer = record.values[signer_index];
    validate_token(signer, record.line_number, "signer")?;
    let signature = parse_hybrid_signature(record.values[signature_index], record.line_number)?;
    let suffix = format!(" signature={}", record.values[signature_index]);
    let message = record.line.strip_suffix(&suffix).ok_or_else(|| {
        VerificationError::new(
            ErrorKind::MissingOrExtraField,
            Some(record.line_number),
            "signature must be the final field",
        )
    })?;

    match provider.verify_signature(signer, domain, message.as_bytes(), &signature) {
        Ok(true) => Ok(()),
        Ok(false) => Err(VerificationError::new(
            if watchdog {
                ErrorKind::WatchdogRejected
            } else {
                ErrorKind::SignatureRejected
            },
            Some(record.line_number),
            "signature verification rejected the record",
        )),
        Err(failure) => Err(VerificationError::new(
            ErrorKind::ProviderFailure,
            Some(record.line_number),
            format!("signature provider failed: {failure}"),
        )),
    }
}

fn validate_transport(input: &str) -> Result<Vec<&str>, VerificationError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(VerificationError::new(
            ErrorKind::InputTooLarge,
            None,
            "evidence exceeds the 65536-byte limit",
        ));
    }
    if !input.is_ascii() || input.contains('\r') {
        return Err(VerificationError::new(
            ErrorKind::NonCanonicalTransport,
            None,
            "evidence must be ASCII with LF line endings",
        ));
    }
    if !input.ends_with('\n') {
        return Err(VerificationError::new(
            ErrorKind::NonCanonicalTransport,
            None,
            "evidence must end in exactly one LF",
        ));
    }
    let body = &input[..input.len() - 1];
    if body.ends_with('\n') {
        return Err(VerificationError::new(
            ErrorKind::NonCanonicalTransport,
            None,
            "evidence must not contain a trailing blank line",
        ));
    }
    let lines: Vec<&str> = body.split('\n').collect();
    if lines.len() > MAX_LINES {
        return Err(VerificationError::new(
            ErrorKind::InputTooLarge,
            None,
            "evidence exceeds the 32-line limit",
        ));
    }
    for (index, line) in lines.iter().enumerate() {
        if line.is_empty() || line.len() > MAX_LINE_BYTES {
            return Err(VerificationError::new(
                if line.len() > MAX_LINE_BYTES {
                    ErrorKind::InputTooLarge
                } else {
                    ErrorKind::NonCanonicalTransport
                },
                Some(index + 1),
                "blank or overlong line",
            ));
        }
    }
    if lines.first().copied() != Some(HEADER) {
        return Err(VerificationError::new(
            ErrorKind::UnexpectedRecord,
            Some(1),
            "invalid or missing evidence header",
        ));
    }
    Ok(lines)
}

const REQUEST_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "issued_at",
    "expires_at",
    "requested_max_uses",
    "requested_max_lease_ms",
];
const OBSERVATION_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "observed_at",
];
const ENVELOPE_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "decision",
    "not_before",
    "expires_at",
    "max_uses",
    "max_lease_ms",
];
const PROOF_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "proof_id",
    "issued_at",
    "expires_at",
    "max_uses",
    "signer",
    "signature",
];
const PREPARE_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "proof_id",
    "at",
];
const LEASE_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "proof_id",
    "lease_id",
    "issued_at",
    "expires_at",
    "max_uses",
    "signer",
    "signature",
];
const REDEEM_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "proof_id",
    "lease_id",
    "use",
    "point_of_use",
    "at",
];
const COMMIT_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "proof_id",
    "lease_id",
    "prepare",
    "redemption",
    "at",
];
const RECEIPT_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "receipt_id",
    "subject",
    "outcome",
    "at",
    "signer",
    "signature",
];
const WATCHDOG_KEYS: &[&str] = &[
    "event_id",
    "seq",
    "prev",
    "request",
    "state",
    "convergence",
    "effect",
    "adapter",
    "extension_admission_binding_digest",
    "capability",
    "receipt_id",
    "mode",
    "checked_at",
    "status",
    "signer",
    "signature",
];
const END_KEYS: &[&str] = &["events", "head"];

#[derive(Debug, Clone, Copy)]
struct RequestLimits {
    issued_at: u64,
    expires_at: u64,
    max_uses: u64,
    max_lease_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct EnvelopeLimits {
    not_before: u64,
    expires_at: u64,
    max_lease_ms: u64,
}

/// Verify a complete canonical evidence trace.
///
/// Passing `None` is always a hard failure after minimal transport/header
/// validation. There is no insecure fallback provider.
pub fn verify(
    input: &str,
    provider: Option<&dyn VerificationProvider>,
) -> Result<VerifiedTrace, VerificationError> {
    let lines = validate_transport(input)?;
    let provider = provider.ok_or_else(|| {
        VerificationError::new(
            ErrorKind::ProviderRequired,
            None,
            "a production cryptographic verification provider is required",
        )
    })?;

    let mut cursor = Cursor::new(&lines[1..]);
    let mut chain = Chain::new(provider);

    let request = take_event(&mut cursor, &mut chain, "REQUEST", REQUEST_KEYS)?;
    let bindings = bindings_from(
        &request.values,
        request.line_number,
        request.extension_admission_binding,
    )?;
    let request_limits = RequestLimits {
        issued_at: parse_u64(request.values[9], request.line_number, "issued_at")?,
        expires_at: parse_u64(request.values[10], request.line_number, "expires_at")?,
        max_uses: parse_u64(
            request.values[11],
            request.line_number,
            "requested_max_uses",
        )?,
        max_lease_ms: parse_u64(
            request.values[12],
            request.line_number,
            "requested_max_lease_ms",
        )?,
    };
    if request_limits.issued_at >= request_limits.expires_at {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(request.line_number),
            "request must expire after issuance",
        ));
    }
    if request_limits.max_uses == 0 || request_limits.max_lease_ms == 0 {
        return Err(VerificationError::new(
            ErrorKind::InvalidUseCount,
            Some(request.line_number),
            "requested limits must be nonzero",
        ));
    }

    let state = take_event(&mut cursor, &mut chain, "STATE", OBSERVATION_KEYS)?;
    require_bindings(&state, &bindings)?;
    let state_at = parse_u64(state.values[9], state.line_number, "observed_at")?;
    if state_at < request_limits.issued_at || state_at >= request_limits.expires_at {
        return Err(VerificationError::new(
            ErrorKind::InvalidOrdering,
            Some(state.line_number),
            "state observation is outside the request lifetime",
        ));
    }

    let convergence = take_event(&mut cursor, &mut chain, "CONVERGENCE", OBSERVATION_KEYS)?;
    require_bindings(&convergence, &bindings)?;
    let convergence_at = parse_u64(
        convergence.values[9],
        convergence.line_number,
        "observed_at",
    )?;
    if convergence_at < state_at || convergence_at >= request_limits.expires_at {
        return Err(VerificationError::new(
            ErrorKind::InvalidOrdering,
            Some(convergence.line_number),
            "convergence must follow state observation within the request lifetime",
        ));
    }

    let envelope = take_event(&mut cursor, &mut chain, "ENVELOPE", ENVELOPE_KEYS)?;
    require_bindings(&envelope, &bindings)?;
    let decision = match envelope.values[9] {
        "ALLOW" => Decision::Allow,
        "BLOCK" => Decision::Block,
        _ => {
            return Err(VerificationError::new(
                ErrorKind::InvalidToken,
                Some(envelope.line_number),
                "decision must be ALLOW or BLOCK",
            ))
        }
    };
    let envelope_limits = EnvelopeLimits {
        not_before: parse_u64(envelope.values[10], envelope.line_number, "not_before")?,
        expires_at: parse_u64(envelope.values[11], envelope.line_number, "expires_at")?,
        max_lease_ms: parse_u64(envelope.values[13], envelope.line_number, "max_lease_ms")?,
    };
    let envelope_uses = parse_u64(envelope.values[12], envelope.line_number, "max_uses")?;
    if envelope_limits.not_before < convergence_at
        || envelope_limits.expires_at > request_limits.expires_at
        || envelope_limits.not_before >= envelope_limits.expires_at
        || envelope_uses > request_limits.max_uses
        || envelope_limits.max_lease_ms > request_limits.max_lease_ms
    {
        return Err(VerificationError::new(
            ErrorKind::EnvelopeBroadened,
            Some(envelope.line_number),
            "safety envelope broadens or escapes request limits",
        ));
    }
    match decision {
        Decision::Allow => {
            if envelope_uses != 1 {
                return Err(VerificationError::new(
                    ErrorKind::InvalidUseCount,
                    Some(envelope.line_number),
                    "high-risk ALLOW envelope must narrow to exactly one use",
                ));
            }
            if envelope_limits.max_lease_ms == 0
                || envelope_limits.max_lease_ms > MAX_LEASE_LIFETIME_MS
            {
                return Err(VerificationError::new(
                    ErrorKind::InvalidLifetime,
                    Some(envelope.line_number),
                    "high-risk ALLOW lease limit must be 1..=30000 ms",
                ));
            }
        }
        Decision::Block => {
            if envelope_uses != 0 || envelope_limits.max_lease_ms != 0 {
                return Err(VerificationError::new(
                    ErrorKind::EnvelopeBroadened,
                    Some(envelope.line_number),
                    "BLOCK envelope must grant zero uses and zero lease time",
                ));
            }
        }
    }

    match decision {
        Decision::Allow => verify_allow(
            &mut cursor,
            &mut chain,
            provider,
            bindings,
            request_limits,
            envelope_limits,
        ),
        Decision::Block => verify_block(
            &mut cursor,
            &mut chain,
            provider,
            bindings,
            request_limits,
            convergence_at,
            envelope_limits,
            envelope.event_id,
        ),
    }
}

fn verify_allow<'a, 'p>(
    cursor: &mut Cursor<'a>,
    chain: &mut Chain<'a, 'p>,
    provider: &'p dyn VerificationProvider,
    bindings: Bindings,
    _request_limits: RequestLimits,
    envelope_limits: EnvelopeLimits,
) -> Result<VerifiedTrace, VerificationError> {
    let proof = take_event(cursor, chain, "PROOF", PROOF_KEYS)?;
    require_bindings(&proof, &bindings)?;
    let proof_id = parse_nonzero_hex(proof.values[9], proof.line_number, "proof_id")?;
    let proof_issued = parse_u64(proof.values[10], proof.line_number, "issued_at")?;
    let proof_expires = parse_u64(proof.values[11], proof.line_number, "expires_at")?;
    let proof_uses = parse_u64(proof.values[12], proof.line_number, "max_uses")?;
    let proof_lifetime = checked_span(
        proof_issued,
        proof_expires,
        proof.line_number,
        "proof lifetime",
    )?;
    if proof_issued < envelope_limits.not_before
        || proof_expires > envelope_limits.expires_at
        || proof_lifetime == 0
        || proof_lifetime > MAX_PROOF_LIFETIME_MS
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(proof.line_number),
            "proof lifetime is not a nonempty subset of the envelope or exceeds 300000 ms",
        ));
    }
    if proof_uses != 1 {
        return Err(VerificationError::new(
            ErrorKind::InvalidUseCount,
            Some(proof.line_number),
            "proof must be single-use",
        ));
    }
    verify_signed_record(provider, &proof, 13, 14, PROOF_DOMAIN, false)?;

    let prepare = take_event(cursor, chain, "PREPARE", PREPARE_KEYS)?;
    require_bindings(&prepare, &bindings)?;
    if parse_nonzero_hex(prepare.values[9], prepare.line_number, "proof_id")? != proof_id {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(prepare.line_number),
            "PREPARE references a different proof",
        ));
    }
    let prepare_at = parse_u64(prepare.values[10], prepare.line_number, "at")?;
    if prepare_at < proof_issued || prepare_at >= proof_expires {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(prepare.line_number),
            "PREPARE occurs outside proof validity",
        ));
    }

    let lease = take_event(cursor, chain, "LEASE", LEASE_KEYS)?;
    require_bindings(&lease, &bindings)?;
    if parse_nonzero_hex(lease.values[9], lease.line_number, "proof_id")? != proof_id {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(lease.line_number),
            "lease references a different proof",
        ));
    }
    let lease_id = parse_nonzero_hex(lease.values[10], lease.line_number, "lease_id")?;
    let lease_issued = parse_u64(lease.values[11], lease.line_number, "issued_at")?;
    let lease_expires = parse_u64(lease.values[12], lease.line_number, "expires_at")?;
    let lease_uses = parse_u64(lease.values[13], lease.line_number, "max_uses")?;
    let lease_lifetime = checked_span(
        lease_issued,
        lease_expires,
        lease.line_number,
        "lease lifetime",
    )?;
    if lease_issued < prepare_at
        || lease_expires > proof_expires
        || lease_expires > envelope_limits.expires_at
        || lease_lifetime == 0
        || lease_lifetime > envelope_limits.max_lease_ms
        || lease_lifetime > MAX_LEASE_LIFETIME_MS
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(lease.line_number),
            "lease is not short-lived or escapes proof/envelope validity",
        ));
    }
    if lease_uses != 1 {
        return Err(VerificationError::new(
            ErrorKind::InvalidUseCount,
            Some(lease.line_number),
            "lease must be single-use",
        ));
    }
    verify_signed_record(provider, &lease, 14, 15, LEASE_DOMAIN, false)?;

    let redeem = take_event(cursor, chain, "REDEEM", REDEEM_KEYS)?;
    require_bindings(&redeem, &bindings)?;
    if parse_nonzero_hex(redeem.values[9], redeem.line_number, "proof_id")? != proof_id
        || parse_nonzero_hex(redeem.values[10], redeem.line_number, "lease_id")? != lease_id
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(redeem.line_number),
            "redemption references a different proof or lease",
        ));
    }
    if parse_u64(redeem.values[11], redeem.line_number, "use")? != 1 {
        return Err(VerificationError::new(
            ErrorKind::InvalidUseCount,
            Some(redeem.line_number),
            "the only redemption must be use number 1",
        ));
    }
    if parse_nonzero_hex(redeem.values[12], redeem.line_number, "point_of_use")? != bindings.adapter
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidPointOfUse,
            Some(redeem.line_number),
            "point-of-use redemption is not at the bound adapter",
        ));
    }
    let redeem_at = parse_u64(redeem.values[13], redeem.line_number, "at")?;
    if redeem_at < lease_issued
        || redeem_at >= lease_expires
        || redeem_at < proof_issued
        || redeem_at >= proof_expires
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(redeem.line_number),
            "redemption occurs outside proof or lease validity",
        ));
    }

    // The grammar admits exactly one REDEEM and requires COMMIT immediately
    // after it. This closes duplicate/deferred point-of-use redemption paths.
    let commit = take_event(cursor, chain, "COMMIT", COMMIT_KEYS)?;
    require_bindings(&commit, &bindings)?;
    if parse_nonzero_hex(commit.values[9], commit.line_number, "proof_id")? != proof_id
        || parse_nonzero_hex(commit.values[10], commit.line_number, "lease_id")? != lease_id
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(commit.line_number),
            "COMMIT references a different proof or lease",
        ));
    }
    if parse_nonzero_hex(commit.values[11], commit.line_number, "prepare")? != prepare.event_id
        || parse_nonzero_hex(commit.values[12], commit.line_number, "redemption")?
            != redeem.event_id
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(commit.line_number),
            "COMMIT does not reference the preceding PREPARE and redemption",
        ));
    }
    let commit_at = parse_u64(commit.values[13], commit.line_number, "at")?;
    if commit_at != redeem_at || commit_at < prepare_at || commit_at >= lease_expires {
        return Err(VerificationError::new(
            ErrorKind::InvalidOrdering,
            Some(commit.line_number),
            "COMMIT must occur at the redeemed point of use after PREPARE",
        ));
    }

    let receipt = take_event(cursor, chain, "RECEIPT", RECEIPT_KEYS)?;
    require_bindings(&receipt, &bindings)?;
    let receipt_id = parse_nonzero_hex(receipt.values[9], receipt.line_number, "receipt_id")?;
    if parse_nonzero_hex(receipt.values[10], receipt.line_number, "subject")? != commit.event_id
        || receipt.values[11] != "APPLIED"
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(receipt.line_number),
            "receipt must attest APPLIED for this COMMIT event",
        ));
    }
    let receipt_at = parse_u64(receipt.values[12], receipt.line_number, "at")?;
    let receipt_delay = checked_span(commit_at, receipt_at, receipt.line_number, "receipt delay")?;
    if receipt_at >= lease_expires || receipt_delay > MAX_RECEIPT_DELAY_MS {
        return Err(VerificationError::new(
            ErrorKind::InvalidLifetime,
            Some(receipt.line_number),
            "receipt is outside the half-open lease or prompt bound",
        ));
    }
    verify_signed_record(provider, &receipt, 13, 14, RECEIPT_DOMAIN, false)?;

    verify_watchdog(
        cursor, chain, provider, &bindings, receipt_id, "COMMIT", receipt_at,
    )?;
    let head = verify_end(cursor, chain)?;

    Ok(VerifiedTrace {
        decision: Decision::Allow,
        committed: true,
        event_count: chain.event_count(),
        request_id: bindings.request,
        receipt_id,
        head,
    })
}

// Keep every independently verified BLOCK binding and limit explicit at this
// trust boundary. Hiding them in a convenience aggregate would make field
// omission or substitution harder to review.
#[allow(clippy::too_many_arguments)]
fn verify_block<'a, 'p>(
    cursor: &mut Cursor<'a>,
    chain: &mut Chain<'a, 'p>,
    provider: &'p dyn VerificationProvider,
    bindings: Bindings,
    request_limits: RequestLimits,
    convergence_at: u64,
    envelope_limits: EnvelopeLimits,
    envelope_event_id: [u8; 32],
) -> Result<VerifiedTrace, VerificationError> {
    // Fixed ordering means any PREPARE/LEASE/REDEEM/COMMIT record after BLOCK
    // is rejected here before any success can be reported.
    let receipt = take_event(cursor, chain, "RECEIPT", RECEIPT_KEYS)?;
    require_bindings(&receipt, &bindings)?;
    let receipt_id = parse_nonzero_hex(receipt.values[9], receipt.line_number, "receipt_id")?;
    if parse_nonzero_hex(receipt.values[10], receipt.line_number, "subject")? != envelope_event_id
        || receipt.values[11] != "BLOCKED"
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(receipt.line_number),
            "blocked receipt must attest BLOCKED for this envelope event",
        ));
    }
    let receipt_at = parse_u64(receipt.values[12], receipt.line_number, "at")?;
    let receipt_delay = checked_span(
        envelope_limits.not_before,
        receipt_at,
        receipt.line_number,
        "blocked receipt delay",
    )?;
    if receipt_at < convergence_at
        || receipt_at < request_limits.issued_at
        || receipt_at >= envelope_limits.expires_at
        || receipt_delay > MAX_RECEIPT_DELAY_MS
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidOrdering,
            Some(receipt.line_number),
            "blocked receipt is outside the envelope or is not prompt",
        ));
    }
    verify_signed_record(provider, &receipt, 13, 14, RECEIPT_DOMAIN, false)?;

    verify_watchdog(
        cursor, chain, provider, &bindings, receipt_id, "BLOCK", receipt_at,
    )?;
    let head = verify_end(cursor, chain)?;

    Ok(VerifiedTrace {
        decision: Decision::Block,
        committed: false,
        event_count: chain.event_count(),
        request_id: bindings.request,
        receipt_id,
        head,
    })
}

fn verify_watchdog<'a, 'p>(
    cursor: &mut Cursor<'a>,
    chain: &mut Chain<'a, 'p>,
    provider: &'p dyn VerificationProvider,
    bindings: &Bindings,
    receipt_id: [u8; 32],
    expected_mode: &str,
    receipt_at: u64,
) -> Result<(), VerificationError> {
    let watchdog = take_event(cursor, chain, "WATCHDOG", WATCHDOG_KEYS)?;
    require_bindings(&watchdog, bindings)?;
    if parse_nonzero_hex(watchdog.values[9], watchdog.line_number, "receipt_id")? != receipt_id
        || watchdog.values[10] != expected_mode
    {
        return Err(VerificationError::new(
            ErrorKind::InvalidReference,
            Some(watchdog.line_number),
            "watchdog does not reference the required receipt/mode",
        ));
    }
    let checked_at = parse_u64(watchdog.values[11], watchdog.line_number, "checked_at")?;
    let watchdog_delay = checked_span(
        receipt_at,
        checked_at,
        watchdog.line_number,
        "watchdog delay",
    )?;
    if watchdog_delay > MAX_WATCHDOG_DELAY_MS || watchdog.values[12] != "PASS" {
        return Err(VerificationError::new(
            ErrorKind::WatchdogRejected,
            Some(watchdog.line_number),
            "watchdog is late, absent, or not PASS",
        ));
    }
    verify_signed_record(provider, &watchdog, 13, 14, WATCHDOG_DOMAIN, true)
}

fn verify_end<'a, 'p>(
    cursor: &mut Cursor<'a>,
    chain: &Chain<'a, 'p>,
) -> Result<[u8; 32], VerificationError> {
    let (line_number, _, values) = cursor.take_exact("END", END_KEYS)?;
    let declared_events = parse_u64(values[0], line_number, "events")?;
    if declared_events != chain.event_count() {
        return Err(VerificationError::new(
            ErrorKind::EndMismatch,
            Some(line_number),
            "END event count does not match the trace",
        ));
    }
    let declared_head = parse_hex(values[1], line_number, "head")?;
    let expected_head = chain.expected_head(line_number)?;
    if declared_head != expected_head {
        return Err(VerificationError::new(
            ErrorKind::EndMismatch,
            Some(line_number),
            "END head does not hash the final event",
        ));
    }
    if !cursor.is_finished() {
        return Err(VerificationError::new(
            ErrorKind::UnexpectedRecord,
            Some(cursor.index + 2),
            "records after END are forbidden",
        ));
    }
    Ok(declared_head)
}

#[cfg(test)]
mod parser_tests {
    use super::{parse_u64, ErrorKind};

    #[test]
    fn decimal_parser_rejects_noncanonical_and_overflow_values() {
        for value in ["", "+1", "01", "-1", "1_0", "18446744073709551616"] {
            assert_eq!(
                parse_u64(value, 1, "value").unwrap_err().kind,
                ErrorKind::InvalidInteger
            );
        }
        assert_eq!(
            parse_u64("18446744073709551615", 1, "value").unwrap(),
            u64::MAX
        );
    }
}
