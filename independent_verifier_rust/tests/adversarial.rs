#![forbid(unsafe_code)]

use sbp_lex_independent_verifier::{
    verify, Decision, ErrorKind, ProviderFailure, VerificationProvider,
};

/// Deterministic test fixture only. This is intentionally not cryptography and
/// is never available from the production library or CLI.
struct NonProductionFixtureProvider;

struct SignatureProviderFailure;

impl NonProductionFixtureProvider {
    fn mix(domain: &[u8], message: &[u8]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        let mut state = 0x6a09_e667_f3bc_c908_u64;
        for (index, byte) in domain
            .iter()
            .chain([0xff_u8].iter())
            .chain(message.iter())
            .enumerate()
        {
            state ^= u64::from(*byte) | ((index as u64) << 17);
            state = state.rotate_left(11).wrapping_mul(0x9e37_79b1_85eb_ca87);
            let slot = index % 32;
            output[slot] = output[slot]
                .wrapping_add((state >> ((index % 8) * 8)) as u8)
                .rotate_left((index % 7) as u32);
        }
        for round in 0..64 {
            let slot = round % 32;
            let other = output[(slot + 13) % 32];
            output[slot] = output[slot]
                .wrapping_add(other)
                .rotate_left(((round % 7) + 1) as u32)
                ^ (round as u8);
        }
        output
    }

    fn signature(key_id: &str, domain: &[u8], message: &[u8]) -> Vec<u8> {
        let mut authenticated = Vec::new();
        authenticated.extend_from_slice(key_id.as_bytes());
        authenticated.push(0);
        authenticated.extend_from_slice(message);
        let seed = Self::mix(domain, &authenticated);
        let signer = sbp_lex_v2_hybrid_signature::SoftwareHybridSigningKey::from_seed_slices(
            &seed,
            &[0x44; 57],
        )
        .expect("fixture signer");
        signer
            .sign("INDEPENDENT_EVIDENCE", 1, domain, message)
            .expect("fixture hybrid signature")
            .to_combined()
    }
}

impl VerificationProvider for NonProductionFixtureProvider {
    fn hash256(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], ProviderFailure> {
        Ok(Self::mix(domain, message))
    }

    fn verify_signature(
        &self,
        key_id: &str,
        domain: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, ProviderFailure> {
        let mut authenticated = Vec::new();
        authenticated.extend_from_slice(key_id.as_bytes());
        authenticated.push(0);
        authenticated.extend_from_slice(message);
        let seed = Self::mix(domain, &authenticated);
        let signer = sbp_lex_v2_hybrid_signature::SoftwareHybridSigningKey::from_seed_slices(
            &seed,
            &[0x44; 57],
        )
        .map_err(|_| ProviderFailure::Internal)?;
        let signature = sbp_lex_v2_hybrid_signature::HybridSignature::from_combined(signature)
            .map_err(|_| ProviderFailure::Internal)?;
        Ok(signer
            .public_key()
            .verify("INDEPENDENT_EVIDENCE", 1, domain, message, &signature)
            .is_ok())
    }
}

impl VerificationProvider for SignatureProviderFailure {
    fn hash256(&self, domain: &[u8], message: &[u8]) -> Result<[u8; 32], ProviderFailure> {
        Ok(NonProductionFixtureProvider::mix(domain, message))
    }

    fn verify_signature(
        &self,
        _key_id: &str,
        _domain: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<bool, ProviderFailure> {
        Err(ProviderFailure::Unavailable)
    }
}

const CHAIN_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-CHAIN-V1";
const PROOF_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-PROOF-V1";
const LEASE_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-LEASE-V1";
const RECEIPT_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-RECEIPT-V1";
const WATCHDOG_DOMAIN: &[u8] = b"SBP-LEX-INDEPENDENT-WATCHDOG-V1";

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn id(byte: u8) -> String {
    hex(&[byte; 32])
}

struct TraceBuilder {
    provider: NonProductionFixtureProvider,
    lines: Vec<String>,
    previous_event: Option<String>,
    next_id: u8,
    next_sequence: u64,
}

impl TraceBuilder {
    fn new() -> Self {
        Self {
            provider: NonProductionFixtureProvider,
            lines: vec!["SBP-LEX-INDEPENDENT-EVIDENCE-V2".to_owned()],
            previous_event: None,
            next_id: 1,
            next_sequence: 1,
        }
    }

    fn event(&mut self, tag: &str, rest: &str) -> String {
        let event_id = id(self.next_id);
        self.next_id += 1;
        let previous = self.previous_event.as_ref().map_or([0_u8; 32], |line| {
            self.provider
                .hash256(CHAIN_DOMAIN, line.as_bytes())
                .unwrap()
        });
        let line = format!(
            "{tag} event_id={event_id} seq={} prev={} {rest}",
            self.next_sequence,
            hex(&previous)
        );
        self.next_sequence += 1;
        self.previous_event = Some(line.clone());
        self.lines.push(line);
        event_id
    }

    fn signed_event(&mut self, tag: &str, rest: &str, signer: &str, domain: &[u8]) -> String {
        let event_id = id(self.next_id);
        self.next_id += 1;
        let previous = self.previous_event.as_ref().map_or([0_u8; 32], |line| {
            self.provider
                .hash256(CHAIN_DOMAIN, line.as_bytes())
                .unwrap()
        });
        let prefix = format!(
            "{tag} event_id={event_id} seq={} prev={} {rest} signer={signer}",
            self.next_sequence,
            hex(&previous)
        );
        let signature = hex(&NonProductionFixtureProvider::signature(
            signer,
            domain,
            prefix.as_bytes(),
        ));
        let line = format!("{prefix} signature={signature}");
        self.next_sequence += 1;
        self.previous_event = Some(line.clone());
        self.lines.push(line);
        event_id
    }

    fn finish(mut self) -> String {
        let last = self.previous_event.as_ref().unwrap();
        let head = self
            .provider
            .hash256(CHAIN_DOMAIN, last.as_bytes())
            .unwrap();
        self.lines.push(format!(
            "END events={} head={}",
            self.next_sequence - 1,
            hex(&head)
        ));
        let mut result = self.lines.join("\n");
        result.push('\n');
        result
    }
}

fn bindings() -> String {
    format!(
        "request={} state={} convergence={} effect={} adapter={} extension_admission_binding_digest={} capability=write.asset",
        id(0xa1),
        id(0xa2),
        id(0xa3),
        id(0xa4),
        id(0xa5),
        id(0xa6),
    )
}

fn valid_allow() -> String {
    let bind = bindings();
    let mut trace = TraceBuilder::new();
    trace.event(
        "REQUEST",
        &format!(
            "{bind} issued_at=1000 expires_at=20000 requested_max_uses=5 requested_max_lease_ms=25000"
        ),
    );
    trace.event("STATE", &format!("{bind} observed_at=1100"));
    trace.event("CONVERGENCE", &format!("{bind} observed_at=1200"));
    trace.event(
        "ENVELOPE",
        &format!(
            "{bind} decision=ALLOW not_before=1200 expires_at=10000 max_uses=1 max_lease_ms=5000"
        ),
    );
    let proof_id = id(0xb1);
    trace.signed_event(
        "PROOF",
        &format!("{bind} proof_id={proof_id} issued_at=1300 expires_at=9000 max_uses=1"),
        "authority.primary",
        PROOF_DOMAIN,
    );
    let prepare_id = trace.event("PREPARE", &format!("{bind} proof_id={proof_id} at=1400"));
    let lease_id = id(0xb2);
    trace.signed_event(
        "LEASE",
        &format!(
            "{bind} proof_id={proof_id} lease_id={lease_id} issued_at=1400 expires_at=4000 max_uses=1"
        ),
        "lease.issuer",
        LEASE_DOMAIN,
    );
    let redemption_id = trace.event(
        "REDEEM",
        &format!(
            "{bind} proof_id={proof_id} lease_id={lease_id} use=1 point_of_use={} at=1500",
            id(0xa5)
        ),
    );
    let commit_id = trace.event(
        "COMMIT",
        &format!(
            "{bind} proof_id={proof_id} lease_id={lease_id} prepare={prepare_id} redemption={redemption_id} at=1500"
        ),
    );
    let receipt_id = id(0xb3);
    trace.signed_event(
        "RECEIPT",
        &format!("{bind} receipt_id={receipt_id} subject={commit_id} outcome=APPLIED at=1501"),
        "receipt.authority",
        RECEIPT_DOMAIN,
    );
    trace.signed_event(
        "WATCHDOG",
        &format!("{bind} receipt_id={receipt_id} mode=COMMIT checked_at=1502 status=PASS"),
        "watchdog.primary",
        WATCHDOG_DOMAIN,
    );
    trace.finish()
}

fn valid_block() -> String {
    let bind = bindings();
    let mut trace = TraceBuilder::new();
    trace.event(
        "REQUEST",
        &format!(
            "{bind} issued_at=1000 expires_at=20000 requested_max_uses=5 requested_max_lease_ms=25000"
        ),
    );
    trace.event("STATE", &format!("{bind} observed_at=1100"));
    trace.event("CONVERGENCE", &format!("{bind} observed_at=1200"));
    let envelope_id = trace.event(
        "ENVELOPE",
        &format!(
            "{bind} decision=BLOCK not_before=1200 expires_at=10000 max_uses=0 max_lease_ms=0"
        ),
    );
    let receipt_id = id(0xb3);
    trace.signed_event(
        "RECEIPT",
        &format!("{bind} receipt_id={receipt_id} subject={envelope_id} outcome=BLOCKED at=1300"),
        "receipt.authority",
        RECEIPT_DOMAIN,
    );
    trace.signed_event(
        "WATCHDOG",
        &format!("{bind} receipt_id={receipt_id} mode=BLOCK checked_at=1301 status=PASS"),
        "watchdog.primary",
        WATCHDOG_DOMAIN,
    );
    trace.finish()
}

fn replace_once(source: &str, from: &str, to: &str) -> String {
    assert_eq!(
        source.matches(from).count(),
        1,
        "mutation must be unambiguous"
    );
    source.replacen(from, to, 1)
}

fn replace_first(source: &str, from: &str, to: &str) -> String {
    assert!(source.contains(from), "mutation target must exist");
    source.replacen(from, to, 1)
}

fn resign_and_rechain(input: &str) -> String {
    let mut builder = TraceBuilder::new();
    for original in input.lines().skip(1) {
        if original.starts_with("END ") {
            break;
        }
        let mut parts = original.split(' ');
        let tag = parts.next().unwrap();
        let fields: Vec<&str> = parts.collect();
        let rest = fields[3..].join(" ");
        let signed = matches!(tag, "PROOF" | "LEASE" | "RECEIPT" | "WATCHDOG");
        if signed {
            let without_signature = rest
                .rsplit_once(" signature=")
                .map(|(prefix, _)| prefix)
                .unwrap();
            let (without_signer, signer) = without_signature.rsplit_once(" signer=").unwrap();
            let domain = match tag {
                "PROOF" => PROOF_DOMAIN,
                "LEASE" => LEASE_DOMAIN,
                "RECEIPT" => RECEIPT_DOMAIN,
                "WATCHDOG" => WATCHDOG_DOMAIN,
                _ => unreachable!(),
            };
            builder.signed_event(tag, without_signer, signer, domain);
        } else {
            builder.event(tag, &rest);
        }
    }
    builder.finish()
}

#[test]
fn accepts_valid_allow_and_block_traces() {
    let allow = verify(&valid_allow(), Some(&NonProductionFixtureProvider)).unwrap();
    assert_eq!(allow.decision, Decision::Allow);
    assert!(allow.committed);
    assert_eq!(allow.event_count, 11);

    let block = verify(&valid_block(), Some(&NonProductionFixtureProvider)).unwrap();
    assert_eq!(block.decision, Decision::Block);
    assert!(!block.committed);
    assert_eq!(block.event_count, 6);
}

#[test]
fn absent_provider_fails_closed() {
    assert_eq!(
        verify(&valid_allow(), None).unwrap_err().kind,
        ErrorKind::ProviderRequired
    );
}

#[test]
fn rejects_tampering_without_rechain() {
    let changed = replace_once(&valid_allow(), "at=1501", "at=1502");
    assert!(verify(&changed, Some(&NonProductionFixtureProvider)).is_err());
}

#[test]
fn provider_failure_fails_closed() {
    assert_eq!(
        verify(&valid_allow(), Some(&SignatureProviderFailure))
            .unwrap_err()
            .kind,
        ErrorKind::ProviderFailure
    );
}

#[test]
fn rejects_duplicate_event_id_before_following_the_chain() {
    let changed = replace_once(
        &valid_allow(),
        &format!("STATE event_id={}", id(0x02)),
        &format!("STATE event_id={}", id(0x01)),
    );
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::DuplicateEventId
    );
}

#[test]
fn rejects_sequence_gap() {
    let changed = valid_allow().replacen(" seq=2 prev=", " seq=3 prev=", 1);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::NonMonotonicSequence
    );
}

#[test]
fn rejects_duplicate_sequence_and_broken_chain_link() {
    let duplicate = valid_allow().replacen(" seq=2 prev=", " seq=1 prev=", 1);
    assert_eq!(
        verify(&duplicate, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::DuplicateSequence
    );

    let original = valid_allow();
    let state = original.find("STATE event_id=").unwrap();
    let previous = state + original[state..].find(" prev=").unwrap() + " prev=".len();
    let mut broken = original.into_bytes();
    broken[previous] = if broken[previous] == b'0' { b'1' } else { b'0' };
    let broken = String::from_utf8(broken).unwrap();
    assert_eq!(
        verify(&broken, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::BrokenHashChain
    );
}

#[test]
fn rejects_missing_prepare_and_action_after_block() {
    let no_prepare = replace_once(&valid_allow(), "PREPARE event_id=", "SKIP event_id=");
    assert_eq!(
        verify(&no_prepare, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::UnexpectedRecord
    );

    let action_after_block = replace_once(&valid_block(), "RECEIPT event_id=", "COMMIT event_id=");
    assert_eq!(
        verify(&action_after_block, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::UnexpectedRecord
    );
}

#[test]
fn rejects_multi_use_proof_even_when_resigned_and_rechained() {
    let changed = replace_once(
        &valid_allow(),
        "expires_at=9000 max_uses=1 signer=authority.primary",
        "expires_at=9000 max_uses=2 signer=authority.primary",
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidUseCount
    );
}

#[test]
fn rejects_effect_binding_change_even_when_resigned_and_rechained() {
    let changed = replace_first(
        &valid_allow(),
        &format!("effect={}", id(0xa4)),
        &format!("effect={}", id(0xcc)),
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::BindingMismatch
    );
}

#[test]
fn rejects_extension_admission_binding_change_even_when_resigned_and_rechained() {
    let changed = replace_first(
        &valid_allow(),
        &format!("extension_admission_binding_digest={}", id(0xa6)),
        &format!("extension_admission_binding_digest={}", id(0xcc)),
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::BindingMismatch
    );
}

#[test]
fn rejects_legacy_evidence_v1_header() {
    let changed = replace_once(
        &valid_allow(),
        "SBP-LEX-INDEPENDENT-EVIDENCE-V2",
        "SBP-LEX-INDEPENDENT-EVIDENCE-V1",
    );
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::UnexpectedRecord
    );
}

#[test]
fn rejects_broadened_envelope_even_when_resigned_and_rechained() {
    let changed = replace_once(
        &valid_allow(),
        "max_uses=1 max_lease_ms=5000",
        "max_uses=2 max_lease_ms=5000",
    );
    let changed = resign_and_rechain(&changed);
    assert!(matches!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidUseCount | ErrorKind::EnvelopeBroadened
    ));
}

#[test]
fn rejects_expired_proof_at_redemption() {
    let changed = replace_once(&valid_allow(), "at=1500\nCOMMIT", "at=9000\nCOMMIT");
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidLifetime
    );
}

#[test]
fn rejects_blocked_receipt_at_exact_envelope_deadline() {
    let changed = replace_once(
        &valid_block(),
        "outcome=BLOCKED at=1300",
        "outcome=BLOCKED at=10000",
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidOrdering
    );
}

#[test]
fn rejects_applied_receipt_at_exact_lease_deadline() {
    let changed = replace_once(
        &valid_allow(),
        "outcome=APPLIED at=1501",
        "outcome=APPLIED at=4000",
    );
    let changed = replace_once(&changed, "checked_at=1502", "checked_at=4001");
    let changed = resign_and_rechain(&changed);
    let error = verify(&changed, Some(&NonProductionFixtureProvider)).unwrap_err();
    assert_eq!(error.kind, ErrorKind::InvalidLifetime);
}

#[test]
fn rejects_wrong_point_of_use() {
    let changed = replace_once(
        &valid_allow(),
        &format!("point_of_use={}", id(0xa5)),
        &format!("point_of_use={}", id(0xdd)),
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidPointOfUse
    );
}

#[test]
fn rejects_long_lease() {
    let changed = replace_once(
        &valid_allow(),
        "issued_at=1400 expires_at=4000 max_uses=1",
        "issued_at=1400 expires_at=8000 max_uses=1",
    );
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidLifetime
    );
}

#[test]
fn rejects_watchdog_failure_even_when_validly_signed() {
    let changed = replace_once(&valid_allow(), "status=PASS", "status=FAIL");
    let changed = resign_and_rechain(&changed);
    assert_eq!(
        verify(&changed, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::WatchdogRejected
    );
}

#[test]
fn rejects_bad_signature() {
    let original = valid_allow();
    let position = original.find(" signature=").unwrap() + " signature=".len();
    let mut changed = original.into_bytes();
    changed[position] = if changed[position] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let changed = String::from_utf8(changed).unwrap();
    assert!(verify(&changed, Some(&NonProductionFixtureProvider)).is_err());
}

#[test]
fn rejects_unknown_field_and_uppercase_hex() {
    let extra = replace_once(
        &valid_allow(),
        " issued_at=1000",
        " surprise=x issued_at=1000",
    );
    assert_eq!(
        verify(&extra, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::MissingOrExtraField
    );

    let upper = replace_first(&valid_allow(), &id(0xa1), &id(0xa1).to_uppercase());
    assert_eq!(
        verify(&upper, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::InvalidHex
    );
}

#[test]
fn rejects_noncanonical_transport() {
    let crlf = valid_allow().replace('\n', "\r\n");
    assert_eq!(
        verify(&crlf, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::NonCanonicalTransport
    );
    let no_final_lf = valid_allow().trim_end_matches('\n').to_owned();
    assert_eq!(
        verify(&no_final_lf, Some(&NonProductionFixtureProvider))
            .unwrap_err()
            .kind,
        ErrorKind::NonCanonicalTransport
    );
}
