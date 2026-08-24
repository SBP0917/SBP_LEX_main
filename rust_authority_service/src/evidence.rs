//! Explicitly nonproduction fixtures.
//!
//! This module is absent from ordinary builds.  It exists to exercise the Rust
//! typestate and restart/replay semantics in an evidence build; it supplies no
//! cryptographic, custody, rollback-anchor, independent-inhibit, or external
//! watchdog assurance.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use sbp_lex_v2_hybrid_signature::{SoftwareHybridSigningKey, SUITE_ID};

use trusted_authority_core::{
    ExternalFailure, ExternalSignatureProvider, FailClosedWatchdog, InhibitDecision, InhibitPermit,
    InhibitRequest, InterlockDecision, InterlockRequest, KeyCustodyProvider, KeyCustodyStatus,
    KeyId, ProviderSignature, ReplayClaim, ReplayKey, ReplayProtector, SafetyEnvelopeInterlock,
    SafetyInhibit, SafetyPermit, SignaturePurpose, Time, Ttl, WatchdogArm, WatchdogHealth,
    WatchdogTripReason,
};

use crate::profile::ORACLE_SHA512;
use crate::replay_journal::{
    ReplayJournalError, COMPILED_EVIDENCE_KNOWN_FOLDER, EVIDENCE_REPLAY_IDENTITY,
};
use crate::sha512::digest;

const MARKER_NAME: &str = "EVIDENCE_ONLY_REPLAY_STORE.marker";
const MARKER_CONTENT: &[u8] =
    b"SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY_REPLAY_V1\nNONPRODUCTION_EVIDENCE_ONLY\n";
const BUILD_DESCRIPTOR_NAME: &str = "SBP_LEX_EVIDENCE_BUILD_IDENTITY.txt";
const TERMINAL_AUDIT_MARKER_NAME: &str = "EVIDENCE_ONLY_TERMINAL_AUDIT.marker";
const TERMINAL_AUDIT_MARKER_CONTENT: &[u8] =
    b"SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY_TERMINAL_AUDIT_V1\nNONPRODUCTION_EVIDENCE_ONLY\n";

/// A create-once evidence replay store.
///
/// The service path is captured at compile time and cannot be supplied through
/// a request, CLI argument, or runtime environment variable.  A claim file is
/// created atomically at its final name; a crash can conservatively leave an
/// incomplete file, which still means "consumed" after restart.
pub struct EvidenceReplayJournal {
    root: PathBuf,
}

impl EvidenceReplayJournal {
    pub fn open_compiled() -> Result<Self, ReplayJournalError> {
        let configured =
            COMPILED_EVIDENCE_KNOWN_FOLDER.ok_or(ReplayJournalError::CompileTimeRootMissing)?;
        let known_folder = Path::new(configured);
        if !known_folder.is_absolute() {
            return Err(ReplayJournalError::CompileTimeRootNotAbsolute);
        }
        let descriptor = known_folder.join(BUILD_DESCRIPTOR_NAME);
        let expected_descriptor = format!(
            "SBP_LEX_EVIDENCE_BUILD_IDENTITY_V1\nidentity={EVIDENCE_REPLAY_IDENTITY}\noracle_sha512={ORACLE_SHA512}\n"
        );
        let actual_descriptor =
            fs::read_to_string(descriptor).map_err(|error| match error.kind() {
                ErrorKind::NotFound => ReplayJournalError::BuildDescriptorMissing,
                _ => ReplayJournalError::Io(error),
            })?;
        if actual_descriptor != expected_descriptor {
            return Err(ReplayJournalError::BuildDescriptorMismatch);
        }
        Self::open_at(&known_folder.join(EVIDENCE_REPLAY_IDENTITY))
    }

    pub(crate) fn open_at(root: &Path) -> Result<Self, ReplayJournalError> {
        fs::create_dir_all(root)?;
        let marker_path = root.join(MARKER_NAME);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
        {
            Ok(mut marker) => {
                marker.write_all(MARKER_CONTENT)?;
                marker.sync_all()?;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let mut marker = Vec::new();
                File::open(&marker_path)?.read_to_end(&mut marker)?;
                if marker != MARKER_CONTENT {
                    return Err(ReplayJournalError::MarkerMismatch);
                }
            }
            Err(error) => return Err(ReplayJournalError::Io(error)),
        }
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }

    /// Stable evidence-only provider identity used by the private session to
    /// reject replay-store path substitution.  This is not a production trust
    /// anchor: it binds the fixed local fixture path and marker only.
    pub(crate) fn provider_identity(&self) -> trusted_authority_core::Digest {
        let mut input = b"SBP-LEX-RUST-AUTHORITY/2\0EVIDENCE-REPLAY-PROVIDER\0".to_vec();
        input.extend_from_slice(self.root.to_string_lossy().as_bytes());
        input.push(0);
        input.extend_from_slice(EVIDENCE_REPLAY_IDENTITY.as_bytes());
        input.push(0);
        input.extend_from_slice(MARKER_CONTENT);
        trusted_authority_core::Digest::new(digest(&input))
    }

    fn claim_path(&self, key: ReplayKey) -> PathBuf {
        let (class, epoch, identifier) = match key {
            ReplayKey::TraversalIntent {
                epoch,
                durable_consumption_digest,
            } => (
                "traversal-intent",
                epoch,
                durable_consumption_digest.as_bytes().to_vec(),
            ),
            ReplayKey::Prepare { epoch, id } => ("prepare", epoch, id.as_bytes().to_vec()),
            ReplayKey::Capability { epoch, id } => ("capability", epoch, id.as_bytes().to_vec()),
            ReplayKey::LeaseEffect { epoch, id } => ("lease-effect", epoch, id.as_bytes().to_vec()),
            ReplayKey::LeaseReceipt { epoch, id } => {
                ("lease-receipt", epoch, id.as_bytes().to_vec())
            }
        };
        let mut identifier_hex = String::with_capacity(identifier.len() * 2);
        for byte in identifier {
            use std::fmt::Write as _;
            write!(&mut identifier_hex, "{byte:02x}").expect("writing to String cannot fail");
        }
        self.root.join(format!(
            "claim-{class}-{epoch:016x}-{identifier_hex}.record"
        ))
    }
}

impl ReplayProtector for EvidenceReplayJournal {
    fn claim_once(
        &mut self,
        key: ReplayKey,
        retain_until: Time,
    ) -> Result<ReplayClaim, ExternalFailure> {
        let path = self.claim_path(key);
        let mut claim = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                return Ok(ReplayClaim::AlreadyClaimed)
            }
            Err(_) => return Err(ExternalFailure::new(11_001)),
        };
        let record = format!(
            "SBP_LEX_EVIDENCE_REPLAY_CLAIM_V1\nclass={}\nretain_until={}\n",
            key.class() as u8,
            retain_until.as_millis_since_epoch()
        );
        if claim.write_all(record.as_bytes()).is_err() || claim.sync_all().is_err() {
            // The final-name file remains.  Treating the uncertain claim as spent
            // is the safe outcome on this and every later process invocation.
            return Err(ExternalFailure::new(11_002));
        }
        #[cfg(unix)]
        if File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .is_err()
        {
            return Err(ExternalFailure::new(11_003));
        }
        Ok(ReplayClaim::Claimed)
    }
}

/// Local durability fixture for terminal-tail ordering tests.
///
/// This is intentionally not a production audit service: it has no external
/// custody, privileged rollback anchor, or transactional coupling to a
/// physical watchdog.  A pending record means IN_DOUBT until a separate
/// acknowledgement marker is durably created.
#[allow(dead_code)]
pub(crate) struct EvidenceTerminalAuditSink {
    root: PathBuf,
}

#[allow(dead_code)]
impl EvidenceTerminalAuditSink {
    pub(crate) fn open_at(root: &Path) -> Result<Self, ReplayJournalError> {
        fs::create_dir_all(root)?;
        let marker_path = root.join(TERMINAL_AUDIT_MARKER_NAME);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker_path)
        {
            Ok(mut marker) => {
                marker.write_all(TERMINAL_AUDIT_MARKER_CONTENT)?;
                marker.sync_all()?;
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let mut marker = Vec::new();
                File::open(&marker_path)?.read_to_end(&mut marker)?;
                if marker != TERMINAL_AUDIT_MARKER_CONTENT {
                    return Err(ReplayJournalError::MarkerMismatch);
                }
            }
            Err(error) => return Err(ReplayJournalError::Io(error)),
        }
        Ok(Self {
            root: fs::canonicalize(root)?,
        })
    }

    pub(crate) fn provider_identity(&self) -> trusted_authority_core::Digest {
        let mut input = b"SBP-LEX-RUST-AUTHORITY/2\0EVIDENCE-TERMINAL-AUDIT\0".to_vec();
        input.extend_from_slice(self.root.to_string_lossy().as_bytes());
        input.push(0);
        input.extend_from_slice(TERMINAL_AUDIT_MARKER_CONTENT);
        trusted_authority_core::Digest::new(digest(&input))
    }

    fn pending_path(&self, durable_key_hex: &str) -> PathBuf {
        self.root
            .join(format!("terminal-{durable_key_hex}.pending"))
    }

    fn acknowledged_path(&self, durable_key_hex: &str) -> PathBuf {
        self.root
            .join(format!("terminal-{durable_key_hex}.acknowledged"))
    }

    pub(crate) fn append_pending(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
        disposition: &str,
        transcript: &[u8],
    ) -> Result<(), ExternalFailure> {
        let mut record = format!(
            "SBP_LEX_EVIDENCE_TERMINAL_AUDIT_V1\nstatus=PENDING_IN_DOUBT\ndisposition={disposition}\ndurable_key={durable_key_hex}\nterminal_digest={terminal_digest_hex}\nlength={}\n\n",
            transcript.len()
        )
        .into_bytes();
        record.extend_from_slice(transcript);
        let path = self.pending_path(durable_key_hex);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if file.write_all(&record).is_err() || file.sync_all().is_err() {
                    return Err(ExternalFailure::new(11_401));
                }
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let actual = fs::read(&path).map_err(|_| ExternalFailure::new(11_402))?;
                if actual != record {
                    return Err(ExternalFailure::new(11_403));
                }
            }
            Err(_) => return Err(ExternalFailure::new(11_404)),
        }
        Ok(())
    }

    pub(crate) fn finalize_acknowledged(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
    ) -> Result<(), ExternalFailure> {
        if !self.pending_path(durable_key_hex).is_file() {
            return Err(ExternalFailure::new(11_405));
        }
        let record = format!(
            "SBP_LEX_EVIDENCE_TERMINAL_ACK_V1\nstatus=ACKNOWLEDGED\ndurable_key={durable_key_hex}\nterminal_digest={terminal_digest_hex}\n"
        );
        let path = self.acknowledged_path(durable_key_hex);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                if file.write_all(record.as_bytes()).is_err() || file.sync_all().is_err() {
                    return Err(ExternalFailure::new(11_406));
                }
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let actual = fs::read_to_string(&path).map_err(|_| ExternalFailure::new(11_407))?;
                if actual != record {
                    return Err(ExternalFailure::new(11_408));
                }
            }
            Err(_) => return Err(ExternalFailure::new(11_409)),
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn pending_record(&self, durable_key_hex: &str) -> Option<Vec<u8>> {
        fs::read(self.pending_path(durable_key_hex)).ok()
    }

    #[cfg(test)]
    pub(crate) fn is_acknowledged(&self, durable_key_hex: &str) -> bool {
        self.acknowledged_path(durable_key_hex).is_file()
    }
}

const EVIDENCE_SIGNATURE_CONTEXT: &[u8] = b"trusted-authority-core/evidence-only/2";

/// Standards-conformant hybrid cryptography under explicitly nonproduction
/// in-process software custody. This exercises the exact provider boundary but
/// cannot satisfy production custody or attestation requirements.
#[derive(Default)]
pub struct EvidenceSignatureProvider;

impl EvidenceSignatureProvider {
    fn signer(key: KeyId) -> Result<SoftwareHybridSigningKey, ExternalFailure> {
        // Legacy wire-v2 registries supply a single compatibility handle rather
        // than the two raw hybrid lane keys. The evidence profile therefore
        // derives a deterministic software-only key pair from that handle. It
        // remains non-effect compatibility material and can never satisfy the
        // production custody check. The versioned hybrid wire schema carries
        // and validates the real per-lane SHA-512 key IDs separately.
        let mut ml_seed = [0u8; 32];
        ml_seed.copy_from_slice(&key.as_bytes()[..32]);
        let mut ed_seed = [0u8; 57];
        for (index, byte) in ed_seed.iter_mut().enumerate() {
            *byte = key.as_bytes()[index] ^ 0xa5;
        }
        SoftwareHybridSigningKey::from_seed_slices(&ml_seed, &ed_seed)
            .map_err(|_| ExternalFailure::new(11_102))
    }

    fn purpose(purpose: SignaturePurpose) -> &'static str {
        match purpose {
            SignaturePurpose::NonAuthorizingPrepare => "NON_AUTHORIZING_PREPARE",
            SignaturePurpose::CapabilityCommit => "CAPABILITY_COMMIT",
            SignaturePurpose::EffectLease => "EFFECT_LEASE",
            SignaturePurpose::AdapterReceipt => "ADAPTER_RECEIPT",
        }
    }

    fn epoch(message: &[u8]) -> Option<u64> {
        const PREFIX: &[u8] = b"trusted-authority-core";
        let offset = PREFIX.len() + 2 + 2 + SUITE_ID.len() + 1 + 64;
        let bytes: [u8; 8] = message.get(offset..offset + 8)?.try_into().ok()?;
        Some(u64::from_be_bytes(bytes))
    }
}

impl ExternalSignatureProvider for EvidenceSignatureProvider {
    fn sign(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
    ) -> Result<ProviderSignature, ExternalFailure> {
        let signer = Self::signer(key_id)?;
        let epoch = Self::epoch(canonical_message).ok_or_else(|| ExternalFailure::new(11_103))?;
        let signature = signer
            .sign(
                Self::purpose(purpose),
                epoch,
                EVIDENCE_SIGNATURE_CONTEXT,
                canonical_message,
            )
            .map_err(|_| ExternalFailure::new(11_104))?;
        ProviderSignature::new(key_id, signature.to_combined())
            .map_err(|_| ExternalFailure::new(11_101))
    }

    fn verify(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
        signature: &ProviderSignature,
    ) -> Result<bool, ExternalFailure> {
        if signature.key_id() != key_id {
            return Ok(false);
        }
        let signer = Self::signer(key_id)?;
        let epoch = Self::epoch(canonical_message).ok_or_else(|| ExternalFailure::new(11_106))?;
        let parsed =
            sbp_lex_v2_hybrid_signature::HybridSignature::from_combined(signature.as_bytes())
                .map_err(|_| ExternalFailure::new(11_107))?;
        Ok(signer
            .public_key()
            .verify(
                Self::purpose(purpose),
                epoch,
                EVIDENCE_SIGNATURE_CONTEXT,
                canonical_message,
                &parsed,
            )
            .is_ok())
    }
}

impl KeyCustodyProvider for EvidenceSignatureProvider {
    fn key_custody_status(
        &mut self,
        _key_id: KeyId,
        _purpose: SignaturePurpose,
        _now: Time,
    ) -> Result<KeyCustodyStatus, ExternalFailure> {
        Ok(KeyCustodyStatus::NonproductionFixture)
    }
}

#[derive(Default)]
pub struct EvidenceInterlock;

impl SafetyEnvelopeInterlock for EvidenceInterlock {
    fn evaluate(
        &mut self,
        request: InterlockRequest,
    ) -> Result<InterlockDecision, ExternalFailure> {
        Ok(InterlockDecision::Permit(SafetyPermit::new(
            request.binding().safety_envelope_digest(),
            request.requested_valid_until(),
            Ttl::from_millis(60_000).map_err(|_| ExternalFailure::new(11_201))?,
        )))
    }
}

#[derive(Default)]
pub struct EvidenceInhibit;

impl SafetyInhibit for EvidenceInhibit {
    fn check(&mut self, request: InhibitRequest) -> Result<InhibitDecision, ExternalFailure> {
        Ok(InhibitDecision::Permit(InhibitPermit::new(
            request.binding(),
            request.phase(),
            request.now(),
            Time::from_millis_since_epoch(
                request.now().as_millis_since_epoch().saturating_add(60_000),
            ),
        )))
    }
}

#[derive(Default)]
struct EvidenceWatchdogState {
    arm: Option<WatchdogArm>,
    tripped: bool,
    fail_tighten: bool,
    fail_acknowledge: bool,
}

/// Cloneable evidence-only handle to one shared watchdog fixture.
///
/// The private authority engine owns one handle for the complete lifecycle;
/// tests retain only an observer/fault-injection handle to the same state.  A
/// clone is not a second watchdog identity or namespace.
#[derive(Clone, Default)]
pub struct EvidenceWatchdog {
    state: Arc<Mutex<EvidenceWatchdogState>>,
}

#[cfg(test)]
impl EvidenceWatchdog {
    pub(crate) fn fail_next_tighten(&self) {
        self.state
            .lock()
            .expect("evidence watchdog state")
            .fail_tighten = true;
    }

    pub(crate) fn fail_next_acknowledgement(&self) {
        self.state
            .lock()
            .expect("evidence watchdog state")
            .fail_acknowledge = true;
    }

    pub(crate) fn is_armed(&self) -> bool {
        self.state
            .lock()
            .expect("evidence watchdog state")
            .arm
            .is_some()
    }

    pub(crate) fn is_tripped(&self) -> bool {
        self.state.lock().expect("evidence watchdog state").tripped
    }

    pub(crate) fn armed_request(&self) -> Option<WatchdogArm> {
        self.state.lock().expect("evidence watchdog state").arm
    }

    /// Simulate the separately scheduled evidence watchdog reaching its
    /// persisted deadline without any authority-service callback.
    pub(crate) fn independent_deadline_tick(&self, now: Time) {
        let mut state = self.state.lock().expect("evidence watchdog state");
        if state.arm.is_some_and(|arm| now >= arm.receipt_deadline()) {
            state.tripped = true;
        }
    }
}

impl FailClosedWatchdog for EvidenceWatchdog {
    fn health(&mut self, _now: Time) -> Result<WatchdogHealth, ExternalFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        Ok(if state.tripped {
            WatchdogHealth::Unsafe
        } else {
            WatchdogHealth::Ready
        })
    }

    fn arm(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        if state.arm.is_some() || state.tripped {
            return Err(ExternalFailure::new(11_301));
        }
        state.arm = Some(request);
        Ok(())
    }

    fn tighten(
        &mut self,
        existing: WatchdogArm,
        tightened: WatchdogArm,
    ) -> Result<(), ExternalFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        if state.fail_tighten {
            state.fail_tighten = false;
            return Err(ExternalFailure::new(11_308));
        }
        let current = state.arm.ok_or_else(|| ExternalFailure::new(11_305))?;
        if state.tripped
            || current != existing
            || tightened.binding() != existing.binding()
            || tightened.capability_id() != existing.capability_id()
            || tightened.lease_id() != existing.lease_id()
            || tightened.lease_expires_at() != existing.lease_expires_at()
            || tightened.receipt_deadline() > existing.receipt_deadline()
        {
            return Err(ExternalFailure::new(11_306));
        }
        state.arm = Some(tightened);
        Ok(())
    }

    fn verify_armed(&mut self, request: WatchdogArm, now: Time) -> Result<bool, ExternalFailure> {
        let state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        Ok(state.arm == Some(request)
            && !state.tripped
            && now < request.lease_expires_at()
            && now < request.receipt_deadline())
    }

    fn acknowledge(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        if state.fail_acknowledge {
            state.fail_acknowledge = false;
            return Err(ExternalFailure::new(11_304));
        }
        if state.arm != Some(request) || state.tripped {
            return Err(ExternalFailure::new(11_302));
        }
        state.arm = None;
        Ok(())
    }

    fn trip(
        &mut self,
        request: WatchdogArm,
        _reason: WatchdogTripReason,
    ) -> Result<(), ExternalFailure> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ExternalFailure::new(11_307))?;
        if state.arm.is_some() && state.arm != Some(request) {
            return Err(ExternalFailure::new(11_303));
        }
        state.tripped = true;
        Ok(())
    }
}

/// Bundle used by the evidence-only service engine.  Keeping these providers in
/// separate fields allows the Rust borrow checker to enforce their distinct
/// roles at each transition.
pub struct EvidenceAuthorityDependencies {
    pub signatures: EvidenceSignatureProvider,
    pub replay: EvidenceReplayJournal,
    pub interlock: EvidenceInterlock,
    pub inhibit: EvidenceInhibit,
    pub watchdog: EvidenceWatchdog,
}

impl EvidenceAuthorityDependencies {
    pub fn open_compiled() -> Result<Self, ReplayJournalError> {
        Ok(Self {
            signatures: EvidenceSignatureProvider,
            replay: EvidenceReplayJournal::open_compiled()?,
            interlock: EvidenceInterlock,
            inhibit: EvidenceInhibit,
            watchdog: EvidenceWatchdog::default(),
        })
    }
}

pub fn evidence_authority_key() -> KeyId {
    let signer = SoftwareHybridSigningKey::from_seed_slices(&[0xe1; 32], &[0x1e; 57])
        .expect("fixed evidence authority seed sizes");
    match KeyId::new(signer.public_key().ordered_key_set_digest()) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

pub fn evidence_adapter_key() -> KeyId {
    let signer = SoftwareHybridSigningKey::from_seed_slices(&[0xe2; 32], &[0x2e; 57])
        .expect("fixed evidence adapter seed sizes");
    match KeyId::new(signer.public_key().ordered_key_set_digest()) {
        Ok(value) => value,
        Err(_) => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbp_lex_wire_contract::{encode_frame, parse_message, seal_message, Value};
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};
    use trusted_authority_core::{Binding, CapabilityId, Digest, PrepareId, ReplayClass};

    const GOLDEN: &str = include_str!("../../wire_protocol/vectors/golden_transcript.jsonl");

    fn temporary_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sbp-lex-rust-authority-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    fn prepare_key(value: u8) -> ReplayKey {
        ReplayKey::Prepare {
            epoch: 1,
            id: PrepareId::new([value; 16]).expect("non-zero id"),
        }
    }

    #[test]
    fn claim_survives_reopen_and_cannot_be_replayed() {
        let root = temporary_root("restart");
        let key = prepare_key(7);
        let mut first = EvidenceReplayJournal::open_at(&root).expect("first open");
        assert_eq!(
            first.claim_once(key, Time::MAX).expect("first claim"),
            ReplayClaim::Claimed
        );
        drop(first);
        let mut restarted = EvidenceReplayJournal::open_at(&root).expect("reopen");
        assert_eq!(
            restarted.claim_once(key, Time::MAX).expect("replay check"),
            ReplayClaim::AlreadyClaimed
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[test]
    fn concurrent_claim_is_linearized_by_create_new() {
        let root = temporary_root("race");
        let key = ReplayKey::Capability {
            epoch: 9,
            id: CapabilityId::new([8; 16]).expect("non-zero id"),
        };
        EvidenceReplayJournal::open_at(&root).expect("initialize");
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut journal = EvidenceReplayJournal::open_at(&root).expect("open");
                barrier.wait();
                journal.claim_once(key, Time::MAX).expect("claim")
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReplayClaim::Claimed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == ReplayClaim::AlreadyClaimed)
                .count(),
            1
        );
        assert_eq!(key.class(), ReplayClass::CapabilityRedemption);
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[test]
    fn runtime_environment_cannot_supply_missing_compiled_root() {
        if COMPILED_EVIDENCE_KNOWN_FOLDER.is_none() {
            std::env::set_var(
                "SBP_LEX_COMPILED_EVIDENCE_KNOWN_FOLDER",
                temporary_root("ignored"),
            );
            assert!(matches!(
                EvidenceReplayJournal::open_compiled(),
                Err(ReplayJournalError::CompileTimeRootMissing)
            ));
            std::env::remove_var("SBP_LEX_COMPILED_EVIDENCE_KNOWN_FOLDER");
        }
    }

    #[test]
    fn evidence_provider_identity_is_explicitly_fixture_only() {
        assert_ne!(evidence_authority_key(), evidence_adapter_key());
        let binding_digest = Digest::new([1; 64]);
        assert_ne!(binding_digest, Digest::new([0xE3; 64]));
        let _binding_type_check: Option<Binding> = None;
        let mut provider = EvidenceSignatureProvider;
        assert_eq!(
            provider
                .key_custody_status(
                    evidence_authority_key(),
                    SignaturePurpose::CapabilityCommit,
                    Time::from_millis_since_epoch(1),
                )
                .expect("explicit evidence custody status"),
            KeyCustodyStatus::NonproductionFixture
        );
    }

    #[test]
    fn traversal_intent_claim_uses_short_digest_filename_and_survives_restart() {
        let root = temporary_root("traversal-intent");
        let key = ReplayKey::TraversalIntent {
            epoch: 77,
            durable_consumption_digest: Digest::new([0xA5; 64]),
        };
        let mut first = EvidenceReplayJournal::open_at(&root).expect("open");
        let path = first.claim_path(key);
        assert!(path.file_name().expect("filename").to_string_lossy().len() < 255);
        assert_eq!(
            first.claim_once(key, Time::MAX).expect("first claim"),
            ReplayClaim::Claimed
        );
        drop(first);
        let mut restarted = EvidenceReplayJournal::open_at(&root).expect("restart");
        assert_eq!(
            restarted.claim_once(key, Time::MAX).expect("replay"),
            ReplayClaim::AlreadyClaimed
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[test]
    fn fresh_wire_metadata_cannot_bypass_durable_effect_intent_claim() {
        let root = temporary_root("wire-intent-replay");
        let mut original = parse_message(
            GOLDEN
                .lines()
                .next()
                .expect("golden convergence request")
                .as_bytes(),
        )
        .expect("valid golden request");
        let original_frame = encode_frame(&original).expect("original frame");
        let first_inspection = crate::inspect_convergence_frame(&original_frame, 1_900_000_000_100)
            .expect("non-authorizing inspection");
        let first_key = ReplayKey::TraversalIntent {
            epoch: 77,
            durable_consumption_digest: first_inspection.durable_consumption_digest(),
        };
        let mut journal = EvidenceReplayJournal::open_at(&root).expect("open");
        assert_eq!(
            journal
                .claim_once(first_key, Time::MAX)
                .expect("first claim"),
            ReplayClaim::Claimed
        );

        original.insert("traversal_id".into(), Value::Text("a".repeat(32)));
        original.insert("operation_id".into(), Value::Text("b".repeat(32)));
        original.insert("challenge".into(), Value::Text("c".repeat(64)));
        original.insert("nonce".into(), Value::Text("d".repeat(64)));
        let changed = seal_message(&original).expect("reseal fresh metadata");
        let changed_frame = encode_frame(&changed).expect("changed frame");
        let changed_inspection =
            crate::inspect_convergence_frame(&changed_frame, 1_900_000_000_100)
                .expect("changed inspection");
        assert_eq!(
            changed_inspection.stable_effect_intent_digest(),
            first_inspection.stable_effect_intent_digest()
        );
        let changed_key = ReplayKey::TraversalIntent {
            epoch: 77,
            durable_consumption_digest: changed_inspection.durable_consumption_digest(),
        };
        assert_eq!(
            journal
                .claim_once(changed_key, Time::MAX)
                .expect("replay check"),
            ReplayClaim::AlreadyClaimed
        );
        fs::remove_dir_all(root).expect("test cleanup");
    }

    #[test]
    fn terminal_audit_pending_survives_restart_and_is_never_implicit_ack() {
        let root = temporary_root("terminal-pending");
        let durable = "a".repeat(64);
        let terminal = "b".repeat(64);
        let transcript = b"signed-terminal-tail\n";
        let mut first = EvidenceTerminalAuditSink::open_at(&root).expect("first audit sink");
        first
            .append_pending(
                &durable,
                &terminal,
                "COMPLETED_PENDING_WATCHDOG_ACK",
                transcript,
            )
            .expect("pending append");
        assert!(first.pending_record(&durable).is_some());
        assert!(!first.is_acknowledged(&durable));
        drop(first);

        let restarted = EvidenceTerminalAuditSink::open_at(&root).expect("restart audit sink");
        let pending = restarted.pending_record(&durable).expect("durable pending");
        assert!(String::from_utf8_lossy(&pending).contains("status=PENDING_IN_DOUBT"));
        assert!(!restarted.is_acknowledged(&durable));
        fs::remove_dir_all(root).expect("cleanup");
    }
}
