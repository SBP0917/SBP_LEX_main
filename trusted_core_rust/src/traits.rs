use core::fmt;

use crate::types::{
    Binding, CapabilityId, CoreError, Digest, EffectOutcome, KeyId, LeaseId, PrepareId, Time, Ttl,
};

pub const SIGNATURE_SUITE_ID: &str = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1";
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4_627;
pub const ED448_SIGNATURE_BYTES: usize = 114;
pub const HYBRID_SIGNATURE_BYTES: usize = ML_DSA_87_SIGNATURE_BYTES + ED448_SIGNATURE_BYTES;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExternalFailure {
    code: u32,
}

impl ExternalFailure {
    pub const fn new(code: u32) -> Self {
        Self { code }
    }

    pub const fn code(self) -> u32 {
        self.code
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SignaturePurpose {
    NonAuthorizingPrepare = 1,
    CapabilityCommit = 2,
    EffectLease = 3,
    AdapterReceipt = 4,
}

/// Opaque bytes emitted by an external signing provider.
///
/// Signature bytes are not secret, but they are overwritten on drop as a
/// defense-in-depth measure against avoidable residue. This is not a substitute
/// for a dedicated zeroization crate or for keeping private keys in an HSM.
pub struct ProviderSignature {
    key_id: KeyId,
    bytes: Vec<u8>,
}

impl ProviderSignature {
    pub const EXACT_BYTES: usize = HYBRID_SIGNATURE_BYTES;

    pub fn new(key_id: KeyId, bytes: Vec<u8>) -> Result<Self, CoreError> {
        if bytes.len() != Self::EXACT_BYTES {
            return Err(CoreError::SignatureWrongLength);
        }
        Ok(Self { key_id, bytes })
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for ProviderSignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderSignature")
            .field("key_id", &self.key_id)
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ProviderSignature {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// Boundary to an HSM, TPM, remote signer, or audited cryptographic provider.
///
/// The core never receives private key material. Implementations must enforce
/// key purpose, algorithm, policy, and audit requirements outside this crate.
pub trait ExternalSignatureProvider {
    fn sign(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
    ) -> Result<ProviderSignature, ExternalFailure>;

    fn verify(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
        signature: &ProviderSignature,
    ) -> Result<bool, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CustodyTechnology {
    Hsm,
    Tpm,
}

/// A provider-reported identity for a production key whose private material is
/// non-exportable and held by an HSM or TPM.
///
/// This is a status contract, not physical evidence. The production provider and
/// its attestation verification remain independently reviewable trust anchors.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NonExportableProductionKeyIdentity {
    key_id: KeyId,
    technology: CustodyTechnology,
    provider_identity: crate::types::Digest,
    observed_at: Time,
    fresh_until: Time,
}

impl NonExportableProductionKeyIdentity {
    pub const fn new(
        key_id: KeyId,
        technology: CustodyTechnology,
        provider_identity: crate::types::Digest,
        observed_at: Time,
        fresh_until: Time,
    ) -> Self {
        Self {
            key_id,
            technology,
            provider_identity,
            observed_at,
            fresh_until,
        }
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub const fn technology(&self) -> CustodyTechnology {
        self.technology
    }

    pub const fn provider_identity(&self) -> crate::types::Digest {
        self.provider_identity
    }

    pub const fn observed_at(&self) -> Time {
        self.observed_at
    }

    pub const fn fresh_until(&self) -> Time {
        self.fresh_until
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeyCustodyStatus {
    ProductionNonExportable(NonExportableProductionKeyIdentity),
    /// A compiled test fixture may exercise call ordering but can never satisfy
    /// production custody checks.
    NonproductionFixture,
    NonProduction,
    Unavailable,
}

/// Production key-custody status supplied by the same provider instance that
/// performs signing or verification.
///
/// Authorizing paths require `ExternalSignatureProvider + KeyCustodyProvider` on
/// one value. Implementations must validate hardware/provider attestation and
/// key-purpose policy before returning `ProductionNonExportable`.
pub trait KeyCustodyProvider {
    fn key_custody_status(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        now: Time,
    ) -> Result<KeyCustodyStatus, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum ReplayClass {
    PrepareCommit = 1,
    CapabilityRedemption = 2,
    LeaseEffect = 3,
    LeaseReceipt = 4,
    /// The exact converged execution intent may enter PREPARE only once per
    /// authority epoch, regardless of fresh artifact identifiers.
    TraversalIntent = 5,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ReplayKey {
    TraversalIntent {
        epoch: u64,
        /// Exact wire-v2 `durable_consumption_digest`, independently
        /// recomputed from the owner-admitted replay namespace and stable
        /// effect-intent digest. It excludes traversal IDs, challenges,
        /// nonces, time and artifact IDs so refreshing transport values cannot
        /// bypass consumption.
        durable_consumption_digest: crate::types::Digest,
    },
    Prepare {
        epoch: u64,
        id: PrepareId,
    },
    Capability {
        epoch: u64,
        id: CapabilityId,
    },
    LeaseEffect {
        epoch: u64,
        id: LeaseId,
    },
    LeaseReceipt {
        epoch: u64,
        id: LeaseId,
    },
}

impl ReplayKey {
    pub const fn class(self) -> ReplayClass {
        match self {
            Self::TraversalIntent { .. } => ReplayClass::TraversalIntent,
            Self::Prepare { .. } => ReplayClass::PrepareCommit,
            Self::Capability { .. } => ReplayClass::CapabilityRedemption,
            Self::LeaseEffect { .. } => ReplayClass::LeaseEffect,
            Self::LeaseReceipt { .. } => ReplayClass::LeaseReceipt,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReplayClaim {
    Claimed,
    AlreadyClaimed,
}

/// Durable, atomic claim-once storage.
///
/// Production implementations must make `claim_once` linearizable across all
/// authority replicas and durable across crashes. `retain_until == Time::MAX`
/// means the claim is permanent for the authority epoch.
pub trait ReplayProtector {
    fn claim_once(
        &mut self,
        key: ReplayKey,
        retain_until: Time,
    ) -> Result<ReplayClaim, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InterlockPhase {
    Commit,
    PointOfUse,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InterlockRequest {
    binding: Binding,
    phase: InterlockPhase,
    now: Time,
    requested_valid_until: Time,
}

impl InterlockRequest {
    pub const fn new(
        binding: Binding,
        phase: InterlockPhase,
        now: Time,
        requested_valid_until: Time,
    ) -> Self {
        Self {
            binding,
            phase,
            now,
            requested_valid_until,
        }
    }

    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn phase(&self) -> InterlockPhase {
        self.phase
    }

    pub const fn now(&self) -> Time {
        self.now
    }

    pub const fn requested_valid_until(&self) -> Time {
        self.requested_valid_until
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct SafetyPermit {
    envelope_digest: Digest,
    valid_until: Time,
    maximum_lease_ttl: Ttl,
}

impl SafetyPermit {
    pub const fn new(envelope_digest: Digest, valid_until: Time, maximum_lease_ttl: Ttl) -> Self {
        Self {
            envelope_digest,
            valid_until,
            maximum_lease_ttl,
        }
    }

    pub const fn envelope_digest(&self) -> Digest {
        self.envelope_digest
    }

    pub const fn valid_until(&self) -> Time {
        self.valid_until
    }

    pub const fn maximum_lease_ttl(&self) -> Ttl {
        self.maximum_lease_ttl
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InterlockDecision {
    Permit(SafetyPermit),
    Deny,
}

/// Independently administered safety-envelope decision point.
pub trait SafetyEnvelopeInterlock {
    fn evaluate(&mut self, request: InterlockRequest)
        -> Result<InterlockDecision, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InhibitPhase {
    Commit,
    LeaseRedemption,
    Effect,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InhibitRequest {
    binding: Binding,
    phase: InhibitPhase,
    now: Time,
}

impl InhibitRequest {
    pub const fn new(binding: Binding, phase: InhibitPhase, now: Time) -> Self {
        Self {
            binding,
            phase,
            now,
        }
    }

    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn phase(&self) -> InhibitPhase {
        self.phase
    }

    pub const fn now(&self) -> Time {
        self.now
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InhibitPermit {
    binding: Binding,
    phase: InhibitPhase,
    observed_at: Time,
    fresh_until: Time,
}

impl InhibitPermit {
    pub const fn new(
        binding: Binding,
        phase: InhibitPhase,
        observed_at: Time,
        fresh_until: Time,
    ) -> Self {
        Self {
            binding,
            phase,
            observed_at,
            fresh_until,
        }
    }

    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn phase(&self) -> InhibitPhase {
        self.phase
    }

    pub const fn observed_at(&self) -> Time {
        self.observed_at
    }

    pub const fn fresh_until(&self) -> Time {
        self.fresh_until
    }
}

/// Separately controlled, out-of-band safety inhibit.
///
/// It can only permit the already-bound request, block it, or demand a stop. It
/// returns no capability, broader binding, or longer lifetime. Every authorizing
/// phase requires this trait; there is no bypass/default implementation in core.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
// This fixed-size decision remains Copy and allocation-free across the
// separately controlled inhibit boundary; Block and Stop intentionally carry
// no authority-bearing material.
#[allow(clippy::large_enum_variant)]
pub enum InhibitDecision {
    Permit(InhibitPermit),
    Block,
    Stop,
}

pub trait SafetyInhibit {
    fn check(&mut self, request: InhibitRequest) -> Result<InhibitDecision, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct WatchdogArm {
    binding: Binding,
    capability_id: CapabilityId,
    lease_id: LeaseId,
    lease_expires_at: Time,
    receipt_deadline: Time,
}

impl WatchdogArm {
    pub const fn new(
        binding: Binding,
        capability_id: CapabilityId,
        lease_id: LeaseId,
        lease_expires_at: Time,
        receipt_deadline: Time,
    ) -> Self {
        Self {
            binding,
            capability_id,
            lease_id,
            lease_expires_at,
            receipt_deadline,
        }
    }

    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    pub const fn lease_expires_at(&self) -> Time {
        self.lease_expires_at
    }

    pub const fn receipt_deadline(&self) -> Time {
        self.receipt_deadline
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WatchdogHealth {
    Ready,
    Unsafe,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WatchdogTripReason {
    ReceiptDeadlineElapsed,
    /// The independently authenticated wire permit's stricter point-of-use
    /// deadline elapsed before a terminal receipt.  This can only narrow the
    /// core lease/watchdog window and therefore fails closed.
    IntegratedPermitDeadlineElapsed,
    InvalidReceipt,
    ReceiptReplay,
    WatchdogBecameUnsafe,
    LeaseIssuanceFailedAfterArm,
    AcknowledgementFailed,
    PointOfUseArmMissing,
    /// The durable effect slot was consumed, but the adapter did not return a
    /// trustworthy effect outcome. The independent stop must remain asserted.
    EffectAdapterFailedAfterConsumptionClaim,
    /// The adapter reported an effect, but its completion time could not be
    /// trusted or fell outside the authorized half-open lease interval.
    EffectCompletionInvalidAfterConsumptionClaim,
    /// A receipt slot was permanently claimed, but the complete authenticated
    /// terminal audit tail could not be durably persisted.  The watchdog must
    /// remain asserted or armed; it must never be acknowledged on this path.
    TerminalAuditUnavailableAfterReceiptClaim,
}

/// External fail-closed watchdog controlling the consequential stop.
///
/// `arm` must persist the deadline before returning. Once armed, loss of the
/// authority process or failure to acknowledge must independently trigger the
/// stop. `trip` must be idempotent.
pub trait FailClosedWatchdog {
    fn health(&mut self, now: Time) -> Result<WatchdogHealth, ExternalFailure>;

    fn arm(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure>;

    /// Durably replace an existing exact arm with a strictly narrower deadline.
    /// Implementations must accept an identical `tightened` arm idempotently,
    /// reject every widening or identity/binding substitution, and return only
    /// after the new arm is persisted independently of this process.
    fn tighten(
        &mut self,
        existing: WatchdogArm,
        tightened: WatchdogArm,
    ) -> Result<(), ExternalFailure>;

    /// Revalidate the exact persisted arm immediately before point-of-use
    /// effect consumption. General health is insufficient: a different,
    /// missing, acknowledged, expired or rolled-back arm must fail closed.
    fn verify_armed(&mut self, request: WatchdogArm, now: Time) -> Result<bool, ExternalFailure>;

    fn acknowledge(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure>;

    fn trip(
        &mut self,
        request: WatchdogArm,
        reason: WatchdogTripReason,
    ) -> Result<(), ExternalFailure>;
}

/// Ephemeral, non-serializable dispatch value whose lifetime is scoped to one
/// synchronous adapter call. Safe Rust cannot retain it after that call.
pub struct EffectDispatch<'a> {
    binding: Binding,
    capability_id: CapabilityId,
    lease_id: LeaseId,
    authorized_at: Time,
    expires_at: Time,
    _scope: core::marker::PhantomData<&'a mut ()>,
}

impl<'a> EffectDispatch<'a> {
    pub(crate) const fn new(
        binding: Binding,
        capability_id: CapabilityId,
        lease_id: LeaseId,
        authorized_at: Time,
        expires_at: Time,
        _scope: &'a mut (),
    ) -> Self {
        Self {
            binding,
            capability_id,
            lease_id,
            authorized_at,
            expires_at,
            _scope: core::marker::PhantomData,
        }
    }

    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    pub const fn authorized_at(&self) -> Time {
        self.authorized_at
    }

    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }
}

/// Admitted point-of-use adapter boundary.
///
/// It supplies trusted time from inside the same boundary that consumes the
/// effect dispatch. `consume_once` must atomically apply or safely not apply the
/// exact bound effect before returning; the ephemeral dispatch cannot cross the
/// call in safe Rust.
pub trait AtomicEffectAdapter {
    fn trusted_now(&mut self) -> Result<Time, ExternalFailure>;

    fn consume_once(
        &mut self,
        dispatch: EffectDispatch<'_>,
    ) -> Result<EffectOutcome, ExternalFailure>;
}
