use crate::state::{
    claim_once, ensure_time_window, require_classed_custody, require_safety_inhibit,
    trip_or_original, verify_checked,
};
use crate::traits::{
    AtomicEffectAdapter, EffectDispatch, ExternalSignatureProvider, FailClosedWatchdog,
    InhibitPhase, KeyCustodyProvider, ProviderSignature, ReplayKey, ReplayProtector, SafetyInhibit,
    SignaturePurpose, WatchdogArm, WatchdogHealth, WatchdogTripReason, SIGNATURE_SUITE_ID,
};
use crate::types::{
    ArtifactKind, Binding, CapabilityId, CoreError, CorePolicy, EffectOutcome, KeyId, LeaseId,
    PrepareId, Time,
};

const CANONICAL_PREFIX: &[u8] = b"trusted-authority-core";
const CANONICAL_VERSION: u16 = 2;

pub(crate) struct CanonicalMessage(Vec<u8>);

impl CanonicalMessage {
    fn begin(purpose: SignaturePurpose) -> Self {
        let mut bytes = Vec::with_capacity(320);
        bytes.extend_from_slice(CANONICAL_PREFIX);
        bytes.extend_from_slice(&CANONICAL_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(SIGNATURE_SUITE_ID.len() as u16).to_be_bytes());
        bytes.extend_from_slice(SIGNATURE_SUITE_ID.as_bytes());
        bytes.push(purpose as u8);
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CanonicalMessage {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PrepareClaims {
    binding: Binding,
    prepare_id: PrepareId,
    issued_at: Time,
    expires_at: Time,
}

impl PrepareClaims {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn prepare_id(&self) -> PrepareId {
        self.prepare_id
    }

    pub const fn issued_at(&self) -> Time {
        self.issued_at
    }

    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }

    pub(crate) fn new(
        binding: Binding,
        prepare_id: PrepareId,
        issued_at: Time,
        expires_at: Time,
    ) -> Self {
        Self {
            binding,
            prepare_id,
            issued_at,
            expires_at,
        }
    }

    pub(crate) fn canonical_message(&self) -> CanonicalMessage {
        let mut message = CanonicalMessage::begin(SignaturePurpose::NonAuthorizingPrepare);
        self.binding.encode_into(&mut message.0);
        self.prepare_id.encode_into(&mut message.0);
        self.issued_at.encode_into(&mut message.0);
        self.expires_at.encode_into(&mut message.0);
        message
    }
}

#[derive(Debug)]
pub struct PrepareToken {
    claims: PrepareClaims,
    signature: ProviderSignature,
}

impl PrepareToken {
    pub const fn claims(&self) -> PrepareClaims {
        self.claims
    }

    pub const fn signature(&self) -> &ProviderSignature {
        &self.signature
    }

    pub(crate) fn new(claims: PrepareClaims, signature: ProviderSignature) -> Self {
        Self { claims, signature }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CapabilityClaims {
    binding: Binding,
    prepare_id: PrepareId,
    capability_id: CapabilityId,
    committed_at: Time,
    expires_at: Time,
}

impl CapabilityClaims {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn prepare_id(&self) -> PrepareId {
        self.prepare_id
    }

    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    pub const fn committed_at(&self) -> Time {
        self.committed_at
    }

    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }

    pub(crate) fn new(
        binding: Binding,
        prepare_id: PrepareId,
        capability_id: CapabilityId,
        committed_at: Time,
        expires_at: Time,
    ) -> Self {
        Self {
            binding,
            prepare_id,
            capability_id,
            committed_at,
            expires_at,
        }
    }

    pub(crate) fn canonical_message(&self) -> CanonicalMessage {
        let mut message = CanonicalMessage::begin(SignaturePurpose::CapabilityCommit);
        self.binding.encode_into(&mut message.0);
        self.prepare_id.encode_into(&mut message.0);
        self.capability_id.encode_into(&mut message.0);
        self.committed_at.encode_into(&mut message.0);
        self.expires_at.encode_into(&mut message.0);
        message
    }
}

#[derive(Debug)]
pub struct Capability {
    claims: CapabilityClaims,
    signature: ProviderSignature,
}

impl Capability {
    pub const fn claims(&self) -> CapabilityClaims {
        self.claims
    }

    pub const fn signature(&self) -> &ProviderSignature {
        &self.signature
    }

    pub(crate) fn new(claims: CapabilityClaims, signature: ProviderSignature) -> Self {
        Self { claims, signature }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LeaseClaims {
    binding: Binding,
    capability_id: CapabilityId,
    lease_id: LeaseId,
    issued_at: Time,
    expires_at: Time,
    receipt_deadline: Time,
}

impl LeaseClaims {
    /// Decode fixed-width untrusted claims at an adapter boundary. This does not
    /// validate or authorize them; `EffectLease::dispatch_effect_at_point_of_use`
    /// performs the authoritative checks.
    pub const fn from_untrusted_fields(
        binding: Binding,
        capability_id: CapabilityId,
        lease_id: LeaseId,
        issued_at: Time,
        expires_at: Time,
        receipt_deadline: Time,
    ) -> Self {
        Self {
            binding,
            capability_id,
            lease_id,
            issued_at,
            expires_at,
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

    pub const fn issued_at(&self) -> Time {
        self.issued_at
    }

    pub const fn expires_at(&self) -> Time {
        self.expires_at
    }

    pub const fn receipt_deadline(&self) -> Time {
        self.receipt_deadline
    }

    pub(crate) fn new(
        binding: Binding,
        capability_id: CapabilityId,
        lease_id: LeaseId,
        issued_at: Time,
        expires_at: Time,
        receipt_deadline: Time,
    ) -> Self {
        Self::from_untrusted_fields(
            binding,
            capability_id,
            lease_id,
            issued_at,
            expires_at,
            receipt_deadline,
        )
    }

    pub(crate) fn canonical_message(&self) -> CanonicalMessage {
        let mut message = CanonicalMessage::begin(SignaturePurpose::EffectLease);
        self.binding.encode_into(&mut message.0);
        self.capability_id.encode_into(&mut message.0);
        self.lease_id.encode_into(&mut message.0);
        self.issued_at.encode_into(&mut message.0);
        self.expires_at.encode_into(&mut message.0);
        self.receipt_deadline.encode_into(&mut message.0);
        message
    }
}

#[derive(Debug)]
pub struct EffectLease {
    claims: LeaseClaims,
    signature: ProviderSignature,
}

impl EffectLease {
    pub const fn claims(&self) -> LeaseClaims {
        self.claims
    }

    pub const fn signature(&self) -> &ProviderSignature {
        &self.signature
    }

    pub(crate) fn new(claims: LeaseClaims, signature: ProviderSignature) -> Self {
        Self { claims, signature }
    }

    /// Reconstruct an untrusted lease at the effect-adapter boundary.
    ///
    /// The adapter must call `dispatch_effect_at_point_of_use`; construction by
    /// itself conveys no authority.
    pub fn from_untrusted_parts(claims: LeaseClaims, signature: ProviderSignature) -> Self {
        Self { claims, signature }
    }

    /// Final effect-side gate and atomic adapter dispatch.
    ///
    /// No reusable permit is returned. Trusted time is obtained from the
    /// consuming adapter immediately before validation and effect dispatch.
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_effect_at_point_of_use<P, R, S, W, A>(
        self,
        policy: CorePolicy,
        actual_binding: Binding,
        exact_watchdog_arm: WatchdogArm,
        provider: &mut P,
        replay: &mut R,
        inhibit: &mut S,
        watchdog: &mut W,
        adapter: &mut A,
    ) -> Result<AppliedEffect, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
        S: SafetyInhibit,
        W: FailClosedWatchdog + ?Sized,
        A: AtomicEffectAdapter,
    {
        let claims = self.claims;
        if claims.binding() != actual_binding
            || actual_binding.domain_id() != policy.domain_id()
            || actual_binding.authority_epoch() != policy.authority_epoch()
        {
            return Err(CoreError::BindingMismatch);
        }
        if exact_watchdog_arm.binding() != claims.binding()
            || exact_watchdog_arm.capability_id() != claims.capability_id()
            || exact_watchdog_arm.lease_id() != claims.lease_id()
            || exact_watchdog_arm.lease_expires_at() != claims.expires_at()
            || exact_watchdog_arm.receipt_deadline() > claims.receipt_deadline()
        {
            return Err(CoreError::WatchdogArmMismatch);
        }
        let now = adapter
            .trusted_now()
            .map_err(|failure| CoreError::EffectAdapterFailure(failure.code()))?;
        ensure_time_window(
            now,
            claims.issued_at(),
            claims.expires_at(),
            ArtifactKind::Lease,
        )?;
        require_classed_custody(
            provider,
            policy.authority_signing_key(),
            policy.authority_custody_provider_identity(),
            policy.authority_class(),
            SignaturePurpose::EffectLease,
            now,
        )?;
        let message = claims.canonical_message();
        verify_checked(
            provider,
            policy.authority_signing_key(),
            SignaturePurpose::EffectLease,
            ArtifactKind::Lease,
            message.as_bytes(),
            &self.signature,
        )?;
        require_safety_inhibit(inhibit, actual_binding, InhibitPhase::Effect, now)?;
        let arm = exact_watchdog_arm;
        if watchdog
            .health(now)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?
            != WatchdogHealth::Ready
        {
            return Err(CoreError::WatchdogUnsafe);
        }
        if !watchdog
            .verify_armed(arm, now)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?
        {
            watchdog
                .trip(arm, WatchdogTripReason::PointOfUseArmMissing)
                .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
            return Err(CoreError::WatchdogArmMismatch);
        }
        claim_once(
            replay,
            ReplayKey::LeaseEffect {
                epoch: policy.authority_epoch(),
                id: claims.lease_id(),
            },
        )?;

        let effect_deadline =
            core::cmp::min(claims.expires_at(), exact_watchdog_arm.receipt_deadline());
        let mut scope = ();
        let dispatch = EffectDispatch::new(
            claims.binding(),
            claims.capability_id(),
            claims.lease_id(),
            now,
            effect_deadline,
            &mut scope,
        );
        let outcome = match adapter.consume_once(dispatch) {
            Ok(outcome) => outcome,
            Err(failure) => {
                return Err(trip_or_original(
                    watchdog,
                    arm,
                    WatchdogTripReason::EffectAdapterFailedAfterConsumptionClaim,
                    CoreError::EffectAdapterFailure(failure.code()),
                ));
            }
        };
        let completed_at = match adapter.trusted_now() {
            Ok(completed_at) => completed_at,
            Err(failure) => {
                return Err(trip_or_original(
                    watchdog,
                    arm,
                    WatchdogTripReason::EffectCompletionInvalidAfterConsumptionClaim,
                    CoreError::EffectAdapterFailure(failure.code()),
                ));
            }
        };
        if completed_at < now || completed_at >= effect_deadline {
            return Err(trip_or_original(
                watchdog,
                arm,
                WatchdogTripReason::EffectCompletionInvalidAfterConsumptionClaim,
                CoreError::CompletionOutsideLease,
            ));
        }
        Ok(AppliedEffect {
            binding: claims.binding(),
            capability_id: claims.capability_id(),
            lease_id: claims.lease_id(),
            completed_at,
            outcome,
        })
    }
}

/// Non-authorizing result evidence returned only after the adapter has consumed
/// the ephemeral dispatch. It cannot be used to trigger another effect.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AppliedEffect {
    binding: Binding,
    capability_id: CapabilityId,
    lease_id: LeaseId,
    completed_at: Time,
    outcome: EffectOutcome,
}

impl AppliedEffect {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn capability_id(&self) -> CapabilityId {
        self.capability_id
    }

    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    pub const fn completed_at(&self) -> Time {
        self.completed_at
    }

    pub const fn outcome(&self) -> EffectOutcome {
        self.outcome
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AdapterReceiptClaims {
    binding: Binding,
    capability_id: CapabilityId,
    lease_id: LeaseId,
    completed_at: Time,
    outcome: EffectOutcome,
}

impl AdapterReceiptClaims {
    pub const fn new(
        binding: Binding,
        capability_id: CapabilityId,
        lease_id: LeaseId,
        completed_at: Time,
        outcome: EffectOutcome,
    ) -> Self {
        Self {
            binding,
            capability_id,
            lease_id,
            completed_at,
            outcome,
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

    pub const fn completed_at(&self) -> Time {
        self.completed_at
    }

    pub const fn outcome(&self) -> EffectOutcome {
        self.outcome
    }

    pub(crate) fn canonical_message(&self) -> CanonicalMessage {
        let mut message = CanonicalMessage::begin(SignaturePurpose::AdapterReceipt);
        self.binding.encode_into(&mut message.0);
        self.capability_id.encode_into(&mut message.0);
        self.lease_id.encode_into(&mut message.0);
        self.completed_at.encode_into(&mut message.0);
        message.0.push(self.outcome as u8);
        message
    }
}

#[derive(Debug)]
pub struct SignedAdapterReceipt {
    claims: AdapterReceiptClaims,
    signature: ProviderSignature,
}

impl SignedAdapterReceipt {
    /// Sign receipt claims through the supplied external provider.
    ///
    /// This helper contains no cryptographic implementation. The provider must
    /// keep the adapter private key outside this process in production.
    pub fn issue<P: ExternalSignatureProvider>(
        claims: AdapterReceiptClaims,
        adapter_key: KeyId,
        provider: &mut P,
    ) -> Result<Self, CoreError> {
        let message = claims.canonical_message();
        let signature = provider
            .sign(
                adapter_key,
                SignaturePurpose::AdapterReceipt,
                message.as_bytes(),
            )
            .map_err(|failure| CoreError::SignatureProviderFailure(failure.code()))?;
        if signature.key_id() != adapter_key {
            return Err(CoreError::WrongSignatureKey(
                crate::types::ArtifactKind::Receipt,
            ));
        }
        Ok(Self { claims, signature })
    }

    /// Reconstruct an untrusted receipt received across an integration boundary.
    /// Acceptance always verifies it against the configured adapter key.
    pub fn from_untrusted_parts(
        claims: AdapterReceiptClaims,
        signature: ProviderSignature,
    ) -> Self {
        Self { claims, signature }
    }

    pub const fn claims(&self) -> AdapterReceiptClaims {
        self.claims
    }

    pub const fn signature(&self) -> &ProviderSignature {
        &self.signature
    }
}
