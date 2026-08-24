use crate::artifacts::{
    AdapterReceiptClaims, Capability, CapabilityClaims, EffectLease, LeaseClaims, PrepareClaims,
    PrepareToken, SignedAdapterReceipt,
};
use crate::traits::{
    ExternalSignatureProvider, FailClosedWatchdog, InhibitDecision, InhibitPhase, InhibitRequest,
    InterlockDecision, InterlockPhase, InterlockRequest, KeyCustodyProvider, KeyCustodyStatus,
    ProviderSignature, ReplayClaim, ReplayKey, ReplayProtector, SafetyEnvelopeInterlock,
    SafetyInhibit, SignaturePurpose, WatchdogArm, WatchdogHealth, WatchdogTripReason,
};
use crate::types::{
    ArtifactKind, AuthorityClass, Binding, CapabilityId, ConvergenceEvidence, CoreError,
    CorePolicy, PointOfUseRequest, PrepareId, Time, Ttl,
};

#[derive(Debug)]
pub struct Candidate {
    policy: CorePolicy,
}

impl Candidate {
    pub const fn new(policy: CorePolicy) -> Self {
        Self { policy }
    }

    /// Require byte-for-byte equality of intended, independently observed, and
    /// policy-approved bindings before any token is created.
    pub fn converge(self, evidence: ConvergenceEvidence) -> Result<Converged, CoreError> {
        if !evidence.is_exact() {
            return Err(CoreError::ExactConvergenceFailed);
        }
        let binding = evidence.intended();
        if binding.domain_id() != self.policy.domain_id()
            || binding.authority_epoch() != self.policy.authority_epoch()
            || binding.authority_class() != self.policy.authority_class()
            || binding.authority_profile_digest() != self.policy.authority_profile_digest()
            || binding.authority_build_digest() != self.policy.authority_build_digest()
        {
            return Err(CoreError::BindingMismatch);
        }
        Ok(Converged {
            policy: self.policy,
            binding,
        })
    }
}

#[derive(Debug)]
pub struct Converged {
    policy: CorePolicy,
    binding: Binding,
}

impl Converged {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    /// Issue an expiring, non-authorizing PREPARE token.
    ///
    /// A PREPARE has no API that can yield a lease. It must be consumed by the
    /// sole `commit` transition, which is also guarded by durable replay state.
    pub fn prepare<P: ExternalSignatureProvider + KeyCustodyProvider>(
        self,
        now: Time,
        ttl: Ttl,
        prepare_id: PrepareId,
        provider: &mut P,
    ) -> Result<Prepared, CoreError> {
        self.prepare_with_replay(
            now,
            ttl,
            prepare_id,
            // A nonzero fail-closed sentinel reaches the deliberately
            // unavailable replay provider. It is never persisted or signed.
            crate::types::Digest::new([0xff; 64]),
            provider,
            &mut ReplayUnavailable,
        )
    }

    /// PREPARE with durable traversal-intent consumption.
    ///
    /// A service must use this entry point. The legacy `prepare` convenience
    /// method above now fails closed because it has no durable replay provider.
    pub fn prepare_with_replay<P, R>(
        self,
        now: Time,
        ttl: Ttl,
        prepare_id: PrepareId,
        durable_consumption_digest: crate::types::Digest,
        provider: &mut P,
        replay: &mut R,
    ) -> Result<Prepared, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
    {
        if durable_consumption_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(CoreError::InvalidPolicy(
                "durable consumption digest must be non-zero",
            ));
        }
        ensure_ttl(ttl, self.policy.max_prepare_ttl())?;
        let expires_at = now.checked_add(ttl)?;
        require_classed_custody(
            provider,
            self.policy.authority_signing_key(),
            self.policy.authority_custody_provider_identity(),
            self.policy.authority_class(),
            SignaturePurpose::NonAuthorizingPrepare,
            now,
        )?;
        claim_once(
            replay,
            ReplayKey::TraversalIntent {
                epoch: self.policy.authority_epoch(),
                durable_consumption_digest,
            },
        )?;
        let claims = PrepareClaims::new(self.binding, prepare_id, now, expires_at);
        let message = claims.canonical_message();
        let signature = sign_checked(
            provider,
            self.policy.authority_signing_key(),
            SignaturePurpose::NonAuthorizingPrepare,
            ArtifactKind::Prepare,
            message.as_bytes(),
        )?;
        Ok(Prepared {
            policy: self.policy,
            binding: self.binding,
            token: PrepareToken::new(claims, signature),
        })
    }
}

struct ReplayUnavailable;

impl ReplayProtector for ReplayUnavailable {
    fn claim_once(
        &mut self,
        _key: ReplayKey,
        _retain_until: Time,
    ) -> Result<ReplayClaim, crate::traits::ExternalFailure> {
        Err(crate::traits::ExternalFailure::new(60_001))
    }
}

#[derive(Debug)]
pub struct Prepared {
    policy: CorePolicy,
    binding: Binding,
    token: PrepareToken,
}

impl Prepared {
    pub const fn prepare_token(&self) -> &PrepareToken {
        &self.token
    }

    /// Sole authorizing COMMIT transition.
    ///
    /// `self` is consumed and the prepare ID is atomically claimed before the
    /// capability is signed. A failure after the claim is intentionally not
    /// retryable with this state object.
    #[allow(clippy::too_many_arguments)]
    pub fn commit<P, R, I, S>(
        self,
        now: Time,
        capability_ttl: Ttl,
        capability_id: CapabilityId,
        provider: &mut P,
        replay: &mut R,
        interlock: &mut I,
        inhibit: &mut S,
    ) -> Result<Committed, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
        I: SafetyEnvelopeInterlock,
        S: SafetyInhibit,
    {
        let prepare = self.token.claims();
        if prepare.binding() != self.binding {
            return Err(CoreError::BindingMismatch);
        }
        ensure_time_window(
            now,
            prepare.issued_at(),
            prepare.expires_at(),
            ArtifactKind::Prepare,
        )?;
        let prepare_message = prepare.canonical_message();
        verify_checked(
            provider,
            self.policy.authority_signing_key(),
            SignaturePurpose::NonAuthorizingPrepare,
            ArtifactKind::Prepare,
            prepare_message.as_bytes(),
            self.token.signature(),
        )?;

        if prepare.prepare_id().as_bytes() == capability_id.as_bytes() {
            return Err(CoreError::IdentifierReuse);
        }
        ensure_ttl(capability_ttl, self.policy.max_capability_ttl())?;
        let expires_at = now.checked_add(capability_ttl)?;
        require_classed_custody(
            provider,
            self.policy.authority_signing_key(),
            self.policy.authority_custody_provider_identity(),
            self.policy.authority_class(),
            SignaturePurpose::CapabilityCommit,
            now,
        )?;
        require_safety_inhibit(inhibit, self.binding, InhibitPhase::Commit, now)?;
        let request = InterlockRequest::new(self.binding, InterlockPhase::Commit, now, expires_at);
        require_interlock(interlock, request, self.binding, None)?;

        claim_once(
            replay,
            ReplayKey::Prepare {
                epoch: self.policy.authority_epoch(),
                id: prepare.prepare_id(),
            },
        )?;

        let claims = CapabilityClaims::new(
            self.binding,
            prepare.prepare_id(),
            capability_id,
            now,
            expires_at,
        );
        let message = claims.canonical_message();
        let signature = sign_checked(
            provider,
            self.policy.authority_signing_key(),
            SignaturePurpose::CapabilityCommit,
            ArtifactKind::Capability,
            message.as_bytes(),
        )?;
        Ok(Committed {
            policy: self.policy,
            binding: self.binding,
            capability: Capability::new(claims, signature),
        })
    }
}

#[derive(Debug)]
pub struct Committed {
    policy: CorePolicy,
    binding: Binding,
    capability: Capability,
}

impl Committed {
    pub const fn capability(&self) -> &Capability {
        &self.capability
    }

    /// Redeem the capability exactly once at the point of use.
    ///
    /// The actual adapter/effect binding is compared in full, the interlock is
    /// re-evaluated, replay state is claimed, and the external watchdog is armed
    /// before the short-lived lease signature is emitted.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_at_point_of_use<P, R, I, S, W>(
        self,
        now: Time,
        request: PointOfUseRequest,
        provider: &mut P,
        replay: &mut R,
        interlock: &mut I,
        inhibit: &mut S,
        watchdog: &mut W,
    ) -> Result<AwaitingReceipt, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
        I: SafetyEnvelopeInterlock,
        S: SafetyInhibit,
        W: FailClosedWatchdog + ?Sized,
    {
        let capability = self.capability.claims();
        if capability.binding() != self.binding || request.actual_binding() != self.binding {
            return Err(CoreError::BindingMismatch);
        }
        ensure_time_window(
            now,
            capability.committed_at(),
            capability.expires_at(),
            ArtifactKind::Capability,
        )?;
        let capability_message = capability.canonical_message();
        verify_checked(
            provider,
            self.policy.authority_signing_key(),
            SignaturePurpose::CapabilityCommit,
            ArtifactKind::Capability,
            capability_message.as_bytes(),
            self.capability.signature(),
        )?;

        if request.lease_id().as_bytes() == capability.capability_id().as_bytes()
            || request.lease_id().as_bytes() == capability.prepare_id().as_bytes()
        {
            return Err(CoreError::IdentifierReuse);
        }
        ensure_ttl(request.lease_ttl(), self.policy.max_lease_ttl())?;
        let lease_expires_at = now.checked_add(request.lease_ttl())?;
        if lease_expires_at > capability.expires_at() {
            return Err(CoreError::Expired(ArtifactKind::Capability));
        }
        let receipt_deadline = lease_expires_at.checked_add(self.policy.receipt_grace())?;

        require_classed_custody(
            provider,
            self.policy.authority_signing_key(),
            self.policy.authority_custody_provider_identity(),
            self.policy.authority_class(),
            SignaturePurpose::EffectLease,
            now,
        )?;
        require_safety_inhibit(inhibit, self.binding, InhibitPhase::LeaseRedemption, now)?;

        let interlock_request = InterlockRequest::new(
            self.binding,
            InterlockPhase::PointOfUse,
            now,
            lease_expires_at,
        );
        require_interlock(
            interlock,
            interlock_request,
            self.binding,
            Some(request.lease_ttl()),
        )?;

        let health = watchdog
            .health(now)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
        if health != WatchdogHealth::Ready {
            return Err(CoreError::WatchdogUnsafe);
        }

        claim_once(
            replay,
            ReplayKey::Capability {
                epoch: self.policy.authority_epoch(),
                id: capability.capability_id(),
            },
        )?;

        let watchdog_arm = WatchdogArm::new(
            self.binding,
            capability.capability_id(),
            request.lease_id(),
            lease_expires_at,
            receipt_deadline,
        );
        watchdog
            .arm(watchdog_arm)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;

        let claims = LeaseClaims::new(
            self.binding,
            capability.capability_id(),
            request.lease_id(),
            now,
            lease_expires_at,
            receipt_deadline,
        );
        let message = claims.canonical_message();
        let signature = match sign_checked(
            provider,
            self.policy.authority_signing_key(),
            SignaturePurpose::EffectLease,
            ArtifactKind::Lease,
            message.as_bytes(),
        ) {
            Ok(signature) => signature,
            Err(error) => {
                return Err(trip_or_original(
                    watchdog,
                    watchdog_arm,
                    WatchdogTripReason::LeaseIssuanceFailedAfterArm,
                    error,
                ));
            }
        };

        Ok(AwaitingReceipt {
            policy: self.policy,
            binding: self.binding,
            lease: EffectLease::new(claims, signature),
            watchdog_arm,
        })
    }
}

#[derive(Debug)]
pub struct AwaitingReceipt {
    policy: CorePolicy,
    binding: Binding,
    lease: EffectLease,
    watchdog_arm: WatchdogArm,
}

impl AwaitingReceipt {
    pub const fn lease(&self) -> &EffectLease {
        &self.lease
    }

    pub const fn watchdog_arm(&self) -> WatchdogArm {
        self.watchdog_arm
    }

    /// Durably narrow the exact persisted watchdog deadline and move the
    /// typestate to own that confirmed arm.  Widening or identity substitution
    /// is rejected before calling the provider.
    pub fn tighten_watchdog<W: FailClosedWatchdog + ?Sized>(
        mut self,
        now: Time,
        effective_deadline: Time,
        watchdog: &mut W,
    ) -> Result<Self, CoreError> {
        if now >= effective_deadline
            || effective_deadline > self.watchdog_arm.receipt_deadline()
            || effective_deadline > self.watchdog_arm.lease_expires_at()
        {
            return Err(CoreError::WatchdogArmMismatch);
        }
        let tightened = WatchdogArm::new(
            self.watchdog_arm.binding(),
            self.watchdog_arm.capability_id(),
            self.watchdog_arm.lease_id(),
            self.watchdog_arm.lease_expires_at(),
            effective_deadline,
        );
        watchdog
            .tighten(self.watchdog_arm, tightened)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
        let persisted = watchdog
            .verify_armed(tightened, now)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
        if !persisted {
            return Err(CoreError::WatchdogArmMismatch);
        }
        self.watchdog_arm = tightened;
        Ok(self)
    }

    /// Polling is supplementary: the external watchdog must enforce its persisted
    /// deadline even if this process never polls again.
    pub fn poll_watchdog<W: FailClosedWatchdog + ?Sized>(
        self,
        now: Time,
        watchdog: &mut W,
    ) -> Result<ReceiptPoll, CoreError> {
        if now >= self.watchdog_arm.receipt_deadline() {
            watchdog
                .trip(
                    self.watchdog_arm,
                    WatchdogTripReason::ReceiptDeadlineElapsed,
                )
                .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
            return Ok(ReceiptPoll::Stopped(Stopped {
                binding: self.binding,
                watchdog_arm: self.watchdog_arm,
                reason: WatchdogTripReason::ReceiptDeadlineElapsed,
            }));
        }

        match watchdog
            .health(now)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?
        {
            WatchdogHealth::Ready => Ok(ReceiptPoll::Waiting(self)),
            WatchdogHealth::Unsafe => {
                watchdog
                    .trip(self.watchdog_arm, WatchdogTripReason::WatchdogBecameUnsafe)
                    .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
                Ok(ReceiptPoll::Stopped(Stopped {
                    binding: self.binding,
                    watchdog_arm: self.watchdog_arm,
                    reason: WatchdogTripReason::WatchdogBecameUnsafe,
                }))
            }
        }
    }

    /// Validate the adapter receipt and permanently claim the lease receipt
    /// slot while deliberately retaining the exact external watchdog arm.
    ///
    /// Any invalid, late, mismatched, or replayed receipt trips the watchdog and
    /// consumes this state object.
    #[allow(clippy::too_many_arguments)]
    pub fn claim_validated_receipt<P, R, W>(
        self,
        now: Time,
        receipt: SignedAdapterReceipt,
        provider: &mut P,
        replay: &mut R,
        watchdog: &mut W,
    ) -> Result<ClaimedReceipt, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
        W: FailClosedWatchdog + ?Sized,
    {
        let claims = receipt.claims();
        let validation = self.validate_receipt(now, claims, receipt.signature(), provider);
        if let Err(error) = validation {
            return Err(trip_or_original(
                watchdog,
                self.watchdog_arm,
                WatchdogTripReason::InvalidReceipt,
                error,
            ));
        }

        let replay_key = ReplayKey::LeaseReceipt {
            epoch: self.policy.authority_epoch(),
            id: self.watchdog_arm.lease_id(),
        };
        match replay.claim_once(replay_key, Time::MAX) {
            Ok(ReplayClaim::Claimed) => {}
            Ok(ReplayClaim::AlreadyClaimed) => {
                return Err(trip_or_original(
                    watchdog,
                    self.watchdog_arm,
                    WatchdogTripReason::ReceiptReplay,
                    CoreError::ReplayDetected(replay_key.class()),
                ));
            }
            Err(failure) => {
                return Err(trip_or_original(
                    watchdog,
                    self.watchdog_arm,
                    WatchdogTripReason::InvalidReceipt,
                    CoreError::ReplayStoreFailure(failure.code()),
                ));
            }
        }

        Ok(ClaimedReceipt {
            binding: self.binding,
            receipt,
            watchdog_arm: self.watchdog_arm,
        })
    }

    /// Permanently consume the receipt slot and assert STOP for an effect whose
    /// outcome cannot be authenticated as a core adapter receipt.  This path
    /// never acknowledges or clears the watchdog arm.
    pub fn claim_and_stop_untrusted_effect<R, W>(
        self,
        replay: &mut R,
        watchdog: &mut W,
        reason: WatchdogTripReason,
    ) -> Result<Stopped, CoreError>
    where
        R: ReplayProtector,
        W: FailClosedWatchdog + ?Sized,
    {
        let replay_key = ReplayKey::LeaseReceipt {
            epoch: self.policy.authority_epoch(),
            id: self.watchdog_arm.lease_id(),
        };
        match replay.claim_once(replay_key, Time::MAX) {
            Ok(ReplayClaim::Claimed) => {}
            Ok(ReplayClaim::AlreadyClaimed) => {
                return Err(trip_or_original(
                    watchdog,
                    self.watchdog_arm,
                    WatchdogTripReason::ReceiptReplay,
                    CoreError::ReplayDetected(replay_key.class()),
                ));
            }
            Err(failure) => {
                return Err(trip_or_original(
                    watchdog,
                    self.watchdog_arm,
                    WatchdogTripReason::InvalidReceipt,
                    CoreError::ReplayStoreFailure(failure.code()),
                ));
            }
        }
        watchdog
            .trip(self.watchdog_arm, reason)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
        Ok(Stopped {
            binding: self.binding,
            watchdog_arm: self.watchdog_arm,
            reason,
        })
    }

    /// Test-only compatibility wrapper.  Non-test consumers must explicitly
    /// cross the durable-terminal boundary before acknowledging the watchdog.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn accept_receipt<P, R, W>(
        self,
        now: Time,
        receipt: SignedAdapterReceipt,
        provider: &mut P,
        replay: &mut R,
        watchdog: &mut W,
    ) -> Result<Completed, CoreError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        R: ReplayProtector,
        W: FailClosedWatchdog + ?Sized,
    {
        self.claim_validated_receipt(now, receipt, provider, replay, watchdog)?
            .acknowledge_after_durable_terminal(watchdog)
    }

    fn validate_receipt<P: ExternalSignatureProvider + KeyCustodyProvider>(
        &self,
        now: Time,
        receipt: AdapterReceiptClaims,
        signature: &ProviderSignature,
        provider: &mut P,
    ) -> Result<(), CoreError> {
        require_classed_custody(
            provider,
            self.policy.adapter_receipt_key(),
            self.policy.adapter_custody_provider_identity(),
            self.policy.authority_class(),
            SignaturePurpose::AdapterReceipt,
            now,
        )?;
        let lease = self.lease.claims();
        // A later watchdog timeout may provide time to assert a fail-closed
        // STOP after process/transport loss, but it can never extend effect
        // authority. Successful receipt validation and watchdog ACK must occur
        // inside both half-open windows. In the integrated service the lease
        // expiry is additionally bounded by the wire point-of-use permit.
        let successful_receipt_deadline =
            core::cmp::min(lease.expires_at(), self.watchdog_arm.receipt_deadline());
        if now >= successful_receipt_deadline {
            return Err(CoreError::Expired(ArtifactKind::Receipt));
        }
        if receipt.binding() != self.binding
            || receipt.capability_id() != lease.capability_id()
            || receipt.lease_id() != lease.lease_id()
        {
            return Err(CoreError::ReceiptMismatch);
        }
        if receipt.completed_at() < lease.issued_at()
            || receipt.completed_at() >= successful_receipt_deadline
            || receipt.completed_at() > now
        {
            return Err(CoreError::CompletionOutsideLease);
        }
        let message = receipt.canonical_message();
        verify_checked(
            provider,
            self.policy.adapter_receipt_key(),
            SignaturePurpose::AdapterReceipt,
            ArtifactKind::Receipt,
            message.as_bytes(),
            signature,
        )
    }
}

/// Move-only evidence that the exact adapter receipt was authenticated and its
/// permanent replay slot was claimed while the watchdog remained armed.
#[derive(Debug)]
pub struct ClaimedReceipt {
    binding: Binding,
    receipt: SignedAdapterReceipt,
    watchdog_arm: WatchdogArm,
}

impl ClaimedReceipt {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn receipt(&self) -> &SignedAdapterReceipt {
        &self.receipt
    }

    pub const fn watchdog_arm(&self) -> WatchdogArm {
        self.watchdog_arm
    }

    /// Cross this boundary only after the complete terminal audit tail is
    /// validated and durably persisted by an independently pinned sink.
    pub fn acknowledge_after_durable_terminal<W: FailClosedWatchdog + ?Sized>(
        self,
        watchdog: &mut W,
    ) -> Result<Completed, CoreError> {
        if let Err(failure) = watchdog.acknowledge(self.watchdog_arm) {
            let original = CoreError::WatchdogFailure(failure.code());
            return Err(trip_or_original(
                watchdog,
                self.watchdog_arm,
                WatchdogTripReason::AcknowledgementFailed,
                original,
            ));
        }
        Ok(Completed {
            binding: self.binding,
            receipt: self.receipt,
        })
    }

    /// Assert STOP for a valid but unsuccessful receipt without ever clearing
    /// the watchdog arm.
    pub fn stop_without_ack<W: FailClosedWatchdog + ?Sized>(
        self,
        watchdog: &mut W,
        reason: WatchdogTripReason,
    ) -> Result<Stopped, CoreError> {
        watchdog
            .trip(self.watchdog_arm, reason)
            .map_err(|failure| CoreError::WatchdogFailure(failure.code()))?;
        Ok(Stopped {
            binding: self.binding,
            watchdog_arm: self.watchdog_arm,
            reason,
        })
    }
}

#[derive(Debug)]
// Keep the typestate value owned and allocation-free. Boxing only to equalize
// enum variant sizes would add a fallible heap boundary to watchdog polling.
#[allow(clippy::large_enum_variant)]
pub enum ReceiptPoll {
    Waiting(AwaitingReceipt),
    Stopped(Stopped),
}

#[derive(Debug)]
pub struct Stopped {
    binding: Binding,
    watchdog_arm: WatchdogArm,
    reason: WatchdogTripReason,
}

impl Stopped {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn watchdog_arm(&self) -> WatchdogArm {
        self.watchdog_arm
    }

    pub const fn reason(&self) -> WatchdogTripReason {
        self.reason
    }
}

#[derive(Debug)]
pub struct Completed {
    binding: Binding,
    receipt: SignedAdapterReceipt,
}

impl Completed {
    pub const fn binding(&self) -> Binding {
        self.binding
    }

    pub const fn receipt(&self) -> &SignedAdapterReceipt {
        &self.receipt
    }
}

fn ensure_ttl(requested: Ttl, maximum: Ttl) -> Result<(), CoreError> {
    if requested > maximum {
        return Err(CoreError::InvalidTtl);
    }
    Ok(())
}

pub(crate) fn ensure_time_window(
    now: Time,
    not_before: Time,
    expires_at: Time,
    kind: ArtifactKind,
) -> Result<(), CoreError> {
    if now < not_before {
        return Err(CoreError::NotYetValid(kind));
    }
    if now >= expires_at {
        return Err(CoreError::Expired(kind));
    }
    Ok(())
}

fn sign_checked<P: ExternalSignatureProvider>(
    provider: &mut P,
    key_id: crate::types::KeyId,
    purpose: SignaturePurpose,
    kind: ArtifactKind,
    message: &[u8],
) -> Result<ProviderSignature, CoreError> {
    let signature = provider
        .sign(key_id, purpose, message)
        .map_err(|failure| CoreError::SignatureProviderFailure(failure.code()))?;
    if signature.key_id() != key_id {
        return Err(CoreError::WrongSignatureKey(kind));
    }
    Ok(signature)
}

pub(crate) fn verify_checked<P: ExternalSignatureProvider>(
    provider: &mut P,
    key_id: crate::types::KeyId,
    purpose: SignaturePurpose,
    kind: ArtifactKind,
    message: &[u8],
    signature: &ProviderSignature,
) -> Result<(), CoreError> {
    if signature.key_id() != key_id {
        return Err(CoreError::WrongSignatureKey(kind));
    }
    let valid = provider
        .verify(key_id, purpose, message, signature)
        .map_err(|failure| CoreError::SignatureProviderFailure(failure.code()))?;
    if !valid {
        return Err(CoreError::InvalidSignature(kind));
    }
    Ok(())
}

pub(crate) fn claim_once<R: ReplayProtector>(
    replay: &mut R,
    key: ReplayKey,
) -> Result<(), CoreError> {
    match replay.claim_once(key, Time::MAX) {
        Ok(ReplayClaim::Claimed) => Ok(()),
        Ok(ReplayClaim::AlreadyClaimed) => Err(CoreError::ReplayDetected(key.class())),
        Err(failure) => Err(CoreError::ReplayStoreFailure(failure.code())),
    }
}

fn require_interlock<I: SafetyEnvelopeInterlock>(
    interlock: &mut I,
    request: InterlockRequest,
    binding: Binding,
    requested_lease_ttl: Option<Ttl>,
) -> Result<(), CoreError> {
    let permit = match interlock
        .evaluate(request)
        .map_err(|failure| CoreError::InterlockFailure(failure.code()))?
    {
        InterlockDecision::Permit(permit) => permit,
        InterlockDecision::Deny => return Err(CoreError::InterlockDenied),
    };
    if permit.envelope_digest() != binding.safety_envelope_digest()
        || permit.valid_until() < request.requested_valid_until()
        || requested_lease_ttl
            .map(|ttl| permit.maximum_lease_ttl() < ttl)
            .unwrap_or(false)
    {
        return Err(CoreError::InterlockMismatch);
    }
    Ok(())
}

pub(crate) fn require_classed_custody<P: KeyCustodyProvider>(
    provider: &mut P,
    key_id: crate::types::KeyId,
    expected_provider_identity: crate::types::Digest,
    authority_class: AuthorityClass,
    purpose: SignaturePurpose,
    now: Time,
) -> Result<(), CoreError> {
    let status = provider
        .key_custody_status(key_id, purpose, now)
        .map_err(|failure| CoreError::KeyCustodyFailure(failure.code()))?;
    if authority_class == AuthorityClass::NonproductionEvidenceOnly {
        return match status {
            KeyCustodyStatus::NonproductionFixture => Ok(()),
            KeyCustodyStatus::ProductionNonExportable(_)
            | KeyCustodyStatus::NonProduction
            | KeyCustodyStatus::Unavailable => Err(CoreError::KeyCustodyClassMismatch),
        };
    }
    let identity = match status {
        KeyCustodyStatus::ProductionNonExportable(identity) => identity,
        KeyCustodyStatus::NonproductionFixture => return Err(CoreError::NonProductionKeyCustody),
        KeyCustodyStatus::NonProduction => return Err(CoreError::NonProductionKeyCustody),
        KeyCustodyStatus::Unavailable => return Err(CoreError::KeyCustodyUnavailable),
    };
    let expected_technology = match authority_class {
        AuthorityClass::ProductionHsm => crate::traits::CustodyTechnology::Hsm,
        AuthorityClass::ProductionTpm => crate::traits::CustodyTechnology::Tpm,
        AuthorityClass::NonproductionEvidenceOnly => unreachable!(),
    };
    if identity.technology() != expected_technology {
        return Err(CoreError::KeyCustodyTechnologyMismatch);
    }
    if identity.key_id() != key_id || identity.provider_identity() != expected_provider_identity {
        return Err(CoreError::KeyCustodyIdentityMismatch);
    }
    if now < identity.observed_at() || now >= identity.fresh_until() {
        return Err(CoreError::KeyCustodyStatusStale);
    }
    Ok(())
}

pub(crate) fn require_safety_inhibit<S: SafetyInhibit>(
    inhibit: &mut S,
    binding: Binding,
    phase: InhibitPhase,
    now: Time,
) -> Result<(), CoreError> {
    let request = InhibitRequest::new(binding, phase, now);
    let permit = match inhibit
        .check(request)
        .map_err(|failure| CoreError::SafetyInhibitFailure(failure.code()))?
    {
        InhibitDecision::Permit(permit) => permit,
        InhibitDecision::Block => return Err(CoreError::SafetyInhibitBlocked),
        InhibitDecision::Stop => return Err(CoreError::SafetyInhibitStop),
    };
    if permit.binding() != binding || permit.phase() != phase {
        return Err(CoreError::SafetyInhibitMismatch);
    }
    if now < permit.observed_at() || now >= permit.fresh_until() {
        return Err(CoreError::SafetyInhibitStale);
    }
    Ok(())
}

pub(crate) fn trip_or_original<W: FailClosedWatchdog + ?Sized>(
    watchdog: &mut W,
    arm: WatchdogArm,
    reason: WatchdogTripReason,
    original: CoreError,
) -> CoreError {
    match watchdog.trip(arm, reason) {
        Ok(()) => original,
        Err(failure) => CoreError::WatchdogFailure(failure.code()),
    }
}
