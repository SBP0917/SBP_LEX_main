use std::collections::BTreeSet;

use crate::*;

/// NON-PRODUCTION deterministic signature fixture.
///
/// This is deliberately a reversible checksum-like construction with public
/// inputs. It provides test repeatability and purpose separation only. It has no
/// cryptographic assurance and must never be used outside tests.
#[derive(Default)]
struct NonProductionDeterministicSignatureFixture {
    fail_sign_for: Option<SignaturePurpose>,
    fail_verify: bool,
    return_wrong_key: Option<KeyId>,
}

impl NonProductionDeterministicSignatureFixture {
    fn bytes(key_id: KeyId, purpose: SignaturePurpose, message: &[u8]) -> Vec<u8> {
        let mut output = vec![0u8; HYBRID_SIGNATURE_BYTES];
        for (index, byte) in key_id
            .as_bytes()
            .iter()
            .copied()
            .chain(core::iter::once(purpose as u8))
            .chain(message.iter().copied())
            .enumerate()
        {
            let slot = index % output.len();
            output[slot] = output[slot]
                .wrapping_add(byte)
                .rotate_left((index % 7) as u32)
                ^ (index as u8).wrapping_mul(17);
        }
        output
    }
}

impl ExternalSignatureProvider for NonProductionDeterministicSignatureFixture {
    fn sign(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
    ) -> Result<ProviderSignature, ExternalFailure> {
        if self.fail_sign_for == Some(purpose) {
            return Err(ExternalFailure::new(701));
        }
        let returned_key = self.return_wrong_key.unwrap_or(key_id);
        ProviderSignature::new(
            returned_key,
            Self::bytes(returned_key, purpose, canonical_message),
        )
        .map_err(|_| ExternalFailure::new(702))
    }

    fn verify(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
        signature: &ProviderSignature,
    ) -> Result<bool, ExternalFailure> {
        if self.fail_verify {
            return Err(ExternalFailure::new(703));
        }
        let expected = Self::bytes(key_id, purpose, canonical_message);
        Ok(signature.key_id() == key_id && signature.as_bytes() == expected.as_slice())
    }
}

impl KeyCustodyProvider for NonProductionDeterministicSignatureFixture {
    fn key_custody_status(
        &mut self,
        _key_id: KeyId,
        _purpose: SignaturePurpose,
        _now: Time,
    ) -> Result<KeyCustodyStatus, ExternalFailure> {
        Ok(KeyCustodyStatus::NonproductionFixture)
    }
}

/// TEST-ONLY facade that exercises the production-status branch.
///
/// It delegates signatures to the explicitly nonproduction deterministic fixture
/// and provides no cryptographic assurance, hardware attestation, or physical
/// evidence. A real deployment must never use or imitate this facade.
#[derive(Default)]
struct TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
    signatures: NonProductionDeterministicSignatureFixture,
    custody_unavailable: bool,
    custody_stale: bool,
    custody_technology: Option<CustodyTechnology>,
}

impl ExternalSignatureProvider for TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
    fn sign(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
    ) -> Result<ProviderSignature, ExternalFailure> {
        self.signatures.sign(key_id, purpose, canonical_message)
    }

    fn verify(
        &mut self,
        key_id: KeyId,
        purpose: SignaturePurpose,
        canonical_message: &[u8],
        signature: &ProviderSignature,
    ) -> Result<bool, ExternalFailure> {
        self.signatures
            .verify(key_id, purpose, canonical_message, signature)
    }
}

impl KeyCustodyProvider for TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
    fn key_custody_status(
        &mut self,
        key_id: KeyId,
        _purpose: SignaturePurpose,
        now: Time,
    ) -> Result<KeyCustodyStatus, ExternalFailure> {
        if self.custody_unavailable {
            return Ok(KeyCustodyStatus::Unavailable);
        }
        let (observed_at, fresh_until) = if self.custody_stale {
            (time(1), now)
        } else {
            (time(1), time(10_000))
        };
        Ok(KeyCustodyStatus::ProductionNonExportable(
            NonExportableProductionKeyIdentity::new(
                key_id,
                self.custody_technology.unwrap_or(CustodyTechnology::Hsm),
                digest(201),
                observed_at,
                fresh_until,
            ),
        ))
    }
}

#[derive(Default)]
struct MemoryReplayFixture {
    claimed: BTreeSet<ReplayKey>,
    fail: bool,
}

impl ReplayProtector for MemoryReplayFixture {
    fn claim_once(
        &mut self,
        key: ReplayKey,
        retain_until: Time,
    ) -> Result<ReplayClaim, ExternalFailure> {
        assert_eq!(retain_until, Time::MAX);
        if self.fail {
            return Err(ExternalFailure::new(801));
        }
        if self.claimed.insert(key) {
            Ok(ReplayClaim::Claimed)
        } else {
            Ok(ReplayClaim::AlreadyClaimed)
        }
    }
}

struct PermitInterlockFixture {
    envelope: Digest,
    valid_until: Time,
    maximum_lease_ttl: Ttl,
    deny: bool,
    fail: bool,
    phases: Vec<InterlockPhase>,
}

impl PermitInterlockFixture {
    fn for_binding(binding: Binding) -> Self {
        Self {
            envelope: binding.safety_envelope_digest(),
            valid_until: time(10_000),
            maximum_lease_ttl: ttl(100),
            deny: false,
            fail: false,
            phases: Vec::new(),
        }
    }
}

impl SafetyEnvelopeInterlock for PermitInterlockFixture {
    fn evaluate(
        &mut self,
        request: InterlockRequest,
    ) -> Result<InterlockDecision, ExternalFailure> {
        self.phases.push(request.phase());
        if self.fail {
            return Err(ExternalFailure::new(901));
        }
        if self.deny {
            return Ok(InterlockDecision::Deny);
        }
        Ok(InterlockDecision::Permit(SafetyPermit::new(
            self.envelope,
            self.valid_until,
            self.maximum_lease_ttl,
        )))
    }
}

struct PermitSafetyInhibitFixture {
    decision: Option<InhibitDecision>,
    observed_at: Time,
    fresh_until: Time,
    fail: bool,
    phases: Vec<InhibitPhase>,
}

impl Default for PermitSafetyInhibitFixture {
    fn default() -> Self {
        Self {
            decision: None,
            observed_at: time(1),
            fresh_until: time(10_000),
            fail: false,
            phases: Vec::new(),
        }
    }
}

impl SafetyInhibit for PermitSafetyInhibitFixture {
    fn check(&mut self, request: InhibitRequest) -> Result<InhibitDecision, ExternalFailure> {
        self.phases.push(request.phase());
        if self.fail {
            return Err(ExternalFailure::new(951));
        }
        if let Some(decision) = self.decision {
            return Ok(decision);
        }
        Ok(InhibitDecision::Permit(InhibitPermit::new(
            request.binding(),
            request.phase(),
            self.observed_at,
            self.fresh_until,
        )))
    }
}

struct RecordingWatchdogFixture {
    health: WatchdogHealth,
    armed: Option<WatchdogArm>,
    acknowledged: bool,
    trips: Vec<WatchdogTripReason>,
    fail_arm: bool,
    fail_acknowledge: bool,
    fail_trip: bool,
}

impl Default for RecordingWatchdogFixture {
    fn default() -> Self {
        Self {
            health: WatchdogHealth::Ready,
            armed: None,
            acknowledged: false,
            trips: Vec::new(),
            fail_arm: false,
            fail_acknowledge: false,
            fail_trip: false,
        }
    }
}

impl FailClosedWatchdog for RecordingWatchdogFixture {
    fn health(&mut self, _now: Time) -> Result<WatchdogHealth, ExternalFailure> {
        Ok(self.health)
    }

    fn arm(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure> {
        if self.fail_arm {
            return Err(ExternalFailure::new(1_001));
        }
        self.armed = Some(request);
        Ok(())
    }

    fn tighten(
        &mut self,
        existing: WatchdogArm,
        tightened: WatchdogArm,
    ) -> Result<(), ExternalFailure> {
        if self.armed != Some(existing)
            || self.acknowledged
            || tightened.binding() != existing.binding()
            || tightened.capability_id() != existing.capability_id()
            || tightened.lease_id() != existing.lease_id()
            || tightened.lease_expires_at() != existing.lease_expires_at()
            || tightened.receipt_deadline() > existing.receipt_deadline()
        {
            return Err(ExternalFailure::new(1_006));
        }
        self.armed = Some(tightened);
        Ok(())
    }

    fn verify_armed(&mut self, request: WatchdogArm, now: Time) -> Result<bool, ExternalFailure> {
        Ok(self.armed == Some(request)
            && !self.acknowledged
            && self.trips.is_empty()
            && now < request.lease_expires_at()
            && now < request.receipt_deadline())
    }

    fn acknowledge(&mut self, request: WatchdogArm) -> Result<(), ExternalFailure> {
        if self.fail_acknowledge || self.armed != Some(request) {
            return Err(ExternalFailure::new(1_002));
        }
        self.acknowledged = true;
        Ok(())
    }

    fn trip(
        &mut self,
        request: WatchdogArm,
        reason: WatchdogTripReason,
    ) -> Result<(), ExternalFailure> {
        if self.fail_trip {
            return Err(ExternalFailure::new(1_003));
        }
        if self.armed.is_some() && self.armed != Some(request) {
            return Err(ExternalFailure::new(1_003));
        }
        self.trips.push(reason);
        self.health = WatchdogHealth::Unsafe;
        Ok(())
    }
}

struct RecordingEffectAdapter {
    now: Time,
    post_consume_now: Option<Time>,
    consumed: usize,
    fail: bool,
    fail_post_consume_time: bool,
}

impl RecordingEffectAdapter {
    const fn at(now: Time) -> Self {
        Self {
            now,
            post_consume_now: None,
            consumed: 0,
            fail: false,
            fail_post_consume_time: false,
        }
    }
}

impl AtomicEffectAdapter for RecordingEffectAdapter {
    fn trusted_now(&mut self) -> Result<Time, ExternalFailure> {
        if self.consumed > 0 && self.fail_post_consume_time {
            return Err(ExternalFailure::new(1_102));
        }
        Ok(if self.consumed > 0 {
            self.post_consume_now.unwrap_or(self.now)
        } else {
            self.now
        })
    }

    fn consume_once(
        &mut self,
        dispatch: EffectDispatch<'_>,
    ) -> Result<EffectOutcome, ExternalFailure> {
        if self.fail || dispatch.authorized_at() >= dispatch.expires_at() {
            return Err(ExternalFailure::new(1_101));
        }
        self.consumed += 1;
        Ok(EffectOutcome::Applied)
    }
}

fn raw16(value: u8) -> [u8; 16] {
    [value; 16]
}

fn raw64(value: u8) -> [u8; 64] {
    [value; 64]
}

fn digest(value: u8) -> Digest {
    Digest::new([value; 64])
}

fn domain(value: u8) -> DomainId {
    DomainId::new(raw64(value)).expect("non-zero test ID")
}

fn operation(value: u8) -> OperationId {
    OperationId::new(raw16(value)).expect("non-zero test ID")
}

fn subject(value: u8) -> SubjectId {
    SubjectId::new(raw64(value)).expect("non-zero test ID")
}

fn adapter(value: u8) -> AdapterId {
    AdapterId::new(raw64(value)).expect("non-zero test ID")
}

fn effect(value: u8) -> EffectId {
    EffectId::new(raw64(value)).expect("non-zero test ID")
}

fn key(value: u8) -> KeyId {
    KeyId::new(raw64(value)).expect("non-zero test ID")
}

fn prepare_id(value: u8) -> PrepareId {
    PrepareId::new(raw16(value)).expect("non-zero test ID")
}

fn capability_id(value: u8) -> CapabilityId {
    CapabilityId::new(raw16(value)).expect("non-zero test ID")
}

fn lease_id(value: u8) -> LeaseId {
    LeaseId::new(raw16(value)).expect("non-zero test ID")
}

fn time(value: u64) -> Time {
    Time::from_millis_since_epoch(value)
}

fn ttl(value: u64) -> Ttl {
    Ttl::from_millis(value).expect("non-zero test TTL")
}

fn binding_with(adapter_value: u8, effect_value: u8, state_value: u8) -> Binding {
    binding_with_class(
        adapter_value,
        effect_value,
        state_value,
        AuthorityClass::ProductionHsm,
    )
}

fn binding_with_class(
    adapter_value: u8,
    effect_value: u8,
    state_value: u8,
    authority_class: AuthorityClass,
) -> Binding {
    Binding::new(
        domain(1),
        7,
        authority_class,
        digest(220),
        digest(221),
        digest(222),
        operation(2),
        subject(3),
        digest(state_value),
        digest(5),
        digest(6),
        digest(7),
        adapter(adapter_value),
        effect(effect_value),
        digest(9),
    )
    .expect("valid test binding")
}

fn binding() -> Binding {
    binding_with(7, 8, 4)
}

#[test]
fn semantic_and_key_identities_preserve_all_512_bits() {
    let left = [0x51; 64];
    let mut right = left;
    right[31] ^= 0x01;
    assert_ne!(
        DomainId::new(left).expect("domain"),
        DomainId::new(right).expect("domain tail")
    );
    assert_ne!(
        SubjectId::new(left).expect("subject"),
        SubjectId::new(right).expect("subject tail")
    );
    assert_ne!(
        AdapterId::new(left).expect("adapter"),
        AdapterId::new(right).expect("adapter tail")
    );
    assert_ne!(
        EffectId::new(left).expect("effect"),
        EffectId::new(right).expect("effect tail")
    );
    assert_ne!(
        KeyId::new(left).expect("key"),
        KeyId::new(right).expect("key tail")
    );
}

fn policy() -> CorePolicy {
    policy_with_class(AuthorityClass::ProductionHsm)
}

fn policy_with_class(authority_class: AuthorityClass) -> CorePolicy {
    CorePolicy::new(
        domain(1),
        7,
        authority_class,
        digest(220),
        digest(221),
        key(10),
        key(11),
        digest(201),
        digest(201),
        ttl(100),
        ttl(500),
        ttl(100),
        ttl(50),
    )
    .expect("valid test policy")
}

fn converged(for_binding: Binding) -> Converged {
    Candidate::new(policy())
        .converge(ConvergenceEvidence::new(
            for_binding,
            for_binding,
            for_binding,
        ))
        .expect("exact test convergence")
}

fn prepared(
    provider: &mut TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence,
    for_binding: Binding,
    prepare_value: u8,
) -> Prepared {
    let mut replay = MemoryReplayFixture::default();
    converged(for_binding)
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(prepare_value),
            digest(210),
            provider,
            &mut replay,
        )
        .expect("test PREPARE")
}

fn committed(
    provider: &mut TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence,
    replay: &mut MemoryReplayFixture,
    interlock: &mut PermitInterlockFixture,
    for_binding: Binding,
    prepare_value: u8,
    capability_value: u8,
) -> Committed {
    let mut inhibit = PermitSafetyInhibitFixture::default();
    prepared(provider, for_binding, prepare_value)
        .commit(
            time(1_010),
            ttl(400),
            capability_id(capability_value),
            provider,
            replay,
            interlock,
            &mut inhibit,
        )
        .expect("test COMMIT")
}

// A single helper exposes each independently controlled test double and each
// artifact identifier explicitly; grouping them would obscure negative-case
// substitutions in the authority-path tests.
#[allow(clippy::too_many_arguments)]
fn awaiting(
    provider: &mut TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence,
    replay: &mut MemoryReplayFixture,
    interlock: &mut PermitInterlockFixture,
    watchdog: &mut RecordingWatchdogFixture,
    for_binding: Binding,
    prepare_value: u8,
    capability_value: u8,
    lease_value: u8,
) -> AwaitingReceipt {
    let committed = committed(
        provider,
        replay,
        interlock,
        for_binding,
        prepare_value,
        capability_value,
    );
    let mut inhibit = PermitSafetyInhibitFixture::default();
    committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(for_binding, lease_id(lease_value), ttl(100)),
            provider,
            replay,
            interlock,
            &mut inhibit,
            watchdog,
        )
        .expect("test redemption")
}

fn valid_receipt(
    awaiter: &AwaitingReceipt,
    provider: &mut TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence,
) -> SignedAdapterReceipt {
    let lease = awaiter.lease().claims();
    SignedAdapterReceipt::issue(
        AdapterReceiptClaims::new(
            lease.binding(),
            lease.capability_id(),
            lease.lease_id(),
            time(1_100),
            EffectOutcome::Applied,
        ),
        policy().adapter_receipt_key(),
        provider,
    )
    .expect("test receipt")
}

fn effect_side_lease(
    awaiter: &AwaitingReceipt,
    provider: &mut TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence,
) -> EffectLease {
    let claims = awaiter.lease().claims();
    let message = claims.canonical_message();
    let signature = provider
        .sign(
            policy().authority_signing_key(),
            SignaturePurpose::EffectLease,
            message.as_bytes(),
        )
        .expect("test transport copy of lease signature");
    EffectLease::from_untrusted_parts(claims, signature)
}

#[test]
fn end_to_end_happy_path_acks_watchdog_only_after_receipt() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();

    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        20,
        21,
        22,
    );
    assert!(watchdog.armed.is_some());
    assert!(!watchdog.acknowledged);
    let receipt = valid_receipt(&awaiter, &mut provider);
    let completed = awaiter
        .accept_receipt(
            time(1_110),
            receipt,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect("valid receipt accepted");

    assert_eq!(completed.binding(), binding());
    assert!(watchdog.acknowledged);
    assert!(watchdog.trips.is_empty());
    assert_eq!(
        interlock.phases,
        vec![InterlockPhase::Commit, InterlockPhase::PointOfUse]
    );
}

#[test]
fn exact_convergence_rejects_any_digest_mismatch() {
    let intended = binding();
    let different = binding_with(7, 8, 99);
    let error = Candidate::new(policy())
        .converge(ConvergenceEvidence::new(intended, different, intended))
        .expect_err("mismatch must fail");
    assert_eq!(error, CoreError::ExactConvergenceFailed);
}

#[test]
fn production_policy_rejects_evidence_class_binding_before_prepare() {
    let production_policy = CorePolicy::new(
        domain(1),
        7,
        AuthorityClass::ProductionHsm,
        digest(220),
        digest(221),
        key(10),
        key(11),
        digest(201),
        digest(201),
        ttl(100),
        ttl(500),
        ttl(100),
        ttl(50),
    )
    .expect("valid production-class test policy");
    let evidence_binding = binding_with_class(7, 8, 4, AuthorityClass::NonproductionEvidenceOnly);
    let error = Candidate::new(production_policy)
        .converge(ConvergenceEvidence::new(
            evidence_binding,
            evidence_binding,
            evidence_binding,
        ))
        .expect_err("evidence authority class must never satisfy production policy");
    assert_eq!(error, CoreError::BindingMismatch);
    assert_ne!(
        evidence_binding,
        binding_with_class(7, 8, 4, AuthorityClass::ProductionHsm)
    );
}

#[test]
fn authority_class_requires_exact_hsm_tpm_or_fixture_custody() {
    let tpm_binding = binding_with_class(7, 8, 4, AuthorityClass::ProductionTpm);
    let tpm_policy = policy_with_class(AuthorityClass::ProductionTpm);
    let mut wrong_provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let error = Candidate::new(tpm_policy)
        .converge(ConvergenceEvidence::new(
            tpm_binding,
            tpm_binding,
            tpm_binding,
        ))
        .expect("exact TPM convergence")
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(140),
            digest(230),
            &mut wrong_provider,
            &mut replay,
        )
        .expect_err("an HSM attestation cannot satisfy TPM even at PREPARE");
    assert_eq!(error, CoreError::KeyCustodyTechnologyMismatch);
    assert!(replay.claimed.is_empty());

    let mut tpm_provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
        custody_technology: Some(CustodyTechnology::Tpm),
        ..TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default()
    };
    let mut replay = MemoryReplayFixture::default();
    let prepared = Candidate::new(tpm_policy)
        .converge(ConvergenceEvidence::new(
            tpm_binding,
            tpm_binding,
            tpm_binding,
        ))
        .expect("exact TPM convergence")
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(142),
            digest(231),
            &mut tpm_provider,
            &mut replay,
        )
        .expect("non-authorizing prepare");
    let mut interlock = PermitInterlockFixture::for_binding(tpm_binding);
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let committed = prepared
        .commit(
            time(1_010),
            ttl(100),
            capability_id(143),
            &mut tpm_provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect("matching TPM test facade reaches the classed code path");
    assert_eq!(
        committed.capability().claims().binding().authority_class(),
        AuthorityClass::ProductionTpm
    );
}

#[test]
fn evidence_fixture_can_only_create_evidence_class_artifacts() {
    let evidence_binding = binding_with_class(7, 8, 4, AuthorityClass::NonproductionEvidenceOnly);
    let mut fixture = NonProductionDeterministicSignatureFixture::default();
    let mut replay = MemoryReplayFixture::default();
    let prepared = Candidate::new(policy_with_class(AuthorityClass::NonproductionEvidenceOnly))
        .converge(ConvergenceEvidence::new(
            evidence_binding,
            evidence_binding,
            evidence_binding,
        ))
        .expect("exact evidence-only convergence")
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(144),
            digest(232),
            &mut fixture,
            &mut replay,
        )
        .expect("evidence PREPARE");
    let mut interlock = PermitInterlockFixture::for_binding(evidence_binding);
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let committed = prepared
        .commit(
            time(1_010),
            ttl(100),
            capability_id(145),
            &mut fixture,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect("fixture may exercise only the evidence-class typestate");
    assert_eq!(
        committed.capability().claims().binding().authority_class(),
        AuthorityClass::NonproductionEvidenceOnly
    );
}

#[test]
fn same_execution_intent_cannot_prepare_again_with_fresh_artifact_id() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(50),
            prepare_id(28),
            digest(211),
            &mut provider,
            &mut replay,
        )
        .expect("first traversal intent claim");
    let error = converged(binding())
        .prepare_with_replay(
            time(1_001),
            ttl(50),
            prepare_id(29),
            digest(211),
            &mut provider,
            &mut replay,
        )
        .expect_err("fresh PREPARE ID must not re-authorize the same execution intent");
    assert_eq!(
        error,
        CoreError::ReplayDetected(ReplayClass::TraversalIntent)
    );
}

#[test]
fn zero_durable_consumption_digest_is_rejected_before_replay_or_signing() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let error = converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(20),
            Digest::new([0; 64]),
            &mut provider,
            &mut replay,
        )
        .expect_err("zero durable consumption identity must fail closed");
    assert_eq!(
        error,
        CoreError::InvalidPolicy("durable consumption digest must be non-zero")
    );
    assert!(replay.claimed.is_empty());
}

#[test]
fn prepare_without_durable_replay_provider_fails_closed() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let error = converged(binding())
        .prepare(time(1_000), ttl(50), prepare_id(27), &mut provider)
        .expect_err("non-durable PREPARE must be unavailable");
    assert_eq!(error, CoreError::ReplayStoreFailure(60_001));
}

#[test]
fn prepare_is_non_authorizing_and_expires_at_boundary() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let prepared = converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(50),
            prepare_id(30),
            digest(212),
            &mut provider,
            &mut replay,
        )
        .expect("PREPARE issued");

    assert_eq!(prepared.prepare_token().claims().expires_at(), time(1_050));
    assert_eq!(replay.claimed.len(), 1);
    assert!(interlock.phases.is_empty());
    let error = prepared
        .commit(
            time(1_050),
            ttl(100),
            capability_id(31),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("expiry is exclusive");
    assert_eq!(error, CoreError::Expired(ArtifactKind::Prepare));
}

#[test]
fn sole_commit_is_enforced_by_durable_prepare_claim() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();

    prepared(&mut provider, binding(), 40)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(41),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect("first commit");
    let error = prepared(&mut provider, binding(), 40)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(42),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("second commit must replay-fail");
    assert_eq!(error, CoreError::ReplayDetected(ReplayClass::PrepareCommit));
}

#[test]
fn commit_denial_does_not_create_a_capability_or_claim_prepare() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    interlock.deny = true;

    let error = prepared(&mut provider, binding(), 50)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(51),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("denied commit");
    assert_eq!(error, CoreError::InterlockDenied);
    assert!(replay.claimed.is_empty());
}

#[test]
fn interlock_envelope_mismatch_is_rejected() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    interlock.envelope = digest(77);

    let error = prepared(&mut provider, binding(), 52)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(53),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("wrong envelope");
    assert_eq!(error, CoreError::InterlockMismatch);
}

#[test]
fn point_of_use_rejects_adapter_or_effect_binding_mismatch() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut watchdog = RecordingWatchdogFixture::default();
    let committed = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        60,
        61,
    );

    let error = committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding_with(70, 8, 4), lease_id(62), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog,
        )
        .expect_err("adapter mismatch");
    assert_eq!(error, CoreError::BindingMismatch);
    assert!(watchdog.armed.is_none());
}

#[test]
fn capability_expiry_and_lease_overrun_are_rejected() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut watchdog = RecordingWatchdogFixture::default();
    let committed = prepared(&mut provider, binding(), 63)
        .commit(
            time(1_010),
            ttl(40),
            capability_id(64),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect("short capability");

    let error = committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(65), ttl(40)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog,
        )
        .expect_err("lease cannot exceed capability");
    assert_eq!(error, CoreError::Expired(ArtifactKind::Capability));
}

#[test]
fn capability_redemption_is_single_use_even_across_recreated_state() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut watchdog_one = RecordingWatchdogFixture::default();
    let mut watchdog_two = RecordingWatchdogFixture::default();

    let first = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        66,
        68,
    );
    first
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(69), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog_one,
        )
        .expect("first redemption");

    let recreated = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        67,
        68,
    );
    let error = recreated
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(70), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog_two,
        )
        .expect_err("same capability ID must replay-fail");
    assert_eq!(
        error,
        CoreError::ReplayDetected(ReplayClass::CapabilityRedemption)
    );
    assert!(watchdog_two.armed.is_none());
}

#[test]
fn unsafe_watchdog_blocks_point_of_use_before_claim_or_lease() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let committed = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        71,
        72,
    );
    let claims_before = replay.claimed.len();
    let mut watchdog = RecordingWatchdogFixture {
        health: WatchdogHealth::Unsafe,
        ..RecordingWatchdogFixture::default()
    };

    let error = committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(73), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog,
        )
        .expect_err("unsafe watchdog");
    assert_eq!(error, CoreError::WatchdogUnsafe);
    assert_eq!(replay.claimed.len(), claims_before);
    assert!(watchdog.armed.is_none());
}

#[test]
fn lease_signing_failure_after_arm_trips_watchdog() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let committed = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        74,
        75,
    );
    let mut watchdog = RecordingWatchdogFixture::default();
    provider.signatures.fail_sign_for = Some(SignaturePurpose::EffectLease);

    let error = committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(76), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog,
        )
        .expect_err("lease signing failed");
    assert_eq!(error, CoreError::SignatureProviderFailure(701));
    assert_eq!(
        watchdog.trips,
        vec![WatchdogTripReason::LeaseIssuanceFailedAfterArm]
    );
}

#[test]
fn mismatched_receipt_trips_fail_closed_watchdog() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        77,
        78,
        79,
    );
    let lease = awaiter.lease().claims();
    let bad_receipt = SignedAdapterReceipt::issue(
        AdapterReceiptClaims::new(
            binding_with(7, 88, 4),
            lease.capability_id(),
            lease.lease_id(),
            time(1_100),
            EffectOutcome::Applied,
        ),
        policy().adapter_receipt_key(),
        &mut provider,
    )
    .expect("signed but semantically wrong receipt");

    let error = awaiter
        .accept_receipt(
            time(1_110),
            bad_receipt,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("mismatched receipt");
    assert_eq!(error, CoreError::ReceiptMismatch);
    assert_eq!(watchdog.trips, vec![WatchdogTripReason::InvalidReceipt]);
}

#[test]
fn signature_purpose_separation_rejects_out_of_order_artifact() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        80,
        81,
        82,
    );
    let lease = awaiter.lease().claims();
    let claims = AdapterReceiptClaims::new(
        binding(),
        lease.capability_id(),
        lease.lease_id(),
        time(1_100),
        EffectOutcome::Applied,
    );
    let message = claims.canonical_message();
    let wrong_purpose_signature = provider
        .sign(
            policy().adapter_receipt_key(),
            SignaturePurpose::NonAuthorizingPrepare,
            message.as_bytes(),
        )
        .expect("fixture signature");
    let out_of_order = SignedAdapterReceipt::from_untrusted_parts(claims, wrong_purpose_signature);

    let error = awaiter
        .accept_receipt(
            time(1_110),
            out_of_order,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("wrong signature purpose");
    assert_eq!(error, CoreError::InvalidSignature(ArtifactKind::Receipt));
    assert_eq!(watchdog.trips, vec![WatchdogTripReason::InvalidReceipt]);
}

#[test]
fn receipt_completion_must_be_within_the_effect_lease() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        83,
        84,
        85,
    );
    let lease = awaiter.lease().claims();
    let late_completion = SignedAdapterReceipt::issue(
        AdapterReceiptClaims::new(
            binding(),
            lease.capability_id(),
            lease.lease_id(),
            time(1_121),
            EffectOutcome::Applied,
        ),
        policy().adapter_receipt_key(),
        &mut provider,
    )
    .expect("test receipt");

    let error = awaiter
        .accept_receipt(
            time(1_110),
            late_completion,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("completion after lease");
    assert_eq!(error, CoreError::CompletionOutsideLease);
    assert_eq!(watchdog.trips, vec![WatchdogTripReason::InvalidReceipt]);
}

#[test]
fn receipt_deadline_poll_trips_and_returns_stopped_state() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        86,
        87,
        88,
    );

    match awaiter
        .poll_watchdog(time(1_170), &mut watchdog)
        .expect("watchdog trip")
    {
        ReceiptPoll::Stopped(stopped) => {
            assert_eq!(stopped.reason(), WatchdogTripReason::ReceiptDeadlineElapsed);
        }
        ReceiptPoll::Waiting(_) => panic!("deadline boundary must stop"),
    }
    assert_eq!(
        watchdog.trips,
        vec![WatchdogTripReason::ReceiptDeadlineElapsed]
    );
}

#[test]
fn receipt_at_exact_lease_expiry_is_rejected_before_watchdog_grace() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        144,
        145,
        146,
    );
    let receipt = valid_receipt(&awaiter, &mut provider);
    assert_eq!(awaiter.lease().claims().expires_at(), time(1_120));
    assert_eq!(awaiter.lease().claims().receipt_deadline(), time(1_170));

    let error = awaiter
        .accept_receipt(
            time(1_120),
            receipt,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("lease expiry equality must reject success and ACK");
    assert_eq!(error, CoreError::Expired(ArtifactKind::Receipt));
    assert!(!watchdog.acknowledged);
    assert_eq!(watchdog.trips, vec![WatchdogTripReason::InvalidReceipt]);
}

#[test]
fn receipt_after_lease_but_before_watchdog_timeout_is_rejected() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        147,
        148,
        149,
    );
    let receipt = valid_receipt(&awaiter, &mut provider);

    let error = awaiter
        .accept_receipt(
            time(1_130),
            receipt,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("watchdog grace must never extend successful authorization");
    assert_eq!(error, CoreError::Expired(ArtifactKind::Receipt));
    assert!(!watchdog.acknowledged);
    assert_eq!(watchdog.trips, vec![WatchdogTripReason::InvalidReceipt]);
}

#[test]
fn replayed_lease_receipt_trips_second_watchdog() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog_one = RecordingWatchdogFixture::default();
    let first = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog_one,
        binding(),
        89,
        90,
        91,
    );
    let first_receipt = valid_receipt(&first, &mut provider);
    first
        .accept_receipt(
            time(1_110),
            first_receipt,
            &mut provider,
            &mut replay,
            &mut watchdog_one,
        )
        .expect("first receipt");

    let mut watchdog_two = RecordingWatchdogFixture::default();
    let second = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog_two,
        binding(),
        92,
        93,
        91,
    );
    let second_receipt = valid_receipt(&second, &mut provider);
    let error = second
        .accept_receipt(
            time(1_110),
            second_receipt,
            &mut provider,
            &mut replay,
            &mut watchdog_two,
        )
        .expect_err("reused lease ID");
    assert_eq!(error, CoreError::ReplayDetected(ReplayClass::LeaseReceipt));
    assert_eq!(watchdog_two.trips, vec![WatchdogTripReason::ReceiptReplay]);
}

#[test]
fn watchdog_acknowledgement_failure_trips_fail_closed() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        94,
        95,
        96,
    );
    let receipt = valid_receipt(&awaiter, &mut provider);
    watchdog.fail_acknowledge = true;

    let error = awaiter
        .accept_receipt(
            time(1_110),
            receipt,
            &mut provider,
            &mut replay,
            &mut watchdog,
        )
        .expect_err("acknowledgement failure");
    assert_eq!(error, CoreError::WatchdogFailure(1_002));
    assert_eq!(
        watchdog.trips,
        vec![WatchdogTripReason::AcknowledgementFailed]
    );
}

#[test]
fn time_rollback_is_rejected_as_not_yet_valid() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let error = prepared(&mut provider, binding(), 97)
        .commit(
            time(999),
            ttl(100),
            capability_id(98),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("time rollback");
    assert_eq!(error, CoreError::NotYetValid(ArtifactKind::Prepare));
}

#[test]
fn top_commit_rejects_explicitly_nonproduction_signature_fixture() {
    let mut provider = NonProductionDeterministicSignatureFixture::default();
    let mut replay = MemoryReplayFixture::default();
    let interlock = PermitInterlockFixture::for_binding(binding());
    let inhibit = PermitSafetyInhibitFixture::default();
    let error = converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(101),
            digest(213),
            &mut provider,
            &mut replay,
        )
        .expect_err("even PREPARE must reject a production-class fixture signer");
    assert_eq!(error, CoreError::NonProductionKeyCustody);
    assert!(replay.claimed.is_empty());
    assert!(interlock.phases.is_empty());
    assert!(inhibit.phases.is_empty());
}

#[test]
fn top_commit_fails_closed_when_hsm_status_is_unavailable() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
        custody_unavailable: true,
        ..TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default()
    };
    let mut replay = MemoryReplayFixture::default();

    let error = converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(103),
            digest(214),
            &mut provider,
            &mut replay,
        )
        .expect_err("unavailable custody must fail closed before PREPARE");
    assert_eq!(error, CoreError::KeyCustodyUnavailable);
    assert!(replay.claimed.is_empty());
}

#[test]
fn top_commit_rejects_stale_hardware_custody_status() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence {
        custody_stale: true,
        ..TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default()
    };
    let mut replay = MemoryReplayFixture::default();

    let error = converged(binding())
        .prepare_with_replay(
            time(1_000),
            ttl(100),
            prepare_id(105),
            digest(215),
            &mut provider,
            &mut replay,
        )
        .expect_err("stale custody status must fail closed before PREPARE");
    assert_eq!(error, CoreError::KeyCustodyStatusStale);
    assert!(replay.claimed.is_empty());
}

#[test]
fn inhibit_block_prevents_commit_without_spending_prepare() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture {
        decision: Some(InhibitDecision::Block),
        ..PermitSafetyInhibitFixture::default()
    };

    let error = prepared(&mut provider, binding(), 107)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(108),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("BLOCK must prevent commit");
    assert_eq!(error, CoreError::SafetyInhibitBlocked);
    assert!(replay.claimed.is_empty());
    assert!(interlock.phases.is_empty());
    assert_eq!(inhibit.phases, vec![InhibitPhase::Commit]);
}

#[test]
fn inhibit_stop_prevents_lease_redemption_and_watchdog_arm() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let committed = committed(
        &mut provider,
        &mut replay,
        &mut interlock,
        binding(),
        109,
        110,
    );
    let claims_before = replay.claimed.len();
    let mut inhibit = PermitSafetyInhibitFixture {
        decision: Some(InhibitDecision::Stop),
        ..PermitSafetyInhibitFixture::default()
    };
    let mut watchdog = RecordingWatchdogFixture::default();

    let error = committed
        .redeem_at_point_of_use(
            time(1_020),
            PointOfUseRequest::new(binding(), lease_id(111), ttl(50)),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
            &mut watchdog,
        )
        .expect_err("STOP must prevent lease redemption");
    assert_eq!(error, CoreError::SafetyInhibitStop);
    assert_eq!(replay.claimed.len(), claims_before);
    assert!(watchdog.armed.is_none());
    assert_eq!(inhibit.phases, vec![InhibitPhase::LeaseRedemption]);
}

#[test]
fn unavailable_inhibit_fails_closed() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture {
        fail: true,
        ..PermitSafetyInhibitFixture::default()
    };

    let error = prepared(&mut provider, binding(), 112)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(113),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("inhibit transport/provider failure");
    assert_eq!(error, CoreError::SafetyInhibitFailure(951));
    assert!(replay.claimed.is_empty());
}

#[test]
fn inhibit_cannot_widen_or_substitute_the_exact_authority_binding() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut inhibit = PermitSafetyInhibitFixture {
        decision: Some(InhibitDecision::Permit(InhibitPermit::new(
            binding_with(99, 8, 4),
            InhibitPhase::Commit,
            time(1),
            time(10_000),
        ))),
        ..PermitSafetyInhibitFixture::default()
    };

    let error = prepared(&mut provider, binding(), 114)
        .commit(
            time(1_010),
            ttl(100),
            capability_id(115),
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut inhibit,
        )
        .expect_err("permit cannot substitute a broader/different binding");
    assert_eq!(error, CoreError::SafetyInhibitMismatch);
    assert!(replay.claimed.is_empty());
}

#[test]
fn effect_requires_fresh_inhibit_and_redeems_lease_once() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        116,
        117,
        118,
    );
    let first_copy = effect_side_lease(&awaiter, &mut provider);
    let replay_copy = effect_side_lease(&awaiter, &mut provider);
    let mut inhibit = PermitSafetyInhibitFixture::default();

    let mut effect_adapter = RecordingEffectAdapter::at(time(1_050));
    let applied = first_copy
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut watchdog,
            &mut effect_adapter,
        )
        .expect("fresh exact effect dispatch");
    assert_eq!(applied.binding(), binding());
    assert_eq!(applied.lease_id(), lease_id(118));
    assert_eq!(applied.outcome(), EffectOutcome::Applied);
    assert_eq!(effect_adapter.consumed, 1);
    assert_eq!(inhibit.phases, vec![InhibitPhase::Effect]);

    effect_adapter.now = time(1_051);
    let error = replay_copy
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut watchdog,
            &mut effect_adapter,
        )
        .expect_err("lease effect is single-use");
    assert_eq!(error, CoreError::ReplayDetected(ReplayClass::LeaseEffect));
    assert_eq!(effect_adapter.consumed, 1);
}

#[test]
fn adapter_failure_after_durable_effect_claim_trips_watchdog() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        130,
        131,
        132,
    );
    let effect_lease = effect_side_lease(&awaiter, &mut provider);
    let claimed_before = replay.claimed.len();
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut effect_adapter = RecordingEffectAdapter::at(time(1_050));
    effect_adapter.fail = true;

    let error = effect_lease
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut watchdog,
            &mut effect_adapter,
        )
        .expect_err("adapter ambiguity after the permanent claim must stop");
    assert_eq!(error, CoreError::EffectAdapterFailure(1_101));
    assert_eq!(replay.claimed.len(), claimed_before + 1);
    assert_eq!(effect_adapter.consumed, 0);
    assert_eq!(
        watchdog.trips,
        vec![WatchdogTripReason::EffectAdapterFailedAfterConsumptionClaim]
    );
}

#[test]
fn untrusted_or_expired_post_effect_time_trips_watchdog() {
    for fail_time in [false, true] {
        let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
        let mut replay = MemoryReplayFixture::default();
        let mut interlock = PermitInterlockFixture::for_binding(binding());
        let mut watchdog = RecordingWatchdogFixture::default();
        let base = if fail_time { 136 } else { 133 };
        let awaiter = awaiting(
            &mut provider,
            &mut replay,
            &mut interlock,
            &mut watchdog,
            binding(),
            base,
            base + 1,
            base + 2,
        );
        let effect_lease = effect_side_lease(&awaiter, &mut provider);
        let claimed_before = replay.claimed.len();
        let mut inhibit = PermitSafetyInhibitFixture::default();
        let mut effect_adapter = RecordingEffectAdapter::at(time(1_050));
        effect_adapter.post_consume_now = Some(time(1_120));
        effect_adapter.fail_post_consume_time = fail_time;

        let error = effect_lease
            .dispatch_effect_at_point_of_use(
                policy(),
                binding(),
                awaiter.watchdog_arm(),
                &mut provider,
                &mut replay,
                &mut inhibit,
                &mut watchdog,
                &mut effect_adapter,
            )
            .expect_err("post-effect time ambiguity or expiry must stop");
        assert_eq!(
            error,
            if fail_time {
                CoreError::EffectAdapterFailure(1_102)
            } else {
                CoreError::CompletionOutsideLease
            }
        );
        assert_eq!(replay.claimed.len(), claimed_before + 1);
        assert_eq!(effect_adapter.consumed, 1);
        assert_eq!(
            watchdog.trips,
            vec![WatchdogTripReason::EffectCompletionInvalidAfterConsumptionClaim]
        );
    }
}

#[test]
fn stale_effect_inhibit_prevents_effect_and_does_not_spend_lease() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        119,
        120,
        121,
    );
    let effect_lease = effect_side_lease(&awaiter, &mut provider);
    let claimed_before = replay.claimed.len();
    let mut inhibit = PermitSafetyInhibitFixture {
        observed_at: time(1),
        fresh_until: time(1_050),
        ..PermitSafetyInhibitFixture::default()
    };
    let mut effect_adapter = RecordingEffectAdapter::at(time(1_050));

    let error = effect_lease
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut watchdog,
            &mut effect_adapter,
        )
        .expect_err("freshness expiry is exclusive");
    assert_eq!(error, CoreError::SafetyInhibitStale);
    assert_eq!(replay.claimed.len(), claimed_before);
    assert_eq!(effect_adapter.consumed, 0);
}

#[test]
fn missing_exact_watchdog_arm_blocks_point_of_use_before_replay_or_effect() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut original_watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut original_watchdog,
        binding(),
        125,
        126,
        127,
    );
    let effect_lease = effect_side_lease(&awaiter, &mut provider);
    let claimed_before = replay.claimed.len();
    let mut replacement_watchdog = RecordingWatchdogFixture::default();
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut effect_adapter = RecordingEffectAdapter::at(time(1_050));

    let error = effect_lease
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut replacement_watchdog,
            &mut effect_adapter,
        )
        .expect_err("general health without the exact persisted arm must deny");
    // The missing exact arm is itself unsafe. A real independent watchdog must
    // make STOP idempotent even if its local arm record is missing.
    assert_eq!(error, CoreError::WatchdogArmMismatch);
    assert_eq!(
        replacement_watchdog.trips,
        vec![WatchdogTripReason::PointOfUseArmMissing]
    );
    assert_eq!(replay.claimed.len(), claimed_before);
    assert_eq!(effect_adapter.consumed, 0);
}

#[test]
fn adapter_trusted_time_rejects_expired_dispatch_without_effect() {
    let mut provider = TestOnlyClaimedProductionStatusProviderNoPhysicalEvidence::default();
    let mut replay = MemoryReplayFixture::default();
    let mut interlock = PermitInterlockFixture::for_binding(binding());
    let mut watchdog = RecordingWatchdogFixture::default();
    let awaiter = awaiting(
        &mut provider,
        &mut replay,
        &mut interlock,
        &mut watchdog,
        binding(),
        122,
        123,
        124,
    );
    let effect_lease = effect_side_lease(&awaiter, &mut provider);
    let claimed_before = replay.claimed.len();
    let mut inhibit = PermitSafetyInhibitFixture::default();
    let mut effect_adapter = RecordingEffectAdapter::at(time(1_120));
    let error = effect_lease
        .dispatch_effect_at_point_of_use(
            policy(),
            binding(),
            awaiter.watchdog_arm(),
            &mut provider,
            &mut replay,
            &mut inhibit,
            &mut watchdog,
            &mut effect_adapter,
        )
        .expect_err("expiry boundary must deny before adapter consumption");
    assert_eq!(error, CoreError::Expired(ArtifactKind::Lease));
    assert_eq!(replay.claimed.len(), claimed_before);
    assert_eq!(effect_adapter.consumed, 0);
}
