use trusted_authority_core::{
    ExternalFailure, ExternalSignatureProvider, FailClosedWatchdog, InhibitDecision,
    InhibitRequest, InterlockDecision, InterlockRequest, KeyCustodyProvider, KeyCustodyStatus,
    KeyId, ProviderSignature, ReplayClaim, ReplayKey, ReplayProtector, SafetyEnvelopeInterlock,
    SafetyInhibit, SignaturePurpose, Time, WatchdogArm, WatchdogHealth, WatchdogTripReason,
};

/// Deliberately unusable production dependency set.
///
/// It proves that an ordinary build has no software-key, local-ledger, permissive
/// interlock, inhibit, or watchdog fallback.  Real independently administered
/// providers must replace this type in a later owner-admitted integration.
#[derive(Default)]
pub struct ProductionDependenciesUnavailable;

impl ExternalSignatureProvider for ProductionDependenciesUnavailable {
    fn sign(
        &mut self,
        _key_id: KeyId,
        _purpose: SignaturePurpose,
        _canonical_message: &[u8],
    ) -> Result<ProviderSignature, ExternalFailure> {
        Err(ExternalFailure::new(10_001))
    }

    fn verify(
        &mut self,
        _key_id: KeyId,
        _purpose: SignaturePurpose,
        _canonical_message: &[u8],
        _signature: &ProviderSignature,
    ) -> Result<bool, ExternalFailure> {
        Err(ExternalFailure::new(10_002))
    }
}

impl KeyCustodyProvider for ProductionDependenciesUnavailable {
    fn key_custody_status(
        &mut self,
        _key_id: KeyId,
        _purpose: SignaturePurpose,
        _now: Time,
    ) -> Result<KeyCustodyStatus, ExternalFailure> {
        Ok(KeyCustodyStatus::Unavailable)
    }
}

impl ReplayProtector for ProductionDependenciesUnavailable {
    fn claim_once(
        &mut self,
        _key: ReplayKey,
        _retain_until: Time,
    ) -> Result<ReplayClaim, ExternalFailure> {
        Err(ExternalFailure::new(10_003))
    }
}

impl SafetyEnvelopeInterlock for ProductionDependenciesUnavailable {
    fn evaluate(
        &mut self,
        _request: InterlockRequest,
    ) -> Result<InterlockDecision, ExternalFailure> {
        Ok(InterlockDecision::Deny)
    }
}

impl SafetyInhibit for ProductionDependenciesUnavailable {
    fn check(&mut self, _request: InhibitRequest) -> Result<InhibitDecision, ExternalFailure> {
        Ok(InhibitDecision::Stop)
    }
}

impl FailClosedWatchdog for ProductionDependenciesUnavailable {
    fn health(&mut self, _now: Time) -> Result<WatchdogHealth, ExternalFailure> {
        Ok(WatchdogHealth::Unsafe)
    }

    fn arm(&mut self, _request: WatchdogArm) -> Result<(), ExternalFailure> {
        Err(ExternalFailure::new(10_004))
    }

    fn tighten(
        &mut self,
        _existing: WatchdogArm,
        _tightened: WatchdogArm,
    ) -> Result<(), ExternalFailure> {
        Err(ExternalFailure::new(10_008))
    }

    fn verify_armed(&mut self, _request: WatchdogArm, _now: Time) -> Result<bool, ExternalFailure> {
        Err(ExternalFailure::new(10_007))
    }

    fn acknowledge(&mut self, _request: WatchdogArm) -> Result<(), ExternalFailure> {
        Err(ExternalFailure::new(10_005))
    }

    fn trip(
        &mut self,
        _request: WatchdogArm,
        _reason: WatchdogTripReason,
    ) -> Result<(), ExternalFailure> {
        Err(ExternalFailure::new(10_006))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_authority_core::{Digest, KeyId};

    #[test]
    fn production_build_has_no_local_signing_fallback() {
        let mut unavailable = ProductionDependenciesUnavailable;
        let key = KeyId::new([1; 64]).expect("non-zero key");
        assert!(unavailable
            .sign(
                key,
                SignaturePurpose::CapabilityCommit,
                Digest::new([2; 64]).as_bytes()
            )
            .is_err());
        assert_eq!(
            unavailable
                .key_custody_status(
                    key,
                    SignaturePurpose::CapabilityCommit,
                    Time::from_millis_since_epoch(1)
                )
                .expect("explicit status"),
            KeyCustodyStatus::Unavailable
        );
    }
}
