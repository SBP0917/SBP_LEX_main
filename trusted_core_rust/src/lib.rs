#![forbid(unsafe_code)]
//! A small, dependency-free authority state machine.
//!
//! This crate deliberately does not implement cryptography, clocks, durable replay
//! storage, a safety interlock, or a watchdog. Those facilities are injected through
//! narrow traits and must be backed by independently administered production systems.

mod artifacts;
mod state;
mod traits;
mod types;

pub use artifacts::{
    AdapterReceiptClaims, AppliedEffect, Capability, CapabilityClaims, EffectLease, LeaseClaims,
    PrepareClaims, PrepareToken, SignedAdapterReceipt,
};
pub use state::{
    AwaitingReceipt, Candidate, ClaimedReceipt, Committed, Completed, Converged, Prepared,
    ReceiptPoll, Stopped,
};
pub use traits::{
    AtomicEffectAdapter, CustodyTechnology, EffectDispatch, ExternalFailure,
    ExternalSignatureProvider, FailClosedWatchdog, InhibitDecision, InhibitPermit, InhibitPhase,
    InhibitRequest, InterlockDecision, InterlockPhase, InterlockRequest, KeyCustodyProvider,
    KeyCustodyStatus, NonExportableProductionKeyIdentity, ProviderSignature, ReplayClaim,
    ReplayClass, ReplayKey, ReplayProtector, SafetyEnvelopeInterlock, SafetyInhibit, SafetyPermit,
    SignaturePurpose, WatchdogArm, WatchdogHealth, WatchdogTripReason, ED448_SIGNATURE_BYTES,
    HYBRID_SIGNATURE_BYTES, ML_DSA_87_SIGNATURE_BYTES, SIGNATURE_SUITE_ID,
};
pub use types::{
    AdapterId, ArtifactKind, AuthorityClass, Binding, CapabilityId, ConvergenceEvidence, CoreError,
    CorePolicy, Digest, DomainId, EffectId, EffectOutcome, KeyId, LeaseId, OperationId,
    PointOfUseRequest, PrepareId, SubjectId, Time, Ttl,
};

#[cfg(test)]
mod tests;
