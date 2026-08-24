#![forbid(unsafe_code)]
//! Process-boundary support for the Rust authority core.
//!
//! This crate deliberately contains no production substitute for an HSM/TPM,
//! rollback-resistant external replay anchor, independent safety inhibit, or
//! external fail-closed watchdog.  The ordinary build therefore cannot issue a
//! PREPARE, COMMIT, lease, or effect permit.  Explicit evidence-only fixtures
//! are compiled only with `evidence-only-fixtures`; their artifacts are tagged
//! so programme consumers can reject them.

mod production_unavailable;
mod profile;
mod replay_journal;
mod sha256;
mod sha512;
mod wire_boundary;
// Transport-independent, bounded intake for untrusted v2 frames.  This stays
// crate-private: deployment authentication and the authority typestate are not
// represented as a public software API.
#[allow(dead_code)]
mod wire_v2_session_private;
// The v2 engine is compiled but deliberately unreachable from any shipped
// route until the owner-pinned physical dependencies are provisioned. Its
// private typestates are exercised by crate-local evidence tests.
#[allow(dead_code)]
mod wire_v2_private;

#[cfg(feature = "evidence-only-fixtures")]
mod evidence;

pub use production_unavailable::ProductionDependenciesUnavailable;
pub use profile::{
    require_programme_artifact, ArtifactAuthorityClass, AuthorityProfile, EVIDENCE_PROFILE,
    PRODUCTION_HSM_PROFILE, PRODUCTION_PROFILE, PRODUCTION_TPM_PROFILE, SIGNATURE_SUITE_ID,
    WIRE_CONTRACT_SHA256,
};
pub use replay_journal::{
    ReplayJournalError, COMPILED_EVIDENCE_KNOWN_FOLDER, EVIDENCE_REPLAY_IDENTITY,
};
pub use wire_boundary::{
    inspect_convergence_frame, verify_embedded_wire_contract, NonAuthorizingWireInspection,
    WireBoundaryError,
};

#[cfg(feature = "evidence-only-fixtures")]
pub use evidence::{
    evidence_adapter_key, evidence_authority_key, EvidenceAuthorityDependencies,
    EvidenceReplayJournal,
};

/// The production binary stays unavailable until independently provisioned
/// providers are integrated and admitted.  Returning an error is intentional:
/// there is no local software-key or local-only replay fallback.
pub fn assert_production_dependencies_available() -> Result<(), &'static str> {
    Err("PRODUCTION_AUTHORITY_DEPENDENCIES_NOT_PROVISIONED")
}
