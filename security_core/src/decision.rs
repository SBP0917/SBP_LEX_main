use core::fmt;

/// Closed boundary result vocabulary. There is intentionally no governance ALLOW.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClosedDecision {
    /// All Rust prerequisites for an already-authorised effect were verified.
    PermitExistingAuthorization,
    Deny(BoundaryError),
    Escalate(BoundaryError),
    Revoke(BoundaryError),
    Unsupported(Gap),
    Indeterminate(BoundaryError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Gap {
    HybridHardwareCustodyAndPinningUnavailable,
    ThreePSubstantiveEvidenceRulesExternal,
    SkgSubstantiveEvidenceRulesExternal,
    FiledFrameworkSubstantiveRulesExternal,
    FiledLifecycleOrderImplementationDefined,
    DurableReplayStoreNotInjected,
    DurableRevocationStoreNotInjected,
    TerminalAuditCanonicalSinkNotInjected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundaryError {
    Missing(&'static str),
    Malformed(&'static str),
    UnknownValue(&'static str),
    DigestMismatch(&'static str),
    SignatureInvalid,
    SignerMissing,
    SignerMismatch,
    WrongOrder(&'static str),
    Duplicate(&'static str),
    Substitution(&'static str),
    Revoked,
    Rollback,
    Replay,
    Expired,
    NotYetValid,
    FailedPrerequisite(&'static str),
    ProviderUnavailable,
    ProviderFailure(i32),
    Unsupported(Gap),
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BoundaryError {}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum Component {
    Request,
    ThreeP,
    Skg,
    Authority,
    FiledFramework,
    FiledLifecycle,
    Licence,
    TokenStack,
    HashChain,
    Audit,
    EffectPermit,
    PreEffect,
    Revocation,
    Replay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    component: Component,
    request_fingerprint: String,
}

impl Proof {
    pub(crate) fn new(
        component: Component,
        request_fingerprint: &str,
    ) -> Result<Self, BoundaryError> {
        if !crate::digest::is_sha512(request_fingerprint) {
            return Err(BoundaryError::Malformed("request_fingerprint"));
        }
        Ok(Self {
            component,
            request_fingerprint: request_fingerprint.to_owned(),
        })
    }

    pub const fn component(&self) -> Component {
        self.component
    }

    pub fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }
}
