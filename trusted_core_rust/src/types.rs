use core::fmt;

macro_rules! typed_identifier {
    ($name:ident, $label:literal, $width:literal) => {
        #[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name([u8; $width]);

        impl $name {
            pub fn new(bytes: [u8; $width]) -> Result<Self, CoreError> {
                if bytes.iter().all(|byte| *byte == 0) {
                    return Err(CoreError::ZeroIdentifier($label));
                }
                Ok(Self(bytes))
            }

            pub const fn as_bytes(&self) -> &[u8; $width] {
                &self.0
            }

            #[allow(dead_code)]
            pub(crate) fn encode_into(&self, output: &mut Vec<u8>) {
                output.extend_from_slice(&self.0);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, concat!(stringify!($name), "("))?;
                for byte in &self.0[..4] {
                    write!(formatter, "{byte:02x}")?;
                }
                write!(formatter, "…)")
            }
        }
    };
}

// Wire-v2 semantic identities and key IDs are full SHA-512 values. Keeping all
// 64 bytes avoids collision-prone truncation at the trusted boundary.
typed_identifier!(DomainId, "domain_id", 64);
typed_identifier!(SubjectId, "subject_id", 64);
typed_identifier!(AdapterId, "adapter_id", 64);
typed_identifier!(EffectId, "effect_id", 64);
typed_identifier!(KeyId, "key_id", 64);

// Operation and internal artifact IDs are exact 128-bit protocol/service
// values, not truncated semantic digests.
typed_identifier!(OperationId, "operation_id", 16);
typed_identifier!(PrepareId, "prepare_id", 16);
typed_identifier!(CapabilityId, "capability_id", 16);
typed_identifier!(LeaseId, "lease_id", 16);

/// Authority assurance class is part of every signed artifact binding.
///
/// Nonproduction evidence can exercise state-machine shape but cannot be
/// admitted by a production policy or silently upgraded by a consumer.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum AuthorityClass {
    NonproductionEvidenceOnly = 1,
    ProductionHsm = 2,
    ProductionTpm = 3,
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Digest([u8; 64]);

impl Digest {
    pub const fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Digest(")?;
        for byte in &self.0[..6] {
            write!(formatter, "{byte:02x}")?;
        }
        write!(formatter, "…)")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Time(u64);

impl Time {
    pub const MAX: Self = Self(u64::MAX);

    pub const fn from_millis_since_epoch(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_millis_since_epoch(self) -> u64 {
        self.0
    }

    pub fn checked_add(self, ttl: Ttl) -> Result<Self, CoreError> {
        self.0
            .checked_add(ttl.0)
            .map(Self)
            .ok_or(CoreError::TimeOverflow)
    }

    pub(crate) fn encode_into(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0.to_be_bytes());
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Ttl(u64);

impl Ttl {
    pub fn from_millis(value: u64) -> Result<Self, CoreError> {
        if value == 0 {
            return Err(CoreError::InvalidTtl);
        }
        Ok(Self(value))
    }

    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

/// Every value that must converge exactly before PREPARE.
///
/// The digests are computed outside this crate by the independently specified
/// canonicalization and digest scheme. This core only compares and binds them.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Binding {
    domain_id: DomainId,
    authority_epoch: u64,
    authority_class: AuthorityClass,
    authority_profile_digest: Digest,
    authority_build_digest: Digest,
    /// SHA-512 of the normative whole-wire execution binding, including the
    /// oracle, runtime subject/tree, mode, challenge, request, A/B provenance,
    /// projections, effect intent, adapter boundary and replay namespace.
    wire_binding_digest: Digest,
    operation_id: OperationId,
    subject_id: SubjectId,
    state_digest: Digest,
    policy_digest: Digest,
    configuration_digest: Digest,
    /// Distinct extension admission carrier. This must never be folded into
    /// the general configuration digest because both bindings are verified
    /// independently at the wire/core handoff.
    extension_admission_binding_digest: Digest,
    adapter_id: AdapterId,
    effect_id: EffectId,
    safety_envelope_digest: Digest,
}

impl Binding {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: DomainId,
        authority_epoch: u64,
        authority_class: AuthorityClass,
        authority_profile_digest: Digest,
        authority_build_digest: Digest,
        wire_binding_digest: Digest,
        operation_id: OperationId,
        subject_id: SubjectId,
        state_digest: Digest,
        policy_digest: Digest,
        configuration_digest: Digest,
        extension_admission_binding_digest: Digest,
        adapter_id: AdapterId,
        effect_id: EffectId,
        safety_envelope_digest: Digest,
    ) -> Result<Self, CoreError> {
        if authority_epoch == 0 {
            return Err(CoreError::InvalidPolicy("authority_epoch must be non-zero"));
        }
        if authority_profile_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || authority_build_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || wire_binding_digest.as_bytes().iter().all(|byte| *byte == 0)
            || extension_admission_binding_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(CoreError::InvalidPolicy(
                "authority profile/build/wire/extension digests must be non-zero",
            ));
        }
        Ok(Self {
            domain_id,
            authority_epoch,
            authority_class,
            authority_profile_digest,
            authority_build_digest,
            wire_binding_digest,
            operation_id,
            subject_id,
            state_digest,
            policy_digest,
            configuration_digest,
            extension_admission_binding_digest,
            adapter_id,
            effect_id,
            safety_envelope_digest,
        })
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn authority_class(&self) -> AuthorityClass {
        self.authority_class
    }

    pub const fn authority_profile_digest(&self) -> Digest {
        self.authority_profile_digest
    }

    pub const fn authority_build_digest(&self) -> Digest {
        self.authority_build_digest
    }

    pub const fn wire_binding_digest(&self) -> Digest {
        self.wire_binding_digest
    }

    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    pub const fn state_digest(&self) -> Digest {
        self.state_digest
    }

    pub const fn policy_digest(&self) -> Digest {
        self.policy_digest
    }

    pub const fn configuration_digest(&self) -> Digest {
        self.configuration_digest
    }

    pub const fn extension_admission_binding_digest(&self) -> Digest {
        self.extension_admission_binding_digest
    }

    pub const fn adapter_id(&self) -> AdapterId {
        self.adapter_id
    }

    pub const fn effect_id(&self) -> EffectId {
        self.effect_id
    }

    pub const fn safety_envelope_digest(&self) -> Digest {
        self.safety_envelope_digest
    }

    pub(crate) fn encode_into(&self, output: &mut Vec<u8>) {
        self.domain_id.encode_into(output);
        output.extend_from_slice(&self.authority_epoch.to_be_bytes());
        output.push(self.authority_class as u8);
        self.authority_profile_digest.encode_into(output);
        self.authority_build_digest.encode_into(output);
        self.wire_binding_digest.encode_into(output);
        self.operation_id.encode_into(output);
        self.subject_id.encode_into(output);
        self.state_digest.encode_into(output);
        self.policy_digest.encode_into(output);
        self.configuration_digest.encode_into(output);
        self.extension_admission_binding_digest.encode_into(output);
        self.adapter_id.encode_into(output);
        self.effect_id.encode_into(output);
        self.safety_envelope_digest.encode_into(output);
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConvergenceEvidence {
    intended: Binding,
    independently_observed: Binding,
    policy_approved: Binding,
}

impl ConvergenceEvidence {
    pub const fn new(
        intended: Binding,
        independently_observed: Binding,
        policy_approved: Binding,
    ) -> Self {
        Self {
            intended,
            independently_observed,
            policy_approved,
        }
    }

    pub(crate) const fn intended(&self) -> Binding {
        self.intended
    }

    pub(crate) fn is_exact(&self) -> bool {
        self.intended == self.independently_observed && self.intended == self.policy_approved
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct CorePolicy {
    domain_id: DomainId,
    authority_epoch: u64,
    authority_class: AuthorityClass,
    authority_profile_digest: Digest,
    authority_build_digest: Digest,
    authority_signing_key: KeyId,
    adapter_receipt_key: KeyId,
    authority_custody_provider_identity: Digest,
    adapter_custody_provider_identity: Digest,
    max_prepare_ttl: Ttl,
    max_capability_ttl: Ttl,
    max_lease_ttl: Ttl,
    /// Upper bound for the fail-closed watchdog STOP timeout after lease
    /// expiry. This never extends successful receipt/ACK authorization beyond
    /// the lease or integrated point-of-use permit deadline.
    receipt_grace: Ttl,
}

impl CorePolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        domain_id: DomainId,
        authority_epoch: u64,
        authority_class: AuthorityClass,
        authority_profile_digest: Digest,
        authority_build_digest: Digest,
        authority_signing_key: KeyId,
        adapter_receipt_key: KeyId,
        authority_custody_provider_identity: Digest,
        adapter_custody_provider_identity: Digest,
        max_prepare_ttl: Ttl,
        max_capability_ttl: Ttl,
        max_lease_ttl: Ttl,
        receipt_grace: Ttl,
    ) -> Result<Self, CoreError> {
        if authority_epoch == 0 {
            return Err(CoreError::InvalidPolicy("authority_epoch must be non-zero"));
        }
        if authority_profile_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || authority_build_digest
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(CoreError::InvalidPolicy(
                "authority profile and build digests must be non-zero",
            ));
        }
        if max_lease_ttl > max_capability_ttl {
            return Err(CoreError::InvalidPolicy(
                "max_lease_ttl must not exceed max_capability_ttl",
            ));
        }
        if authority_signing_key == adapter_receipt_key {
            return Err(CoreError::InvalidPolicy(
                "authority and adapter receipt keys must be distinct",
            ));
        }
        if authority_custody_provider_identity
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || adapter_custody_provider_identity
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(CoreError::InvalidPolicy(
                "custody provider identities must be non-zero",
            ));
        }
        Ok(Self {
            domain_id,
            authority_epoch,
            authority_class,
            authority_profile_digest,
            authority_build_digest,
            authority_signing_key,
            adapter_receipt_key,
            authority_custody_provider_identity,
            adapter_custody_provider_identity,
            max_prepare_ttl,
            max_capability_ttl,
            max_lease_ttl,
            receipt_grace,
        })
    }

    pub const fn domain_id(&self) -> DomainId {
        self.domain_id
    }

    pub const fn authority_epoch(&self) -> u64 {
        self.authority_epoch
    }

    pub const fn authority_class(&self) -> AuthorityClass {
        self.authority_class
    }

    pub const fn authority_profile_digest(&self) -> Digest {
        self.authority_profile_digest
    }

    pub const fn authority_build_digest(&self) -> Digest {
        self.authority_build_digest
    }

    pub const fn authority_signing_key(&self) -> KeyId {
        self.authority_signing_key
    }

    pub const fn adapter_receipt_key(&self) -> KeyId {
        self.adapter_receipt_key
    }

    pub const fn authority_custody_provider_identity(&self) -> Digest {
        self.authority_custody_provider_identity
    }

    pub const fn adapter_custody_provider_identity(&self) -> Digest {
        self.adapter_custody_provider_identity
    }

    pub const fn max_prepare_ttl(&self) -> Ttl {
        self.max_prepare_ttl
    }

    pub const fn max_capability_ttl(&self) -> Ttl {
        self.max_capability_ttl
    }

    pub const fn max_lease_ttl(&self) -> Ttl {
        self.max_lease_ttl
    }

    pub const fn receipt_grace(&self) -> Ttl {
        self.receipt_grace
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PointOfUseRequest {
    actual_binding: Binding,
    lease_id: LeaseId,
    lease_ttl: Ttl,
}

impl PointOfUseRequest {
    pub const fn new(actual_binding: Binding, lease_id: LeaseId, lease_ttl: Ttl) -> Self {
        Self {
            actual_binding,
            lease_id,
            lease_ttl,
        }
    }

    pub const fn actual_binding(&self) -> Binding {
        self.actual_binding
    }

    pub const fn lease_id(&self) -> LeaseId {
        self.lease_id
    }

    pub const fn lease_ttl(&self) -> Ttl {
        self.lease_ttl
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum EffectOutcome {
    Applied = 1,
    SafelyNotApplied = 2,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArtifactKind {
    Prepare,
    Capability,
    Lease,
    Receipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoreError {
    ZeroIdentifier(&'static str),
    InvalidPolicy(&'static str),
    InvalidTtl,
    TimeOverflow,
    ExactConvergenceFailed,
    BindingMismatch,
    IdentifierReuse,
    NotYetValid(ArtifactKind),
    Expired(ArtifactKind),
    InvalidSignature(ArtifactKind),
    WrongSignatureKey(ArtifactKind),
    SignatureWrongLength,
    SignatureProviderFailure(u32),
    NonProductionKeyCustody,
    KeyCustodyUnavailable,
    KeyCustodyClassMismatch,
    KeyCustodyTechnologyMismatch,
    KeyCustodyIdentityMismatch,
    KeyCustodyStatusStale,
    KeyCustodyFailure(u32),
    ReplayDetected(crate::traits::ReplayClass),
    ReplayStoreFailure(u32),
    InterlockDenied,
    InterlockMismatch,
    InterlockFailure(u32),
    SafetyInhibitBlocked,
    SafetyInhibitStop,
    SafetyInhibitMismatch,
    SafetyInhibitStale,
    SafetyInhibitFailure(u32),
    WatchdogUnsafe,
    WatchdogArmMismatch,
    WatchdogFailure(u32),
    ReceiptMismatch,
    CompletionOutsideLease,
    EffectAdapterFailure(u32),
}
