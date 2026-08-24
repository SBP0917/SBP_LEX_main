pub const ORACLE_SHA256: &str = "94578afd81a13aab31904f1fb3c8733addd8718658602f638ad4086d2e9d4df0";
/// V2 SHA-512 migration pin over the former V2 oracle bytes.  Wire-v1 keeps
/// its separately named historical SHA-256 provenance value above.
#[allow(dead_code)]
pub const ORACLE_SHA512: &str = "4953fa1136348279509933ddb91102591015af3e7d45f1d6b1ca39ccb9e44190b5880c9f1a0ec054add824dd31d74feefc2922aa652833b16252cac159921f82";
pub const WIRE_CONTRACT_SHA256: &str =
    "f084a52597df0db1466ef9681273deb7513fa1818b41060f443802aafa8db76c";
pub const SIGNATURE_SUITE_ID: &str = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ArtifactAuthorityClass {
    ProgrammeProductionHsm,
    ProgrammeProductionTpm,
    NonproductionEvidenceOnly,
}

impl ArtifactAuthorityClass {
    /// Exact SBP-LEX-WIRE/1 authority-class value. This mapping is lossless:
    /// programme HSM and TPM authority are distinct types, and a fixture can
    /// never acquire either label by context.
    pub const fn wire_authority_class(self) -> &'static str {
        match self {
            Self::ProgrammeProductionHsm => "HSM",
            Self::ProgrammeProductionTpm => "TPM",
            Self::NonproductionEvidenceOnly => "TEST_ONLY",
        }
    }

    pub const fn programme_label(self) -> &'static str {
        match self {
            Self::ProgrammeProductionHsm => "PROGRAMME_PRODUCTION_HSM_AUTHORITY",
            Self::ProgrammeProductionTpm => "PROGRAMME_PRODUCTION_TPM_AUTHORITY",
            Self::NonproductionEvidenceOnly => "NONPRODUCTION_EVIDENCE_ONLY",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AuthorityProfile {
    pub profile_id: &'static str,
    pub authority_class: ArtifactAuthorityClass,
    pub oracle_sha256: &'static str,
    pub wire_contract_sha256: &'static str,
    /// Exact authority-capable contract required before any live route. Empty
    /// means no v2 has been independently frozen/admitted, so route is denied.
    pub authority_wire_v2_sha512: Option<&'static str>,
    pub signature_suite_id: &'static str,
    pub production_custody_required: bool,
    pub external_replay_anchor_required: bool,
    pub independent_inhibit_required: bool,
    pub external_watchdog_required: bool,
    /// True means controls in this build are simulations suitable only for
    /// negative testing; it never relaxes any programme requirement.
    pub fixture_controls_nonproduction: bool,
}

pub const PRODUCTION_HSM_PROFILE: AuthorityProfile = AuthorityProfile {
    profile_id: "SBP_LEX_RUST_AUTHORITY_PRODUCTION_HSM_V1",
    authority_class: ArtifactAuthorityClass::ProgrammeProductionHsm,
    oracle_sha256: ORACLE_SHA256,
    wire_contract_sha256: WIRE_CONTRACT_SHA256,
    authority_wire_v2_sha512: None,
    signature_suite_id: SIGNATURE_SUITE_ID,
    production_custody_required: true,
    external_replay_anchor_required: true,
    independent_inhibit_required: true,
    external_watchdog_required: true,
    fixture_controls_nonproduction: false,
};

pub const PRODUCTION_TPM_PROFILE: AuthorityProfile = AuthorityProfile {
    profile_id: "SBP_LEX_RUST_AUTHORITY_PRODUCTION_TPM_V1",
    authority_class: ArtifactAuthorityClass::ProgrammeProductionTpm,
    oracle_sha256: ORACLE_SHA256,
    wire_contract_sha256: WIRE_CONTRACT_SHA256,
    authority_wire_v2_sha512: None,
    signature_suite_id: SIGNATURE_SUITE_ID,
    production_custody_required: true,
    external_replay_anchor_required: true,
    independent_inhibit_required: true,
    external_watchdog_required: true,
    fixture_controls_nonproduction: false,
};

/// The initial programme build target is HSM-specific. A TPM build must name
/// and bind `PRODUCTION_TPM_PROFILE`; it cannot reuse an ambiguous class.
pub const PRODUCTION_PROFILE: AuthorityProfile = PRODUCTION_HSM_PROFILE;

pub const EVIDENCE_PROFILE: AuthorityProfile = AuthorityProfile {
    profile_id: "SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY_V1",
    authority_class: ArtifactAuthorityClass::NonproductionEvidenceOnly,
    oracle_sha256: ORACLE_SHA256,
    wire_contract_sha256: WIRE_CONTRACT_SHA256,
    authority_wire_v2_sha512: None,
    signature_suite_id: SIGNATURE_SUITE_ID,
    production_custody_required: true,
    external_replay_anchor_required: true,
    independent_inhibit_required: true,
    external_watchdog_required: true,
    fixture_controls_nonproduction: true,
};

/// Necessary class filter, never sufficient admission. The consumer must also
/// verify the owner-pinned profile/build/key, cryptographic signature, replay
/// state and physical-control evidence. Evidence artifacts are never upgraded
/// by context.
pub const fn require_programme_artifact(
    authority_class: ArtifactAuthorityClass,
) -> Result<(), &'static str> {
    match authority_class {
        ArtifactAuthorityClass::ProgrammeProductionHsm
        | ArtifactAuthorityClass::ProgrammeProductionTpm => Ok(()),
        ArtifactAuthorityClass::NonproductionEvidenceOnly => {
            Err("NONPRODUCTION_EVIDENCE_ARTIFACT_REJECTED")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_artifact_cannot_be_consumed_as_programme_authority() {
        assert_eq!(
            require_programme_artifact(ArtifactAuthorityClass::NonproductionEvidenceOnly),
            Err("NONPRODUCTION_EVIDENCE_ARTIFACT_REJECTED")
        );
        assert_eq!(
            EVIDENCE_PROFILE.authority_class.wire_authority_class(),
            "TEST_ONLY"
        );
        assert_eq!(
            EVIDENCE_PROFILE.authority_class.programme_label(),
            "NONPRODUCTION_EVIDENCE_ONLY"
        );
        assert_eq!(EVIDENCE_PROFILE.wire_contract_sha256, WIRE_CONTRACT_SHA256);
        assert_eq!(
            PRODUCTION_HSM_PROFILE
                .authority_class
                .wire_authority_class(),
            "HSM"
        );
        assert_eq!(
            PRODUCTION_TPM_PROFILE
                .authority_class
                .wire_authority_class(),
            "TPM"
        );
        assert_ne!(
            PRODUCTION_HSM_PROFILE.profile_id,
            PRODUCTION_TPM_PROFILE.profile_id
        );
    }
}
