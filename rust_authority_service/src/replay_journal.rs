use std::fmt;

/// The evidence replay identity is fixed in source and bound to the approved
/// oracle.  A build environment may supply only the parent known-folder path;
/// the service derives this immutable child identity and validates a build
/// descriptor before use.  The runtime environment/request/CLI cannot choose
/// either the identity or namespace.
pub const EVIDENCE_REPLAY_IDENTITY: &str =
    "SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY_V1-94578afd81a13aab";
pub const COMPILED_EVIDENCE_KNOWN_FOLDER: Option<&str> =
    option_env!("SBP_LEX_COMPILED_EVIDENCE_KNOWN_FOLDER");

#[derive(Debug)]
pub enum ReplayJournalError {
    CompileTimeRootMissing,
    CompileTimeRootNotAbsolute,
    BuildDescriptorMissing,
    BuildDescriptorMismatch,
    Io(std::io::Error),
    MarkerMismatch,
}

impl fmt::Display for ReplayJournalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CompileTimeRootMissing => {
                formatter.write_str("COMPILED_EVIDENCE_REPLAY_ROOT_MISSING")
            }
            Self::CompileTimeRootNotAbsolute => {
                formatter.write_str("COMPILED_EVIDENCE_REPLAY_ROOT_NOT_ABSOLUTE")
            }
            Self::BuildDescriptorMissing => {
                formatter.write_str("EVIDENCE_BUILD_DESCRIPTOR_MISSING")
            }
            Self::BuildDescriptorMismatch => {
                formatter.write_str("EVIDENCE_BUILD_DESCRIPTOR_MISMATCH")
            }
            Self::Io(error) => write!(formatter, "REPLAY_JOURNAL_IO:{error}"),
            Self::MarkerMismatch => formatter.write_str("REPLAY_JOURNAL_MARKER_MISMATCH"),
        }
    }
}

impl From<std::io::Error> for ReplayJournalError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
