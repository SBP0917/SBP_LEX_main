//! Private authority-bearing integration for the fixed wire-v2 contract.
//!
//! Nothing in this module is exported from the crate.  In particular, neither
//! an authenticated convergence state nor a still-redeemable effect dispatch
//! can cross the process API.  The ordinary and evidence binaries continue to
//! exit fail closed; these types are exercised only by crate-local tests until
//! the explicitly listed physical dependencies are provisioned and admitted.

use std::collections::BTreeMap;

use sbp_lex_authority_wire_v2::{
    adapter_consumption_digest, admission_policy_digest, authority_artifact_digest,
    authority_artifact_id, effect_receipt_digest, encode_message, point_of_use_digest,
    rendezvous_release_digest, signature_preimage, transcript_digest, validate_and_append_result,
    validate_effect_permit_for_atomic_consumption, validate_request_prefix, validate_transcript,
    AdmissionPolicy, KeyRecord, Message, SignatureVerifier, TrustRegistry, Value,
    VerifiedEffectPermitContext, VerifiedStageContext, ZERO, ZERO_ID,
};
use trusted_authority_core::{
    AdapterId, AdapterReceiptClaims, AppliedEffect, AtomicEffectAdapter, AuthorityClass,
    AwaitingReceipt, Binding, Candidate, CapabilityId, ConvergenceEvidence, CorePolicy, Digest,
    EffectDispatch, EffectId, EffectLease, EffectOutcome, ExternalFailure,
    ExternalSignatureProvider, FailClosedWatchdog, KeyCustodyProvider, KeyId, LeaseId, OperationId,
    PointOfUseRequest, PrepareId, ProviderSignature, ReplayProtector, SafetyEnvelopeInterlock,
    SafetyInhibit, SignedAdapterReceipt, SubjectId, Time, Ttl, WatchdogTripReason,
};
use trusted_authority_core::{DomainId, Prepared};

use crate::sha512::digest;

const V2_SPEC_SHA512: &str = "e1b79cf73411ca5fc7704c02ba153e9824eaf35748300ac515f62e4d528561600497acf05be8bdb67ab1b6e1ea643e46b8ab4f729e11103f415cf6754a07d7e7";
const V2_PYTHON_CORE_SHA512: &str =
    "76788a5377413d364b172d37986b504405efab8d36d003de402e499b7d74419df9a39786dd2c0a0ceaa5c6d80d56c5618dcfc60461f11a5556912d248ba2f603";
const V2_RUST_CORE_SHA512: &str =
    "9b286950344d7e844c9ebb660f0597d3f352f87d95fc8d30a5e4ed8439393b445c3de3798305d72bb5c46abed5f463d526e307373265eef28cd7fb6b482b8ed9";
const V2_HYBRID_RUST_CORE_SHA512: &str =
    "0daaab828b031a58cddc4038d4d69cfafe39ff098bd8cf8b554a12f65d465065f8f5b1245d42d04b727026f3a7a1459f43dad9cef5e75481fc31dc34cc9553bd";
const V2_MODE1_GOLDEN_SHA512: &str =
    "823f83c2989e79d180a48a289f02977003b2210033764b99be149945868449ed1b2dc7f6f6d04fb59cc2578484970ba95009fd612cc8f229078abf45613b5303";
const V2_MODE2_GOLDEN_SHA512: &str =
    "d523aeda9a35c2a8792da92fd3f2d735c83cef0708282e062405abcd431edae95d5ec2005213a5a65ba7725e99be142266dea068b391705cafa725eec97aebcc";
const V2_MODE2_FAILURE_GOLDEN_SHA512: &str =
    "a7650b600c72d5df2fec03a5ef7ce27188a14ba42876eb7bd1e7e40236968a3a93375bbdb590cf3442e4d9513135a80bfd92a3309ba0b05ea8e3d110cb17029d";
const V2_MODE2_UNKNOWN_GOLDEN_SHA512: &str =
    "3e4973038108a8bbf8550b45ccc80a8e39e203d41d639e0e351e463117a6a15c9a0ecb4085da9ff63d200d0cfd064a6a092643f389eb03d569c4a7bd59b2d7f5";
const V2_MODE2_TIMEOUT_GOLDEN_SHA512: &str =
    "400ec4288e748c74c78af4620f2eb1084325ba584d0995a9e04881f05b2b88df222c6c10f7568640505ee2d25d5f9ea999e2fc49bec5aaf5e62671f30b660b45";
const V2_MODE3_GOLDEN_SHA512: &str =
    "25e9c31e3892fe7b408eff5c123a093bdd47445ad11f52961d5aeb6220e7e09dc62be2d60b0fb8ec0500ed8861ec65b78fa52044f201025c65e180bf4cb2e5c5";
const V2_MODE3_FAILURE_GOLDEN_SHA512: &str =
    "9072db1dd1306d89959c473ce454cef97b9b95ecef8b467043422dc9f8f9e0f250f6d37cf0980bfd79ac631c44bed18f89fe32cd6188c672bb0bc66f0d0488b9";
const V2_MODE3_UNKNOWN_GOLDEN_SHA512: &str =
    "99fca59bf0189253c95d2bc231807e2f59047110957984e7de39313dc7f5f7f0a966b17cbd2fc29ba24c24868c15a5336fdc25474e2f28cb0a325dec90a54ecf";
const V2_MODE3_TIMEOUT_GOLDEN_SHA512: &str =
    "83a4c95273015847e9422a2f30a3013d6b3b7445be885f65a258090be6fa78b231a47c0447851b9763bcbaac2c04044e3d459d86534e700963af3d1324e90f1a";
const V2_ADVERSARIAL_INVENTORY_SHA512: &str =
    "4766806bcca1a855a0f3cdff9c4c28887b64d673ae6c8fead92ed2c4637bd89884a506815b22703909fef9eea4f31937cb16b5ffbfc99068d0f01898cba0822b";

const V2_SPEC_BYTES: &[u8] = include_bytes!("../../wire_protocol/v2/SPEC.md");
const V2_PYTHON_CORE_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/python/sbp_lex_wire_v2.py");
const V2_RUST_CORE_BYTES: &[u8] = include_bytes!("../../wire_protocol/v2/rust/src/lib.rs");
const V2_HYBRID_RUST_CORE_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/rust/src/hybrid.rs");
const V2_MODE1_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode1_golden.jsonl");
const V2_MODE2_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode_2_golden.jsonl");
const V2_MODE2_FAILURE_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode2_failure_golden.jsonl");
const V2_MODE2_UNKNOWN_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode2_unknown_golden.jsonl");
const V2_MODE2_TIMEOUT_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode2_timeout_golden.jsonl");
const V2_MODE3_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode_3_golden.jsonl");
const V2_MODE3_FAILURE_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode3_failure_golden.jsonl");
const V2_MODE3_UNKNOWN_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode3_unknown_golden.jsonl");
const V2_MODE3_TIMEOUT_GOLDEN_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/mode3_timeout_golden.jsonl");
const V2_ADVERSARIAL_INVENTORY_BYTES: &[u8] =
    include_bytes!("../../wire_protocol/v2/vectors/adversarial_cases.txt");

#[derive(Debug, Eq, PartialEq)]
enum IntegrationError {
    FixedBytesMismatch(&'static str),
    Wire(String),
    Core(String),
    Invalid(&'static str),
    SignerRejected,
    AuditSink(u32),
}

fn wire_error(error: impl std::fmt::Display) -> IntegrationError {
    IntegrationError::Wire(error.to_string())
}

fn core_error(error: impl std::fmt::Debug) -> IntegrationError {
    IntegrationError::Core(format!("{error:?}"))
}

fn verify_fixed_v2_bytes() -> Result<(), IntegrationError> {
    for (name, bytes, expected) in [
        ("SPEC", V2_SPEC_BYTES, V2_SPEC_SHA512),
        ("PYTHON_CORE", V2_PYTHON_CORE_BYTES, V2_PYTHON_CORE_SHA512),
        ("RUST_CORE", V2_RUST_CORE_BYTES, V2_RUST_CORE_SHA512),
        (
            "HYBRID_RUST_CORE",
            V2_HYBRID_RUST_CORE_BYTES,
            V2_HYBRID_RUST_CORE_SHA512,
        ),
        (
            "MODE1_GOLDEN",
            V2_MODE1_GOLDEN_BYTES,
            V2_MODE1_GOLDEN_SHA512,
        ),
        (
            "MODE2_GOLDEN",
            V2_MODE2_GOLDEN_BYTES,
            V2_MODE2_GOLDEN_SHA512,
        ),
        (
            "MODE2_FAILURE_GOLDEN",
            V2_MODE2_FAILURE_GOLDEN_BYTES,
            V2_MODE2_FAILURE_GOLDEN_SHA512,
        ),
        (
            "MODE2_UNKNOWN_GOLDEN",
            V2_MODE2_UNKNOWN_GOLDEN_BYTES,
            V2_MODE2_UNKNOWN_GOLDEN_SHA512,
        ),
        (
            "MODE2_TIMEOUT_GOLDEN",
            V2_MODE2_TIMEOUT_GOLDEN_BYTES,
            V2_MODE2_TIMEOUT_GOLDEN_SHA512,
        ),
        (
            "MODE3_GOLDEN",
            V2_MODE3_GOLDEN_BYTES,
            V2_MODE3_GOLDEN_SHA512,
        ),
        (
            "MODE3_FAILURE_GOLDEN",
            V2_MODE3_FAILURE_GOLDEN_BYTES,
            V2_MODE3_FAILURE_GOLDEN_SHA512,
        ),
        (
            "MODE3_UNKNOWN_GOLDEN",
            V2_MODE3_UNKNOWN_GOLDEN_BYTES,
            V2_MODE3_UNKNOWN_GOLDEN_SHA512,
        ),
        (
            "MODE3_TIMEOUT_GOLDEN",
            V2_MODE3_TIMEOUT_GOLDEN_BYTES,
            V2_MODE3_TIMEOUT_GOLDEN_SHA512,
        ),
        (
            "ADVERSARIAL_INVENTORY",
            V2_ADVERSARIAL_INVENTORY_BYTES,
            V2_ADVERSARIAL_INVENTORY_SHA512,
        ),
    ] {
        if lower_hex(&digest(bytes)) != expected {
            return Err(IntegrationError::FixedBytesMismatch(name));
        }
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], IntegrationError> {
    if value.len() != N * 2 {
        return Err(IntegrationError::Invalid("hex width"));
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        output[index] = (digit(pair[0]).ok_or(IntegrationError::Invalid("lower hex"))? << 4)
            | digit(pair[1]).ok_or(IntegrationError::Invalid("lower hex"))?;
    }
    Ok(output)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Digest {
    let mut input = Vec::from(domain);
    for part in parts {
        input.extend_from_slice(&(part.len() as u32).to_be_bytes());
        input.extend_from_slice(part);
    }
    Digest::new(digest(&input))
}

fn text<'a>(message: &'a Message, key: &str) -> Result<&'a str, IntegrationError> {
    match message.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(IntegrationError::Invalid("missing text field")),
    }
}

fn number(message: &Message, key: &str) -> Result<u64, IntegrationError> {
    match message.get(key) {
        Some(Value::Number(value)) => Ok(*value),
        _ => Err(IntegrationError::Invalid("missing number field")),
    }
}

fn authority_class(value: &str) -> Result<AuthorityClass, IntegrationError> {
    match value {
        "TEST_ONLY" => Ok(AuthorityClass::NonproductionEvidenceOnly),
        "PRODUCTION_HSM" => Ok(AuthorityClass::ProductionHsm),
        "PRODUCTION_TPM" => Ok(AuthorityClass::ProductionTpm),
        _ => Err(IntegrationError::Invalid("authority class")),
    }
}

#[derive(Copy, Clone)]
struct PinnedCoreConfiguration {
    authority_custody_provider_identity: Digest,
    adapter_custody_provider_identity: Digest,
    replay_provider_identity: Digest,
    terminal_audit_provider_identity: Digest,
    watchdog_provider_identity: Digest,
    max_prepare_ttl: Ttl,
    max_capability_ttl: Ttl,
    max_lease_ttl: Ttl,
    receipt_grace: Ttl,
}

/// Private extension that gives the one replay backend a stable, externally
/// pinned identity.  The trusted core still consumes only `ReplayProtector`;
/// this service boundary additionally prevents swapping an empty provider or
/// path between transitions.
trait PrivateReplayAnchor: ReplayProtector {
    fn provider_identity(&self) -> Digest;
}

/// Service-private verifier providers must expose an externally admitted,
/// stable identity.  Because this trait is private, an untrusted route cannot
/// substitute an arbitrary permissive `SignatureVerifier` implementation.
trait PrivateWireVerificationProvider: SignatureVerifier {
    fn provider_identity(&self) -> Digest;
}

/// Engine-owned durable terminal-tail sink.  A pending append records a fully
/// signed, revalidated transcript as IN_DOUBT while the watchdog remains armed.
/// Only a later acknowledgement marker can record that the physical watchdog
/// ACK returned.  Production must provide this under external custody; the
/// local implementation is evidence-only.
trait PrivateTerminalAuditSink {
    fn provider_identity(&self) -> Digest;

    fn append_pending(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
        disposition: &str,
        transcript: &[u8],
    ) -> Result<(), ExternalFailure>;

    fn finalize_acknowledged(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
    ) -> Result<(), ExternalFailure>;
}

/// Engine-owned physical watchdog identity. A route cannot swap watchdog
/// providers between arm, durable tighten, point-of-use verification and
/// terminal handling.
trait PrivateWatchdogProvider: FailClosedWatchdog {
    fn provider_identity(&self) -> Digest;
}

#[cfg(feature = "evidence-only-fixtures")]
impl PrivateWatchdogProvider for crate::evidence::EvidenceWatchdog {
    fn provider_identity(&self) -> Digest {
        Digest::new([0xD3; 64])
    }
}

#[cfg(feature = "evidence-only-fixtures")]
impl PrivateTerminalAuditSink for crate::evidence::EvidenceTerminalAuditSink {
    fn provider_identity(&self) -> Digest {
        self.provider_identity()
    }

    fn append_pending(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
        disposition: &str,
        transcript: &[u8],
    ) -> Result<(), ExternalFailure> {
        self.append_pending(
            durable_key_hex,
            terminal_digest_hex,
            disposition,
            transcript,
        )
    }

    fn finalize_acknowledged(
        &mut self,
        durable_key_hex: &str,
        terminal_digest_hex: &str,
    ) -> Result<(), ExternalFailure> {
        self.finalize_acknowledged(durable_key_hex, terminal_digest_hex)
    }
}

#[cfg(feature = "evidence-only-fixtures")]
impl PrivateReplayAnchor for crate::evidence::EvidenceReplayJournal {
    fn provider_identity(&self) -> Digest {
        self.provider_identity()
    }
}

struct PrivateAuthorityEngine<R> {
    replay: R,
    provider_identity: Digest,
    registry_digest: String,
    admission_digest: String,
    verifier_provider_identity: Digest,
    terminal_audit_provider_identity: Digest,
    terminal_audit: Box<dyn PrivateTerminalAuditSink>,
    watchdog_provider_identity: Digest,
    watchdog: Box<dyn PrivateWatchdogProvider>,
    signers: PrivateSessionSigners,
}

struct PrivateSessionSigners {
    authority: Box<dyn PrivateWireAuthoritySigner>,
    adapter: Box<dyn PrivateWireAdapterSigner>,
    watchdog: Box<dyn PrivateWireWatchdogSigner>,
}

impl PrivateSessionSigners {
    fn new(
        authority: Box<dyn PrivateWireAuthoritySigner>,
        adapter: Box<dyn PrivateWireAdapterSigner>,
        watchdog: Box<dyn PrivateWireWatchdogSigner>,
    ) -> Self {
        Self {
            authority,
            adapter,
            watchdog,
        }
    }
}

struct PrivateMode1Released<R> {
    transcript: Vec<Message>,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> PrivateMode1Released<R> {
    #[allow(clippy::too_many_arguments)]
    fn from_release_request<V: PrivateWireVerificationProvider>(
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        released_at_ms: u64,
        replay: R,
        expected_replay_provider_identity: Digest,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        expected_terminal_audit_provider_identity: Digest,
        watchdog: Box<dyn PrivateWatchdogProvider>,
        expected_watchdog_provider_identity: Digest,
        signers: PrivateSessionSigners,
    ) -> Result<Self, IntegrationError> {
        verify_fixed_v2_bytes()?;
        let mut engine = PrivateAuthorityEngine::new(
            replay,
            expected_replay_provider_identity,
            terminal_audit,
            expected_terminal_audit_provider_identity,
            watchdog,
            expected_watchdog_provider_identity,
            registry,
            admission,
            verifier,
            signers,
        )?;
        let prefix = vec![request];
        let stage = validate_request_prefix(
            &prefix,
            "mode1_release_request",
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let request = prefix.last().expect("one release request");
        let release_digest = rendezvous_release_digest(
            stage
                .derived_text("a_checkpoint_digest")
                .map_err(wire_error)?,
            stage
                .derived_text("b_checkpoint_digest")
                .map_err(wire_error)?,
            stage
                .derived_number("rendezvous_opened_at_ms")
                .map_err(wire_error)?,
            released_at_ms,
        )
        .map_err(wire_error)?;
        let draft = private_result_draft(
            request,
            prefix.len(),
            "mode1_release_result",
            "AUTHORITY",
            "NONE",
            issue,
            registry,
            engine.signers.authority.algorithm(),
            BTreeMap::from([
                (
                    "a_checkpoint_digest".into(),
                    Value::Text(
                        stage
                            .derived_text("a_checkpoint_digest")
                            .map_err(wire_error)?
                            .into(),
                    ),
                ),
                (
                    "b_checkpoint_digest".into(),
                    Value::Text(
                        stage
                            .derived_text("b_checkpoint_digest")
                            .map_err(wire_error)?
                            .into(),
                    ),
                ),
                ("decision".into(), Value::Text("ALLOW".into())),
                (
                    "release_request_digest".into(),
                    Value::Text(
                        stage
                            .derived_text("release_request_digest")
                            .map_err(wire_error)?
                            .into(),
                    ),
                ),
                (
                    "rendezvous_opened_at_ms".into(),
                    Value::Number(
                        stage
                            .derived_number("rendezvous_opened_at_ms")
                            .map_err(wire_error)?,
                    ),
                ),
                (
                    "rendezvous_release_digest".into(),
                    Value::Text(release_digest),
                ),
                (
                    "rendezvous_released_at_ms".into(),
                    Value::Number(released_at_ms),
                ),
            ]),
        )?;
        let result = seal_private_result(draft, registry, engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &prefix,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        Ok(Self { transcript, engine })
    }

    fn converge<V: PrivateWireVerificationProvider>(
        self,
        external_execution_suffix: Vec<Message>,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
    ) -> Result<PrivatelyConverged<R>, IntegrationError> {
        if external_execution_suffix.len() != 4
            || text(&external_execution_suffix[0], "kind")? != "branch_a_statement"
            || text(&external_execution_suffix[1], "kind")? != "branch_b_statement"
            || text(&external_execution_suffix[2], "kind")? != "mode1_overlap_witness"
            || text(&external_execution_suffix[3], "kind")? != "convergence_request"
        {
            return Err(IntegrationError::Invalid("Mode 1 convergence suffix shape"));
        }
        let mut prefix = self.transcript;
        prefix.extend(external_execution_suffix);
        private_converge_prefix(prefix, self.engine, registry, admission, verifier, issue)
    }
}

/// Mode 2 has no release stage.  The service still owns the convergence result
/// signer and accepts only the exact primary/validator/request prefix already
/// authenticated by the independent wire implementation.
struct PrivateMode2Convergence;

impl PrivateMode2Convergence {
    #[allow(clippy::too_many_arguments)]
    fn from_external_prefix<R: PrivateReplayAnchor, V: PrivateWireVerificationProvider>(
        prefix: Vec<Message>,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        replay: R,
        expected_replay_provider_identity: Digest,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        expected_terminal_audit_provider_identity: Digest,
        watchdog: Box<dyn PrivateWatchdogProvider>,
        expected_watchdog_provider_identity: Digest,
        signers: PrivateSessionSigners,
    ) -> Result<PrivatelyConverged<R>, IntegrationError> {
        if prefix.len() != 3
            || text(&prefix[0], "kind")? != "branch_a_statement"
            || text(&prefix[1], "kind")? != "mode2_validator_certificate"
            || text(&prefix[2], "kind")? != "convergence_request"
        {
            return Err(IntegrationError::Invalid("Mode 2 convergence prefix shape"));
        }
        verify_fixed_v2_bytes()?;
        let engine = PrivateAuthorityEngine::new(
            replay,
            expected_replay_provider_identity,
            terminal_audit,
            expected_terminal_audit_provider_identity,
            watchdog,
            expected_watchdog_provider_identity,
            registry,
            admission,
            verifier,
            signers,
        )?;
        private_converge_prefix(prefix, engine, registry, admission, verifier, issue)
    }
}

/// Mode 3 has one externally signed proof followed by the coordinator request.
/// It joins the same private PREPARE path after exact wire verification.
struct PrivateMode3Convergence;

impl PrivateMode3Convergence {
    #[allow(clippy::too_many_arguments)]
    fn from_external_prefix<R: PrivateReplayAnchor, V: PrivateWireVerificationProvider>(
        prefix: Vec<Message>,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        replay: R,
        expected_replay_provider_identity: Digest,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        expected_terminal_audit_provider_identity: Digest,
        watchdog: Box<dyn PrivateWatchdogProvider>,
        expected_watchdog_provider_identity: Digest,
        signers: PrivateSessionSigners,
    ) -> Result<PrivatelyConverged<R>, IntegrationError> {
        if prefix.len() != 2
            || text(&prefix[0], "kind")? != "mode3_single_state_proof"
            || text(&prefix[1], "kind")? != "convergence_request"
        {
            return Err(IntegrationError::Invalid("Mode 3 convergence prefix shape"));
        }
        verify_fixed_v2_bytes()?;
        let engine = PrivateAuthorityEngine::new(
            replay,
            expected_replay_provider_identity,
            terminal_audit,
            expected_terminal_audit_provider_identity,
            watchdog,
            expected_watchdog_provider_identity,
            registry,
            admission,
            verifier,
            signers,
        )?;
        private_converge_prefix(prefix, engine, registry, admission, verifier, issue)
    }
}

fn private_converge_prefix<R: PrivateReplayAnchor, V: PrivateWireVerificationProvider>(
    prefix: Vec<Message>,
    mut engine: PrivateAuthorityEngine<R>,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &V,
    issue: StageIssue<'_>,
) -> Result<PrivatelyConverged<R>, IntegrationError> {
    engine.verify_trust_context(registry, admission, verifier)?;
    let stage = validate_request_prefix(
        &prefix,
        "convergence_request",
        registry,
        admission,
        verifier,
        issue.at_ms,
    )
    .map_err(wire_error)?;
    let request = prefix
        .last()
        .ok_or(IntegrationError::Invalid("convergence request absent"))?;
    let mut extras = BTreeMap::from([("decision".into(), Value::Text("ALLOW".into()))]);
    for field in [
        "convergence_digest",
        "evidence_a_digest",
        "evidence_b_digest",
        "mode_evidence_digest",
        "projection_digest",
    ] {
        extras.insert(
            field.into(),
            stage
                .derived(field)
                .cloned()
                .ok_or(IntegrationError::Invalid("convergence derivation"))?,
        );
    }
    let draft = private_result_draft(
        request,
        prefix.len(),
        "convergence_result",
        "AUTHORITY",
        "NONE",
        issue,
        registry,
        engine.signers.authority.algorithm(),
        extras,
    )?;
    let result = seal_private_result(draft, registry, engine.signers.authority.as_mut())?;
    let transcript = validate_and_append_result(
        &prefix,
        &result,
        &stage,
        registry,
        admission,
        verifier,
        issue.at_ms,
    )
    .map_err(wire_error)?;
    Ok(PrivatelyConverged { transcript, engine })
}

struct PrivatelyConverged<R> {
    transcript: Vec<Message>,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> PrivatelyConverged<R> {
    fn accept_prepare_request<V: PrivateWireVerificationProvider>(
        self,
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        trusted_now_ms: u64,
        pinned: PinnedCoreConfiguration,
    ) -> Result<AuthenticatedConvergence<R>, IntegrationError> {
        let mut transcript = self.transcript;
        transcript.push(request);
        AuthenticatedConvergence::from_prepare_prefix_with_engine(
            &transcript,
            registry,
            admission,
            verifier,
            trusted_now_ms,
            pinned,
            self.engine,
        )
    }
}

impl<R: PrivateReplayAnchor> PrivateAuthorityEngine<R> {
    #[allow(clippy::too_many_arguments)]
    fn new<V: PrivateWireVerificationProvider>(
        replay: R,
        expected_provider_identity: Digest,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        expected_terminal_audit_provider_identity: Digest,
        watchdog: Box<dyn PrivateWatchdogProvider>,
        expected_watchdog_provider_identity: Digest,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        signers: PrivateSessionSigners,
    ) -> Result<Self, IntegrationError> {
        if expected_provider_identity
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || replay.provider_identity() != expected_provider_identity
        {
            return Err(IntegrationError::Invalid(
                "replay provider identity mismatch",
            ));
        }
        if expected_terminal_audit_provider_identity
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || terminal_audit.provider_identity() != expected_terminal_audit_provider_identity
        {
            return Err(IntegrationError::Invalid(
                "terminal audit provider identity mismatch",
            ));
        }
        if expected_watchdog_provider_identity
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || watchdog.provider_identity() != expected_watchdog_provider_identity
        {
            return Err(IntegrationError::Invalid(
                "watchdog provider identity mismatch",
            ));
        }
        let verifier_provider_identity = verifier.provider_identity();
        if verifier_provider_identity
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(IntegrationError::Invalid("zero verifier provider identity"));
        }
        Ok(Self {
            replay,
            provider_identity: expected_provider_identity,
            registry_digest: registry.digest().map_err(wire_error)?,
            admission_digest: admission_policy_digest(admission).map_err(wire_error)?,
            verifier_provider_identity,
            terminal_audit_provider_identity: expected_terminal_audit_provider_identity,
            terminal_audit,
            watchdog_provider_identity: expected_watchdog_provider_identity,
            watchdog,
            signers,
        })
    }

    fn verify_trust_context<V: PrivateWireVerificationProvider>(
        &self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
    ) -> Result<(), IntegrationError> {
        if registry.digest().map_err(wire_error)? != self.registry_digest
            || admission_policy_digest(admission).map_err(wire_error)? != self.admission_digest
            || verifier.provider_identity() != self.verifier_provider_identity
            || self.terminal_audit.provider_identity() != self.terminal_audit_provider_identity
            || self.watchdog.provider_identity() != self.watchdog_provider_identity
        {
            return Err(IntegrationError::Invalid("private trust context changed"));
        }
        Ok(())
    }

    fn replay_mut(&mut self) -> &mut R {
        &mut self.replay
    }

    fn replay_and_watchdog_mut(&mut self) -> (&mut R, &mut dyn PrivateWatchdogProvider) {
        (&mut self.replay, self.watchdog.as_mut())
    }
}

/// Move-only evidence that the independent wire library authenticated the full
/// convergence lifecycle and the next PREPARE request against externally
/// supplied, pinned policy and registry values.
struct AuthenticatedConvergence<R> {
    transcript: Vec<Message>,
    stage: VerifiedStageContext,
    binding: Binding,
    core_policy: CorePolicy,
    converged: trusted_authority_core::Converged,
    durable_consumption_digest: Digest,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> AuthenticatedConvergence<R> {
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    fn from_prepare_prefix<V: PrivateWireVerificationProvider>(
        transcript: &[Message],
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        trusted_now_ms: u64,
        pinned: PinnedCoreConfiguration,
        replay: R,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        watchdog: Box<dyn PrivateWatchdogProvider>,
        signers: PrivateSessionSigners,
    ) -> Result<Self, IntegrationError> {
        let engine = PrivateAuthorityEngine::new(
            replay,
            pinned.replay_provider_identity,
            terminal_audit,
            pinned.terminal_audit_provider_identity,
            watchdog,
            pinned.watchdog_provider_identity,
            registry,
            admission,
            verifier,
            signers,
        )?;
        Self::from_prepare_prefix_with_engine(
            transcript,
            registry,
            admission,
            verifier,
            trusted_now_ms,
            pinned,
            engine,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_prepare_prefix_with_engine<V: PrivateWireVerificationProvider>(
        transcript: &[Message],
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        trusted_now_ms: u64,
        pinned: PinnedCoreConfiguration,
        engine: PrivateAuthorityEngine<R>,
    ) -> Result<Self, IntegrationError> {
        if engine.provider_identity != pinned.replay_provider_identity
            || engine.terminal_audit_provider_identity != pinned.terminal_audit_provider_identity
        {
            return Err(IntegrationError::Invalid(
                "engine provider changed before PREPARE",
            ));
        }
        engine.verify_trust_context(registry, admission, verifier)?;
        verify_fixed_v2_bytes()?;
        let stage = validate_request_prefix(
            transcript,
            "prepare_request",
            registry,
            admission,
            verifier,
            trusted_now_ms,
        )
        .map_err(wire_error)?;
        if stage.authenticated_convergence_binding_digest() == ZERO {
            return Err(IntegrationError::Invalid("zero authenticated convergence"));
        }
        let binding = binding_from_verified(transcript, &stage, admission)?;
        let core_policy = core_policy_from_pins(registry, admission, binding, pinned)?;
        let evidence = ConvergenceEvidence::new(binding, binding, binding);
        let converged = Candidate::new(core_policy)
            .converge(evidence)
            .map_err(core_error)?;
        let durable_consumption_digest = Digest::new(decode_hex(text(
            transcript
                .first()
                .ok_or(IntegrationError::Invalid("empty authenticated transcript"))?,
            "durable_consumption_digest",
        )?)?);
        Ok(Self {
            transcript: transcript.to_vec(),
            stage,
            binding,
            core_policy,
            converged,
            durable_consumption_digest,
            engine,
        })
    }
}

fn binding_from_verified(
    transcript: &[Message],
    stage: &VerifiedStageContext,
    admission: &AdmissionPolicy,
) -> Result<Binding, IntegrationError> {
    let convergence = transcript
        .iter()
        .find(|message| text(message, "kind").ok() == Some("convergence_request"))
        .ok_or(IntegrationError::Invalid("convergence request absent"))?;
    let admission_digest = admission_policy_digest(admission).map_err(wire_error)?;
    let profile_digest = digest_parts(
        b"SBP-LEX-RUST-AUTHORITY/2\0AUTHORITY-PROFILE\0",
        &[
            admission.authority_class.as_bytes(),
            admission.authority_profile.as_bytes(),
            admission_digest.as_bytes(),
        ],
    );
    let build_digest = digest_parts(
        b"SBP-LEX-RUST-AUTHORITY/2\0AUTHORITY-BUILD\0",
        &[
            admission.authority_build_id.as_bytes(),
            admission.runtime_subject.as_bytes(),
            admission.runtime_tree.as_bytes(),
        ],
    );
    Binding::new(
        DomainId::new(decode_hex(&admission.domain_digest)?).map_err(core_error)?,
        admission.authority_epoch,
        authority_class(&admission.authority_class)?,
        profile_digest,
        build_digest,
        Digest::new(decode_hex(
            stage.authenticated_convergence_binding_digest(),
        )?),
        OperationId::new(decode_hex(&admission.operation_id)?).map_err(core_error)?,
        SubjectId::new(decode_hex(&admission.subject_digest)?).map_err(core_error)?,
        Digest::new(decode_hex(&admission.state_digest)?),
        Digest::new(decode_hex(text(convergence, "projection_digest")?)?),
        Digest::new(decode_hex(&admission_digest)?),
        Digest::new(decode_hex(&admission.extension_admission_binding_digest)?),
        AdapterId::new(decode_hex(&admission.adapter_digest)?).map_err(core_error)?,
        EffectId::new(decode_hex(&admission.effect_digest)?).map_err(core_error)?,
        Digest::new(decode_hex(&admission.interlock_digest)?),
    )
    .map_err(core_error)
}

fn core_policy_from_pins(
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    binding: Binding,
    pinned: PinnedCoreConfiguration,
) -> Result<CorePolicy, IntegrationError> {
    let authority_key = registry
        .entries
        .get("AUTHORITY")
        .ok_or(IntegrationError::Invalid("authority registry entry"))?
        .key_id()
        .map_err(wire_error)?;
    let adapter_key = registry
        .entries
        .get("ADAPTER")
        .ok_or(IntegrationError::Invalid("adapter registry entry"))?
        .key_id()
        .map_err(wire_error)?;
    CorePolicy::new(
        binding.domain_id(),
        admission.authority_epoch,
        binding.authority_class(),
        binding.authority_profile_digest(),
        binding.authority_build_digest(),
        KeyId::new(decode_hex(&authority_key)?).map_err(core_error)?,
        KeyId::new(decode_hex(&adapter_key)?).map_err(core_error)?,
        pinned.authority_custody_provider_identity,
        pinned.adapter_custody_provider_identity,
        pinned.max_prepare_ttl,
        pinned.max_capability_ttl,
        pinned.max_lease_ttl,
        pinned.receipt_grace,
    )
    .map_err(core_error)
}

const COPIED_COMMON_FIELDS: &[&str] = &[
    "adapter_boundary_digest",
    "adapter_digest",
    "audit_anchor_digest",
    "authority_build_id",
    "authority_class",
    "authority_epoch",
    "authority_profile",
    "challenge",
    "domain_digest",
    "durable_consumption_digest",
    "effect_digest",
    "effect_intent_digest",
    "expires_at_ms",
    "extension_admission_binding_digest",
    "extension_admission_mode",
    "extension_configuration_digest",
    "extension_schema",
    "inhibit_binding_digest",
    "interlock_digest",
    "issued_at_ms",
    "mode",
    "not_before_ms",
    "operation_id",
    "oracle_sha512",
    "protocol",
    "replay_namespace",
    "request_digest",
    "runtime_subject",
    "runtime_tree",
    "stable_effect_intent_digest",
    "stable_request_digest",
    "state_digest",
    "subject_digest",
    "traversal_id",
    "trust_registry_digest",
    "trust_root_digest",
];

#[derive(Copy, Clone)]
struct StageIssue<'a> {
    at_ms: u64,
    nonce: &'a str,
}

/// A service-internal signer boundary.  It is deliberately not exported and
/// receives only the already typed authority stage preimage.  The wire crate
/// exposes no signing callback and cannot invoke this trait.
trait PrivateWireAuthoritySigner {
    fn algorithm(&self) -> &'static str;
    fn sign_authority_stage(
        &mut self,
        key: &KeyRecord,
        preimage: &[u8],
    ) -> Result<Vec<u8>, IntegrationError>;
}

trait PrivateWireWatchdogSigner {
    fn watchdog_algorithm(&self) -> &'static str;
    fn sign_watchdog_stage(
        &mut self,
        key: &KeyRecord,
        preimage: &[u8],
    ) -> Result<Vec<u8>, IntegrationError>;
}

trait PrivateWireAdapterSigner {
    fn adapter_algorithm(&self) -> &'static str;
    fn sign_adapter_stage(
        &mut self,
        key: &KeyRecord,
        preimage: &[u8],
    ) -> Result<Vec<u8>, IntegrationError>;
}

#[allow(clippy::too_many_arguments)]
fn private_result_draft(
    request: &Message,
    prefix_len: usize,
    kind: &str,
    role: &str,
    error_code: &str,
    issue: StageIssue<'_>,
    registry: &TrustRegistry,
    algorithm: &str,
    extras: BTreeMap<String, Value>,
) -> Result<Message, IntegrationError> {
    let mut result = Message::new();
    for field in COPIED_COMMON_FIELDS {
        result.insert(
            (*field).to_owned(),
            request
                .get(*field)
                .cloned()
                .ok_or(IntegrationError::Invalid("missing immutable field"))?,
        );
    }
    let key = registry
        .entries
        .get(role)
        .ok_or(IntegrationError::Invalid("missing stage signer"))?;
    if key.role != role {
        return Err(IntegrationError::Invalid("registry role mismatch"));
    }
    result.insert("error_code".into(), Value::Text(error_code.into()));
    result.insert("kind".into(), Value::Text(kind.into()));
    result.insert("message_time_ms".into(), Value::Number(issue.at_ms));
    result.insert("nonce".into(), Value::Text(issue.nonce.into()));
    result.insert(
        "prior_transcript_digest".into(),
        Value::Text(text(request, "transcript_digest")?.into()),
    );
    result.insert("sequence".into(), Value::Number(prefix_len as u64));
    result.insert("signature_algorithm".into(), Value::Text(algorithm.into()));
    result.insert(
        "signer_key_class".into(),
        Value::Text(key.key_class.clone()),
    );
    result.insert(
        "signer_key_id".into(),
        Value::Text(key.key_id().map_err(wire_error)?),
    );
    result.insert("signer_role".into(), Value::Text(role.into()));
    result.insert(
        "signing_public_key_hex".into(),
        Value::Text(key.public_key_hex.clone()),
    );
    result.insert("signature_hex".into(), Value::Text("00".into()));
    result.insert("transcript_digest".into(), Value::Text(ZERO.into()));
    result.extend(extras);
    Ok(result)
}

fn seal_private_result<S: PrivateWireAuthoritySigner + ?Sized>(
    mut draft: Message,
    registry: &TrustRegistry,
    signer: &mut S,
) -> Result<Message, IntegrationError> {
    let key = registry
        .entries
        .get("AUTHORITY")
        .ok_or(IntegrationError::Invalid("authority registry entry"))?;
    if text(&draft, "signer_key_id")? != key.key_id().map_err(wire_error)?
        || text(&draft, "signer_key_class")? != key.key_class
        || text(&draft, "signing_public_key_hex")? != key.public_key_hex
        || text(&draft, "signature_algorithm")? != signer.algorithm()
    {
        return Err(IntegrationError::Invalid(
            "private signer identity mismatch",
        ));
    }
    let transcript = transcript_digest(&draft).map_err(wire_error)?;
    draft.insert("transcript_digest".into(), Value::Text(transcript));
    let preimage = signature_preimage(&draft).map_err(wire_error)?;
    let signature = signer.sign_authority_stage(key, &preimage)?;
    if signature.is_empty() {
        return Err(IntegrationError::SignerRejected);
    }
    draft.insert("signature_hex".into(), Value::Text(lower_hex(&signature)));
    Ok(draft)
}

fn seal_private_watchdog_result<S: PrivateWireWatchdogSigner + ?Sized>(
    mut draft: Message,
    registry: &TrustRegistry,
    signer: &mut S,
) -> Result<Message, IntegrationError> {
    let key = checked_signer_key(&draft, registry, "WATCHDOG", signer.watchdog_algorithm())?;
    let transcript = transcript_digest(&draft).map_err(wire_error)?;
    draft.insert("transcript_digest".into(), Value::Text(transcript));
    let preimage = signature_preimage(&draft).map_err(wire_error)?;
    let signature = signer.sign_watchdog_stage(key, &preimage)?;
    finish_private_signature(draft, signature)
}

fn seal_private_adapter_result<S: PrivateWireAdapterSigner + ?Sized>(
    mut draft: Message,
    registry: &TrustRegistry,
    signer: &mut S,
) -> Result<Message, IntegrationError> {
    let key = checked_signer_key(&draft, registry, "ADAPTER", signer.adapter_algorithm())?;
    let transcript = transcript_digest(&draft).map_err(wire_error)?;
    draft.insert("transcript_digest".into(), Value::Text(transcript));
    let preimage = signature_preimage(&draft).map_err(wire_error)?;
    let signature = signer.sign_adapter_stage(key, &preimage)?;
    finish_private_signature(draft, signature)
}

fn checked_signer_key<'a>(
    draft: &Message,
    registry: &'a TrustRegistry,
    role: &str,
    algorithm: &str,
) -> Result<&'a KeyRecord, IntegrationError> {
    let key = registry
        .entries
        .get(role)
        .ok_or(IntegrationError::Invalid("stage registry entry"))?;
    if text(draft, "signer_role")? != role
        || text(draft, "signer_key_id")? != key.key_id().map_err(wire_error)?
        || text(draft, "signer_key_class")? != key.key_class
        || text(draft, "signing_public_key_hex")? != key.public_key_hex
        || text(draft, "signature_algorithm")? != algorithm
    {
        return Err(IntegrationError::Invalid(
            "private signer identity mismatch",
        ));
    }
    Ok(key)
}

fn finish_private_signature(
    mut draft: Message,
    signature: Vec<u8>,
) -> Result<Message, IntegrationError> {
    if signature.is_empty() {
        return Err(IntegrationError::SignerRejected);
    }
    draft.insert("signature_hex".into(), Value::Text(lower_hex(&signature)));
    Ok(draft)
}

fn refreshed_stage(
    prefix: &[Message],
    expected_kind: &str,
    prior: &VerifiedStageContext,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<VerifiedStageContext, IntegrationError> {
    let fresh = validate_request_prefix(
        prefix,
        expected_kind,
        registry,
        admission,
        verifier,
        trusted_now_ms,
    )
    .map_err(wire_error)?;
    if fresh.context_digest() != prior.context_digest()
        || fresh.authenticated_convergence_binding_digest()
            != prior.authenticated_convergence_binding_digest()
    {
        return Err(IntegrationError::Invalid("stale or foreign stage context"));
    }
    Ok(fresh)
}

struct PrivatelyPrepared<R> {
    transcript: Vec<Message>,
    binding: Binding,
    core_policy: CorePolicy,
    prepared: Prepared,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> AuthenticatedConvergence<R> {
    #[allow(clippy::too_many_arguments)]
    fn prepare<P, V>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        ttl: Ttl,
        core_provider: &mut P,
    ) -> Result<PrivatelyPrepared<R>, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let stage = refreshed_stage(
            &self.transcript,
            "prepare_request",
            &self.stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )?;
        let request = self
            .transcript
            .last()
            .ok_or(IntegrationError::Invalid("prepare request absent"))?;
        let mut draft = private_result_draft(
            request,
            self.transcript.len(),
            "prepare_result",
            "AUTHORITY",
            "NONE",
            issue,
            registry,
            self.engine.signers.authority.algorithm(),
            BTreeMap::from([
                ("decision".into(), Value::Text("ALLOW".into())),
                ("prepare_id".into(), Value::Text(ZERO_ID.into())),
                ("prepare_proof_digest".into(), Value::Text(ZERO.into())),
            ]),
        )?;
        let artifact = authority_artifact_digest("prepare_request", &stage, request, &draft)
            .map_err(wire_error)?;
        let identity = authority_artifact_id("prepare_request", &artifact).map_err(wire_error)?;
        draft.insert("prepare_id".into(), Value::Text(identity.clone()));
        draft.insert("prepare_proof_digest".into(), Value::Text(artifact));

        let prepared = self
            .converged
            .prepare_with_replay(
                Time::from_millis_since_epoch(issue.at_ms),
                ttl,
                PrepareId::new(decode_hex(&identity)?).map_err(core_error)?,
                self.durable_consumption_digest,
                core_provider,
                self.engine.replay_mut(),
            )
            .map_err(core_error)?;
        let result = seal_private_result(draft, registry, self.engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &self.transcript,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        Ok(PrivatelyPrepared {
            transcript,
            binding: self.binding,
            core_policy: self.core_policy,
            prepared,
            engine: self.engine,
        })
    }
}

struct PrivatelyCommitted<R> {
    transcript: Vec<Message>,
    binding: Binding,
    core_policy: CorePolicy,
    committed: trusted_authority_core::Committed,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> PrivatelyPrepared<R> {
    #[allow(clippy::too_many_arguments)]
    fn commit<P, I, H, V>(
        mut self,
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        capability_ttl: Ttl,
        core_provider: &mut P,
        interlock: &mut I,
        inhibit: &mut H,
    ) -> Result<PrivatelyCommitted<R>, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        I: SafetyEnvelopeInterlock,
        H: SafetyInhibit,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let mut prefix = self.transcript;
        prefix.push(request);
        let stage = validate_request_prefix(
            &prefix,
            "commit_request",
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let request = prefix.last().expect("request appended");
        let mut draft = private_result_draft(
            request,
            prefix.len(),
            "commit_result",
            "AUTHORITY",
            "NONE",
            issue,
            registry,
            self.engine.signers.authority.algorithm(),
            BTreeMap::from([
                ("capability_digest".into(), Value::Text(ZERO.into())),
                ("capability_id".into(), Value::Text(ZERO_ID.into())),
                ("decision".into(), Value::Text("ALLOW".into())),
            ]),
        )?;
        let artifact = authority_artifact_digest("commit_request", &stage, request, &draft)
            .map_err(wire_error)?;
        let identity = authority_artifact_id("commit_request", &artifact).map_err(wire_error)?;
        draft.insert("capability_digest".into(), Value::Text(artifact));
        draft.insert("capability_id".into(), Value::Text(identity.clone()));
        let committed = self
            .prepared
            .commit(
                Time::from_millis_since_epoch(issue.at_ms),
                capability_ttl,
                CapabilityId::new(decode_hex(&identity)?).map_err(core_error)?,
                core_provider,
                self.engine.replay_mut(),
                interlock,
                inhibit,
            )
            .map_err(core_error)?;
        let result = seal_private_result(draft, registry, self.engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &prefix,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        Ok(PrivatelyCommitted {
            transcript,
            binding: self.binding,
            core_policy: self.core_policy,
            committed,
            engine: self.engine,
        })
    }
}

struct PrivatelyLeased<R> {
    transcript: Vec<Message>,
    binding: Binding,
    core_policy: CorePolicy,
    awaiting: AwaitingReceipt,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> PrivatelyCommitted<R> {
    /// Construct the ADAPTER-role lease request with the engine-owned adapter
    /// signer.  An untrusted Python caller supplies no adapter message or key.
    #[allow(clippy::too_many_arguments)]
    fn redeem_lease_from_private_adapter<P, I, H, V>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        request_issue: StageIssue<'_>,
        result_issue: StageIssue<'_>,
        lease_deadline_ms: u64,
        core_provider: &mut P,
        interlock: &mut I,
        inhibit: &mut H,
    ) -> Result<PrivatelyLeased<R>, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        I: SafetyEnvelopeInterlock,
        H: SafetyInhibit,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let prior = self
            .transcript
            .last()
            .ok_or(IntegrationError::Invalid("commit result absent"))?;
        if text(prior, "kind")? != "commit_result" || text(prior, "decision")? != "ALLOW" {
            return Err(IntegrationError::Invalid(
                "authorizing commit result absent",
            ));
        }
        let draft = private_result_draft(
            prior,
            self.transcript.len(),
            "lease_redeem_request",
            "ADAPTER",
            "NONE",
            request_issue,
            registry,
            self.engine.signers.adapter.adapter_algorithm(),
            BTreeMap::from([
                (
                    "capability_digest".into(),
                    prior
                        .get("capability_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("capability digest absent"))?,
                ),
                (
                    "capability_id".into(),
                    prior
                        .get("capability_id")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("capability ID absent"))?,
                ),
                ("lease_deadline_ms".into(), Value::Number(lease_deadline_ms)),
            ]),
        )?;
        let request =
            seal_private_adapter_result(draft, registry, self.engine.signers.adapter.as_mut())?;
        self.redeem_lease(
            request,
            registry,
            admission,
            verifier,
            result_issue,
            core_provider,
            interlock,
            inhibit,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_lease<P, I, H, V>(
        mut self,
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        core_provider: &mut P,
        interlock: &mut I,
        inhibit: &mut H,
    ) -> Result<PrivatelyLeased<R>, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        I: SafetyEnvelopeInterlock,
        H: SafetyInhibit,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let mut prefix = self.transcript;
        prefix.push(request);
        let stage = validate_request_prefix(
            &prefix,
            "lease_redeem_request",
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let request = prefix.last().expect("request appended");
        let lease_deadline = number(request, "lease_deadline_ms")?;
        if issue.at_ms >= lease_deadline {
            return Err(IntegrationError::Invalid("lease deadline"));
        }
        let mut draft = private_result_draft(
            request,
            prefix.len(),
            "lease_redeem_result",
            "AUTHORITY",
            "NONE",
            issue,
            registry,
            self.engine.signers.authority.algorithm(),
            BTreeMap::from([
                ("decision".into(), Value::Text("ALLOW".into())),
                ("lease_deadline_ms".into(), Value::Number(lease_deadline)),
                ("lease_digest".into(), Value::Text(ZERO.into())),
                ("lease_id".into(), Value::Text(ZERO_ID.into())),
            ]),
        )?;
        let artifact = authority_artifact_digest("lease_redeem_request", &stage, request, &draft)
            .map_err(wire_error)?;
        let identity =
            authority_artifact_id("lease_redeem_request", &artifact).map_err(wire_error)?;
        draft.insert("lease_digest".into(), Value::Text(artifact));
        draft.insert("lease_id".into(), Value::Text(identity.clone()));
        let lease_ttl = Ttl::from_millis(lease_deadline - issue.at_ms).map_err(core_error)?;
        let (replay, watchdog) = self.engine.replay_and_watchdog_mut();
        let awaiting = self
            .committed
            .redeem_at_point_of_use(
                Time::from_millis_since_epoch(issue.at_ms),
                PointOfUseRequest::new(
                    self.binding,
                    LeaseId::new(decode_hex(&identity)?).map_err(core_error)?,
                    lease_ttl,
                ),
                core_provider,
                replay,
                interlock,
                inhibit,
                watchdog,
            )
            .map_err(core_error)?;
        if awaiting
            .lease()
            .claims()
            .expires_at()
            .as_millis_since_epoch()
            != lease_deadline
        {
            return Err(IntegrationError::Invalid(
                "core/wire lease deadline mismatch",
            ));
        }
        let result = seal_private_result(draft, registry, self.engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &prefix,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        Ok(PrivatelyLeased {
            transcript,
            binding: self.binding,
            core_policy: self.core_policy,
            awaiting,
            engine: self.engine,
        })
    }
}

struct PrivatelyWatchdogArmed<R> {
    transcript: Vec<Message>,
    binding: Binding,
    core_policy: CorePolicy,
    awaiting: AwaitingReceipt,
    wire_watchdog_deadline_ms: u64,
    engine: PrivateAuthorityEngine<R>,
}

impl<R: PrivateReplayAnchor> PrivatelyLeased<R> {
    #[allow(clippy::too_many_arguments)]
    fn arm_watchdog<V: PrivateWireVerificationProvider>(
        mut self,
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
    ) -> Result<PrivatelyWatchdogArmed<R>, IntegrationError> {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let mut prefix = self.transcript;
        prefix.push(request);
        let stage = validate_request_prefix(
            &prefix,
            "watchdog_arm_request",
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let request = prefix.last().expect("request appended");
        if decode_hex::<16>(text(request, "lease_id")?)?
            != *self.awaiting.watchdog_arm().lease_id().as_bytes()
        {
            return Err(IntegrationError::Invalid("watchdog lease ID mismatch"));
        }
        let watchdog_deadline_ms = number(request, "watchdog_deadline_ms")?;
        let mut draft = private_result_draft(
            request,
            prefix.len(),
            "watchdog_arm_result",
            "WATCHDOG",
            "NONE",
            issue,
            registry,
            self.engine.signers.watchdog.watchdog_algorithm(),
            BTreeMap::from([
                ("decision".into(), Value::Text("ALLOW".into())),
                (
                    "watchdog_deadline_ms".into(),
                    Value::Number(watchdog_deadline_ms),
                ),
                ("watchdog_digest".into(), Value::Text(ZERO.into())),
            ]),
        )?;
        let artifact = authority_artifact_digest("watchdog_arm_request", &stage, request, &draft)
            .map_err(wire_error)?;
        draft.insert("watchdog_digest".into(), Value::Text(artifact));
        let result =
            seal_private_watchdog_result(draft, registry, self.engine.signers.watchdog.as_mut())?;
        let transcript = validate_and_append_result(
            &prefix,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        Ok(PrivatelyWatchdogArmed {
            transcript,
            binding: self.binding,
            core_policy: self.core_policy,
            awaiting: self.awaiting,
            wire_watchdog_deadline_ms: watchdog_deadline_ms,
            engine: self.engine,
        })
    }
}

struct AtomicDispatch<R> {
    fixed_prefix: Vec<Message>,
    permit_context: VerifiedEffectPermitContext,
    permit_id: [u8; 16],
    permit_digest: [u8; 64],
    core_policy: CorePolicy,
    binding: Binding,
    effect_lease: EffectLease,
    awaiting: AwaitingReceipt,
    engine: PrivateAuthorityEngine<R>,
}

/// A private, lifetime-scoped adapter call containing the exact v2 permit pair.
/// It is neither public nor cloneable and exists only during one synchronous
/// core dispatch.
struct PermitBoundEffect<'a> {
    core: EffectDispatch<'a>,
    permit_id: [u8; 16],
    permit_digest: [u8; 64],
}

trait PrivateAdmittedAdapter {
    fn trusted_now(&mut self) -> Result<Time, ExternalFailure>;
    fn consume_once(
        &mut self,
        effect: PermitBoundEffect<'_>,
    ) -> Result<PrivateEffectObservation, ExternalFailure>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum PrivateEffectObservation {
    Succeeded,
    Failed,
    Unknown,
}

struct AdapterBridge<'a, A> {
    adapter: &'a mut A,
    permit_id: [u8; 16],
    permit_digest: [u8; 64],
    observation: Option<PrivateEffectObservation>,
    consumed_at: Option<Time>,
}

impl<A: PrivateAdmittedAdapter> AtomicEffectAdapter for AdapterBridge<'_, A> {
    fn trusted_now(&mut self) -> Result<Time, ExternalFailure> {
        self.adapter.trusted_now()
    }

    fn consume_once(
        &mut self,
        dispatch: EffectDispatch<'_>,
    ) -> Result<EffectOutcome, ExternalFailure> {
        self.consumed_at = Some(dispatch.authorized_at());
        let observation = self.adapter.consume_once(PermitBoundEffect {
            core: dispatch,
            permit_id: self.permit_id,
            permit_digest: self.permit_digest,
        })?;
        self.observation = Some(observation);
        match observation {
            PrivateEffectObservation::Succeeded => Ok(EffectOutcome::Applied),
            PrivateEffectObservation::Failed => Ok(EffectOutcome::SafelyNotApplied),
            PrivateEffectObservation::Unknown => Err(ExternalFailure::new(12_002)),
        }
    }
}

struct PostEffectState<R> {
    fixed_prefix: Vec<Message>,
    core_policy: CorePolicy,
    binding: Binding,
    applied: Option<AppliedEffect>,
    observation: PrivateEffectObservation,
    consumed_at: Time,
    awaiting: AwaitingReceipt,
    permit_id: [u8; 16],
    permit_digest: [u8; 64],
    engine: PrivateAuthorityEngine<R>,
}

struct PrivateTerminalState {
    transcript: Vec<Message>,
    disposition: TerminalDisposition,
}

#[derive(Copy, Clone)]
struct TerminalIssue<'a> {
    receipt: StageIssue<'a>,
    receipt_ack: StageIssue<'a>,
    watchdog_terminal: StageIssue<'a>,
    watchdog_result: StageIssue<'a>,
}

#[derive(Copy, Clone)]
struct TimeoutIssue<'a> {
    watchdog_terminal: StageIssue<'a>,
    watchdog_result: StageIssue<'a>,
}

impl<R: PrivateReplayAnchor> PrivatelyWatchdogArmed<R> {
    /// Construct the final ADAPTER-role permit request inside the Rust service.
    /// The signed permit result is consumed by `AtomicDispatch` and cannot be
    /// returned while redeemable.
    #[allow(clippy::too_many_arguments)]
    fn issue_effect_permit_from_private_adapter<V: PrivateWireVerificationProvider>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        request_issue: StageIssue<'_>,
        result_issue: StageIssue<'_>,
        permit_deadline_ms: u64,
    ) -> Result<AtomicDispatch<R>, IntegrationError> {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let prior = self
            .transcript
            .last()
            .ok_or(IntegrationError::Invalid("watchdog result absent"))?;
        if text(prior, "kind")? != "watchdog_arm_result" || text(prior, "decision")? != "ALLOW" {
            return Err(IntegrationError::Invalid("armed watchdog result absent"));
        }
        let lease = self
            .transcript
            .iter()
            .find(|message| text(message, "kind").ok() == Some("lease_redeem_result"))
            .ok_or(IntegrationError::Invalid("lease result absent"))?;
        let mut draft = private_result_draft(
            prior,
            self.transcript.len(),
            "effect_permit_request",
            "ADAPTER",
            "NONE",
            request_issue,
            registry,
            self.engine.signers.adapter.adapter_algorithm(),
            BTreeMap::from([
                (
                    "lease_deadline_ms".into(),
                    lease
                        .get("lease_deadline_ms")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("lease deadline absent"))?,
                ),
                (
                    "lease_digest".into(),
                    lease
                        .get("lease_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("lease digest absent"))?,
                ),
                (
                    "lease_id".into(),
                    lease
                        .get("lease_id")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("lease ID absent"))?,
                ),
                ("point_of_use_digest".into(), Value::Text(ZERO.into())),
                (
                    "watchdog_deadline_ms".into(),
                    prior
                        .get("watchdog_deadline_ms")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("watchdog deadline absent"))?,
                ),
                (
                    "watchdog_digest".into(),
                    prior
                        .get("watchdog_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("watchdog digest absent"))?,
                ),
            ]),
        )?;
        let point_of_use = point_of_use_digest(&draft).map_err(wire_error)?;
        draft.insert("point_of_use_digest".into(), Value::Text(point_of_use));
        let request =
            seal_private_adapter_result(draft, registry, self.engine.signers.adapter.as_mut())?;
        self.issue_effect_permit(
            request,
            registry,
            admission,
            verifier,
            result_issue,
            permit_deadline_ms,
        )
    }

    /// Persist the exact physical stop deadline before any effect permit can be
    /// signed or returned. The returned typestate owns the confirmed narrowed
    /// arm; a crash after this transition leaves the independent watchdog able
    /// to stop at the same deadline without this process.
    fn durably_tighten_for_permit(
        mut self,
        now_ms: u64,
        requested_permit_deadline_ms: u64,
    ) -> Result<(Self, u64), IntegrationError> {
        let lease_deadline_ms = self
            .awaiting
            .lease()
            .claims()
            .expires_at()
            .as_millis_since_epoch();
        let effective_deadline_ms = core::cmp::min(
            lease_deadline_ms,
            core::cmp::min(self.wire_watchdog_deadline_ms, requested_permit_deadline_ms),
        );
        if requested_permit_deadline_ms != effective_deadline_ms {
            return Err(IntegrationError::Invalid(
                "permit deadline is not the effective minimum",
            ));
        }
        self.awaiting = self
            .awaiting
            .tighten_watchdog(
                Time::from_millis_since_epoch(now_ms),
                Time::from_millis_since_epoch(effective_deadline_ms),
                self.engine.watchdog.as_mut(),
            )
            .map_err(core_error)?;
        if self
            .awaiting
            .watchdog_arm()
            .receipt_deadline()
            .as_millis_since_epoch()
            != effective_deadline_ms
        {
            return Err(IntegrationError::Invalid("watchdog tighten mismatch"));
        }
        Ok((self, effective_deadline_ms))
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_effect_permit<V: PrivateWireVerificationProvider>(
        self,
        request: Message,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: StageIssue<'_>,
        permit_deadline_ms: u64,
    ) -> Result<AtomicDispatch<R>, IntegrationError> {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let mut prefix = self.transcript.clone();
        prefix.push(request);
        let stage = validate_request_prefix(
            &prefix,
            "effect_permit_request",
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let (mut tightened, effective_deadline_ms) =
            self.durably_tighten_for_permit(issue.at_ms, permit_deadline_ms)?;
        let request = prefix.last().expect("request appended");
        let mut draft = private_result_draft(
            request,
            prefix.len(),
            "effect_permit_result",
            "AUTHORITY",
            "NONE",
            issue,
            registry,
            tightened.engine.signers.authority.algorithm(),
            BTreeMap::from([
                ("decision".into(), Value::Text("ALLOW".into())),
                (
                    "permit_deadline_ms".into(),
                    Value::Number(effective_deadline_ms),
                ),
                ("permit_digest".into(), Value::Text(ZERO.into())),
                ("permit_id".into(), Value::Text(ZERO_ID.into())),
                (
                    "watchdog_digest".into(),
                    request
                        .get("watchdog_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("watchdog digest"))?,
                ),
            ]),
        )?;
        let artifact = authority_artifact_digest("effect_permit_request", &stage, request, &draft)
            .map_err(wire_error)?;
        let identity =
            authority_artifact_id("effect_permit_request", &artifact).map_err(wire_error)?;
        draft.insert("permit_digest".into(), Value::Text(artifact));
        draft.insert("permit_id".into(), Value::Text(identity));
        let result =
            seal_private_result(draft, registry, tightened.engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &prefix,
            &result,
            &stage,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        let permit_context = validate_effect_permit_for_atomic_consumption(
            &transcript,
            registry,
            admission,
            verifier,
            issue.at_ms,
        )
        .map_err(wire_error)?;
        atomic_dispatch_from_verified(
            permit_context,
            transcript,
            tightened.core_policy,
            tightened.binding,
            tightened.awaiting,
            tightened.engine,
            admission,
        )
    }
}

fn atomic_dispatch_from_verified<R: PrivateReplayAnchor>(
    permit_context: VerifiedEffectPermitContext,
    fixed_prefix: Vec<Message>,
    core_policy: CorePolicy,
    binding: Binding,
    awaiting: AwaitingReceipt,
    engine: PrivateAuthorityEngine<R>,
    admission: &AdmissionPolicy,
) -> Result<AtomicDispatch<R>, IntegrationError> {
    let expected_durable = admission_durable(admission)?;
    if permit_context.authenticated_convergence_binding_digest()
        != lower_hex(binding.wire_binding_digest().as_bytes())
        || permit_context.admission_policy_digest()
            != admission_policy_digest(admission).map_err(wire_error)?
        || permit_context
            .derived_number("authority_epoch")
            .map_err(wire_error)?
            != admission.authority_epoch
        || permit_context
            .derived_text("durable_consumption_digest")
            .map_err(wire_error)?
            != expected_durable
    {
        return Err(IntegrationError::Invalid("permit immutable binding"));
    }
    for (wire_field, expected) in [
        ("domain_digest", admission.domain_digest.as_str()),
        ("subject_digest", admission.subject_digest.as_str()),
        ("effect_digest", admission.effect_digest.as_str()),
        ("adapter_digest", admission.adapter_digest.as_str()),
        ("operation_id", admission.operation_id.as_str()),
        ("traversal_id", admission.traversal_id.as_str()),
    ] {
        if permit_context
            .derived_text(wire_field)
            .map_err(wire_error)?
            != expected
        {
            return Err(IntegrationError::Invalid("permit semantic transplant"));
        }
    }
    let lease_claims = awaiting.lease().claims();
    if decode_hex::<16>(
        permit_context
            .derived_text("lease_id")
            .map_err(wire_error)?,
    )? != *lease_claims.lease_id().as_bytes()
        || permit_context
            .derived_number("permit_deadline_ms")
            .map_err(wire_error)?
            > lease_claims.expires_at().as_millis_since_epoch()
    {
        return Err(IntegrationError::Invalid("permit/lease transplant"));
    }
    let signature = ProviderSignature::new(
        awaiting.lease().signature().key_id(),
        awaiting.lease().signature().as_bytes().to_vec(),
    )
    .map_err(core_error)?;
    let effect_lease = EffectLease::from_untrusted_parts(lease_claims, signature);
    Ok(AtomicDispatch {
        fixed_prefix,
        permit_id: decode_hex(
            permit_context
                .derived_text("permit_id")
                .map_err(wire_error)?,
        )?,
        permit_digest: decode_hex(
            permit_context
                .derived_text("permit_digest")
                .map_err(wire_error)?,
        )?,
        permit_context,
        core_policy,
        binding,
        effect_lease,
        awaiting,
        engine,
    })
}

fn admission_durable(admission: &AdmissionPolicy) -> Result<String, IntegrationError> {
    // Recompute from the externally pinned namespace and stable effect intent;
    // never accept a traversal-, nonce- or process-selected replay identity.
    sbp_lex_authority_wire_v2::durable_consumption_digest(
        &admission.replay_namespace,
        &sbp_lex_authority_wire_v2::stable_effect_intent_digest(
            &admission.stable_request_digest,
            &admission.effect_intent_digest,
            &admission.effect_digest,
            &admission.adapter_digest,
            &admission.adapter_boundary_digest,
        )
        .map_err(wire_error)?,
    )
    .map_err(wire_error)
}

impl<R: PrivateReplayAnchor> AtomicDispatch<R> {
    #[allow(clippy::too_many_arguments)]
    fn consume<P, H, A, V>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        core_provider: &mut P,
        inhibit: &mut H,
        adapter: &mut A,
    ) -> Result<PostEffectState<R>, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        H: SafetyInhibit,
        A: PrivateAdmittedAdapter,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let now = adapter.trusted_now().map_err(core_error)?;
        let refreshed = validate_effect_permit_for_atomic_consumption(
            &self.fixed_prefix,
            registry,
            admission,
            verifier,
            now.as_millis_since_epoch(),
        )
        .map_err(wire_error)?;
        if refreshed.stage_context_digest() != self.permit_context.stage_context_digest()
            || decode_hex::<16>(refreshed.derived_text("permit_id").map_err(wire_error)?)?
                != self.permit_id
            || decode_hex::<64>(
                refreshed
                    .derived_text("permit_digest")
                    .map_err(wire_error)?,
            )? != self.permit_digest
        {
            return Err(IntegrationError::Invalid("point-of-use permit mutation"));
        }
        let mut bridge = AdapterBridge {
            adapter,
            permit_id: self.permit_id,
            permit_digest: self.permit_digest,
            observation: None,
            consumed_at: None,
        };
        let (replay, watchdog) = self.engine.replay_and_watchdog_mut();
        let dispatched = self.effect_lease.dispatch_effect_at_point_of_use(
            self.core_policy,
            self.binding,
            self.awaiting.watchdog_arm(),
            core_provider,
            replay,
            inhibit,
            watchdog,
            &mut bridge,
        );
        let observation = bridge.observation.ok_or_else(|| {
            dispatched.as_ref().err().map_or_else(
                || IntegrationError::Invalid("adapter produced no observation"),
                core_error,
            )
        })?;
        let consumed_at = bridge
            .consumed_at
            .ok_or(IntegrationError::Invalid("adapter consumption time absent"))?;
        let applied = match (observation, dispatched) {
            (PrivateEffectObservation::Succeeded, Ok(applied))
                if applied.outcome() == EffectOutcome::Applied =>
            {
                Some(applied)
            }
            (PrivateEffectObservation::Failed, Ok(applied))
                if applied.outcome() == EffectOutcome::SafelyNotApplied =>
            {
                Some(applied)
            }
            (PrivateEffectObservation::Unknown, Err(_)) => None,
            _ => return Err(IntegrationError::Invalid("adapter/core outcome mismatch")),
        };
        Ok(PostEffectState {
            fixed_prefix: self.fixed_prefix,
            core_policy: self.core_policy,
            binding: self.binding,
            applied,
            observation,
            consumed_at,
            awaiting: self.awaiting,
            permit_id: self.permit_id,
            permit_digest: self.permit_digest,
            engine: self.engine,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn timeout<V>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: TimeoutIssue<'_>,
    ) -> Result<PrivateTerminalState, IntegrationError>
    where
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let expected_deadline = self
            .awaiting
            .watchdog_arm()
            .receipt_deadline()
            .as_millis_since_epoch();
        if issue.watchdog_terminal.at_ms != expected_deadline {
            return Err(IntegrationError::Invalid("watchdog timeout deadline"));
        }
        self.engine
            .watchdog
            .trip(
                self.awaiting.watchdog_arm(),
                WatchdogTripReason::IntegratedPermitDeadlineElapsed,
            )
            .map_err(core_error)?;
        let terminal = terminal_tail(
            self.fixed_prefix,
            self.permit_id,
            self.permit_digest,
            ZERO,
            "TIMEOUT",
            "WATCHDOG_TIMEOUT",
            issue.watchdog_terminal,
            issue.watchdog_result,
            registry,
            admission,
            verifier,
            self.engine.signers.watchdog.as_mut(),
            self.engine.signers.authority.as_mut(),
        )?;
        persist_pending_terminal(self.engine.terminal_audit.as_mut(), admission, &terminal)?;
        Ok(terminal)
    }
}

impl<R: PrivateReplayAnchor> PostEffectState<R> {
    #[allow(clippy::too_many_arguments)]
    fn finish<P, V>(
        mut self,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        verifier: &V,
        issue: TerminalIssue<'_>,
        core_provider: &mut P,
    ) -> Result<PrivateTerminalState, IntegrationError>
    where
        P: ExternalSignatureProvider + KeyCustodyProvider,
        V: PrivateWireVerificationProvider,
    {
        self.engine
            .verify_trust_context(registry, admission, verifier)?;
        let outcome = match self.observation {
            PrivateEffectObservation::Succeeded => "SUCCEEDED",
            PrivateEffectObservation::Failed => "FAILED",
            PrivateEffectObservation::Unknown => "UNKNOWN",
        };
        let permit = self
            .fixed_prefix
            .last()
            .ok_or(IntegrationError::Invalid("permit result absent"))?;
        let mut receipt = private_result_draft(
            permit,
            self.fixed_prefix.len(),
            "effect_receipt",
            "ADAPTER",
            "NONE",
            issue.receipt,
            registry,
            self.engine.signers.adapter.adapter_algorithm(),
            BTreeMap::from([
                (
                    "adapter_consumed_at_ms".into(),
                    Value::Number(self.consumed_at.as_millis_since_epoch()),
                ),
                (
                    "adapter_consumption_digest".into(),
                    Value::Text(ZERO.into()),
                ),
                ("effect_outcome".into(), Value::Text(outcome.into())),
                (
                    "permit_digest".into(),
                    Value::Text(lower_hex(&self.permit_digest)),
                ),
                ("permit_id".into(), Value::Text(lower_hex(&self.permit_id))),
                ("receipt_digest".into(), Value::Text(ZERO.into())),
                (
                    "watchdog_digest".into(),
                    permit
                        .get("watchdog_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("watchdog digest absent"))?,
                ),
            ]),
        )?;
        let consumption = adapter_consumption_digest(
            text(&receipt, "durable_consumption_digest")?,
            text(&receipt, "permit_digest")?,
            text(&receipt, "effect_digest")?,
            text(&receipt, "adapter_digest")?,
            self.consumed_at.as_millis_since_epoch(),
            outcome,
        )
        .map_err(wire_error)?;
        receipt.insert(
            "adapter_consumption_digest".into(),
            Value::Text(consumption),
        );
        let receipt_digest = effect_receipt_digest(&receipt).map_err(wire_error)?;
        receipt.insert("receipt_digest".into(), Value::Text(receipt_digest.clone()));
        let receipt =
            seal_private_adapter_result(receipt, registry, self.engine.signers.adapter.as_mut())?;

        let mut receipt_prefix = self.fixed_prefix;
        receipt_prefix.push(receipt);
        let receipt_stage = validate_request_prefix(
            &receipt_prefix,
            "effect_receipt",
            registry,
            admission,
            verifier,
            issue.receipt_ack.at_ms,
        )
        .map_err(wire_error)?;

        let watchdog_arm = self.awaiting.watchdog_arm();
        // Phase one: authenticate/claim the exact receipt while retaining the
        // watchdog arm. Failed and unknown effects assert STOP immediately and
        // never enter the acknowledgement path.
        let claimed_success = match (self.observation, self.applied) {
            (PrivateEffectObservation::Succeeded, Some(applied)) => {
                let signed_core_receipt = SignedAdapterReceipt::issue(
                    AdapterReceiptClaims::new(
                        self.binding,
                        applied.capability_id(),
                        applied.lease_id(),
                        applied.completed_at(),
                        applied.outcome(),
                    ),
                    self.core_policy.adapter_receipt_key(),
                    core_provider,
                )
                .map_err(core_error)?;
                let (replay, watchdog) = self.engine.replay_and_watchdog_mut();
                Some(
                    self.awaiting
                        .claim_validated_receipt(
                            Time::from_millis_since_epoch(issue.receipt_ack.at_ms),
                            signed_core_receipt,
                            core_provider,
                            replay,
                            watchdog,
                        )
                        .map_err(core_error)?,
                )
            }
            (PrivateEffectObservation::Failed, Some(applied)) => {
                let signed_core_receipt = SignedAdapterReceipt::issue(
                    AdapterReceiptClaims::new(
                        self.binding,
                        applied.capability_id(),
                        applied.lease_id(),
                        applied.completed_at(),
                        applied.outcome(),
                    ),
                    self.core_policy.adapter_receipt_key(),
                    core_provider,
                )
                .map_err(core_error)?;
                let claimed = {
                    let (replay, watchdog) = self.engine.replay_and_watchdog_mut();
                    self.awaiting
                        .claim_validated_receipt(
                            Time::from_millis_since_epoch(issue.receipt_ack.at_ms),
                            signed_core_receipt,
                            core_provider,
                            replay,
                            watchdog,
                        )
                        .map_err(core_error)?
                };
                claimed
                    .stop_without_ack(
                        self.engine.watchdog.as_mut(),
                        WatchdogTripReason::EffectAdapterFailedAfterConsumptionClaim,
                    )
                    .map_err(core_error)?;
                None
            }
            (PrivateEffectObservation::Unknown, None) => {
                let (replay, watchdog) = self.engine.replay_and_watchdog_mut();
                self.awaiting
                    .claim_and_stop_untrusted_effect(
                        replay,
                        watchdog,
                        WatchdogTripReason::EffectAdapterFailedAfterConsumptionClaim,
                    )
                    .map_err(core_error)?;
                None
            }
            _ => return Err(IntegrationError::Invalid("post-effect core state mismatch")),
        };

        let (ack_decision, receipt_status, ack_error, terminal_status, terminal_error) =
            match self.observation {
                PrivateEffectObservation::Succeeded => {
                    ("ACK", "SUCCESS_RECORDED", "NONE", "HEALTHY", "NONE")
                }
                PrivateEffectObservation::Failed => (
                    "FAILURE_ACK",
                    "FAILURE_RECORDED",
                    "EFFECT_NOT_SUCCESSFUL",
                    "STOP",
                    "EFFECT_STOPPED",
                ),
                PrivateEffectObservation::Unknown => (
                    "FAILURE_ACK",
                    "UNKNOWN_BLOCKED",
                    "EFFECT_NOT_SUCCESSFUL",
                    "STOP",
                    "EFFECT_STOPPED",
                ),
            };
        let request = receipt_prefix.last().expect("receipt appended");
        let ack = private_result_draft(
            request,
            receipt_prefix.len(),
            "receipt_ack",
            "AUTHORITY",
            ack_error,
            issue.receipt_ack,
            registry,
            self.engine.signers.authority.algorithm(),
            BTreeMap::from([
                ("decision".into(), Value::Text(ack_decision.into())),
                (
                    "permit_digest".into(),
                    Value::Text(lower_hex(&self.permit_digest)),
                ),
                ("permit_id".into(), Value::Text(lower_hex(&self.permit_id))),
                ("receipt_digest".into(), Value::Text(receipt_digest.clone())),
                ("receipt_status".into(), Value::Text(receipt_status.into())),
                (
                    "watchdog_digest".into(),
                    request
                        .get("watchdog_digest")
                        .cloned()
                        .ok_or(IntegrationError::Invalid("watchdog digest absent"))?,
                ),
            ]),
        )?;
        let ack = seal_private_result(ack, registry, self.engine.signers.authority.as_mut())?;
        let transcript = validate_and_append_result(
            &receipt_prefix,
            &ack,
            &receipt_stage,
            registry,
            admission,
            verifier,
            issue.receipt_ack.at_ms,
        )
        .map_err(wire_error)?;
        let terminal = terminal_tail(
            transcript,
            self.permit_id,
            self.permit_digest,
            &receipt_digest,
            terminal_status,
            terminal_error,
            issue.watchdog_terminal,
            issue.watchdog_result,
            registry,
            admission,
            verifier,
            self.engine.signers.watchdog.as_mut(),
            self.engine.signers.authority.as_mut(),
        );
        let terminal = match terminal {
            Ok(value) => value,
            Err(error) => {
                if let Some(claimed) = claimed_success {
                    claimed
                        .stop_without_ack(
                            self.engine.watchdog.as_mut(),
                            WatchdogTripReason::TerminalAuditUnavailableAfterReceiptClaim,
                        )
                        .map_err(core_error)?;
                }
                return Err(error);
            }
        };

        // Phase two: the complete signed tail is revalidated above and then
        // durably appended as PENDING/IN_DOUBT. Bytes alone never constitute a
        // completed success. Failed/unknown paths are already stopped.
        let (audit_key, terminal_digest) = match persist_pending_terminal(
            self.engine.terminal_audit.as_mut(),
            admission,
            &terminal,
        ) {
            Ok(value) => value,
            Err(error) => {
                if let Some(claimed) = claimed_success {
                    claimed
                        .stop_without_ack(
                            self.engine.watchdog.as_mut(),
                            WatchdogTripReason::TerminalAuditUnavailableAfterReceiptClaim,
                        )
                        .map_err(core_error)?;
                }
                return Err(error);
            }
        };

        if let Some(claimed) = claimed_success {
            // The watchdog can be cleared only after the durable pending tail.
            claimed
                .acknowledge_after_durable_terminal(self.engine.watchdog.as_mut())
                .map_err(core_error)?;
            // Evidence records ACK separately. A failure here is conservatively
            // tripped; production atomicity remains unadmitted until a durable,
            // queryable watchdog and audit service are provisioned together.
            if let Err(failure) = self
                .engine
                .terminal_audit
                .finalize_acknowledged(&audit_key, &terminal_digest)
            {
                self.engine
                    .watchdog
                    .trip(
                        watchdog_arm,
                        WatchdogTripReason::TerminalAuditUnavailableAfterReceiptClaim,
                    )
                    .map_err(core_error)?;
                return Err(IntegrationError::AuditSink(failure.code()));
            }
        }
        Ok(terminal)
    }
}

fn canonical_transcript_bytes(transcript: &[Message]) -> Result<Vec<u8>, IntegrationError> {
    let mut output = Vec::new();
    for message in transcript {
        output.extend_from_slice(&encode_message(message).map_err(wire_error)?);
        output.push(b'\n');
    }
    Ok(output)
}

fn persist_pending_terminal(
    sink: &mut dyn PrivateTerminalAuditSink,
    admission: &AdmissionPolicy,
    terminal: &PrivateTerminalState,
) -> Result<(String, String), IntegrationError> {
    let audit_key = admission_durable(admission)?;
    let terminal_digest = text(
        terminal
            .transcript
            .last()
            .ok_or(IntegrationError::Invalid("terminal transcript absent"))?,
        "transcript_digest",
    )?
    .to_owned();
    let disposition = match terminal.disposition {
        TerminalDisposition::Completed => "COMPLETED_PENDING_WATCHDOG_ACK",
        TerminalDisposition::Stop => "STOP",
    };
    let canonical = canonical_transcript_bytes(&terminal.transcript)?;
    sink.append_pending(&audit_key, &terminal_digest, disposition, &canonical)
        .map_err(|failure| IntegrationError::AuditSink(failure.code()))?;
    Ok((audit_key, terminal_digest))
}

#[allow(clippy::too_many_arguments)]
fn terminal_tail<WS, AS>(
    mut prefix: Vec<Message>,
    permit_id: [u8; 16],
    permit_digest: [u8; 64],
    receipt_digest: &str,
    watchdog_status: &str,
    result_error: &str,
    terminal_issue: StageIssue<'_>,
    result_issue: StageIssue<'_>,
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    watchdog_signer: &mut WS,
    authority_signer: &mut AS,
) -> Result<PrivateTerminalState, IntegrationError>
where
    WS: PrivateWireWatchdogSigner + ?Sized,
    AS: PrivateWireAuthoritySigner + ?Sized,
{
    let prior = prefix
        .last()
        .ok_or(IntegrationError::Invalid("terminal prefix absent"))?;
    let watchdog_digest = prior
        .get("watchdog_digest")
        .cloned()
        .ok_or(IntegrationError::Invalid("watchdog digest absent"))?;
    let terminal = private_result_draft(
        prior,
        prefix.len(),
        "watchdog_terminal",
        "WATCHDOG",
        "NONE",
        terminal_issue,
        registry,
        watchdog_signer.watchdog_algorithm(),
        BTreeMap::from([
            (
                "permit_digest".into(),
                Value::Text(lower_hex(&permit_digest)),
            ),
            ("permit_id".into(), Value::Text(lower_hex(&permit_id))),
            ("receipt_digest".into(), Value::Text(receipt_digest.into())),
            ("watchdog_digest".into(), watchdog_digest.clone()),
            (
                "watchdog_status".into(),
                Value::Text(watchdog_status.into()),
            ),
        ]),
    )?;
    let terminal = seal_private_watchdog_result(terminal, registry, watchdog_signer)?;
    prefix.push(terminal);
    let stage = validate_request_prefix(
        &prefix,
        "watchdog_terminal",
        registry,
        admission,
        verifier,
        result_issue.at_ms,
    )
    .map_err(wire_error)?;
    let request = prefix.last().expect("terminal appended");
    let decision = if watchdog_status == "HEALTHY" {
        "ACK"
    } else {
        "BLOCK"
    };
    let result = private_result_draft(
        request,
        prefix.len(),
        "watchdog_result",
        "AUTHORITY",
        result_error,
        result_issue,
        registry,
        authority_signer.algorithm(),
        BTreeMap::from([
            ("decision".into(), Value::Text(decision.into())),
            (
                "permit_digest".into(),
                Value::Text(lower_hex(&permit_digest)),
            ),
            ("permit_id".into(), Value::Text(lower_hex(&permit_id))),
            ("receipt_digest".into(), Value::Text(receipt_digest.into())),
            ("watchdog_digest".into(), watchdog_digest),
        ]),
    )?;
    let result = seal_private_result(result, registry, authority_signer)?;
    let transcript = validate_and_append_result(
        &prefix,
        &result,
        &stage,
        registry,
        admission,
        verifier,
        result_issue.at_ms,
    )
    .map_err(wire_error)?;
    let disposition = validated_terminal_disposition(
        &transcript,
        registry,
        admission,
        verifier,
        result_issue.at_ms,
    )?;
    Ok(PrivateTerminalState {
        transcript,
        disposition,
    })
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TerminalDisposition {
    Completed,
    Stop,
}

fn validated_terminal_disposition(
    transcript: &[Message],
    registry: &TrustRegistry,
    admission: &AdmissionPolicy,
    verifier: &dyn SignatureVerifier,
    trusted_now_ms: u64,
) -> Result<TerminalDisposition, IntegrationError> {
    validate_transcript(transcript, registry, admission, verifier, trusted_now_ms)
        .map_err(wire_error)?;
    let last = transcript
        .last()
        .ok_or(IntegrationError::Invalid("empty terminal transcript"))?;
    if text(last, "kind")? != "watchdog_result" {
        return Err(IntegrationError::Invalid("terminal watchdog result absent"));
    }
    Ok(if text(last, "decision")? == "ACK" {
        TerminalDisposition::Completed
    } else {
        // FAILED, UNKNOWN and TIMEOUT are deliberately collapsed to one
        // non-authorizing fail-closed service disposition.
        TerminalDisposition::Stop
    })
}

#[cfg(all(test, feature = "evidence-only-fixtures"))]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use sbp_lex_authority_wire_v2::{parse_message, FixtureVerifier, PROTOCOL as V2_PROTOCOL};

    use crate::evidence::{
        EvidenceAuthorityDependencies, EvidenceInhibit, EvidenceInterlock, EvidenceReplayJournal,
        EvidenceSignatureProvider, EvidenceTerminalAuditSink, EvidenceWatchdog,
    };
    use crate::{EVIDENCE_PROFILE, PRODUCTION_HSM_PROFILE, PRODUCTION_TPM_PROFILE};

    const GOLDEN: &str = include_str!("../../wire_protocol/v2/vectors/mode1_golden.jsonl");
    const MODE2: &str = include_str!("../../wire_protocol/v2/vectors/mode_2_golden.jsonl");
    const MODE3: &str = include_str!("../../wire_protocol/v2/vectors/mode_3_golden.jsonl");
    const FAILURE: &str = include_str!("../../wire_protocol/v2/vectors/mode1_failure_golden.jsonl");
    const UNKNOWN: &str = include_str!("../../wire_protocol/v2/vectors/mode1_unknown_golden.jsonl");
    const TIMEOUT: &str = include_str!("../../wire_protocol/v2/vectors/mode1_timeout_golden.jsonl");
    const TIMEOUT_LEASE_BOUND: &str =
        include_str!("../../wire_protocol/v2/vectors/mode1_timeout_lease_bound_golden.jsonl");
    const TIMEOUT_WATCHDOG_BOUND: &str =
        include_str!("../../wire_protocol/v2/vectors/mode1_timeout_watchdog_bound_golden.jsonl");
    const MODE2_FAILURE: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_failure_golden.jsonl");
    const MODE2_UNKNOWN: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_unknown_golden.jsonl");
    const MODE2_TIMEOUT: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_timeout_golden.jsonl");
    const MODE3_FAILURE: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_failure_golden.jsonl");
    const MODE3_UNKNOWN: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_unknown_golden.jsonl");
    const MODE3_TIMEOUT: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_timeout_golden.jsonl");
    const TEST_REGISTRY: &str =
        include_str!("../../wire_protocol/v2/vectors/test_trust_registry.txt");

    impl PrivateWireVerificationProvider for FixtureVerifier {
        fn provider_identity(&self) -> Digest {
            Digest::new([0xD1; 64])
        }
    }

    fn parse_lines(value: &str) -> Vec<Message> {
        value
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| parse_message(line.as_bytes()).expect("fixed canonical vector"))
            .collect()
    }

    fn txt(message: &Message, key: &str) -> String {
        match message.get(key).expect("fixture field") {
            Value::Text(value) => value.clone(),
            Value::Number(_) => panic!("text fixture field expected"),
        }
    }

    fn num(message: &Message, key: &str) -> u64 {
        match message.get(key).expect("fixture field") {
            Value::Number(value) => *value,
            Value::Text(_) => panic!("numeric fixture field expected"),
        }
    }

    fn registry(messages: &[Message]) -> TrustRegistry {
        let mut entries = BTreeMap::new();
        for line in TEST_REGISTRY.lines() {
            let mut parts = line.split('|');
            let role = parts.next().expect("role").to_owned();
            entries.insert(
                role.clone(),
                KeyRecord {
                    role,
                    key_class: parts.next().expect("class").to_owned(),
                    public_key_hex: parts.next().expect("public key").to_owned(),
                },
            );
            assert!(parts.next().is_none());
        }
        TrustRegistry {
            root_digest: txt(&messages[0], "trust_root_digest"),
            entries,
        }
    }

    fn policy(messages: &[Message], registry: &TrustRegistry) -> AdmissionPolicy {
        let mode1 = parse_lines(GOLDEN);
        let mode2 = parse_lines(MODE2);
        let mode3 = parse_lines(MODE3);
        AdmissionPolicy {
            trust_root_digest: registry.root_digest.clone(),
            registry_digest: registry.digest().expect("registry digest"),
            runtime_subject: txt(&messages[0], "runtime_subject"),
            runtime_tree: txt(&messages[0], "runtime_tree"),
            authority_class: txt(&messages[0], "authority_class"),
            authority_epoch: num(&messages[0], "authority_epoch"),
            authority_profile: txt(&messages[0], "authority_profile"),
            authority_build_id: txt(&messages[0], "authority_build_id"),
            mode: txt(&messages[0], "mode"),
            traversal_id: txt(&messages[0], "traversal_id"),
            operation_id: txt(&messages[0], "operation_id"),
            challenge: txt(&messages[0], "challenge"),
            replay_namespace: txt(&messages[0], "replay_namespace"),
            stable_request_digest: txt(&messages[0], "stable_request_digest"),
            request_digest: txt(&messages[0], "request_digest"),
            state_digest: txt(&messages[0], "state_digest"),
            effect_digest: txt(&messages[0], "effect_digest"),
            effect_intent_digest: txt(&messages[0], "effect_intent_digest"),
            adapter_digest: txt(&messages[0], "adapter_digest"),
            adapter_boundary_digest: txt(&messages[0], "adapter_boundary_digest"),
            inhibit_binding_digest: txt(&messages[0], "inhibit_binding_digest"),
            interlock_digest: txt(&messages[0], "interlock_digest"),
            audit_anchor_digest: txt(&messages[0], "audit_anchor_digest"),
            domain_digest: txt(&messages[0], "domain_digest"),
            subject_digest: txt(&messages[0], "subject_digest"),
            extension_admission_mode: txt(&messages[0], "extension_admission_mode"),
            extension_schema: txt(&messages[0], "extension_schema"),
            extension_configuration_digest: txt(&messages[0], "extension_configuration_digest"),
            extension_admission_binding_digest: txt(
                &messages[0],
                "extension_admission_binding_digest",
            ),
            branch_a_callable_digest: txt(&mode1[2], "callable_digest"),
            branch_a_code_provenance_digest: txt(&mode1[2], "code_provenance_digest"),
            branch_b_callable_digest: txt(&mode1[3], "callable_digest"),
            branch_b_code_provenance_digest: txt(&mode1[3], "code_provenance_digest"),
            validator_code_digest: txt(&mode2[1], "validator_code_digest"),
            validator_provenance_digest: txt(&mode2[1], "validator_provenance_digest"),
            single_state_callable_digest: txt(&mode3[0], "single_state_callable_digest"),
            single_state_provenance_digest: txt(&mode3[0], "single_state_provenance_digest"),
        }
    }

    fn temporary_root(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sbp-lex-v2-private-{label}-{}-{unique}",
            std::process::id()
        ))
    }

    fn evidence_dependencies(root: &Path) -> EvidenceAuthorityDependencies {
        EvidenceAuthorityDependencies {
            signatures: EvidenceSignatureProvider,
            replay: EvidenceReplayJournal::open_at(root).expect("fixed test journal"),
            interlock: EvidenceInterlock,
            inhibit: EvidenceInhibit,
            watchdog: EvidenceWatchdog::default(),
        }
    }

    fn evidence_terminal_audit(root: &Path) -> (Box<dyn PrivateTerminalAuditSink>, Digest) {
        let sink = EvidenceTerminalAuditSink::open_at(&root.join("terminal-audit"))
            .expect("fixed test terminal audit");
        let identity = sink.provider_identity();
        (Box::new(sink), identity)
    }

    fn pinned_configuration(
        replay_provider_identity: Digest,
        terminal_audit_provider_identity: Digest,
    ) -> PinnedCoreConfiguration {
        PinnedCoreConfiguration {
            authority_custody_provider_identity: Digest::new([0xC1; 64]),
            adapter_custody_provider_identity: Digest::new([0xC2; 64]),
            replay_provider_identity,
            terminal_audit_provider_identity,
            watchdog_provider_identity: Digest::new([0xD3; 64]),
            max_prepare_ttl: Ttl::from_millis(10_000).expect("ttl"),
            max_capability_ttl: Ttl::from_millis(10_000).expect("ttl"),
            max_lease_ttl: Ttl::from_millis(5_000).expect("ttl"),
            receipt_grace: Ttl::from_millis(500).expect("ttl"),
        }
    }

    #[derive(Default)]
    struct FixtureWireSigner {
        calls: usize,
    }

    struct CountingAuthoritySigner {
        calls: Rc<Cell<usize>>,
    }

    impl PrivateWireAuthoritySigner for CountingAuthoritySigner {
        fn algorithm(&self) -> &'static str {
            "TEST-SHA512"
        }

        fn sign_authority_stage(
            &mut self,
            key: &KeyRecord,
            preimage: &[u8],
        ) -> Result<Vec<u8>, IntegrationError> {
            self.calls.set(self.calls.get() + 1);
            let mut input = b"SBP-LEX-TEST-SIGNATURE/1\0".to_vec();
            input.extend_from_slice(&decode_hex::<64>(&key.public_key_hex)?);
            input.extend_from_slice(preimage);
            Ok(digest(&input).to_vec())
        }
    }

    impl PrivateWireAuthoritySigner for FixtureWireSigner {
        fn algorithm(&self) -> &'static str {
            "TEST-SHA512"
        }

        fn sign_authority_stage(
            &mut self,
            key: &KeyRecord,
            preimage: &[u8],
        ) -> Result<Vec<u8>, IntegrationError> {
            self.calls += 1;
            let mut input = b"SBP-LEX-TEST-SIGNATURE/1\0".to_vec();
            input.extend_from_slice(&decode_hex::<64>(&key.public_key_hex)?);
            input.extend_from_slice(preimage);
            Ok(digest(&input).to_vec())
        }
    }

    impl PrivateWireWatchdogSigner for FixtureWireSigner {
        fn watchdog_algorithm(&self) -> &'static str {
            "TEST-SHA512"
        }

        fn sign_watchdog_stage(
            &mut self,
            key: &KeyRecord,
            preimage: &[u8],
        ) -> Result<Vec<u8>, IntegrationError> {
            self.sign_authority_stage(key, preimage)
        }
    }

    impl PrivateWireAdapterSigner for FixtureWireSigner {
        fn adapter_algorithm(&self) -> &'static str {
            "TEST-SHA512"
        }

        fn sign_adapter_stage(
            &mut self,
            key: &KeyRecord,
            preimage: &[u8],
        ) -> Result<Vec<u8>, IntegrationError> {
            self.sign_authority_stage(key, preimage)
        }
    }

    fn fixture_signers() -> PrivateSessionSigners {
        PrivateSessionSigners::new(
            Box::new(FixtureWireSigner::default()),
            Box::new(FixtureWireSigner::default()),
            Box::new(FixtureWireSigner::default()),
        )
    }

    #[derive(Default)]
    struct FaultAuditState {
        append_calls: usize,
        finalize_calls: usize,
        pending: Option<Vec<u8>>,
        acknowledged: bool,
        fail_append: bool,
        fail_finalize: bool,
    }

    struct FaultAuditSink {
        identity: Digest,
        state: Rc<RefCell<FaultAuditState>>,
    }

    impl PrivateTerminalAuditSink for FaultAuditSink {
        fn provider_identity(&self) -> Digest {
            self.identity
        }

        fn append_pending(
            &mut self,
            _durable_key_hex: &str,
            _terminal_digest_hex: &str,
            _disposition: &str,
            transcript: &[u8],
        ) -> Result<(), ExternalFailure> {
            let mut state = self.state.borrow_mut();
            state.append_calls += 1;
            if state.fail_append {
                return Err(ExternalFailure::new(12_101));
            }
            state.pending = Some(transcript.to_vec());
            Ok(())
        }

        fn finalize_acknowledged(
            &mut self,
            _durable_key_hex: &str,
            _terminal_digest_hex: &str,
        ) -> Result<(), ExternalFailure> {
            let mut state = self.state.borrow_mut();
            state.finalize_calls += 1;
            if state.fail_finalize {
                return Err(ExternalFailure::new(12_102));
            }
            if state.pending.is_none() {
                return Err(ExternalFailure::new(12_103));
            }
            state.acknowledged = true;
            Ok(())
        }
    }

    fn fault_audit_sink(
        fail_append: bool,
        fail_finalize: bool,
    ) -> (
        Box<dyn PrivateTerminalAuditSink>,
        Digest,
        Rc<RefCell<FaultAuditState>>,
    ) {
        let identity = Digest::new([0xD2; 64]);
        let state = Rc::new(RefCell::new(FaultAuditState {
            fail_append,
            fail_finalize,
            ..FaultAuditState::default()
        }));
        (
            Box::new(FaultAuditSink {
                identity,
                state: Rc::clone(&state),
            }),
            identity,
            state,
        )
    }

    struct RecordingAdapter {
        calls: usize,
        times: Vec<Time>,
        expected_permit_id: [u8; 16],
        expected_permit_digest: [u8; 64],
        expected_effect_deadline: Option<Time>,
        observation: PrivateEffectObservation,
    }

    impl PrivateAdmittedAdapter for RecordingAdapter {
        fn trusted_now(&mut self) -> Result<Time, ExternalFailure> {
            if self.times.is_empty() {
                return Err(ExternalFailure::new(12_001));
            }
            Ok(self.times.remove(0))
        }

        fn consume_once(
            &mut self,
            effect: PermitBoundEffect<'_>,
        ) -> Result<PrivateEffectObservation, ExternalFailure> {
            assert_eq!(effect.permit_id, self.expected_permit_id);
            assert_eq!(effect.permit_digest, self.expected_permit_digest);
            if let Some(expected) = self.expected_effect_deadline {
                assert_eq!(effect.core.expires_at(), expected);
            }
            assert!(effect
                .core
                .binding()
                .wire_binding_digest()
                .as_bytes()
                .iter()
                .any(|byte| *byte != 0));
            self.calls += 1;
            Ok(self.observation)
        }
    }

    fn build_atomic_dispatch(
        root: &Path,
    ) -> (
        AtomicDispatch<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
        Vec<Message>,
    ) {
        let messages = parse_lines(GOLDEN);
        let (atomic, dependencies, registry, admission) =
            build_atomic_dispatch_for_vector(root, &messages);
        (atomic, dependencies, registry, admission, messages)
    }

    fn build_atomic_dispatch_for_vector(
        root: &Path,
        messages: &[Message],
    ) -> (
        AtomicDispatch<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
    ) {
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(root);
        build_atomic_dispatch_for_vector_with_audit(
            root,
            messages,
            terminal_audit,
            terminal_audit_identity,
        )
    }

    fn build_atomic_dispatch_for_vector_with_audit(
        root: &Path,
        messages: &[Message],
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        terminal_audit_identity: Digest,
    ) -> (
        AtomicDispatch<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
    ) {
        let (armed, dependencies, registry, admission) = build_watchdog_armed_for_vector_with_audit(
            root,
            messages,
            terminal_audit,
            terminal_audit_identity,
        );
        let atomic = armed
            .issue_effect_permit_from_private_adapter(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[15], "message_time_ms"),
                    nonce: &txt(&messages[15], "nonce"),
                },
                StageIssue {
                    at_ms: num(&messages[16], "message_time_ms"),
                    nonce: &txt(&messages[16], "nonce"),
                },
                num(&messages[16], "permit_deadline_ms"),
            )
            .expect("private permit");
        assert_eq!(atomic.fixed_prefix, messages[..17]);
        (atomic, dependencies, registry, admission)
    }

    fn build_watchdog_armed_for_vector_with_audit(
        root: &Path,
        messages: &[Message],
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        terminal_audit_identity: Digest,
    ) -> (
        PrivatelyWatchdogArmed<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
    ) {
        let registry = registry(messages);
        let admission = policy(messages, &registry);
        let mut dependencies = evidence_dependencies(root);
        let replay = EvidenceReplayJournal::open_at(root).expect("fixed test journal");
        let replay_identity = replay.provider_identity();
        let watchdog_identity = PrivateWatchdogProvider::provider_identity(&dependencies.watchdog);
        let released = PrivateMode1Released::from_release_request(
            messages[0].clone(),
            &registry,
            &admission,
            &FixtureVerifier,
            StageIssue {
                at_ms: num(&messages[1], "message_time_ms"),
                nonce: &txt(&messages[1], "nonce"),
            },
            num(&messages[1], "rendezvous_released_at_ms"),
            replay,
            replay_identity,
            terminal_audit,
            terminal_audit_identity,
            Box::new(dependencies.watchdog.clone()),
            watchdog_identity,
            fixture_signers(),
        )
        .expect("private release");
        let converged = released
            .converge(
                messages[2..6].to_vec(),
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[6], "message_time_ms"),
                    nonce: &txt(&messages[6], "nonce"),
                },
            )
            .expect("private convergence");
        let authenticated = converged
            .accept_prepare_request(
                messages[7].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                num(&messages[7], "message_time_ms"),
                pinned_configuration(replay_identity, terminal_audit_identity),
            )
            .expect("authenticated convergence");
        let prepared = authenticated
            .prepare(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[8], "message_time_ms"),
                    nonce: &txt(&messages[8], "nonce"),
                },
                Ttl::from_millis(
                    num(&messages[8], "expires_at_ms") - num(&messages[8], "message_time_ms"),
                )
                .expect("prepare ttl"),
                &mut dependencies.signatures,
            )
            .expect("private prepare");
        let committed = prepared
            .commit(
                messages[9].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[10], "message_time_ms"),
                    nonce: &txt(&messages[10], "nonce"),
                },
                Ttl::from_millis(
                    num(&messages[10], "expires_at_ms") - num(&messages[10], "message_time_ms"),
                )
                .expect("capability ttl"),
                &mut dependencies.signatures,
                &mut dependencies.interlock,
                &mut dependencies.inhibit,
            )
            .expect("private commit");
        let leased = committed
            .redeem_lease_from_private_adapter(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[11], "message_time_ms"),
                    nonce: &txt(&messages[11], "nonce"),
                },
                StageIssue {
                    at_ms: num(&messages[12], "message_time_ms"),
                    nonce: &txt(&messages[12], "nonce"),
                },
                num(&messages[11], "lease_deadline_ms"),
                &mut dependencies.signatures,
                &mut dependencies.interlock,
                &mut dependencies.inhibit,
            )
            .expect("private lease");
        let armed = leased
            .arm_watchdog(
                messages[13].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[14], "message_time_ms"),
                    nonce: &txt(&messages[14], "nonce"),
                },
            )
            .expect("private watchdog arm");
        (armed, dependencies, registry, admission)
    }

    fn build_mode23_atomic_dispatch_for_vector(
        root: &Path,
        messages: &[Message],
    ) -> (
        AtomicDispatch<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
    ) {
        let registry = registry(messages);
        let admission = policy(messages, &registry);
        let mut dependencies = evidence_dependencies(root);
        let replay = EvidenceReplayJournal::open_at(root).expect("fixed test journal");
        let replay_identity = replay.provider_identity();
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(root);
        let watchdog_identity = PrivateWatchdogProvider::provider_identity(&dependencies.watchdog);
        let mode = txt(&messages[0], "mode");
        let convergence_result_index = match mode.as_str() {
            "MODE_2" => 3,
            "MODE_3" => 2,
            _ => panic!("Mode 2/3 fixture required"),
        };
        let convergence_nonce = txt(&messages[convergence_result_index], "nonce");
        let convergence_issue = StageIssue {
            at_ms: num(&messages[convergence_result_index], "message_time_ms"),
            nonce: &convergence_nonce,
        };
        let converged = if mode == "MODE_2" {
            PrivateMode2Convergence::from_external_prefix(
                messages[..convergence_result_index].to_vec(),
                &registry,
                &admission,
                &FixtureVerifier,
                convergence_issue,
                replay,
                replay_identity,
                terminal_audit,
                terminal_audit_identity,
                Box::new(dependencies.watchdog.clone()),
                watchdog_identity,
                fixture_signers(),
            )
        } else {
            PrivateMode3Convergence::from_external_prefix(
                messages[..convergence_result_index].to_vec(),
                &registry,
                &admission,
                &FixtureVerifier,
                convergence_issue,
                replay,
                replay_identity,
                terminal_audit,
                terminal_audit_identity,
                Box::new(dependencies.watchdog.clone()),
                watchdog_identity,
                fixture_signers(),
            )
        }
        .expect("private Mode 2/3 convergence");
        assert_eq!(converged.transcript, messages[..=convergence_result_index]);

        let prepare_request_index = convergence_result_index + 1;
        let prepare_result_index = convergence_result_index + 2;
        let commit_request_index = convergence_result_index + 3;
        let commit_result_index = convergence_result_index + 4;
        let lease_request_index = convergence_result_index + 5;
        let lease_result_index = convergence_result_index + 6;
        let watchdog_request_index = convergence_result_index + 7;
        let watchdog_result_index = convergence_result_index + 8;
        let permit_request_index = convergence_result_index + 9;
        let permit_result_index = convergence_result_index + 10;

        let authenticated = converged
            .accept_prepare_request(
                messages[prepare_request_index].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                num(&messages[prepare_request_index], "message_time_ms"),
                pinned_configuration(replay_identity, terminal_audit_identity),
            )
            .expect("authenticated Mode 2/3 convergence");
        let prepared = authenticated
            .prepare(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[prepare_result_index], "message_time_ms"),
                    nonce: &txt(&messages[prepare_result_index], "nonce"),
                },
                Ttl::from_millis(
                    num(&messages[prepare_result_index], "expires_at_ms")
                        - num(&messages[prepare_result_index], "message_time_ms"),
                )
                .expect("prepare ttl"),
                &mut dependencies.signatures,
            )
            .expect("private Mode 2/3 prepare");
        let committed = prepared
            .commit(
                messages[commit_request_index].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[commit_result_index], "message_time_ms"),
                    nonce: &txt(&messages[commit_result_index], "nonce"),
                },
                Ttl::from_millis(
                    num(&messages[commit_result_index], "expires_at_ms")
                        - num(&messages[commit_result_index], "message_time_ms"),
                )
                .expect("capability ttl"),
                &mut dependencies.signatures,
                &mut dependencies.interlock,
                &mut dependencies.inhibit,
            )
            .expect("private Mode 2/3 commit");
        let leased = committed
            .redeem_lease_from_private_adapter(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[lease_request_index], "message_time_ms"),
                    nonce: &txt(&messages[lease_request_index], "nonce"),
                },
                StageIssue {
                    at_ms: num(&messages[lease_result_index], "message_time_ms"),
                    nonce: &txt(&messages[lease_result_index], "nonce"),
                },
                num(&messages[lease_request_index], "lease_deadline_ms"),
                &mut dependencies.signatures,
                &mut dependencies.interlock,
                &mut dependencies.inhibit,
            )
            .expect("private Mode 2/3 lease");
        let armed = leased
            .arm_watchdog(
                messages[watchdog_request_index].clone(),
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[watchdog_result_index], "message_time_ms"),
                    nonce: &txt(&messages[watchdog_result_index], "nonce"),
                },
            )
            .expect("private Mode 2/3 watchdog arm");
        let atomic = armed
            .issue_effect_permit_from_private_adapter(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[permit_request_index], "message_time_ms"),
                    nonce: &txt(&messages[permit_request_index], "nonce"),
                },
                StageIssue {
                    at_ms: num(&messages[permit_result_index], "message_time_ms"),
                    nonce: &txt(&messages[permit_result_index], "nonce"),
                },
                num(&messages[permit_result_index], "permit_deadline_ms"),
            )
            .expect("private Mode 2/3 permit");
        assert_eq!(atomic.fixed_prefix, messages[..=permit_result_index]);
        (atomic, dependencies, registry, admission)
    }

    fn build_post_effect_with_audit(
        root: &Path,
        vector: &str,
        observation: PrivateEffectObservation,
        terminal_audit: Box<dyn PrivateTerminalAuditSink>,
        terminal_audit_identity: Digest,
    ) -> (
        PostEffectState<EvidenceReplayJournal>,
        EvidenceAuthorityDependencies,
        TrustRegistry,
        AdmissionPolicy,
        Vec<Message>,
    ) {
        let messages = parse_lines(vector);
        let (atomic, mut dependencies, registry, admission) =
            build_atomic_dispatch_for_vector_with_audit(
                root,
                &messages,
                terminal_audit,
                terminal_audit_identity,
            );
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![
                Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                Time::from_millis_since_epoch(num(&messages[17], "message_time_ms")),
            ],
            expected_permit_id: atomic.permit_id,
            expected_permit_digest: atomic.permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation,
        };
        let post_effect = atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .expect("private point-of-use observation");
        assert_eq!(adapter.calls, 1);
        (post_effect, dependencies, registry, admission, messages)
    }

    fn finish_post_effect(
        post_effect: PostEffectState<EvidenceReplayJournal>,
        dependencies: &mut EvidenceAuthorityDependencies,
        registry: &TrustRegistry,
        admission: &AdmissionPolicy,
        messages: &[Message],
        receipt_ack_at_ms: u64,
        watchdog_terminal_at_ms: u64,
    ) -> Result<PrivateTerminalState, IntegrationError> {
        let receipt_nonce = txt(&messages[17], "nonce");
        let receipt_ack_nonce = txt(&messages[18], "nonce");
        let watchdog_terminal_nonce = txt(&messages[19], "nonce");
        let watchdog_result_nonce = txt(&messages[20], "nonce");
        post_effect.finish(
            registry,
            admission,
            &FixtureVerifier,
            TerminalIssue {
                receipt: StageIssue {
                    at_ms: num(&messages[17], "message_time_ms"),
                    nonce: &receipt_nonce,
                },
                receipt_ack: StageIssue {
                    at_ms: receipt_ack_at_ms,
                    nonce: &receipt_ack_nonce,
                },
                watchdog_terminal: StageIssue {
                    at_ms: watchdog_terminal_at_ms,
                    nonce: &watchdog_terminal_nonce,
                },
                watchdog_result: StageIssue {
                    at_ms: num(&messages[20], "message_time_ms"),
                    nonce: &watchdog_result_nonce,
                },
            },
            &mut dependencies.signatures,
        )
    }

    #[test]
    fn fixed_v2_bytes_are_exact_and_routes_remain_unadmitted() {
        verify_fixed_v2_bytes().expect("exact fixed wire-v2 bytes");
        assert_eq!(V2_PROTOCOL, "SBP-LEX-AUTH-WIRE/2");
        assert_eq!(PRODUCTION_HSM_PROFILE.authority_wire_v2_sha512, None);
        assert_eq!(PRODUCTION_TPM_PROFILE.authority_wire_v2_sha512, None);
        assert_eq!(EVIDENCE_PROFILE.authority_wire_v2_sha512, None);
    }

    #[test]
    fn physical_watchdog_is_durably_tightened_to_each_effective_minimum() {
        for (label, vector) in [
            ("permit-min", TIMEOUT),
            ("lease-min", TIMEOUT_LEASE_BOUND),
            ("watchdog-min", TIMEOUT_WATCHDOG_BOUND),
        ] {
            let messages = parse_lines(vector);
            let lease_deadline = num(&messages[12], "lease_deadline_ms");
            let watchdog_deadline = num(&messages[14], "watchdog_deadline_ms");
            let permit_deadline = num(&messages[16], "permit_deadline_ms");
            let expected = lease_deadline.min(watchdog_deadline).min(permit_deadline);
            let issue_at = num(&messages[16], "message_time_ms");

            // Crash after durable tighten but before a permit is signed.
            let root = temporary_root(&format!("{label}-before-permit"));
            let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
            let (armed, dependencies, _registry, _admission) =
                build_watchdog_armed_for_vector_with_audit(
                    &root,
                    &messages,
                    terminal_audit,
                    terminal_audit_identity,
                );
            let (tightened, actual) = armed
                .durably_tighten_for_permit(issue_at, permit_deadline)
                .expect("durable exact tighten");
            assert_eq!(actual, expected);
            assert_eq!(
                tightened.awaiting.watchdog_arm().receipt_deadline(),
                Time::from_millis_since_epoch(expected)
            );
            assert_eq!(
                dependencies
                    .watchdog
                    .armed_request()
                    .expect("physical arm")
                    .receipt_deadline(),
                Time::from_millis_since_epoch(expected)
            );
            drop(tightened);
            dependencies
                .watchdog
                .independent_deadline_tick(Time::from_millis_since_epoch(expected));
            assert!(dependencies.watchdog.is_tripped());
            fs::remove_dir_all(root).expect("cleanup");

            // Crash after the authority has signed the permit. The signed
            // deadline and persisted physical arm must be the same minimum,
            // and the fixture watchdog must stop without a service callback.
            let root = temporary_root(&format!("{label}-after-permit"));
            let (atomic, dependencies, _registry, _admission) =
                build_atomic_dispatch_for_vector(&root, &messages);
            assert_eq!(
                num(
                    atomic.fixed_prefix.last().expect("permit result"),
                    "permit_deadline_ms"
                ),
                expected
            );
            assert_eq!(
                atomic.awaiting.watchdog_arm().receipt_deadline(),
                Time::from_millis_since_epoch(expected)
            );
            drop(atomic);
            dependencies
                .watchdog
                .independent_deadline_tick(Time::from_millis_since_epoch(expected));
            assert!(dependencies.watchdog.is_tripped());
            fs::remove_dir_all(root).expect("cleanup");

            // The only in-call authority view exposed to the adapter carries
            // exactly the persisted/signed minimum, never the later lease
            // deadline hidden behind it.
            let root = temporary_root(&format!("{label}-adapter-visible"));
            let (atomic, mut dependencies, registry, admission) =
                build_atomic_dispatch_for_vector(&root, &messages);
            let signed_deadline = num(
                atomic.fixed_prefix.last().expect("permit result"),
                "permit_deadline_ms",
            );
            let persisted_deadline = atomic.awaiting.watchdog_arm().receipt_deadline();
            assert_eq!(signed_deadline, expected);
            assert_eq!(persisted_deadline, Time::from_millis_since_epoch(expected));
            let mut adapter = RecordingAdapter {
                calls: 0,
                times: vec![
                    Time::from_millis_since_epoch(issue_at),
                    Time::from_millis_since_epoch(issue_at),
                    Time::from_millis_since_epoch(issue_at),
                ],
                expected_permit_id: atomic.permit_id,
                expected_permit_digest: atomic.permit_digest,
                expected_effect_deadline: Some(persisted_deadline),
                observation: PrivateEffectObservation::Succeeded,
            };
            let post_effect = atomic
                .consume(
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    &mut dependencies.signatures,
                    &mut dependencies.inhibit,
                    &mut adapter,
                )
                .expect("adapter sees exact effective deadline");
            assert_eq!(adapter.calls, 1);
            drop(post_effect);
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn effective_deadline_equality_blocks_start_and_late_completion() {
        let messages = parse_lines(TIMEOUT);
        let deadline = num(&messages[16], "permit_deadline_ms");

        let root = temporary_root("point-of-use-at-effective-deadline");
        let (atomic, mut dependencies, registry, admission) =
            build_atomic_dispatch_for_vector(&root, &messages);
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![Time::from_millis_since_epoch(deadline)],
            expected_permit_id: atomic.permit_id,
            expected_permit_digest: atomic.permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation: PrivateEffectObservation::Succeeded,
        };
        assert!(atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .is_err());
        assert_eq!(adapter.calls, 0);
        dependencies
            .watchdog
            .independent_deadline_tick(Time::from_millis_since_epoch(deadline));
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");

        let root = temporary_root("completion-at-effective-deadline");
        let (atomic, mut dependencies, registry, admission) =
            build_atomic_dispatch_for_vector(&root, &messages);
        let before_deadline =
            Time::from_millis_since_epoch(num(&messages[17], "message_time_ms").min(deadline - 1));
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![
                before_deadline,
                before_deadline,
                Time::from_millis_since_epoch(deadline),
            ],
            expected_permit_id: atomic.permit_id,
            expected_permit_digest: atomic.permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation: PrivateEffectObservation::Succeeded,
        };
        assert!(atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .is_err());
        assert_eq!(adapter.calls, 1);
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn watchdog_tighten_is_idempotent_but_never_late_or_wider() {
        let messages = parse_lines(TIMEOUT);
        let issue_at = num(&messages[16], "message_time_ms");
        let deadline = num(&messages[16], "permit_deadline_ms");

        let root = temporary_root("tighten-idempotent-and-wider");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let (armed, dependencies, _registry, _admission) =
            build_watchdog_armed_for_vector_with_audit(
                &root,
                &messages,
                terminal_audit,
                terminal_audit_identity,
            );
        let (mut tightened, _) = armed
            .durably_tighten_for_permit(issue_at, deadline)
            .expect("initial tighten");
        let awaiting = tightened.awaiting;
        tightened.awaiting = awaiting
            .tighten_watchdog(
                Time::from_millis_since_epoch(issue_at + 1),
                Time::from_millis_since_epoch(deadline),
                tightened.engine.watchdog.as_mut(),
            )
            .expect("same exact arm is idempotent");
        let exact_arm = dependencies.watchdog.armed_request().expect("physical arm");
        let awaiting = tightened.awaiting;
        assert!(awaiting
            .tighten_watchdog(
                Time::from_millis_since_epoch(issue_at + 2),
                Time::from_millis_since_epoch(deadline + 1),
                tightened.engine.watchdog.as_mut(),
            )
            .is_err());
        assert_eq!(dependencies.watchdog.armed_request(), Some(exact_arm));
        fs::remove_dir_all(root).expect("cleanup");

        let root = temporary_root("tighten-late");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let (armed, dependencies, _registry, _admission) =
            build_watchdog_armed_for_vector_with_audit(
                &root,
                &messages,
                terminal_audit,
                terminal_audit_identity,
            );
        let (mut tightened, _) = armed
            .durably_tighten_for_permit(issue_at, deadline)
            .expect("initial tighten");
        let exact_arm = dependencies.watchdog.armed_request().expect("physical arm");
        let awaiting = tightened.awaiting;
        assert!(awaiting
            .tighten_watchdog(
                Time::from_millis_since_epoch(deadline),
                Time::from_millis_since_epoch(deadline),
                tightened.engine.watchdog.as_mut(),
            )
            .is_err());
        assert_eq!(dependencies.watchdog.armed_request(), Some(exact_arm));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn invalid_or_failed_tighten_never_reaches_authority_signer_or_adapter() {
        let messages = parse_lines(TIMEOUT);
        for (label, requested_deadline, fail_provider) in [
            ("wider", num(&messages[14], "watchdog_deadline_ms"), false),
            (
                "provider-failure",
                num(&messages[16], "permit_deadline_ms"),
                true,
            ),
        ] {
            let root = temporary_root(label);
            let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
            let (mut armed, dependencies, registry, admission) =
                build_watchdog_armed_for_vector_with_audit(
                    &root,
                    &messages,
                    terminal_audit,
                    terminal_audit_identity,
                );
            let calls = Rc::new(Cell::new(0));
            armed.engine.signers.authority = Box::new(CountingAuthoritySigner {
                calls: Rc::clone(&calls),
            });
            if fail_provider {
                dependencies.watchdog.fail_next_tighten();
            }
            let original_arm = dependencies.watchdog.armed_request();
            assert!(armed
                .issue_effect_permit(
                    messages[15].clone(),
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    StageIssue {
                        at_ms: num(&messages[16], "message_time_ms"),
                        nonce: &txt(&messages[16], "nonce"),
                    },
                    requested_deadline,
                )
                .is_err());
            assert_eq!(calls.get(), 0);
            assert_eq!(dependencies.watchdog.armed_request(), original_arm);
            fs::remove_dir_all(root).expect("cleanup");
        }

        let root = temporary_root("watchdog-provider-identity");
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let replay_identity = replay.provider_identity();
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let calls = Rc::new(Cell::new(0));
        let signers = PrivateSessionSigners::new(
            Box::new(CountingAuthoritySigner {
                calls: Rc::clone(&calls),
            }),
            Box::new(FixtureWireSigner::default()),
            Box::new(FixtureWireSigner::default()),
        );
        assert!(PrivateAuthorityEngine::new(
            replay,
            replay_identity,
            terminal_audit,
            terminal_audit_identity,
            Box::new(EvidenceWatchdog::default()),
            Digest::new([0xEE; 64]),
            &registry,
            &admission,
            &FixtureVerifier,
            signers,
        )
        .is_err());
        assert_eq!(calls.get(), 0);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn all_modes_have_private_service_owned_convergence_entrypoints() {
        let source = include_str!("wire_v2_private.rs");
        let non_test = source
            .split("#[cfg(all(test")
            .next()
            .expect("test boundary");
        assert!(non_test.contains("struct PrivateMode1Released"));
        assert!(non_test.contains("struct PrivateMode2Convergence"));
        assert!(non_test.contains("struct PrivateMode3Convergence"));
        assert!(non_test.contains("#[cfg(test)]\n    fn from_prepare_prefix"));
        assert_eq!(PRODUCTION_HSM_PROFILE.authority_wire_v2_sha512, None);
        assert_eq!(PRODUCTION_TPM_PROFILE.authority_wire_v2_sha512, None);
    }

    #[test]
    fn mode2_and_mode3_join_the_same_private_prepare_path() {
        for (label, vector, convergence_request_index, convergence_result_index) in [
            ("mode2", MODE2, 2usize, 3usize),
            ("mode3", MODE3, 1usize, 2usize),
        ] {
            let root = temporary_root(label);
            let messages = parse_lines(vector);
            let registry = registry(&messages);
            let admission = policy(&messages, &registry);
            let replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
            let replay_identity = replay.provider_identity();
            let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
            let watchdog = EvidenceWatchdog::default();
            let watchdog_identity = PrivateWatchdogProvider::provider_identity(&watchdog);
            let convergence_nonce = txt(&messages[convergence_result_index], "nonce");
            let issue = StageIssue {
                at_ms: num(&messages[convergence_result_index], "message_time_ms"),
                nonce: &convergence_nonce,
            };
            let converged = if label == "mode2" {
                PrivateMode2Convergence::from_external_prefix(
                    messages[..=convergence_request_index].to_vec(),
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    issue,
                    replay,
                    replay_identity,
                    terminal_audit,
                    terminal_audit_identity,
                    Box::new(watchdog),
                    watchdog_identity,
                    fixture_signers(),
                )
            } else {
                PrivateMode3Convergence::from_external_prefix(
                    messages[..=convergence_request_index].to_vec(),
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    issue,
                    replay,
                    replay_identity,
                    terminal_audit,
                    terminal_audit_identity,
                    Box::new(watchdog),
                    watchdog_identity,
                    fixture_signers(),
                )
            }
            .expect("private convergence");
            assert_eq!(converged.transcript, messages[..=convergence_result_index],);
            let prepare_request_index = convergence_result_index + 1;
            converged
                .accept_prepare_request(
                    messages[prepare_request_index].clone(),
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    num(&messages[prepare_request_index], "message_time_ms"),
                    pinned_configuration(replay_identity, terminal_audit_identity),
                )
                .expect("common authenticated PREPARE path");
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn private_results_copy_every_extension_admission_field_exactly() {
        let messages = parse_lines(GOLDEN);
        let registry = registry(&messages);
        let request = &messages[0];
        let draft = private_result_draft(
            request,
            1,
            "test_result",
            "AUTHORITY",
            "NONE",
            StageIssue {
                at_ms: num(request, "message_time_ms") + 1,
                nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            },
            &registry,
            "TEST-SHA512",
            BTreeMap::new(),
        )
        .expect("complete immutable common-field copy");
        for field in [
            "extension_admission_mode",
            "extension_schema",
            "extension_configuration_digest",
            "extension_admission_binding_digest",
        ] {
            assert_eq!(draft.get(field), request.get(field), "field {field}");
        }
    }

    #[test]
    fn private_typestates_reproduce_fixed_results_and_dispatch_once() {
        let root = temporary_root("happy");
        let (atomic, mut dependencies, registry, admission, messages) =
            build_atomic_dispatch(&root);
        assert_eq!(
            atomic.binding.domain_id().as_bytes(),
            &decode_hex::<64>(&admission.domain_digest).expect("full domain identity")
        );
        assert_eq!(
            atomic.binding.subject_id().as_bytes(),
            &decode_hex::<64>(&admission.subject_digest).expect("full subject identity")
        );
        assert_eq!(
            atomic.binding.effect_id().as_bytes(),
            &decode_hex::<64>(&admission.effect_digest).expect("full effect identity")
        );
        assert_eq!(
            atomic.binding.adapter_id().as_bytes(),
            &decode_hex::<64>(&admission.adapter_digest).expect("full adapter identity")
        );
        assert_eq!(
            atomic
                .binding
                .extension_admission_binding_digest()
                .as_bytes(),
            &decode_hex::<64>(&admission.extension_admission_binding_digest)
                .expect("distinct extension admission identity")
        );
        assert_ne!(
            atomic.binding.extension_admission_binding_digest(),
            atomic.binding.configuration_digest(),
        );
        let permit_id = atomic.permit_id;
        let permit_digest = atomic.permit_digest;
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![
                Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                Time::from_millis_since_epoch(num(&messages[17], "message_time_ms")),
            ],
            expected_permit_id: permit_id,
            expected_permit_digest: permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation: PrivateEffectObservation::Succeeded,
        };
        let applied = atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .expect("one atomic effect");
        assert_eq!(adapter.calls, 1);
        assert_eq!(
            applied.applied.as_ref().expect("applied effect").outcome(),
            EffectOutcome::Applied
        );
        assert_eq!(applied.permit_id, permit_id);
        assert_eq!(applied.permit_digest, permit_digest);
        assert_eq!(
            applied.awaiting.watchdog_arm().lease_id(),
            applied.applied.as_ref().expect("applied effect").lease_id()
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn private_session_owns_every_authority_stage_and_reproduces_all_mode1_tails() {
        for (label, vector, observation, expected) in [
            (
                "success",
                GOLDEN,
                Some(PrivateEffectObservation::Succeeded),
                TerminalDisposition::Completed,
            ),
            (
                "failure",
                FAILURE,
                Some(PrivateEffectObservation::Failed),
                TerminalDisposition::Stop,
            ),
            (
                "unknown",
                UNKNOWN,
                Some(PrivateEffectObservation::Unknown),
                TerminalDisposition::Stop,
            ),
            ("timeout", TIMEOUT, None, TerminalDisposition::Stop),
        ] {
            let messages = parse_lines(vector);
            let root = temporary_root(label);
            let (atomic, mut dependencies, registry, admission) =
                build_atomic_dispatch_for_vector(&root, &messages);
            let terminal = if let Some(observation) = observation {
                let mut adapter = RecordingAdapter {
                    calls: 0,
                    times: vec![
                        Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                        Time::from_millis_since_epoch(num(&messages[17], "adapter_consumed_at_ms")),
                        Time::from_millis_since_epoch(num(&messages[17], "message_time_ms")),
                    ],
                    expected_permit_id: atomic.permit_id,
                    expected_permit_digest: atomic.permit_digest,
                    expected_effect_deadline: Some(
                        atomic.awaiting.watchdog_arm().receipt_deadline(),
                    ),
                    observation,
                };
                let post_effect = atomic
                    .consume(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        &mut dependencies.signatures,
                        &mut dependencies.inhibit,
                        &mut adapter,
                    )
                    .expect("private point-of-use observation");
                assert_eq!(adapter.calls, 1);
                post_effect
                    .finish(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        TerminalIssue {
                            receipt: StageIssue {
                                at_ms: num(&messages[17], "message_time_ms"),
                                nonce: &txt(&messages[17], "nonce"),
                            },
                            receipt_ack: StageIssue {
                                at_ms: num(&messages[18], "message_time_ms"),
                                nonce: &txt(&messages[18], "nonce"),
                            },
                            watchdog_terminal: StageIssue {
                                at_ms: num(&messages[19], "message_time_ms"),
                                nonce: &txt(&messages[19], "nonce"),
                            },
                            watchdog_result: StageIssue {
                                at_ms: num(&messages[20], "message_time_ms"),
                                nonce: &txt(&messages[20], "nonce"),
                            },
                        },
                        &mut dependencies.signatures,
                    )
                    .expect("private post-effect terminal")
            } else {
                atomic
                    .timeout(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        TimeoutIssue {
                            watchdog_terminal: StageIssue {
                                at_ms: num(&messages[17], "message_time_ms"),
                                nonce: &txt(&messages[17], "nonce"),
                            },
                            watchdog_result: StageIssue {
                                at_ms: num(&messages[18], "message_time_ms"),
                                nonce: &txt(&messages[18], "nonce"),
                            },
                        },
                    )
                    .expect("private timeout terminal")
            };
            assert_eq!(terminal.disposition, expected);
            assert_eq!(terminal.transcript, messages);
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn private_sessions_reproduce_every_mode2_and_mode3_terminal_tail() {
        for (label, vector, observation, expected) in [
            (
                "mode2-success",
                MODE2,
                Some(PrivateEffectObservation::Succeeded),
                TerminalDisposition::Completed,
            ),
            (
                "mode2-failure",
                MODE2_FAILURE,
                Some(PrivateEffectObservation::Failed),
                TerminalDisposition::Stop,
            ),
            (
                "mode2-unknown",
                MODE2_UNKNOWN,
                Some(PrivateEffectObservation::Unknown),
                TerminalDisposition::Stop,
            ),
            (
                "mode2-timeout",
                MODE2_TIMEOUT,
                None,
                TerminalDisposition::Stop,
            ),
            (
                "mode3-success",
                MODE3,
                Some(PrivateEffectObservation::Succeeded),
                TerminalDisposition::Completed,
            ),
            (
                "mode3-failure",
                MODE3_FAILURE,
                Some(PrivateEffectObservation::Failed),
                TerminalDisposition::Stop,
            ),
            (
                "mode3-unknown",
                MODE3_UNKNOWN,
                Some(PrivateEffectObservation::Unknown),
                TerminalDisposition::Stop,
            ),
            (
                "mode3-timeout",
                MODE3_TIMEOUT,
                None,
                TerminalDisposition::Stop,
            ),
        ] {
            let messages = parse_lines(vector);
            let root = temporary_root(label);
            let (atomic, mut dependencies, registry, admission) =
                build_mode23_atomic_dispatch_for_vector(&root, &messages);
            let permit_result_index = if txt(&messages[0], "mode") == "MODE_2" {
                13
            } else {
                12
            };
            let terminal = if let Some(observation) = observation {
                let receipt_index = permit_result_index + 1;
                let receipt_ack_index = permit_result_index + 2;
                let watchdog_terminal_index = permit_result_index + 3;
                let watchdog_result_index = permit_result_index + 4;
                let mut adapter = RecordingAdapter {
                    calls: 0,
                    times: vec![
                        Time::from_millis_since_epoch(num(
                            &messages[receipt_index],
                            "adapter_consumed_at_ms",
                        )),
                        Time::from_millis_since_epoch(num(
                            &messages[receipt_index],
                            "adapter_consumed_at_ms",
                        )),
                        Time::from_millis_since_epoch(num(
                            &messages[receipt_index],
                            "message_time_ms",
                        )),
                    ],
                    expected_permit_id: atomic.permit_id,
                    expected_permit_digest: atomic.permit_digest,
                    expected_effect_deadline: Some(
                        atomic.awaiting.watchdog_arm().receipt_deadline(),
                    ),
                    observation,
                };
                let post_effect = atomic
                    .consume(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        &mut dependencies.signatures,
                        &mut dependencies.inhibit,
                        &mut adapter,
                    )
                    .expect("private Mode 2/3 point-of-use observation");
                assert_eq!(adapter.calls, 1);
                post_effect
                    .finish(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        TerminalIssue {
                            receipt: StageIssue {
                                at_ms: num(&messages[receipt_index], "message_time_ms"),
                                nonce: &txt(&messages[receipt_index], "nonce"),
                            },
                            receipt_ack: StageIssue {
                                at_ms: num(&messages[receipt_ack_index], "message_time_ms"),
                                nonce: &txt(&messages[receipt_ack_index], "nonce"),
                            },
                            watchdog_terminal: StageIssue {
                                at_ms: num(&messages[watchdog_terminal_index], "message_time_ms"),
                                nonce: &txt(&messages[watchdog_terminal_index], "nonce"),
                            },
                            watchdog_result: StageIssue {
                                at_ms: num(&messages[watchdog_result_index], "message_time_ms"),
                                nonce: &txt(&messages[watchdog_result_index], "nonce"),
                            },
                        },
                        &mut dependencies.signatures,
                    )
                    .expect("private Mode 2/3 post-effect terminal")
            } else {
                let watchdog_terminal_index = permit_result_index + 1;
                let watchdog_result_index = permit_result_index + 2;
                atomic
                    .timeout(
                        &registry,
                        &admission,
                        &FixtureVerifier,
                        TimeoutIssue {
                            watchdog_terminal: StageIssue {
                                at_ms: num(&messages[watchdog_terminal_index], "message_time_ms"),
                                nonce: &txt(&messages[watchdog_terminal_index], "nonce"),
                            },
                            watchdog_result: StageIssue {
                                at_ms: num(&messages[watchdog_result_index], "message_time_ms"),
                                nonce: &txt(&messages[watchdog_result_index], "nonce"),
                            },
                        },
                    )
                    .expect("private Mode 2/3 timeout terminal")
            };
            assert_eq!(terminal.disposition, expected);
            assert_eq!(terminal.transcript, messages);
            assert_eq!(PRODUCTION_HSM_PROFILE.authority_wire_v2_sha512, None);
            assert_eq!(PRODUCTION_TPM_PROFILE.authority_wire_v2_sha512, None);
            assert_eq!(EVIDENCE_PROFILE.authority_wire_v2_sha512, None);
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn crash_points_before_and_after_receipt_claim_remain_stop_safe() {
        // Invalid terminal timing fails after the permanent receipt claim but
        // before any audit append; the watchdog is explicitly tripped.
        let root = temporary_root("crash-before-append");
        let (sink, identity, state) = fault_audit_sink(false, false);
        let (post, mut dependencies, registry, admission, messages) = build_post_effect_with_audit(
            &root,
            GOLDEN,
            PrivateEffectObservation::Succeeded,
            sink,
            identity,
        );
        let result = finish_post_effect(
            post,
            &mut dependencies,
            &registry,
            &admission,
            &messages,
            num(&messages[18], "message_time_ms"),
            num(&messages[18], "message_time_ms") - 1,
        );
        assert!(result.is_err());
        assert_eq!(state.borrow().append_calls, 0);
        assert!(dependencies.watchdog.is_armed());
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");

        // A mid/failed durable append also trips while retaining the arm; no
        // completion or acknowledgement marker can be surfaced.
        let root = temporary_root("crash-append-failure");
        let (sink, identity, state) = fault_audit_sink(true, false);
        let (post, mut dependencies, registry, admission, messages) = build_post_effect_with_audit(
            &root,
            GOLDEN,
            PrivateEffectObservation::Succeeded,
            sink,
            identity,
        );
        let result = finish_post_effect(
            post,
            &mut dependencies,
            &registry,
            &admission,
            &messages,
            num(&messages[18], "message_time_ms"),
            num(&messages[19], "message_time_ms"),
        );
        assert!(matches!(result, Err(IntegrationError::AuditSink(12_101))));
        assert_eq!(state.borrow().append_calls, 1);
        assert!(state.borrow().pending.is_none());
        assert!(!state.borrow().acknowledged);
        assert!(dependencies.watchdog.is_armed());
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn pending_tail_is_in_doubt_until_watchdog_ack_and_finalize() {
        // The pending append occurs before physical ACK. If ACK fails, bytes
        // remain explicitly IN_DOUBT and the watchdog is tripped.
        let root = temporary_root("crash-before-ack");
        let (sink, identity, state) = fault_audit_sink(false, false);
        let (post, mut dependencies, registry, admission, messages) = build_post_effect_with_audit(
            &root,
            GOLDEN,
            PrivateEffectObservation::Succeeded,
            sink,
            identity,
        );
        dependencies.watchdog.fail_next_acknowledgement();
        let result = finish_post_effect(
            post,
            &mut dependencies,
            &registry,
            &admission,
            &messages,
            num(&messages[18], "message_time_ms"),
            num(&messages[19], "message_time_ms"),
        );
        assert!(result.is_err());
        assert_eq!(state.borrow().append_calls, 1);
        assert!(state.borrow().pending.is_some());
        assert_eq!(state.borrow().finalize_calls, 0);
        assert!(!state.borrow().acknowledged);
        assert!(dependencies.watchdog.is_armed());
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");

        // Normal evidence execution appends first, then ACKs, then writes the
        // separate acknowledged marker. Only this live call returns Completed.
        let root = temporary_root("after-ack");
        let (sink, identity, state) = fault_audit_sink(false, false);
        let (post, mut dependencies, registry, admission, messages) = build_post_effect_with_audit(
            &root,
            GOLDEN,
            PrivateEffectObservation::Succeeded,
            sink,
            identity,
        );
        let terminal = finish_post_effect(
            post,
            &mut dependencies,
            &registry,
            &admission,
            &messages,
            num(&messages[18], "message_time_ms"),
            num(&messages[19], "message_time_ms"),
        )
        .expect("live success after durable pending + watchdog ACK");
        assert_eq!(terminal.disposition, TerminalDisposition::Completed);
        assert_eq!(state.borrow().append_calls, 1);
        assert_eq!(state.borrow().finalize_calls, 1);
        assert!(state.borrow().pending.is_some());
        assert!(state.borrow().acknowledged);
        assert!(!dependencies.watchdog.is_armed());
        assert!(!dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");

        // ACK followed by a failed finalize is an explicit local evidence
        // ambiguity, never success. The code reasserts STOP and returns error;
        // production atomicity remains unadmitted without an external durable,
        // queryable watchdog/audit service.
        let root = temporary_root("crash-after-ack");
        let (sink, identity, state) = fault_audit_sink(false, true);
        let (post, mut dependencies, registry, admission, messages) = build_post_effect_with_audit(
            &root,
            GOLDEN,
            PrivateEffectObservation::Succeeded,
            sink,
            identity,
        );
        let result = finish_post_effect(
            post,
            &mut dependencies,
            &registry,
            &admission,
            &messages,
            num(&messages[18], "message_time_ms"),
            num(&messages[19], "message_time_ms"),
        );
        assert!(matches!(result, Err(IntegrationError::AuditSink(12_102))));
        assert_eq!(state.borrow().append_calls, 1);
        assert_eq!(state.borrow().finalize_calls, 1);
        assert!(state.borrow().pending.is_some());
        assert!(!state.borrow().acknowledged);
        assert!(dependencies.watchdog.is_tripped());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn failed_and_unknown_trip_without_watchdog_ack() {
        for (label, vector, observation) in [
            ("failed-no-ack", FAILURE, PrivateEffectObservation::Failed),
            ("unknown-no-ack", UNKNOWN, PrivateEffectObservation::Unknown),
        ] {
            let root = temporary_root(label);
            let (sink, identity, state) = fault_audit_sink(false, false);
            let (post, mut dependencies, registry, admission, messages) =
                build_post_effect_with_audit(&root, vector, observation, sink, identity);
            let terminal = finish_post_effect(
                post,
                &mut dependencies,
                &registry,
                &admission,
                &messages,
                num(&messages[18], "message_time_ms"),
                num(&messages[19], "message_time_ms"),
            )
            .expect("durable stopped tail");
            assert_eq!(terminal.disposition, TerminalDisposition::Stop);
            assert_eq!(state.borrow().append_calls, 1);
            assert_eq!(state.borrow().finalize_calls, 0);
            assert!(state.borrow().pending.is_some());
            assert!(!state.borrow().acknowledged);
            assert!(dependencies.watchdog.is_armed());
            assert!(dependencies.watchdog.is_tripped());
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn invalid_or_late_prefix_never_reaches_wire_signer_or_adapter() {
        let messages = parse_lines(GOLDEN);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let root = temporary_root("invalid");
        let mut dependencies = evidence_dependencies(&root);
        let replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let replay_provider_identity = replay.provider_identity();
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let authenticated = AuthenticatedConvergence::from_prepare_prefix(
            &messages[..8],
            &registry,
            &admission,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_provider_identity, terminal_audit_identity),
            replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .expect("authenticated convergence");
        let result = authenticated.prepare(
            &registry,
            &admission,
            &FixtureVerifier,
            StageIssue {
                at_ms: num(&messages[0], "expires_at_ms"),
                nonce: &txt(&messages[8], "nonce"),
            },
            Ttl::from_millis(1).expect("ttl"),
            &mut dependencies.signatures,
        );
        assert!(result.is_err());
        fs::remove_dir_all(root).expect("cleanup");

        let root = temporary_root("late-permit");
        let (atomic, mut dependencies, registry, admission, messages) =
            build_atomic_dispatch(&root);
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![Time::from_millis_since_epoch(num(
                &messages[16],
                "permit_deadline_ms",
            ))],
            expected_permit_id: atomic.permit_id,
            expected_permit_digest: atomic.permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation: PrivateEffectObservation::Succeeded,
        };
        assert!(atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .is_err());
        assert_eq!(adapter.calls, 0);
        fs::remove_dir_all(root).expect("cleanup");

        let root = temporary_root("permit-transplant");
        let (mut atomic, mut dependencies, registry, admission, messages) =
            build_atomic_dispatch(&root);
        atomic
            .fixed_prefix
            .last_mut()
            .expect("permit result")
            .insert("permit_id".into(), Value::Text("f".repeat(32)));
        let mut adapter = RecordingAdapter {
            calls: 0,
            times: vec![Time::from_millis_since_epoch(num(
                &messages[17],
                "adapter_consumed_at_ms",
            ))],
            expected_permit_id: atomic.permit_id,
            expected_permit_digest: atomic.permit_digest,
            expected_effect_deadline: Some(atomic.awaiting.watchdog_arm().receipt_deadline()),
            observation: PrivateEffectObservation::Succeeded,
        };
        assert!(atomic
            .consume(
                &registry,
                &admission,
                &FixtureVerifier,
                &mut dependencies.signatures,
                &mut dependencies.inhibit,
                &mut adapter,
            )
            .is_err());
        assert_eq!(adapter.calls, 0);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn invented_equal_or_fixture_to_production_admission_is_rejected() {
        let messages = parse_lines(GOLDEN);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let root = temporary_root("invented-equal");
        let replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let replay_identity = replay.provider_identity();
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        assert!(AuthenticatedConvergence::from_prepare_prefix(
            &messages[5..8],
            &registry,
            &admission,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_identity, terminal_audit_identity),
            replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .is_err());
        let mut production = admission;
        production.authority_class = "PRODUCTION_HSM".into();
        let replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        assert!(AuthenticatedConvergence::from_prepare_prefix(
            &messages[..8],
            &registry,
            &production,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_identity, terminal_audit_identity),
            replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn replay_survives_restart_and_namespace_substitution_is_rejected() {
        let messages = parse_lines(GOLDEN);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let root = temporary_root("restart");
        let mut first = evidence_dependencies(&root);
        let first_replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let replay_identity = first_replay.provider_identity();
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let authenticated = AuthenticatedConvergence::from_prepare_prefix(
            &messages[..8],
            &registry,
            &admission,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_identity, terminal_audit_identity),
            first_replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .expect("authenticated convergence");
        authenticated
            .prepare(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[8], "message_time_ms"),
                    nonce: &txt(&messages[8], "nonce"),
                },
                Ttl::from_millis(1_000).expect("ttl"),
                &mut first.signatures,
            )
            .expect("first durable claim");
        drop(first);
        let mut restarted = evidence_dependencies(&root);
        let restarted_replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        let replayed = AuthenticatedConvergence::from_prepare_prefix(
            &messages[..8],
            &registry,
            &admission,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_identity, terminal_audit_identity),
            restarted_replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .expect("same authenticated convergence")
        .prepare(
            &registry,
            &admission,
            &FixtureVerifier,
            StageIssue {
                at_ms: num(&messages[8], "message_time_ms"),
                nonce: &txt(&messages[8], "nonce"),
            },
            Ttl::from_millis(1_000).expect("ttl"),
            &mut restarted.signatures,
        );
        assert!(replayed.is_err());

        let mut alternate_namespace = admission;
        alternate_namespace.replay_namespace = "f".repeat(128);
        let alternate_replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
        assert!(AuthenticatedConvergence::from_prepare_prefix(
            &messages[..8],
            &registry,
            &alternate_namespace,
            &FixtureVerifier,
            num(&messages[8], "message_time_ms"),
            pinned_configuration(replay_identity, terminal_audit_identity),
            alternate_replay,
            terminal_audit,
            Box::new(EvidenceWatchdog::default()),
            fixture_signers(),
        )
        .is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn mode2_and_mode3_prepare_replay_survives_restart_before_any_permit_exists() {
        for (label, vector, prepare_request_index, prepare_result_index) in [
            ("mode2-replay", MODE2, 4usize, 5usize),
            ("mode3-replay", MODE3, 3usize, 4usize),
        ] {
            let messages = parse_lines(vector);
            let registry = registry(&messages);
            let admission = policy(&messages, &registry);
            let root = temporary_root(label);
            let mut first = evidence_dependencies(&root);
            let first_replay = EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
            let replay_identity = first_replay.provider_identity();
            let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
            let prepare_ttl = Ttl::from_millis(
                num(&messages[prepare_result_index], "expires_at_ms")
                    - num(&messages[prepare_result_index], "message_time_ms"),
            )
            .expect("prepare ttl");
            AuthenticatedConvergence::from_prepare_prefix(
                &messages[..=prepare_request_index],
                &registry,
                &admission,
                &FixtureVerifier,
                num(&messages[prepare_request_index], "message_time_ms"),
                pinned_configuration(replay_identity, terminal_audit_identity),
                first_replay,
                terminal_audit,
                Box::new(EvidenceWatchdog::default()),
                fixture_signers(),
            )
            .expect("authenticated Mode 2/3 convergence")
            .prepare(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[prepare_result_index], "message_time_ms"),
                    nonce: &txt(&messages[prepare_result_index], "nonce"),
                },
                prepare_ttl,
                &mut first.signatures,
            )
            .expect("first durable Mode 2/3 claim");
            drop(first);

            let mut restarted = evidence_dependencies(&root);
            let restarted_replay =
                EvidenceReplayJournal::open_at(&root).expect("fixed test journal");
            let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&root);
            let replayed = AuthenticatedConvergence::from_prepare_prefix(
                &messages[..=prepare_request_index],
                &registry,
                &admission,
                &FixtureVerifier,
                num(&messages[prepare_request_index], "message_time_ms"),
                pinned_configuration(replay_identity, terminal_audit_identity),
                restarted_replay,
                terminal_audit,
                Box::new(EvidenceWatchdog::default()),
                fixture_signers(),
            )
            .expect("same authenticated Mode 2/3 convergence")
            .prepare(
                &registry,
                &admission,
                &FixtureVerifier,
                StageIssue {
                    at_ms: num(&messages[prepare_result_index], "message_time_ms"),
                    nonce: &txt(&messages[prepare_result_index], "nonce"),
                },
                prepare_ttl,
                &mut restarted.signatures,
            );
            assert!(replayed.is_err());
            fs::remove_dir_all(root).expect("cleanup");
        }
    }

    #[test]
    fn alternate_replay_provider_and_trust_context_cannot_enter_a_session() {
        let messages = parse_lines(GOLDEN);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let expected_root = temporary_root("expected-provider");
        let alternate_root = temporary_root("alternate-provider");
        let expected = EvidenceReplayJournal::open_at(&expected_root).expect("expected replay");
        let expected_identity = expected.provider_identity();
        let alternate = EvidenceReplayJournal::open_at(&alternate_root).expect("alternate replay");
        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&expected_root);
        let watchdog = EvidenceWatchdog::default();
        let watchdog_identity = PrivateWatchdogProvider::provider_identity(&watchdog);
        let rejected = PrivateAuthorityEngine::new(
            alternate,
            expected_identity,
            terminal_audit,
            terminal_audit_identity,
            Box::new(watchdog),
            watchdog_identity,
            &registry,
            &admission,
            &FixtureVerifier,
            fixture_signers(),
        );
        assert!(rejected.is_err());

        let (terminal_audit, terminal_audit_identity) = evidence_terminal_audit(&expected_root);
        let watchdog = EvidenceWatchdog::default();
        let watchdog_identity = PrivateWatchdogProvider::provider_identity(&watchdog);
        let engine = PrivateAuthorityEngine::new(
            expected,
            expected_identity,
            terminal_audit,
            terminal_audit_identity,
            Box::new(watchdog),
            watchdog_identity,
            &registry,
            &admission,
            &FixtureVerifier,
            fixture_signers(),
        )
        .expect("pinned engine");
        let mut changed_admission = admission.clone();
        changed_admission.replay_namespace = "f".repeat(128);
        assert!(engine
            .verify_trust_context(&registry, &changed_admission, &FixtureVerifier)
            .is_err());
        let mut changed_registry = registry.clone();
        changed_registry
            .entries
            .get_mut("AUTHORITY")
            .expect("authority key")
            .public_key_hex = "f".repeat(128);
        assert!(engine
            .verify_trust_context(&changed_registry, &admission, &FixtureVerifier)
            .is_err());
        fs::remove_dir_all(expected_root).expect("cleanup");
        fs::remove_dir_all(alternate_root).expect("cleanup");
    }

    #[test]
    fn failure_unknown_and_timeout_are_only_stop() {
        for vector in [
            FAILURE,
            UNKNOWN,
            TIMEOUT,
            MODE2_FAILURE,
            MODE2_UNKNOWN,
            MODE2_TIMEOUT,
            MODE3_FAILURE,
            MODE3_UNKNOWN,
            MODE3_TIMEOUT,
        ] {
            let messages = parse_lines(vector);
            let registry = registry(&messages);
            let admission = policy(&messages, &registry);
            assert_eq!(
                validated_terminal_disposition(
                    &messages,
                    &registry,
                    &admission,
                    &FixtureVerifier,
                    2_000_000_005_000,
                )
                .expect("valid fail-closed transcript"),
                TerminalDisposition::Stop
            );
        }
    }

    #[test]
    fn service_public_surface_contains_no_v2_authority_typestate_or_signer() {
        let library_source = include_str!("lib.rs");
        assert!(!library_source.contains("pub use wire_v2_private"));
        assert!(!library_source.contains("pub use AuthenticatedConvergence"));
        assert!(!library_source.contains("pub use AtomicDispatch"));
        assert!(!library_source.contains("pub use PrivateWireAuthoritySigner"));
    }
}
