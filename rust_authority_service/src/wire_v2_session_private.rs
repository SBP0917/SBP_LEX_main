//! Bounded, transport-independent intake for the private authority session.
//!
//! A deployment transport must authenticate its peer before calling this
//! layer.  This module adds no named-pipe, socket, credential, process, or
//! binary-identity semantics. It accepts only owner-pinned, mandatory
//! ML-DSA-87 + Ed448 hybrid frames for externally owned roles and never accepts
//! an adapter request, authority result, watchdog result, receipt, or
//! redeemable permit from Python. Legacy wire-v2 remains inspectable only as
//! explicitly non-effect compatibility data.

use sbp_lex_authority_wire_v2::hybrid::{
    decode_for_admission, OwnerPinnedHybridAdmission, WireAdmission, MAX_HYBRID_FRAME_BYTES,
};
use sbp_lex_authority_wire_v2::{Message, Value};

const MAX_EXTERNAL_SESSION_FRAMES: usize = 8;
const MAX_EXTERNAL_SESSION_BYTES: usize =
    MAX_EXTERNAL_SESSION_FRAMES * (MAX_HYBRID_FRAME_BYTES + 4);

#[derive(Debug, Eq, PartialEq)]
enum PrivateSessionError {
    Wire(String),
    SessionComplete,
    SessionByteLimit,
    UnsupportedMode,
    UnexpectedExternallyOwnedStage,
    InternallyOwnedStage,
    NonEffectAdmission,
    HybridRouteBindingChanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionHybridRouteIdentity {
    ordered_key_set_digest: [u8; 64],
    purpose: String,
    authority_epoch: u64,
    context_sha512: [u8; 64],
}

fn text<'a>(message: &'a Message, key: &str) -> Result<&'a str, PrivateSessionError> {
    match message.get(key) {
        Some(Value::Text(value)) => Ok(value),
        _ => Err(PrivateSessionError::Wire(format!("missing {key}"))),
    }
}

fn number(message: &Message, key: &str) -> Result<u64, PrivateSessionError> {
    match message.get(key) {
        Some(Value::Number(value)) => Ok(*value),
        _ => Err(PrivateSessionError::Wire(format!("missing {key}"))),
    }
}

/// Expected messages entering from the untrusted coordinator side. Generated
/// results and the adapter-owned lease/permit/receipt stages are deliberately
/// absent. Sequence values include the private Rust messages between calls.
fn expected_external_stages(
    mode: &str,
) -> Result<&'static [(&'static str, u64)], PrivateSessionError> {
    match mode {
        "MODE_1" => Ok(&[
            ("mode1_release_request", 0),
            ("branch_a_statement", 2),
            ("branch_b_statement", 3),
            ("mode1_overlap_witness", 4),
            ("convergence_request", 5),
            ("prepare_request", 7),
            ("commit_request", 9),
            ("watchdog_arm_request", 13),
        ]),
        "MODE_2" => Ok(&[
            ("branch_a_statement", 0),
            ("mode2_validator_certificate", 1),
            ("convergence_request", 2),
            ("prepare_request", 4),
            ("commit_request", 6),
            ("watchdog_arm_request", 10),
        ]),
        "MODE_3" => Ok(&[
            ("mode3_single_state_proof", 0),
            ("convergence_request", 1),
            ("prepare_request", 3),
            ("commit_request", 5),
            ("watchdog_arm_request", 9),
        ]),
        _ => Err(PrivateSessionError::UnsupportedMode),
    }
}

struct PrivateInboundSession {
    mode: Option<String>,
    accepted: Vec<Message>,
    accepted_bytes: usize,
    hybrid_route_identity: Option<SessionHybridRouteIdentity>,
}

impl PrivateInboundSession {
    fn new() -> Self {
        Self {
            mode: None,
            accepted: Vec::new(),
            accepted_bytes: 0,
            hybrid_route_identity: None,
        }
    }

    fn accept_frame(
        &mut self,
        frame: &[u8],
        owner_pins: Option<&OwnerPinnedHybridAdmission>,
    ) -> Result<&Message, PrivateSessionError> {
        if self.accepted.len() == MAX_EXTERNAL_SESSION_FRAMES {
            return Err(PrivateSessionError::SessionComplete);
        }
        let new_total = self
            .accepted_bytes
            .checked_add(frame.len())
            .ok_or(PrivateSessionError::SessionByteLimit)?;
        if new_total > MAX_EXTERNAL_SESSION_BYTES {
            return Err(PrivateSessionError::SessionByteLimit);
        }
        let (message, route_identity) = match decode_for_admission(frame, owner_pins)
            .map_err(|error| PrivateSessionError::Wire(error.to_string()))?
        {
            WireAdmission::HybridProductionEffect { envelope, payload } => (
                payload,
                SessionHybridRouteIdentity {
                    ordered_key_set_digest: *envelope.ordered_key_set_digest(),
                    purpose: envelope.purpose().to_owned(),
                    authority_epoch: envelope.authority_epoch(),
                    context_sha512: *envelope.context_sha512(),
                },
            ),
            WireAdmission::HybridAuthenticatedNonEffect { .. }
            | WireAdmission::LegacyV2NonEffect(_) => {
                return Err(PrivateSessionError::NonEffectAdmission)
            }
        };
        match &self.hybrid_route_identity {
            None => {}
            Some(expected) if expected == &route_identity => {}
            Some(_) => return Err(PrivateSessionError::HybridRouteBindingChanged),
        }
        let kind = text(&message, "kind")?;
        if matches!(
            kind,
            "lease_redeem_request"
                | "effect_permit_request"
                | "effect_receipt"
                | "mode1_release_result"
                | "convergence_result"
                | "prepare_result"
                | "commit_result"
                | "lease_redeem_result"
                | "watchdog_arm_result"
                | "effect_permit_result"
                | "receipt_ack"
                | "watchdog_terminal"
                | "watchdog_result"
        ) {
            return Err(PrivateSessionError::InternallyOwnedStage);
        }
        let message_mode = text(&message, "mode")?;
        match self.mode.as_deref() {
            None => self.mode = Some(message_mode.to_owned()),
            Some(mode) if mode == message_mode => {}
            Some(_) => return Err(PrivateSessionError::UnexpectedExternallyOwnedStage),
        }
        let expected = expected_external_stages(message_mode)?;
        let (expected_kind, expected_sequence) = expected
            .get(self.accepted.len())
            .ok_or(PrivateSessionError::SessionComplete)?;
        if kind != *expected_kind || number(&message, "sequence")? != *expected_sequence {
            return Err(PrivateSessionError::UnexpectedExternallyOwnedStage);
        }
        if self.hybrid_route_identity.is_none() {
            self.hybrid_route_identity = Some(route_identity);
        }
        self.accepted_bytes = new_total;
        self.accepted.push(message);
        Ok(self.accepted.last().expect("message was just appended"))
    }

    fn is_complete(&self) -> bool {
        self.mode
            .as_deref()
            .and_then(|mode| expected_external_stages(mode).ok())
            .is_some_and(|expected| self.accepted.len() == expected.len())
    }
}

fn inspect_legacy_non_effect(frame: &[u8]) -> Result<Message, PrivateSessionError> {
    match decode_for_admission(frame, None)
        .map_err(|error| PrivateSessionError::Wire(error.to_string()))?
    {
        WireAdmission::LegacyV2NonEffect(message) => Ok(message),
        WireAdmission::HybridAuthenticatedNonEffect { .. }
        | WireAdmission::HybridProductionEffect { .. } => {
            Err(PrivateSessionError::NonEffectAdmission)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbp_lex_authority_wire_v2::hybrid::{
        encode_hybrid_frame, HybridAdmissionClass, HybridEnvelope,
    };
    use sbp_lex_authority_wire_v2::{encode_frame, parse_message};
    use sbp_lex_v2_hybrid_signature::SoftwareHybridSigningKey;

    const MODE1: &str = include_str!("../../wire_protocol/v2/vectors/mode1_golden.jsonl");
    const MODE2: &str = include_str!("../../wire_protocol/v2/vectors/mode_2_golden.jsonl");
    const MODE2_FAILURE: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_failure_golden.jsonl");
    const MODE2_UNKNOWN: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_unknown_golden.jsonl");
    const MODE2_TIMEOUT: &str =
        include_str!("../../wire_protocol/v2/vectors/mode2_timeout_golden.jsonl");
    const MODE3: &str = include_str!("../../wire_protocol/v2/vectors/mode_3_golden.jsonl");
    const MODE3_FAILURE: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_failure_golden.jsonl");
    const MODE3_UNKNOWN: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_unknown_golden.jsonl");
    const MODE3_TIMEOUT: &str =
        include_str!("../../wire_protocol/v2/vectors/mode3_timeout_golden.jsonl");
    const ROUTE_PURPOSE: &str = "AUTHORITY_SESSION";
    const ROUTE_EPOCH: u64 = 89;
    const ROUTE_CONTEXT: &[u8] = b"owner-pinned:bounded-private-session";

    fn messages(vector: &str) -> Vec<Message> {
        vector
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| parse_message(line.as_bytes()).expect("fixed canonical vector"))
            .collect()
    }

    fn route_signer() -> SoftwareHybridSigningKey {
        SoftwareHybridSigningKey::from_seed_slices(&[0xB1; 32], &[0xC2; 57])
            .expect("fixed route signer")
    }

    fn admitted_frame(
        message: &Message,
        signer: &SoftwareHybridSigningKey,
        purpose: &str,
        epoch: u64,
        context: &[u8],
        admission_class: HybridAdmissionClass,
        external_custody_admitted: bool,
    ) -> (Vec<u8>, OwnerPinnedHybridAdmission) {
        let payload = encode_frame(message).expect("legacy payload frame");
        let key = signer.public_key();
        let signature = signer
            .sign(purpose, epoch, context, &payload)
            .expect("strict-dual signature");
        let envelope =
            HybridEnvelope::new(purpose, epoch, context, payload, key.clone(), signature)
                .expect("hybrid envelope");
        let frame = encode_hybrid_frame(&envelope).expect("hybrid frame");
        let pins = OwnerPinnedHybridAdmission::new(
            key.clone(),
            key.ordered_key_set_digest(),
            purpose,
            epoch,
            context,
            text(message, "kind").expect("message kind"),
            admission_class,
            external_custody_admitted,
        )
        .expect("owner pins");
        (frame, pins)
    }

    fn accept_message<'a>(
        session: &'a mut PrivateInboundSession,
        message: &Message,
    ) -> Result<&'a Message, PrivateSessionError> {
        let (frame, pins) = admitted_frame(
            message,
            &route_signer(),
            ROUTE_PURPOSE,
            ROUTE_EPOCH,
            ROUTE_CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        session.accept_frame(&frame, Some(&pins))
    }

    #[test]
    fn one_bounded_driver_accepts_only_external_stages_for_all_modes() {
        for (vector, indexes) in [
            (MODE1, &[0usize, 2, 3, 4, 5, 7, 9, 13][..]),
            (MODE2, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE3, &[0usize, 1, 3, 5, 9][..]),
        ] {
            let source = messages(vector);
            let mut session = PrivateInboundSession::new();
            for index in indexes {
                accept_message(&mut session, &source[*index]).expect("externally owned stage");
            }
            assert!(session.is_complete());
        }
    }

    #[test]
    fn bounded_session_requires_effect_admission_and_one_pinned_route_identity() {
        let source = messages(MODE1);
        let legacy_frame = encode_frame(&source[0]).expect("legacy frame");
        assert_eq!(
            inspect_legacy_non_effect(&legacy_frame).expect("legacy inspection"),
            source[0]
        );
        let mut session = PrivateInboundSession::new();
        assert_eq!(
            session.accept_frame(&legacy_frame, None),
            Err(PrivateSessionError::NonEffectAdmission)
        );

        let signer = route_signer();
        let (first_frame, first_pins) = admitted_frame(
            &source[0],
            &signer,
            ROUTE_PURPOSE,
            ROUTE_EPOCH,
            ROUTE_CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        assert!(matches!(
            session.accept_frame(&first_frame, None),
            Err(PrivateSessionError::Wire(_))
        ));
        session
            .accept_frame(&first_frame, Some(&first_pins))
            .expect("owner-pinned first stage");

        let (test_frame, test_pins) = admitted_frame(
            &source[2],
            &signer,
            ROUTE_PURPOSE,
            ROUTE_EPOCH,
            ROUTE_CONTEXT,
            HybridAdmissionClass::TestOnlyNonEffect,
            false,
        );
        assert_eq!(
            session.accept_frame(&test_frame, Some(&test_pins)),
            Err(PrivateSessionError::NonEffectAdmission)
        );

        let (changed_frame, changed_pins) = admitted_frame(
            &source[2],
            &signer,
            "CHANGED_ROUTE",
            ROUTE_EPOCH,
            ROUTE_CONTEXT,
            HybridAdmissionClass::ProductionEffect,
            true,
        );
        assert_eq!(
            session.accept_frame(&changed_frame, Some(&changed_pins)),
            Err(PrivateSessionError::HybridRouteBindingChanged)
        );
    }

    #[test]
    fn adapter_authority_and_partial_or_malformed_frames_are_rejected() {
        let source = messages(MODE1);
        let mut session = PrivateInboundSession::new();
        accept_message(&mut session, &source[0]).expect("release request");
        assert_eq!(
            accept_message(&mut session, &source[1]),
            Err(PrivateSessionError::InternallyOwnedStage)
        );
        assert!(matches!(
            session.accept_frame(&[0, 0, 0], None),
            Err(PrivateSessionError::Wire(_))
        ));

        let mut later = PrivateInboundSession::new();
        assert_eq!(
            accept_message(&mut later, &source[11]),
            Err(PrivateSessionError::InternallyOwnedStage)
        );
    }

    #[test]
    fn mode2_and_mode3_accept_complete_external_inputs_for_every_terminal_tail() {
        for (vector, indexes) in [
            (MODE2, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE2_FAILURE, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE2_UNKNOWN, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE2_TIMEOUT, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE3, &[0usize, 1, 3, 5, 9][..]),
            (MODE3_FAILURE, &[0usize, 1, 3, 5, 9][..]),
            (MODE3_UNKNOWN, &[0usize, 1, 3, 5, 9][..]),
            (MODE3_TIMEOUT, &[0usize, 1, 3, 5, 9][..]),
        ] {
            let source = messages(vector);
            let mut session = PrivateInboundSession::new();
            for index in indexes {
                accept_message(&mut session, &source[*index]).expect("externally owned stage");
            }
            assert!(session.is_complete());
        }
    }

    #[test]
    fn mode2_and_mode3_partial_wrong_order_and_replay_fail_closed() {
        for (vector, indexes) in [
            (MODE2, &[0usize, 1, 2, 4, 6, 10][..]),
            (MODE3, &[0usize, 1, 3, 5, 9][..]),
        ] {
            let source = messages(vector);

            let mut partial = PrivateInboundSession::new();
            for index in &indexes[..indexes.len() - 1] {
                accept_message(&mut partial, &source[*index]).expect("valid partial prefix");
            }
            assert!(!partial.is_complete());

            let mut wrong_order = PrivateInboundSession::new();
            accept_message(&mut wrong_order, &source[indexes[0]]).expect("first stage");
            assert_eq!(
                accept_message(&mut wrong_order, &source[indexes[2]]),
                Err(PrivateSessionError::UnexpectedExternallyOwnedStage)
            );

            let mut replay = PrivateInboundSession::new();
            accept_message(&mut replay, &source[indexes[0]]).expect("first stage");
            assert_eq!(
                accept_message(&mut replay, &source[indexes[0]]),
                Err(PrivateSessionError::UnexpectedExternallyOwnedStage)
            );
        }
    }

    #[test]
    fn mode2_and_mode3_never_accept_a_permit_or_terminal_tail_from_the_client() {
        for (vector, internal_indexes) in [
            (MODE2, &[12usize, 13, 14, 15, 16, 17][..]),
            (MODE3, &[11usize, 12, 13, 14, 15, 16][..]),
        ] {
            let source = messages(vector);
            for index in internal_indexes {
                let mut session = PrivateInboundSession::new();
                assert_eq!(
                    accept_message(&mut session, &source[*index]),
                    Err(PrivateSessionError::InternallyOwnedStage)
                );
            }
        }
    }
}
