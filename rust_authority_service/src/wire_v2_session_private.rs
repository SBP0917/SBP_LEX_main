//! Bounded, transport-independent intake for the private authority session.
//!
//! A deployment transport must authenticate its peer before calling this
//! layer.  This module adds no named-pipe, socket, credential, process, or
//! binary-identity semantics.  It accepts only exact canonical wire-v2 frames
//! for externally owned roles and never accepts an adapter request, authority
//! result, watchdog result, receipt, or redeemable permit from Python.

use sbp_lex_authority_wire_v2::{decode_frame, Message, Value, MAX_FRAME_BYTES};

const MAX_EXTERNAL_SESSION_FRAMES: usize = 8;
const MAX_EXTERNAL_SESSION_BYTES: usize = MAX_EXTERNAL_SESSION_FRAMES * (MAX_FRAME_BYTES + 4);

#[derive(Debug, Eq, PartialEq)]
enum PrivateSessionError {
    Wire(String),
    SessionComplete,
    SessionByteLimit,
    UnsupportedMode,
    UnexpectedExternallyOwnedStage,
    InternallyOwnedStage,
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
}

impl PrivateInboundSession {
    fn new() -> Self {
        Self {
            mode: None,
            accepted: Vec::new(),
            accepted_bytes: 0,
        }
    }

    fn accept_frame(&mut self, frame: &[u8]) -> Result<&Message, PrivateSessionError> {
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
        let message =
            decode_frame(frame).map_err(|error| PrivateSessionError::Wire(error.to_string()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sbp_lex_authority_wire_v2::{encode_frame, parse_message};

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

    fn messages(vector: &str) -> Vec<Message> {
        vector
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| parse_message(line.as_bytes()).expect("fixed canonical vector"))
            .collect()
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
                session
                    .accept_frame(&encode_frame(&source[*index]).expect("fixed frame"))
                    .expect("externally owned stage");
            }
            assert!(session.is_complete());
        }
    }

    #[test]
    fn adapter_authority_and_partial_or_malformed_frames_are_rejected() {
        let source = messages(MODE1);
        let mut session = PrivateInboundSession::new();
        session
            .accept_frame(&encode_frame(&source[0]).expect("release frame"))
            .expect("release request");
        assert_eq!(
            session.accept_frame(&encode_frame(&source[1]).expect("result frame")),
            Err(PrivateSessionError::InternallyOwnedStage)
        );
        assert!(matches!(
            session.accept_frame(&[0, 0, 0]),
            Err(PrivateSessionError::Wire(_))
        ));

        let mut later = PrivateInboundSession::new();
        assert_eq!(
            later.accept_frame(&encode_frame(&source[11]).expect("lease request frame")),
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
                session
                    .accept_frame(&encode_frame(&source[*index]).expect("fixed frame"))
                    .expect("externally owned stage");
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
                partial
                    .accept_frame(&encode_frame(&source[*index]).expect("partial frame"))
                    .expect("valid partial prefix");
            }
            assert!(!partial.is_complete());

            let first = encode_frame(&source[indexes[0]]).expect("first frame");
            let mut wrong_order = PrivateInboundSession::new();
            wrong_order.accept_frame(&first).expect("first stage");
            assert_eq!(
                wrong_order
                    .accept_frame(&encode_frame(&source[indexes[2]]).expect("wrong-order frame")),
                Err(PrivateSessionError::UnexpectedExternallyOwnedStage)
            );

            let mut replay = PrivateInboundSession::new();
            replay.accept_frame(&first).expect("first stage");
            assert_eq!(
                replay.accept_frame(&first),
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
                    session.accept_frame(
                        &encode_frame(&source[*index]).expect("internally owned frame")
                    ),
                    Err(PrivateSessionError::InternallyOwnedStage)
                );
            }
        }
    }
}
