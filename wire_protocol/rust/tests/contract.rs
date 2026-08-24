use sbp_lex_wire_contract::{
    decode_frame, encode_frame, encode_message, parse_message, seal_message, signature_preimage,
    transcript_digest, validate_transcript, Message, Value, MAX_FRAME_BYTES,
};

const GOLDEN: &str = include_str!("../../vectors/golden_transcript.jsonl");
const CASES: &str = include_str!("../../vectors/adversarial_cases.txt");

fn golden() -> Vec<Message> {
    GOLDEN
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| parse_message(line.as_bytes()).expect("golden vector"))
        .collect()
}

#[test]
fn shared_vectors_round_trip_and_validate() {
    let messages = golden();
    assert_eq!(messages.len(), 16);
    validate_transcript(&messages, Some(1_900_000_000_100)).unwrap();
    for (message, line) in messages.iter().zip(GOLDEN.lines()) {
        assert_eq!(encode_message(message).unwrap(), line.as_bytes());
        assert_eq!(
            decode_frame(&encode_frame(message).unwrap()).unwrap(),
            *message
        );
    }
}

#[test]
fn shared_adversarial_set_is_complete_and_rejected() {
    let names: std::collections::BTreeSet<&str> =
        CASES.lines().filter(|line| !line.is_empty()).collect();
    let expected: std::collections::BTreeSet<&str> = [
        "binding_mutation",
        "duplicate_field",
        "extra_field",
        "kind_mismatch",
        "missing_field",
        "noncanonical_integer",
        "order_mismatch",
        "oversize",
        "replay_nonce",
        "surrogate_escape",
    ]
    .into_iter()
    .collect();
    assert_eq!(names, expected);

    let first = GOLDEN.lines().next().unwrap().as_bytes();
    let mutate = |needle: &[u8], replacement: &[u8]| {
        let at = first
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&first[..at]);
        out.extend_from_slice(replacement);
        out.extend_from_slice(&first[at + needle.len()..]);
        out
    };
    let mut duplicate = first[..first.len() - 1].to_vec();
    duplicate.extend_from_slice(
        b",\"state_digest\":\"0000000000000000000000000000000000000000000000000000000000000000\"}",
    );
    let mut extra = first[..first.len() - 1].to_vec();
    extra.extend_from_slice(b",\"unexpected\":\"value\"}");
    let missing_start = first
        .windows(b"\"adapter_boundary_digest\"".len())
        .position(|w| w == b"\"adapter_boundary_digest\"")
        .unwrap();
    let missing_end = first[missing_start..]
        .iter()
        .position(|b| *b == b',')
        .unwrap()
        + missing_start
        + 1;
    let mut missing = Vec::new();
    missing.extend_from_slice(&first[..missing_start]);
    missing.extend_from_slice(&first[missing_end..]);
    let noncanonical = mutate(b"\"sequence\":0", b"\"sequence\":00");
    let surrogate = mutate(b"\"mode\":\"MODE_1\"", b"\"mode\":\"\\ud800\"");
    let mutation = mutate(b"\"state_digest\":\"", b"\"state_digest\":\"f");
    let oversize = vec![b'x'; MAX_FRAME_BYTES + 1];
    for bad in [
        duplicate,
        extra,
        missing,
        noncanonical,
        surrogate,
        mutation,
        oversize,
    ] {
        assert!(parse_message(&bad).is_err());
    }

    let messages = golden();
    let mut replay = messages.clone();
    let nonce = replay[0].get("nonce").unwrap().clone();
    replay[1].insert("nonce".into(), nonce);
    assert!(validate_transcript(&replay, None).is_err());
    let mut wrong_order = messages.clone();
    wrong_order.swap(2, 3);
    assert!(validate_transcript(&wrong_order, None).is_err());
    let mut wrong_kind = messages.clone();
    wrong_kind[2].insert(
        "kind".into(),
        sbp_lex_wire_contract::Value::Text("commit_request".into()),
    );
    assert!(validate_transcript(&wrong_kind, None).is_err());
}

#[test]
fn frame_and_freshness_fail_closed() {
    let messages = golden();
    let frame = encode_frame(&messages[0]).unwrap();
    assert!(decode_frame(&frame[..3]).is_err());
    assert!(decode_frame(&frame[..frame.len() - 1]).is_err());
    let mut trailing = frame.clone();
    trailing.push(0);
    assert!(decode_frame(&trailing).is_err());
    assert!(validate_transcript(&messages, Some(1_900_000_001_000)).is_err());
}

#[test]
fn timeout_failure_and_signature_preimage_are_unambiguous() {
    let messages = golden();
    let mut timeout = messages[..12].to_vec();
    let mut terminal = messages[14].clone();
    terminal.insert("sequence".into(), Value::Number(12));
    terminal.insert("message_time_ms".into(), Value::Number(1_900_000_000_600));
    terminal.insert(
        "prior_transcript_digest".into(),
        messages[11].get("transcript_digest").unwrap().clone(),
    );
    terminal.insert("receipt_digest".into(), Value::Text("0".repeat(64)));
    terminal.insert("watchdog_status".into(), Value::Text("TIMEOUT".into()));
    terminal = seal_message(&terminal).unwrap();
    let mut result = messages[15].clone();
    result.insert("sequence".into(), Value::Number(13));
    result.insert("message_time_ms".into(), Value::Number(1_900_000_000_610));
    result.insert(
        "prior_transcript_digest".into(),
        terminal.get("transcript_digest").unwrap().clone(),
    );
    result.insert("decision".into(), Value::Text("BLOCK".into()));
    result.insert("error_code".into(), Value::Text("WATCHDOG_TIMEOUT".into()));
    timeout.push(terminal);
    timeout.push(seal_message(&result).unwrap());
    validate_transcript(&timeout, None).unwrap();

    let mut signed = messages[1].clone();
    let digest = transcript_digest(&signed).unwrap();
    signed.insert("signature_hex".into(), Value::Text("ab".repeat(32)));
    assert_eq!(transcript_digest(&signed).unwrap(), digest);
    assert!(signature_preimage(&signed)
        .unwrap()
        .ends_with(&hex_bytes(&digest)));
    encode_message(&signed).unwrap();
    signed.insert("authority_key_id".into(), Value::Text("cd".repeat(32)));
    assert!(seal_message(&signed).is_err());
}

#[test]
fn mode2_set_reduction_is_recomputed() {
    let mut message = golden()[0].clone();
    message.insert("mode".into(), Value::Text("MODE_2".into()));
    message.insert(
        "mode_evidence_type".into(),
        Value::Text("VALIDATOR_REDUCTION_PROOF".into()),
    );
    message.insert(
        "candidate_input_set".into(),
        Value::Text(format!("{},{}", "1".repeat(64), "2".repeat(64))),
    );
    message.insert("candidate_output_set".into(), Value::Text("1".repeat(64)));
    message.insert(
        "pathway_input_set".into(),
        Value::Text(format!("{},{}", "3".repeat(64), "4".repeat(64))),
    );
    message.insert("pathway_output_set".into(), Value::Text("3".repeat(64)));
    message.insert(
        "validator_certificate_digest".into(),
        Value::Text("5".repeat(64)),
    );
    message.insert(
        "no_widening_proof_digest".into(),
        Value::Text("6".repeat(64)),
    );
    assert!(seal_message(&message).is_ok());
    message.insert("candidate_output_set".into(), Value::Text("7".repeat(64)));
    assert!(seal_message(&message).is_err());
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let d = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
            (d(pair[0]) << 4) | d(pair[1])
        })
        .collect()
}
