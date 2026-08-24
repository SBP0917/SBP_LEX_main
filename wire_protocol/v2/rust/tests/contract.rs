use std::collections::BTreeMap;

use sbp_lex_authority_wire_v2::{
    adapter_consumption_digest, admission_policy_digest, authority_artifact_digest,
    authority_artifact_id, convergence_digest, decode_frame, effect_receipt_digest, encode_frame,
    encode_message, parse_message, point_of_use_digest, rendezvous_ack_digest,
    rendezvous_checkpoint_digest, rendezvous_release_digest, seal_fixture_message,
    validate_and_append_result, validate_effect_permit_for_atomic_consumption,
    validate_request_prefix, validate_transcript, AdmissionPolicy, FixtureVerifier, KeyRecord,
    Message, TrustRegistry, Value, MAX_FRAME_BYTES,
};

const GOLDEN: &str = include_str!("../../vectors/mode1_golden.jsonl");
const MODE2: &str = include_str!("../../vectors/mode_2_golden.jsonl");
const MODE3: &str = include_str!("../../vectors/mode_3_golden.jsonl");
const MODE2_EQUAL: &str = include_str!("../../vectors/mode2_equal_golden.jsonl");
const MODE2_MIXED: &str = include_str!("../../vectors/mode2_mixed_golden.jsonl");
const FAILURE: &str = include_str!("../../vectors/mode1_failure_golden.jsonl");
const UNKNOWN: &str = include_str!("../../vectors/mode1_unknown_golden.jsonl");
const TIMEOUT: &str = include_str!("../../vectors/mode1_timeout_golden.jsonl");
const RELEASE_DENIAL: &str = include_str!("../../vectors/mode1_release_denial_golden.jsonl");
const WITNESS_TIME_TRANSPLANT: &str =
    include_str!("../../vectors/mode1_witness_time_transplant_negative.jsonl");
const TIMEOUT_LEASE_BOUND: &str =
    include_str!("../../vectors/mode1_timeout_lease_bound_golden.jsonl");
const TIMEOUT_WATCHDOG_BOUND: &str =
    include_str!("../../vectors/mode1_timeout_watchdog_bound_golden.jsonl");
const MODE2_FAILURE: &str = include_str!("../../vectors/mode2_failure_golden.jsonl");
const MODE2_UNKNOWN: &str = include_str!("../../vectors/mode2_unknown_golden.jsonl");
const MODE2_TIMEOUT: &str = include_str!("../../vectors/mode2_timeout_golden.jsonl");
const MODE3_FAILURE: &str = include_str!("../../vectors/mode3_failure_golden.jsonl");
const MODE3_UNKNOWN: &str = include_str!("../../vectors/mode3_unknown_golden.jsonl");
const MODE3_TIMEOUT: &str = include_str!("../../vectors/mode3_timeout_golden.jsonl");
const TEST_REGISTRY: &str = include_str!("../../vectors/test_trust_registry.txt");
const STAGED_CONTEXTS: &str = include_str!("../../vectors/staged_context_digests.txt");
const LIFECYCLE_DERIVATIONS: &str = include_str!("../../vectors/lifecycle_derivations.txt");

fn messages() -> Vec<Message> {
    parse_lines(GOLDEN)
}

#[test]
fn zero_extension_digests_are_never_admitted() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let mut zero_configuration = admission.clone();
    zero_configuration.extension_configuration_digest = "0".repeat(128);
    assert!(admission_policy_digest(&zero_configuration).is_err());
    let mut zero_binding = admission;
    zero_binding.extension_admission_binding_digest = "0".repeat(128);
    assert!(admission_policy_digest(&zero_binding).is_err());
}

fn parse_lines(value: &str) -> Vec<Message> {
    value
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| parse_message(line.as_bytes()).expect("shared Python-generated golden"))
        .collect()
}

fn txt(message: &Message, key: &str) -> String {
    match message.get(key).unwrap() {
        Value::Text(value) => value.clone(),
        _ => panic!("text"),
    }
}

fn num(message: &Message, key: &str) -> u64 {
    match message.get(key).unwrap() {
        Value::Number(value) => *value,
        _ => panic!("expected numeric field {key}"),
    }
}

fn registry(messages: &[Message]) -> TrustRegistry {
    let mut entries = BTreeMap::new();
    for line in TEST_REGISTRY.lines() {
        let mut parts = line.split('|');
        let role = parts.next().unwrap().to_owned();
        entries.insert(
            role.clone(),
            KeyRecord {
                role,
                key_class: parts.next().unwrap().to_owned(),
                public_key_hex: parts.next().unwrap().to_owned(),
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
    let mode1_fixture = parse_lines(GOLDEN);
    let mode2_fixture = parse_lines(MODE2);
    let mode3_fixture = parse_lines(MODE3);
    AdmissionPolicy {
        trust_root_digest: registry.root_digest.clone(),
        registry_digest: registry.digest().unwrap(),
        runtime_subject: txt(&messages[0], "runtime_subject"),
        runtime_tree: txt(&messages[0], "runtime_tree"),
        authority_class: txt(&messages[0], "authority_class"),
        authority_epoch: match messages[0].get("authority_epoch").unwrap() {
            Value::Number(value) => *value,
            _ => panic!("authority epoch"),
        },
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
        extension_admission_binding_digest: txt(&messages[0], "extension_admission_binding_digest"),
        branch_a_callable_digest: txt(&mode1_fixture[2], "callable_digest"),
        branch_a_code_provenance_digest: txt(&mode1_fixture[2], "code_provenance_digest"),
        branch_b_callable_digest: txt(&mode1_fixture[3], "callable_digest"),
        branch_b_code_provenance_digest: txt(&mode1_fixture[3], "code_provenance_digest"),
        validator_code_digest: txt(&mode2_fixture[1], "validator_code_digest"),
        validator_provenance_digest: txt(&mode2_fixture[1], "validator_provenance_digest"),
        single_state_callable_digest: txt(&mode3_fixture[0], "single_state_callable_digest"),
        single_state_provenance_digest: txt(&mode3_fixture[0], "single_state_provenance_digest"),
    }
}

fn rechain(messages: &[Message], registry: &TrustRegistry) -> Vec<Message> {
    let mut result = Vec::new();
    for (sequence, source) in messages.iter().enumerate() {
        let mut item = source.clone();
        item.insert("sequence".into(), Value::Number(sequence as u64));
        item.insert(
            "prior_transcript_digest".into(),
            Value::Text(if sequence == 0 {
                "0".repeat(128)
            } else {
                txt(&result[sequence - 1], "transcript_digest")
            }),
        );
        let role = txt(&item, "signer_role");
        result.push(seal_fixture_message(&item, registry.entries.get(&role).unwrap()).unwrap());
    }
    result
}

#[test]
fn independent_mode2_and_mode3_vectors_validate() {
    for value in [MODE2, MODE2_EQUAL, MODE2_MIXED, MODE3] {
        let messages = parse_lines(value);
        let registry = registry(&messages);
        validate_transcript(
            &messages,
            &registry,
            &policy(&messages, &registry),
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
    }
}

#[test]
fn failed_effect_and_timeout_vectors_validate_only_as_fail_closed() {
    for value in [
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
        let messages = parse_lines(value);
        let registry = registry(&messages);
        validate_transcript(
            &messages,
            &registry,
            &policy(&messages, &registry),
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
        assert_eq!(txt(messages.last().unwrap(), "decision"), "BLOCK");
    }
}

#[test]
fn mode2_reduction_mode3_provenance_and_authority_matrix_mutations_reject() {
    let mode2_messages = parse_lines(MODE2);
    let mode2_registry = registry(&mode2_messages);
    let mut admission = policy(&mode2_messages, &mode2_registry);
    admission.validator_provenance_digest = "f".repeat(128);
    assert!(validate_transcript(
        &mode2_messages,
        &mode2_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mode3_messages = parse_lines(MODE3);
    let mode3_registry = registry(&mode3_messages);
    let mut admission = policy(&mode3_messages, &mode3_registry);
    admission.single_state_provenance_digest = "f".repeat(128);
    assert!(validate_transcript(
        &mode3_messages,
        &mode3_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mode1_messages = messages();
    let mode1_registry = registry(&mode1_messages);
    let mut admission = policy(&mode1_messages, &mode1_registry);
    admission.authority_class = "PRODUCTION_HSM".into();
    assert!(validate_transcript(
        &mode1_messages,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn stable_effect_replay_identity_and_binding_mutation_reject() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let mut changed = messages.clone();
    changed[5].insert(
        "stable_effect_intent_digest".into(),
        Value::Text("f".repeat(128)),
    );
    assert!(validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut changed = messages.clone();
    changed[5].insert("audit_anchor_digest".into(), Value::Text("f".repeat(128)));
    assert!(validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut changed = messages.clone();
    changed[5].insert(
        "extension_admission_binding_digest".into(),
        Value::Text("f".repeat(128)),
    );
    assert!(validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut wrong_context = admission.clone();
    wrong_context.replay_namespace = "f".repeat(128);
    assert!(validate_transcript(
        &messages,
        &registry,
        &wrong_context,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut wrong_extension_context = admission.clone();
    wrong_extension_context.extension_configuration_digest = "f".repeat(128);
    assert!(validate_transcript(
        &messages,
        &registry,
        &wrong_extension_context,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn exact_deadline_boundaries_are_expired() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (index, key) in [
        (11usize, "lease_deadline_ms"),
        (13usize, "watchdog_deadline_ms"),
        (16usize, "permit_deadline_ms"),
    ] {
        let mut changed = messages.clone();
        let time = changed[index].get("message_time_ms").unwrap().clone();
        changed[index].insert(key.into(), time);
        assert!(validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000
        )
        .is_err());
    }
    let mut changed = messages.clone();
    let permit_deadline = changed[16].get("permit_deadline_ms").unwrap().clone();
    changed[17].insert("adapter_consumed_at_ms".into(), permit_deadline);
    assert!(validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn shared_python_vector_roundtrips_and_authorizes_structurally() {
    let messages = messages();
    assert_eq!(messages.len(), 21);
    assert_eq!(
        num(&messages[4], "rendezvous_opened_at_ms"),
        num(&messages[0], "rendezvous_opened_at_ms")
    );
    assert_eq!(
        num(&messages[4], "rendezvous_released_at_ms"),
        num(&messages[1], "rendezvous_released_at_ms")
    );
    assert_eq!(
        num(&messages[1], "rendezvous_released_at_ms"),
        num(&messages[2], "substantive_start_ms").min(num(&messages[3], "substantive_start_ms"))
    );
    let registry = registry(&messages);
    validate_transcript(
        &messages,
        &registry,
        &policy(&messages, &registry),
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    for (message, line) in messages.iter().zip(GOLDEN.lines()) {
        assert_eq!(encode_message(message).unwrap(), line.as_bytes());
        assert_eq!(
            decode_frame(&encode_frame(message).unwrap()).unwrap(),
            *message
        );
    }
}

#[test]
fn invented_equal_digests_without_signed_prefix_are_rejected() {
    let messages = messages();
    let registry = registry(&messages);
    let policy = policy(&messages, &registry);
    assert!(validate_transcript(
        &messages[5..],
        &registry,
        &policy,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn signature_registry_time_and_semantic_admission_fail_closed() {
    let messages = messages();
    let registry = registry(&messages);
    let mut admission = policy(&messages, &registry);
    assert!(validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_000_050
    )
    .is_err());
    admission.registry_digest = "f".repeat(128);
    assert!(validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut admission = policy(&messages, &registry);
    admission.branch_a_callable_digest = "f".repeat(128);
    assert!(validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn signature_mutation_and_causal_witness_mutation_are_rejected() {
    let messages = messages();
    let registry = registry(&messages);
    let policy = policy(&messages, &registry);
    let mut changed = messages.clone();
    changed[2].insert("signature_hex".into(), Value::Text("00".repeat(32)));
    assert!(validate_transcript(
        &changed,
        &registry,
        &policy,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut changed = messages.clone();
    changed[4].insert(
        "rendezvous_release_digest".into(),
        Value::Text("f".repeat(128)),
    );
    assert!(validate_transcript(
        &changed,
        &registry,
        &policy,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn canonical_json_and_frame_adversaries_are_rejected() {
    let first = GOLDEN.lines().nth(2).unwrap().as_bytes();
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
    duplicate.extend_from_slice(b",\"kind\":\"branch_a_statement\"}");
    let mut extra = first[..first.len() - 1].to_vec();
    extra.extend_from_slice(b",\"zz_extra\":\"x\"}");
    for bad in [
        duplicate,
        extra,
        mutate(b"\"sequence\":2", b"\"sequence\":02"),
        mutate(
            b"\"worker_id\":\"WORKER_A_001\"",
            b"\"worker_id\":\"\\ud800\"",
        ),
    ] {
        assert!(parse_message(&bad).is_err());
    }
    assert!(decode_frame(&vec![b'x'; MAX_FRAME_BYTES + 5]).is_err());
}

#[test]
fn mandatory_lifecycle_and_evidence_regressions_reject() {
    let mode1 = messages();
    let mode1_registry = registry(&mode1);
    let admission = policy(&mode1, &mode1_registry);

    let mut denial = mode1[..13].to_vec();
    denial[9].insert("prepare_proof_digest".into(), Value::Text("f".repeat(128)));
    denial[12].insert("decision".into(), Value::Text("DENY".into()));
    denial[12].insert("error_code".into(), Value::Text("LEASE_DENIED".into()));
    denial = rechain(&denial, &mode1_registry);
    assert!(validate_transcript(
        &denial,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    let mut deadline_denial = mode1[..13].to_vec();
    let deadline = match deadline_denial[12].get("lease_deadline_ms").unwrap() {
        Value::Number(v) => *v,
        _ => unreachable!(),
    };
    deadline_denial[12].insert("lease_deadline_ms".into(), Value::Number(deadline + 1));
    deadline_denial[12].insert("decision".into(), Value::Text("DENY".into()));
    deadline_denial[12].insert("error_code".into(), Value::Text("LEASE_DENIED".into()));
    deadline_denial = rechain(&deadline_denial, &mode1_registry);
    assert!(validate_transcript(
        &deadline_denial,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());

    let mut late = mode1.clone();
    let watchdog_deadline = match late[13].get("watchdog_deadline_ms").unwrap() {
        Value::Number(v) => *v,
        _ => unreachable!(),
    };
    late[17].insert("message_time_ms".into(), Value::Number(watchdog_deadline));
    late[17].insert(
        "adapter_consumed_at_ms".into(),
        Value::Number(watchdog_deadline - 1),
    );
    let consumption = adapter_consumption_digest(
        &txt(&late[17], "durable_consumption_digest"),
        &txt(&late[17], "permit_digest"),
        &txt(&late[17], "effect_digest"),
        &txt(&late[17], "adapter_digest"),
        watchdog_deadline - 1,
        &txt(&late[17], "effect_outcome"),
    )
    .unwrap();
    late[17].insert(
        "adapter_consumption_digest".into(),
        Value::Text(consumption),
    );
    late = rechain(&late, &mode1_registry);
    assert!(validate_transcript(
        &late,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());

    let mut arbitrary = mode1.clone();
    arbitrary[17].insert(
        "adapter_consumption_digest".into(),
        Value::Text("f".repeat(128)),
    );
    arbitrary = rechain(&arbitrary, &mode1_registry);
    assert!(validate_transcript(
        &arbitrary,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
    for index in [18usize, 19usize, 20usize] {
        let mut late_tail = mode1.clone();
        let deadline = match late_tail[16].get("permit_deadline_ms").unwrap() {
            Value::Number(v) => *v,
            _ => unreachable!(),
        };
        late_tail[index].insert("message_time_ms".into(), Value::Number(deadline));
        late_tail = rechain(&late_tail, &mode1_registry);
        assert!(validate_transcript(
            &late_tail,
            &mode1_registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000
        )
        .is_err());
    }

    let mut release = mode1.clone();
    release[1].insert(
        "rendezvous_release_digest".into(),
        Value::Text("f".repeat(128)),
    );
    release = rechain(&release, &mode1_registry);
    assert!(validate_transcript(
        &release,
        &mode1_registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());

    let mode3 = parse_lines(MODE3);
    let mode3_registry = registry(&mode3);
    let mode3_admission = policy(&mode3, &mode3_registry);
    let mut opaque = mode3.clone();
    opaque[0].insert(
        "single_state_proof_digest".into(),
        Value::Text("f".repeat(128)),
    );
    opaque = rechain(&opaque, &mode3_registry);
    assert!(validate_transcript(
        &opaque,
        &mode3_registry,
        &mode3_admission,
        &FixtureVerifier,
        2_000_000_005_000
    )
    .is_err());
}

#[test]
fn staged_requests_validate_before_results_all_modes() {
    for value in [GOLDEN, MODE2, MODE3] {
        let messages = parse_lines(value);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        for kind in [
            "convergence_request",
            "prepare_request",
            "commit_request",
            "lease_redeem_request",
            "watchdog_arm_request",
            "effect_permit_request",
            "effect_receipt",
            "watchdog_terminal",
        ] {
            let index = messages
                .iter()
                .position(|message| txt(message, "kind") == kind)
                .unwrap();
            let context = validate_request_prefix(
                &messages[..=index],
                kind,
                &registry,
                &admission,
                &FixtureVerifier,
                2_000_000_005_000,
            )
            .unwrap();
            assert_eq!(context.stage_kind(), kind);
            assert_ne!(context.context_digest(), "0".repeat(128));
            assert_ne!(
                context.authenticated_convergence_binding_digest(),
                "0".repeat(128)
            );
        }
    }
}

#[test]
fn mode1_release_request_time_equality_accepted_and_retrocausal_release_rejected() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    assert_eq!(
        num(&messages[0], "message_time_ms"),
        num(&messages[1], "rendezvous_released_at_ms")
    );
    validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();

    let context = validate_request_prefix(
        &messages[..1],
        "mode1_release_request",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    validate_and_append_result(
        &messages[..1],
        &messages[1],
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();

    let released_at = num(&messages[0], "message_time_ms") - 1;
    let mut retrocausal = messages[1].clone();
    retrocausal.insert(
        "rendezvous_released_at_ms".into(),
        Value::Number(released_at),
    );
    let release = rendezvous_release_digest(
        &txt(&messages[0], "a_checkpoint_digest"),
        &txt(&messages[0], "b_checkpoint_digest"),
        num(&messages[0], "rendezvous_opened_at_ms"),
        released_at,
    )
    .unwrap();
    retrocausal.insert("rendezvous_release_digest".into(), Value::Text(release));
    retrocausal =
        seal_fixture_message(&retrocausal, registry.entries.get("AUTHORITY").unwrap()).unwrap();
    let error = validate_and_append_result(
        &messages[..1],
        &retrocausal,
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("Mode 1 release result evidence"));

    let mut changed = messages.clone();
    changed[1] = retrocausal;
    changed = rechain(&changed, &registry);
    let error = validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("Mode 1 admitted causal release evidence"));
}

#[test]
fn shared_mode1_release_denial_is_zero_release_and_auditable() {
    let messages = parse_lines(RELEASE_DENIAL);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    assert_eq!(
        txt(&messages[1], "rendezvous_release_digest"),
        "0".repeat(128)
    );
    assert_eq!(num(&messages[1], "rendezvous_released_at_ms"), 0);
    validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    let context = validate_request_prefix(
        &messages[..1],
        "mode1_release_request",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    validate_and_append_result(
        &messages[..1],
        &messages[1],
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();

    let mut forged = messages.clone();
    forged[1].insert(
        "rendezvous_release_digest".into(),
        Value::Text("f".repeat(128)),
    );
    forged = rechain(&forged, &registry);
    let error = validate_transcript(
        &forged,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("denied release evidence"));
}

#[test]
fn shared_mode1_witness_time_transplant_rejects_staged_and_full() {
    let messages = parse_lines(WITNESS_TIME_TRANSPLANT);
    assert_eq!(messages.len(), 7);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let request = &messages[0];
    let result = &messages[1];
    let branch_a = &messages[2];
    let branch_b = &messages[3];
    let witness = &messages[4];
    let convergence_request = &messages[5];
    let convergence_result = &messages[6];

    let release = rendezvous_release_digest(
        &txt(request, "a_checkpoint_digest"),
        &txt(request, "b_checkpoint_digest"),
        num(request, "rendezvous_opened_at_ms"),
        num(result, "rendezvous_released_at_ms"),
    )
    .unwrap();
    assert_eq!(
        txt(result, "release_request_digest"),
        txt(request, "transcript_digest")
    );
    assert_eq!(txt(result, "rendezvous_release_digest"), release);
    assert_eq!(txt(witness, "rendezvous_release_digest"), release);
    assert_eq!(
        txt(witness, "release_result_digest"),
        txt(result, "transcript_digest")
    );
    assert_eq!(
        txt(witness, "statement_a_digest"),
        txt(branch_a, "transcript_digest")
    );
    assert_eq!(
        txt(witness, "statement_b_digest"),
        txt(branch_b, "transcript_digest")
    );
    assert_eq!(
        txt(witness, "a_ack_digest"),
        rendezvous_ack_digest("A", &release, &txt(branch_a, "transcript_digest")).unwrap()
    );
    assert_eq!(
        txt(witness, "b_ack_digest"),
        rendezvous_ack_digest("B", &release, &txt(branch_b, "transcript_digest")).unwrap()
    );
    let convergence = convergence_digest(
        &txt(branch_a, "transcript_digest"),
        &txt(branch_b, "transcript_digest"),
        &txt(witness, "transcript_digest"),
        &txt(branch_a, "projection_digest"),
    )
    .unwrap();
    assert_eq!(txt(convergence_request, "convergence_digest"), convergence);
    assert_eq!(txt(convergence_result, "convergence_digest"), convergence);

    assert_ne!(
        num(witness, "rendezvous_opened_at_ms"),
        num(request, "rendezvous_opened_at_ms")
    );
    assert_ne!(
        num(witness, "rendezvous_released_at_ms"),
        num(result, "rendezvous_released_at_ms")
    );
    assert!(
        num(result, "rendezvous_released_at_ms")
            > num(branch_a, "substantive_start_ms").min(num(branch_b, "substantive_start_ms"))
    );

    let error = validate_request_prefix(
        &messages[..6],
        "convergence_request",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("Mode 1 causal rendezvous"));
    let error = validate_transcript(
        &messages,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("Mode 1 causal rendezvous"));
}

#[test]
fn staged_and_full_half_open_lease_and_watchdog_result_deadlines() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (request_kind, result_kind, deadline_field, artifact_field, identity_field) in [
        (
            "lease_redeem_request",
            "lease_redeem_result",
            "lease_deadline_ms",
            "lease_digest",
            Some("lease_id"),
        ),
        (
            "watchdog_arm_request",
            "watchdog_arm_result",
            "watchdog_deadline_ms",
            "watchdog_digest",
            None,
        ),
    ] {
        let request_index = messages
            .iter()
            .position(|message| txt(message, "kind") == request_kind)
            .unwrap();
        let result_index = messages
            .iter()
            .position(|message| txt(message, "kind") == result_kind)
            .unwrap();
        let prefix = &messages[..=request_index];
        let context = validate_request_prefix(
            prefix,
            request_kind,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
        for delta in [0u64, 1] {
            let mut changed_result = messages[result_index].clone();
            changed_result.insert(
                "message_time_ms".into(),
                Value::Number(num(&changed_result, deadline_field) + delta),
            );
            let artifact = authority_artifact_digest(
                request_kind,
                &context,
                prefix.last().unwrap(),
                &changed_result,
            )
            .unwrap();
            changed_result.insert(artifact_field.into(), Value::Text(artifact.clone()));
            if let Some(identity_field) = identity_field {
                changed_result.insert(
                    identity_field.into(),
                    Value::Text(authority_artifact_id(request_kind, &artifact).unwrap()),
                );
            }
            changed_result = seal_fixture_message(
                &changed_result,
                registry
                    .entries
                    .get(&txt(&changed_result, "signer_role"))
                    .unwrap(),
            )
            .unwrap();
            let error = validate_and_append_result(
                prefix,
                &changed_result,
                &context,
                &registry,
                &admission,
                &FixtureVerifier,
                2_000_000_005_000,
            )
            .unwrap_err();
            assert!(error.0.contains("deadline"));

            let mut completed = messages[..result_index].to_vec();
            completed.push(changed_result);
            completed = rechain(&completed, &registry);
            let error = validate_transcript(
                &completed,
                &registry,
                &admission,
                &FixtureVerifier,
                2_000_000_005_000,
            )
            .unwrap_err();
            assert!(error.0.contains("deadline"));
        }
    }
}

#[test]
fn no_receipt_trip_and_block_result_timing_is_bounded() {
    for value in [TIMEOUT, TIMEOUT_LEASE_BOUND, TIMEOUT_WATCHDOG_BOUND] {
        let messages = parse_lines(value);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let effective_deadline = num(&messages[12], "lease_deadline_ms")
            .min(num(&messages[14], "watchdog_deadline_ms"))
            .min(num(&messages[16], "permit_deadline_ms"));
        assert_eq!(
            num(&messages[messages.len() - 2], "message_time_ms"),
            effective_deadline
        );
        validate_transcript(
            &messages,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
    }

    let messages = parse_lines(TIMEOUT);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let terminal_index = messages.len() - 2;

    let mut early_stop = messages.clone();
    let permit_result_time = num(&early_stop[16], "message_time_ms");
    early_stop[terminal_index].insert("watchdog_status".into(), Value::Text("STOP".into()));
    early_stop[terminal_index].insert("message_time_ms".into(), Value::Number(permit_result_time));
    early_stop[terminal_index + 1].insert(
        "message_time_ms".into(),
        Value::Number(permit_result_time + 1),
    );
    early_stop[terminal_index + 1].insert("error_code".into(), Value::Text("WATCHDOG_STOP".into()));
    early_stop = rechain(&early_stop, &registry);
    validate_transcript(
        &early_stop,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();

    let mut late_terminal = messages.clone();
    let late_time = num(&late_terminal[terminal_index], "message_time_ms") + 1;
    late_terminal[terminal_index].insert("message_time_ms".into(), Value::Number(late_time));
    late_terminal[terminal_index + 1]
        .insert("message_time_ms".into(), Value::Number(late_time + 1));
    late_terminal = rechain(&late_terminal, &registry);
    assert!(validate_transcript(
        &late_terminal,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
    assert!(validate_request_prefix(
        &late_terminal[..=terminal_index],
        "watchdog_terminal",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());

    let mut max_result = messages.clone();
    let terminal_time = num(&max_result[terminal_index], "message_time_ms");
    max_result[terminal_index + 1].insert(
        "message_time_ms".into(),
        Value::Number(terminal_time + 1_000),
    );
    max_result = rechain(&max_result, &registry);
    validate_transcript(
        &max_result,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();

    let mut late_result = messages.clone();
    let terminal_time = num(&late_result[terminal_index], "message_time_ms");
    late_result[terminal_index + 1].insert(
        "message_time_ms".into(),
        Value::Number(terminal_time + 1_001),
    );
    late_result = rechain(&late_result, &registry);
    assert!(validate_transcript(
        &late_result,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
    let context = validate_request_prefix(
        &late_result[..=terminal_index],
        "watchdog_terminal",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    assert!(validate_and_append_result(
        &late_result[..=terminal_index],
        &late_result[terminal_index + 1],
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
}

#[test]
fn invalid_staged_request_cannot_produce_verified_context() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let index = messages
        .iter()
        .position(|message| txt(message, "kind") == "convergence_request")
        .unwrap();
    let mut changed = messages[..=index].to_vec();
    changed[index].insert("projection_digest".into(), Value::Text("f".repeat(128)));
    changed = rechain(&changed, &registry);
    let result = validate_request_prefix(
        &changed,
        "convergence_request",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    );
    assert!(result.is_err());
}

#[test]
fn staged_result_append_rejects_forgery_and_late_watchdog_result() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (request_kind, result_kind) in [
        ("convergence_request", "convergence_result"),
        ("lease_redeem_request", "lease_redeem_result"),
        ("effect_receipt", "receipt_ack"),
        ("watchdog_terminal", "watchdog_result"),
    ] {
        let request = messages
            .iter()
            .position(|message| txt(message, "kind") == request_kind)
            .unwrap();
        let result = messages
            .iter()
            .enumerate()
            .find(|(index, message)| *index > request && txt(message, "kind") == result_kind)
            .unwrap()
            .0;
        let context = validate_request_prefix(
            &messages[..=request],
            request_kind,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
        assert!(validate_and_append_result(
            &messages[..=request],
            &messages[result],
            &context,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .is_ok());
    }
    let request = messages
        .iter()
        .position(|message| txt(message, "kind") == "convergence_request")
        .unwrap();
    let context = validate_request_prefix(
        &messages[..=request],
        "convergence_request",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    let mut forged = messages[request + 1].clone();
    forged.insert("projection_digest".into(), Value::Text("f".repeat(128)));
    forged = seal_fixture_message(&forged, registry.entries.get("AUTHORITY").unwrap()).unwrap();
    assert!(validate_and_append_result(
        &messages[..=request],
        &forged,
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
    let terminal = messages
        .iter()
        .position(|message| txt(message, "kind") == "watchdog_terminal")
        .unwrap();
    let context = validate_request_prefix(
        &messages[..=terminal],
        "watchdog_terminal",
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap();
    let mut late = messages[terminal + 1].clone();
    late.insert(
        "message_time_ms".into(),
        context.derived("completion_deadline_ms").unwrap().clone(),
    );
    late = seal_fixture_message(&late, registry.entries.get("AUTHORITY").unwrap()).unwrap();
    assert!(validate_and_append_result(
        &messages[..=terminal],
        &late,
        &context,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
}

#[test]
fn untrusted_prefix_replays_all_completed_result_semantics() {
    let messages = parse_lines(TIMEOUT);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (result_index, field) in [
        (8usize, "prepare_proof_digest"),
        (10usize, "capability_digest"),
        (12usize, "lease_digest"),
        (14usize, "watchdog_digest"),
        (16usize, "permit_digest"),
    ] {
        let mut changed = messages.clone();
        changed[result_index].insert(field.into(), Value::Text("0".repeat(128)));
        for item in &mut changed[result_index + 1..] {
            if item.contains_key(field) {
                item.insert(field.into(), Value::Text("0".repeat(128)));
            }
        }
        changed = rechain(&changed, &registry);
        assert!(validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .is_err());
    }
}

#[test]
fn nonzero_artifact_transplants_fail_before_later_denial() {
    let messages = parse_lines(TIMEOUT);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (result_index, field, handoff_index, denial_index, denial_artifact) in [
        (
            8usize,
            "prepare_proof_digest",
            9usize,
            10usize,
            Some("capability_digest"),
        ),
        (10, "capability_digest", 11, 12, Some("lease_digest")),
        (12, "lease_digest", 13, 14, Some("watchdog_digest")),
        (14, "watchdog_digest", 15, 16, Some("permit_digest")),
        (16, "permit_digest", 17, 18, None),
    ] {
        let mut changed = messages[..=denial_index].to_vec();
        let replacement = format!("{:0128x}", result_index + 1);
        changed[result_index].insert(field.into(), Value::Text(replacement.clone()));
        changed[handoff_index].insert(field.into(), Value::Text(replacement));
        if field == "watchdog_digest" {
            let point = point_of_use_digest(&changed[handoff_index]).unwrap();
            changed[handoff_index].insert("point_of_use_digest".into(), Value::Text(point));
        }
        if let Some(artifact) = denial_artifact {
            changed[denial_index].insert("decision".into(), Value::Text("DENY".into()));
            changed[denial_index].insert(
                "error_code".into(),
                Value::Text("LATER_STAGE_DENIED".into()),
            );
            changed[denial_index].insert(artifact.into(), Value::Text("0".repeat(128)));
        }
        changed = rechain(&changed, &registry);
        let error = validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(
            error.0.contains("authority artifact derivation"),
            "{}",
            error.0
        );
    }
}

#[test]
fn artifact_ids_are_derived_zero_on_denial_and_handoff_bound() {
    let messages = parse_lines(TIMEOUT);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (result_index, field, handoff_index, artifact) in [
        (8usize, "prepare_id", 9usize, "prepare_proof_digest"),
        (10, "capability_id", 11, "capability_digest"),
        (12, "lease_id", 13, "lease_digest"),
        (16, "permit_id", 17, "permit_digest"),
    ] {
        let mut changed = messages.clone();
        changed[result_index].insert(field.into(), Value::Text("f".repeat(32)));
        changed = rechain(&changed, &registry);
        assert!(validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .is_err());

        let mut denied = messages[..=result_index].to_vec();
        denied[result_index].insert("decision".into(), Value::Text("DENY".into()));
        denied[result_index].insert("error_code".into(), Value::Text("STAGE_DENIED".into()));
        denied[result_index].insert(field.into(), Value::Text("f".repeat(32)));
        denied[result_index].insert(artifact.into(), Value::Text("0".repeat(128)));
        denied = rechain(&denied, &registry);
        let error = validate_transcript(
            &denied,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(error.0.contains("artifact ID must be zero"), "{}", error.0);

        let mut transplanted = messages.clone();
        transplanted[result_index].insert(field.into(), Value::Text("f".repeat(32)));
        for item in &mut transplanted[handoff_index..] {
            if item.contains_key(field) {
                item.insert(field.into(), Value::Text("f".repeat(32)));
            }
        }
        transplanted = rechain(&transplanted, &registry);
        let error = validate_transcript(
            &transplanted,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(
            error.0.contains("artifact ID derivation")
                || error.0.contains("point-of-use derivation"),
            "{}",
            error.0
        );
    }
}

#[test]
fn receipt_digest_and_full_permit_identity_tail_are_bound() {
    for value in [GOLDEN, FAILURE, UNKNOWN] {
        let messages = parse_lines(value);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        for replacement in ["0".repeat(128), "e".repeat(128)] {
            let mut changed = messages.clone();
            let start = changed.len() - 4;
            for item in &mut changed[start..] {
                if item.contains_key("receipt_digest") {
                    item.insert("receipt_digest".into(), Value::Text(replacement.clone()));
                }
            }
            changed = rechain(&changed, &registry);
            let error = validate_transcript(
                &changed,
                &registry,
                &admission,
                &FixtureVerifier,
                2_000_000_005_000,
            )
            .unwrap_err();
            assert!(error.0.contains("effect receipt derivation"), "{}", error.0);
        }
        let mut changed = messages.clone();
        let start = changed.len() - 4;
        for item in &mut changed[start..] {
            if item.contains_key("permit_id") {
                item.insert("permit_id".into(), Value::Text("f".repeat(32)));
            }
        }
        changed = rechain(&changed, &registry);
        let error = validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(
            error.0.contains("authority lifecycle handoff")
                || error.0.contains("receipt permit/watchdog binding"),
            "{}",
            error.0
        );
        for (field, replacement) in [
            ("permit_id", "f".repeat(32)),
            ("permit_digest", "e".repeat(128)),
        ] {
            let mut changed = messages.clone();
            let ack = changed.len() - 3;
            changed[ack].insert(field.into(), Value::Text(replacement));
            changed = rechain(&changed, &registry);
            let error = validate_transcript(
                &changed,
                &registry,
                &admission,
                &FixtureVerifier,
                2_000_000_005_000,
            )
            .unwrap_err();
            assert!(
                error.0.contains("authority lifecycle handoff")
                    || error.0.contains("receipt/watchdog staged semantics"),
                "{}",
                error.0
            );
        }
        let mut changed = messages.clone();
        let tail_suffix = changed.len() - 3;
        for item in &mut changed[tail_suffix..] {
            item.insert("permit_id".into(), Value::Text("f".repeat(32)));
            item.insert("permit_digest".into(), Value::Text("e".repeat(128)));
        }
        changed = rechain(&changed, &registry);
        let error = validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(
            error.0.contains("authority lifecycle handoff")
                || error.0.contains("receipt/watchdog staged semantics"),
            "{}",
            error.0
        );
    }
    let messages = parse_lines(TIMEOUT);
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let mut changed = messages.clone();
    let start = changed.len() - 2;
    for item in &mut changed[start..] {
        item.insert("permit_id".into(), Value::Text("f".repeat(32)));
        item.insert("permit_digest".into(), Value::Text("e".repeat(128)));
    }
    changed = rechain(&changed, &registry);
    let error = validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("no-receipt"), "{}", error.0);
}

#[test]
fn dormant_registry_role_class_mismatch_rejected() {
    let messages = parse_lines(MODE3);
    let original_registry = registry(&messages);
    let mut malformed = original_registry.clone();
    malformed.entries.get_mut("BRANCH_A").unwrap().key_class = "PRODUCTION_HSM".into();
    let registry_digest = malformed.digest().unwrap();
    let mut changed = messages.clone();
    for message in &mut changed {
        message.insert(
            "trust_registry_digest".into(),
            Value::Text(registry_digest.clone()),
        );
    }
    changed = rechain(&changed, &malformed);
    let admission = policy(&changed, &malformed);
    let error = validate_transcript(
        &changed,
        &malformed,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .unwrap_err();
    assert!(error.0.contains("registry authority class mismatch"));
}

#[test]
fn mode1_release_worker_and_process_transplants_rejected() {
    let original = messages();
    let registry = registry(&original);
    let admission = policy(&original, &registry);
    for (key, replacement) in [
        ("worker_a_id", "OTHER_A".to_owned()),
        ("a_process_digest", "f".repeat(128)),
    ] {
        let mut changed = original[..6].to_vec();
        changed[0].insert(key.into(), Value::Text(replacement));
        let checkpoint = rendezvous_checkpoint_digest(
            "A",
            &txt(&changed[0], "traversal_id"),
            &txt(&changed[0], "challenge"),
            &txt(&changed[0], "worker_a_id"),
            &txt(&changed[0], "a_process_digest"),
        )
        .unwrap();
        let release = rendezvous_release_digest(
            &checkpoint,
            &txt(&changed[0], "b_checkpoint_digest"),
            num(&changed[0], "rendezvous_opened_at_ms"),
            num(&changed[1], "rendezvous_released_at_ms"),
        )
        .unwrap();
        changed[0].insert(
            "a_checkpoint_digest".into(),
            Value::Text(checkpoint.clone()),
        );
        changed[1].insert(
            "a_checkpoint_digest".into(),
            Value::Text(checkpoint.clone()),
        );
        changed[1].insert(
            "rendezvous_release_digest".into(),
            Value::Text(release.clone()),
        );
        changed = rechain(&changed, &registry);
        let release_request_digest = txt(&changed[0], "transcript_digest");
        changed[1].insert(
            "release_request_digest".into(),
            Value::Text(release_request_digest),
        );
        changed = rechain(&changed, &registry);
        let release_result_digest = txt(&changed[1], "transcript_digest");
        let statement_a_digest = txt(&changed[2], "transcript_digest");
        let statement_b_digest = txt(&changed[3], "transcript_digest");
        let a_ack = rendezvous_ack_digest("A", &release, &statement_a_digest).unwrap();
        let b_ack = rendezvous_ack_digest("B", &release, &statement_b_digest).unwrap();
        changed[4].insert("a_checkpoint_digest".into(), Value::Text(checkpoint));
        changed[4].insert(
            "rendezvous_release_digest".into(),
            Value::Text(release.clone()),
        );
        changed[4].insert(
            "release_result_digest".into(),
            Value::Text(release_result_digest),
        );
        changed[4].insert("statement_a_digest".into(), Value::Text(statement_a_digest));
        changed[4].insert("statement_b_digest".into(), Value::Text(statement_b_digest));
        changed[4].insert("a_ack_digest".into(), Value::Text(a_ack));
        changed[4].insert("b_ack_digest".into(), Value::Text(b_ack));
        changed = rechain(&changed, &registry);
        let evidence_a = txt(&changed[2], "transcript_digest");
        let evidence_b = txt(&changed[3], "transcript_digest");
        let mode_evidence = txt(&changed[4], "transcript_digest");
        let projection = txt(&changed[5], "projection_digest");
        changed[5].insert("evidence_a_digest".into(), Value::Text(evidence_a.clone()));
        changed[5].insert("evidence_b_digest".into(), Value::Text(evidence_b.clone()));
        changed[5].insert(
            "mode_evidence_digest".into(),
            Value::Text(mode_evidence.clone()),
        );
        let convergence =
            convergence_digest(&evidence_a, &evidence_b, &mode_evidence, &projection).unwrap();
        changed[5].insert("convergence_digest".into(), Value::Text(convergence));
        changed = rechain(&changed, &registry);
        let error = validate_request_prefix(
            &changed,
            "convergence_request",
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap_err();
        assert!(error.0.contains("Mode 1 release identity transplant"));
    }
}

#[test]
fn atomic_permit_context_revalidates_private_prefix_and_deadline() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let permit = messages
        .iter()
        .position(|message| txt(message, "kind") == "effect_permit_result")
        .unwrap();
    let context = validate_effect_permit_for_atomic_consumption(
        &messages[..=permit],
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_001_000,
    )
    .unwrap();
    assert_eq!(
        context.derived_text("permit_digest").unwrap(),
        txt(&messages[permit], "permit_digest")
    );
    assert_eq!(
        context.derived_text("point_of_use_digest").unwrap(),
        txt(&messages[permit - 1], "point_of_use_digest")
    );
    assert_ne!(
        context.authenticated_convergence_binding_digest(),
        "0".repeat(128)
    );
    let deadline = match messages[permit].get("permit_deadline_ms").unwrap() {
        Value::Number(value) => *value,
        _ => unreachable!(),
    };
    assert!(validate_effect_permit_for_atomic_consumption(
        &messages[..=permit],
        &registry,
        &admission,
        &FixtureVerifier,
        deadline,
    )
    .is_err());
}

#[test]
fn shared_python_staged_context_digests_match_independent_rust() {
    let expected: BTreeMap<String, String> = STAGED_CONTEXTS
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('|').unwrap();
            (key.into(), value.into())
        })
        .collect();
    let mut actual = BTreeMap::new();
    for value in [GOLDEN, MODE2, MODE3] {
        let messages = parse_lines(value);
        let registry = registry(&messages);
        let admission = policy(&messages, &registry);
        let mode = txt(&messages[0], "mode");
        let request = messages
            .iter()
            .position(|message| txt(message, "kind") == "convergence_request")
            .unwrap();
        let context = validate_request_prefix(
            &messages[..=request],
            "convergence_request",
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
        actual.insert(
            format!("{}.admission_policy_digest", mode),
            admission_policy_digest(&admission).unwrap(),
        );
        actual.insert(
            format!("{}.authenticated_convergence_binding_digest", mode),
            context.authenticated_convergence_binding_digest().into(),
        );
        actual.insert(
            format!("{}.convergence_stage_context_digest", mode),
            context.context_digest().into(),
        );
    }
    assert_eq!(actual, expected);
}

#[test]
fn shared_python_lifecycle_derivations_match_independent_rust() {
    let expected: BTreeMap<String, String> = LIFECYCLE_DERIVATIONS
        .lines()
        .map(|line| {
            let (key, value) = line.split_once('|').unwrap();
            (key.into(), value.into())
        })
        .collect();
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    let mut actual = BTreeMap::new();
    for (stage, artifact_field, identity_field) in [
        (
            "prepare_request",
            "prepare_proof_digest",
            Some("prepare_id"),
        ),
        ("commit_request", "capability_digest", Some("capability_id")),
        ("lease_redeem_request", "lease_digest", Some("lease_id")),
        ("watchdog_arm_request", "watchdog_digest", None),
        ("effect_permit_request", "permit_digest", Some("permit_id")),
    ] {
        let index = messages
            .iter()
            .position(|message| txt(message, "kind") == stage)
            .unwrap();
        let context = validate_request_prefix(
            &messages[..=index],
            stage,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .unwrap();
        let artifact =
            authority_artifact_digest(stage, &context, &messages[index], &messages[index + 1])
                .unwrap();
        assert_eq!(txt(&messages[index + 1], artifact_field), artifact);
        actual.insert(format!("{stage}.artifact_digest"), artifact.clone());
        if let Some(identity_field) = identity_field {
            let identity = authority_artifact_id(stage, &artifact).unwrap();
            assert_eq!(txt(&messages[index + 1], identity_field), identity);
            actual.insert(format!("{stage}.artifact_id"), identity);
        }
    }
    let receipt = messages
        .iter()
        .find(|message| txt(message, "kind") == "effect_receipt")
        .unwrap();
    actual.insert(
        "effect_receipt.receipt_digest".into(),
        effect_receipt_digest(receipt).unwrap(),
    );
    actual.insert(
        "effect_receipt.permit_digest".into(),
        txt(receipt, "permit_digest"),
    );
    actual.insert("effect_receipt.permit_id".into(), txt(receipt, "permit_id"));
    assert_eq!(actual, expected);
}

#[test]
fn epoch_domain_and_subject_are_owner_admitted_immutable_bindings() {
    let messages = messages();
    let registry = registry(&messages);
    let admission = policy(&messages, &registry);
    for (field, value) in [
        ("domain_digest", Value::Text("d".repeat(128))),
        ("subject_digest", Value::Text("e".repeat(128))),
        ("authority_epoch", Value::Number(8)),
    ] {
        let mut changed = messages.clone();
        for item in &mut changed {
            item.insert(field.into(), value.clone());
        }
        changed = rechain(&changed, &registry);
        assert!(validate_transcript(
            &changed,
            &registry,
            &admission,
            &FixtureVerifier,
            2_000_000_005_000,
        )
        .is_err());
    }
    let mut changed = messages.clone();
    for item in &mut changed {
        item.insert("authority_epoch".into(), Value::Number(0));
    }
    assert!(validate_transcript(
        &changed,
        &registry,
        &admission,
        &FixtureVerifier,
        2_000_000_005_000,
    )
    .is_err());
}
