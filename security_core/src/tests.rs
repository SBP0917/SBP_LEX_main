#![allow(clippy::needless_pass_by_value)]

use std::collections::HashSet;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sbp_lex_v2_hybrid_signature::{SoftwareHybridSigningKey, SUITE_ID};
use serde_json::{json, Map, Value};

use crate::{
    audit::verify_terminal_audit,
    authority::verify_authority_binding,
    canonical::{canonical_assurance_bytes, canonical_integrity_bytes},
    decision::{BoundaryError, Component, Proof},
    digest::{canonical_digest, is_sha512, sha512_hex},
    dispatch::{dispatch_existing_authorization, EffectHandler},
    filed_framework::{verify_filed_frameworks, ORDER as FRAMEWORK_ORDER},
    filed_lifecycle::{verify_filed_lifecycle, ORDER as LIFECYCLE_ORDER},
    hash_chain::{build_entry, verify_exact_hash_chain, verify_hash_chain},
    licence::verify_licence,
    permit::verify_effect_permit,
    pre_effect::immediate_pre_effect_revalidation,
    replay::{claim_replay_slot, ClaimResult, DurableReplayStore},
    request::verify_request_fingerprint,
    revocation::{verify_monotonic_revocation, RevocationState},
    signature::{
        public_key_id, verify_signed_object, LaneCustodyExpectation, SignerExpectation,
        PRODUCTION_DUAL_CUSTODY_CLASS, TEST_ONLY_CUSTODY_CLASS,
    },
    skg::verify_skg_evidence,
    three_p::verify_three_p_evidence,
    token::{verify_token_stack, REQUIRED_CORE_TOKENS, REQUIRED_THRESHOLD_TOKENS},
    tpm::{
        create_nonexportable_signing_key, probe_platform_crypto_provider, sign_with_tpm,
        verify_with_tpm_public_key, TpmProviderStatus,
    },
    ClosedDecision, Gap,
};

/// TEST-ONLY software signing fixture. It is never compiled into production.
struct TestOnlySoftwareSigner {
    key: SoftwareHybridSigningKey,
    expectation: SignerExpectation,
}

impl TestOnlySoftwareSigner {
    fn new(effect_authority: bool) -> Self {
        let key = SoftwareHybridSigningKey::from_seed_slices(&[0x5a; 32], &[0xa5; 57])
            .expect("hybrid fixture key");
        let public_key = key.public_key();
        let key_id = public_key_id(&public_key);
        let ml_dsa_87_key_id = sha512_hex(public_key.ml_dsa_87_bytes());
        let ed448_key_id = sha512_hex(public_key.ed448_bytes());
        Self {
            key,
            expectation: SignerExpectation {
                provider_id: format!("TEST-ONLY-NONPRODUCTION:{key_id}"),
                algorithm: SUITE_ID.to_owned(),
                ml_dsa_87_key_id: ml_dsa_87_key_id.clone(),
                ed448_key_id: ed448_key_id.clone(),
                ordered_key_set_digest: key_id,
                custody_class: TEST_ONLY_CUSTODY_CLASS.to_owned(),
                dual_custody_admission_sha512: "NONE".to_owned(),
                ml_dsa_87_custody: LaneCustodyExpectation {
                    algorithm: "ML-DSA-87".to_owned(),
                    provider_id: "TEST-ONLY-NONPRODUCTION:ML-DSA-87".to_owned(),
                    key_id: ml_dsa_87_key_id,
                    key_epoch: 7,
                    rotation_epoch: 7,
                    custody_class: TEST_ONLY_CUSTODY_CLASS.to_owned(),
                    custody_reference: "TEST-ONLY:PROCESS-MEMORY:ML-DSA-87".to_owned(),
                    lifecycle_status: "ACTIVE".to_owned(),
                    revoked_at_epoch: None,
                    external_custody_admitted: false,
                    custody_admission_sha512: "NONE".to_owned(),
                    non_exportable: false,
                },
                ed448_custody: LaneCustodyExpectation {
                    algorithm: "Ed448".to_owned(),
                    provider_id: "TEST-ONLY-NONPRODUCTION:ED448".to_owned(),
                    key_id: ed448_key_id,
                    key_epoch: 7,
                    rotation_epoch: 7,
                    custody_class: TEST_ONLY_CUSTODY_CLASS.to_owned(),
                    custody_reference: "TEST-ONLY:PROCESS-MEMORY:ED448".to_owned(),
                    lifecycle_status: "ACTIVE".to_owned(),
                    revoked_at_epoch: None,
                    external_custody_admitted: false,
                    custody_admission_sha512: "NONE".to_owned(),
                    non_exportable: false,
                },
                effect_authority,
                authority_epoch: 7,
                purpose: "SECURITY_CORE_OBJECT".to_owned(),
                application_context: b"sbp.lex.security-core.test-context/2".to_vec(),
                public_key,
            },
        }
    }

    fn sign(&self, payload: Value) -> Value {
        let mut object = payload.as_object().expect("test payload object").clone();
        let bytes = canonical_assurance_bytes(&Value::Object(object.clone())).expect("canonical");
        let signature = self
            .key
            .sign(
                &self.expectation.purpose,
                self.expectation.authority_epoch,
                &self.expectation.application_context,
                &bytes,
            )
            .expect("hybrid signature");
        object.insert("digest".to_owned(), Value::String(sha512_hex(&bytes)));
        object.insert(
            "signature".to_owned(),
            json!({
                "provider_id": self.expectation.provider_id,
                "algorithm": self.expectation.algorithm,
                "suite_version": sbp_lex_v2_hybrid_signature::SUITE_VERSION,
                "verification_rule": sbp_lex_v2_hybrid_signature::VERIFICATION_RULE,
                "security_profile": sbp_lex_v2_hybrid_signature::SECURITY_PROFILE,
                "transition_policy": sbp_lex_v2_hybrid_signature::TRANSITION_POLICY,
                "lane_independence_required": true,
                "ml_dsa_87_key_id": self.expectation.ml_dsa_87_key_id,
                "ed448_key_id": self.expectation.ed448_key_id,
                "ordered_key_set_digest": self.expectation.ordered_key_set_digest,
                "custody_class": self.expectation.custody_class,
                "ml_dsa_87_custody_record_sha512": self.expectation.ml_dsa_87_custody.record_sha512().expect("ML-DSA-87 custody digest"),
                "ed448_custody_record_sha512": self.expectation.ed448_custody.record_sha512().expect("Ed448 custody digest"),
                "dual_custody_admission_sha512": self.expectation.dual_custody_admission_sha512,
                "effect_authority": self.expectation.effect_authority,
                "authority_epoch": self.expectation.authority_epoch,
                "purpose": self.expectation.purpose,
                "context_sha512": sha512_hex(&self.expectation.application_context),
                "ml_dsa_87_signature_b64": STANDARD.encode(signature.ml_dsa_87_bytes()),
                "ed448_signature_b64": STANDARD.encode(signature.ed448_bytes()),
            }),
        );
        object.insert("verified".to_owned(), Value::Bool(false));
        Value::Object(object)
    }
}

fn fingerprint() -> String {
    canonical_digest(&json!({"request": "r-1"})).expect("digest")
}

fn digest_text(character: char) -> String {
    character.to_string().repeat(128)
}

fn evidence() -> Value {
    json!([{"evidence_id":"e-1","source":"fixture","digest":digest_text('a')}])
}

fn chain(stages: &[&str]) -> (Value, String) {
    let mut entries = Vec::new();
    let mut previous = "GENESIS".to_owned();
    for stage in stages {
        let entry = build_entry(&previous, stage, &json!({"stage": stage})).expect("entry");
        previous = entry["hash"].as_str().expect("hash").to_owned();
        entries.push(entry);
    }
    (Value::Array(entries), previous)
}

fn licence_fixture(signer: &TestOnlySoftwareSigner) -> (Value, String, Value) {
    let bindings = json!({
        "identity": {"id":"person"},
        "jurisdiction": {"country":"AU"},
        "authority_state": {"authority":"owner"},
        "execution_rights": {"allowed_actions":["act"]},
        "autonomy_level": 0,
    });
    let stages = [
        "filed_licence:root_binding",
        "filed_licence:validation",
        "filed_licence:revalidation",
    ];
    let mut records = Vec::new();
    for (index, stage) in stages.into_iter().enumerate() {
        let snapshot = json!({"stage":stage,"bindings":bindings,"sequence":index + 1});
        let source = signer.sign(json!({
            "evaluator_id":"licence-evaluator",
            "stage":stage,
            "snapshot_digest":canonical_digest(&snapshot).expect("digest"),
            "determination":{
                "result":"ALLOW",
                "licence_id":"licence-1",
                "tier":"TIER_1_PERSONAL",
                "bindings":bindings,
                "invalidation_status":"VALID",
                "revocation_status":"ACTIVE",
                "revocation_sequence":index,
                "evidence_references":evidence(),
            }
        }));
        records.push(json!({
            "stage":stage,
            "evaluation_sequence":index + 1,
            "result":"ALLOW",
            "reason":"FILED_LICENCE_EVALUATION_COMPLETED",
            "evaluation_snapshot":snapshot,
            "evaluation_snapshot_digest":canonical_digest(&snapshot).expect("digest"),
            "evaluation_source":source,
            "evaluation_source_digest":canonical_digest(&source).expect("digest"),
            "authority_granted":false,
            "execution_authority_granted":false,
        }));
    }
    let trace = Value::Array(records);
    let trace_digest = canonical_digest(&trace).expect("digest");
    (trace, trace_digest, bindings)
}

fn token_fixture(signer: &TestOnlySoftwareSigner) -> (Value, Value, Value, Vec<&'static str>) {
    let request = fingerprint();
    let contracts = [
        ("authority", "root_of_trust", "root_of_trust"),
        ("skg", "skg_authority", "skg_authority"),
        (
            "procedural_truth",
            "procedural_truth_engine",
            "procedural_truth",
        ),
        (
            "consequentiality_threshold",
            "threshold_engine",
            "procedural_truth",
        ),
        (
            "corroboration_threshold",
            "threshold_engine",
            "procedural_truth",
        ),
        (
            "financial_threshold",
            "threshold_engine",
            "procedural_truth",
        ),
        ("ptodf", "PTODF", "filed_framework:ptodf"),
        ("classification", "classification_engine", "classification"),
        ("licensing", "licensing_engine", "licensing"),
        ("aj_saaf", "AJ-SAAF", "filed_framework:aj_saaf"),
        ("gala", "GALA", "filed_framework:gala"),
        ("abegf", "ABEGF", "filed_framework:abegf"),
        (
            "ai_obsolescence_lifecycle_supersession",
            "AI_OBSOLESCENCE_LIFECYCLE_SUPERSESSION",
            "filed_lifecycle:ai_obsolescence_lifecycle_supersession",
        ),
        (
            "civilisational_successor_intelligence_transition",
            "CIVILISATIONAL_SUCCESSOR_INTELLIGENCE_TRANSITION",
            "filed_lifecycle:civilisational_successor_intelligence_transition",
        ),
        (
            "structured_post_ai_era_continuity",
            "STRUCTURED_POST_AI_ERA_CONTINUITY",
            "filed_lifecycle:structured_post_ai_era_continuity",
        ),
        ("governance", "governance_engine", "governance"),
        ("domain", "domain_wrap", "domain_wrap"),
        ("aurion", "aurion15_runtime", "aurion_runtime"),
        ("execution_boundary", "execution_gate", "execution_prep"),
        ("execution_attestation", "execution_gate", "execution_prep"),
    ];
    let stages = contracts.map(|(_, _, stage)| stage);
    let (hash_chain, _) = chain(&stages);
    let mut tokens = Map::new();
    let mut trace = Vec::new();
    for (index, (name, issuer, stage)) in contracts.into_iter().enumerate() {
        let chain_entry = &hash_chain[index];
        let token = signer.sign(json!({
            "name":name,
            "request_fingerprint":request,
            "issued_state_hash":chain_entry["hash"],
            "issued_chain_index":index,
            "issued_chain_stage":chain_entry["stage"],
            "issuer":issuer,
            "issued_at_stage":stage,
            "payload":{"result":"PASS"},
        }));
        trace.push(json!({
            "event":"issued", "token":name, "issuer":issuer, "stage":stage,
            "issued_chain_index":index, "issued_chain_stage":chain_entry["stage"],
            "issued_state_hash":chain_entry["hash"],
        }));
        tokens.insert(name.to_owned(), token);
    }
    (
        Value::Object(tokens),
        Value::Array(trace),
        hash_chain,
        REQUIRED_CORE_TOKENS
            .into_iter()
            .chain(REQUIRED_THRESHOLD_TOKENS)
            .collect(),
    )
}

fn permit_fixture(signer: &TestOnlySoftwareSigner) -> (Value, Value, Value) {
    let request = fingerprint();
    let (hash_chain, state_hash) = chain(&["execution_gate"]);
    let body = json!({
        "schema":"SBP_LEX_LOCAL_EFFECT_PERMIT_V1",
        "permit_id":"0123456789abcdef0123456789abcdef",
        "request_fingerprint":request,
        "issued_state_hash":state_hash,
        "action":"act",
        "payload_digest":digest_text('1'),
        "candidate_digest":digest_text('2'),
        "authority_digest":digest_text('3'),
        "jurisdiction_digest":digest_text('4'),
        "three_p_core_digest":digest_text('5'),
        "three_p_trace_hash":digest_text('6'),
        "skg_authority_digest":digest_text('7'),
        "skg_authority_trace_digest":digest_text('8'),
        "filed_lifecycle_digest":digest_text('9'),
        "filed_licence_digest":digest_text('a'),
        "license_tier":"TIER_1_PERSONAL",
        "licence_id":"licence-1",
        "licence_bindings_digest":digest_text('b'),
        "licence_revocation_status":"ACTIVE",
        "licence_revocation_sequence":3,
        "licence_point_of_use_evidence_digest":digest_text('c'),
        "licence_point_of_use_revocation_sequence":3,
        "filed_framework_digest":digest_text('d'),
        "token_stack_digest":digest_text('e'),
        "adapter_id":digest_text('f'),
        "handler_id":"handler-1",
        "effect_id":digest_text('0'),
        "issued_chain_index":0,
        "issued_chain_stage":"execution_gate",
        "issued_at_ms":100,
        "expires_at_ms":200,
    });
    let expected_fields = [
        "request_fingerprint",
        "issued_state_hash",
        "action",
        "payload_digest",
        "candidate_digest",
        "authority_digest",
        "jurisdiction_digest",
        "three_p_core_digest",
        "three_p_trace_hash",
        "skg_authority_digest",
        "skg_authority_trace_digest",
        "filed_lifecycle_digest",
        "filed_licence_digest",
        "license_tier",
        "licence_id",
        "licence_bindings_digest",
        "licence_revocation_status",
        "licence_revocation_sequence",
        "licence_point_of_use_evidence_digest",
        "licence_point_of_use_revocation_sequence",
        "filed_framework_digest",
        "token_stack_digest",
        "adapter_id",
        "handler_id",
        "effect_id",
    ];
    let expected = Value::Object(
        expected_fields
            .into_iter()
            .map(|field| (field.to_owned(), body[field].clone()))
            .collect(),
    );
    (signer.sign(body), expected, hash_chain)
}

fn three_p_fixture(signer: &TestOnlySoftwareSigner) -> (Value, String) {
    let snapshot = json!({
        "request_fingerprint":fingerprint(),
        "state_hash":digest_text('1'),
        "evaluation_time":1,
        "prior_three_p_digest":Value::Null,
    });
    let snapshot_digest = canonical_digest(&snapshot).expect("snapshot digest");
    let source = signer.sign(json!({
        "evaluator_id":"test-evaluator",
        "evaluator_version":"1",
        "authority_credential":{
            "credential_id":"test-credential",
            "authority_role":"CONSTITUTIONAL_3P_EVALUATOR"
        },
        "stage":"three_p",
        "evaluation_sequence":1,
        "request_fingerprint":fingerprint(),
        "pre_evaluation_state_hash":digest_text('1'),
        "evaluation_time":1,
        "prior_three_p_digest":Value::Null,
        "snapshot_digest":snapshot_digest,
        "determinations":{
            "P1":{"result":"SATISFIED","evidence_references":evidence()},
            "P2":{"result":"SATISFIED","evidence_references":evidence()},
            "P3":{"result":"SATISFIED","evidence_references":evidence()},
        },
    }));
    let primitives = ["P1", "P2", "P3"]
        .into_iter()
        .map(|primitive| {
            let references = evidence();
            json!({
                "primitive":primitive,
                "name":primitive,
                "definition":primitive,
                "result":"PASS",
                "reason":format!("{primitive}_EVALUATOR_PASS"),
                "evidence_digest":canonical_digest(&references).expect("evidence digest"),
                "evidence_references":references,
                "authority_granted":false,
            })
        })
        .collect::<Vec<_>>();
    let record = json!({
        "doctrine":"SBP_LEX_3P_CORE_FINAL_MASTER_SPEC_4_3_26",
        "constitutional_layer":true,
        "evaluation_stage":"three_p",
        "evaluator_id":"test-evaluator",
        "evaluator_version":"1",
        "authority_role":"CONSTITUTIONAL_3P_EVALUATOR",
        "authority_credential_id":"test-credential",
        "evaluation_sequence":1,
        "result":"PASS",
        "reason":"3P_CORE_SATISFIED",
        "authority_granted":false,
        "evaluation_source_digest":canonical_digest(&source).expect("source digest"),
        "evaluation_source":source,
        "evaluation_snapshot":snapshot,
        "evaluation_snapshot_digest":snapshot_digest,
        "primitive_order":["P1","P2","P3"],
        "primitives":primitives,
        "mechanically_constrained_processes":[
            "optimisation","modelling","routing","attestation","licensing",
            "escalation","execution","lifecycle_governance",
            "obsolescence_modelling","supersession"
        ],
    });
    let digest = canonical_digest(&record).expect("three-p digest");
    (record, digest)
}

fn skg_fixture(signer: &TestOnlySoftwareSigner) -> (Value, String) {
    let classes = [
        "Authority hierarchies",
        "Jurisdictional legitimacy",
        "Statutory and constitutional precedence",
        "Procedural obligations",
        "Evidentiary sufficiency",
        "Conflict resolution precedence",
        "Treaty and delegated mandates",
    ];
    let references = classes
        .iter()
        .enumerate()
        .map(|(index, content_class)| {
            json!({
                "content_class":content_class,
                "evidence_id":format!("e-{index}"),
                "source":"fixture",
                "digest":digest_text('a'),
            })
        })
        .collect::<Vec<_>>();
    let class_results = classes
        .iter()
        .map(|content_class| ((*content_class).to_owned(), json!("SATISFIED")))
        .collect::<Map<_, _>>();
    let snapshot = json!({
        "contract_id":"SBP_LEX_SKG_AUTHORITY_V2",
        "schema_status":"IMPLEMENTATION_DEFINED_V2_MECHANICS",
        "content_classes":classes,
        "stage":"skg_authority",
        "evaluation_sequence":1,
        "request_fingerprint":fingerprint(),
        "pre_evaluation_state_hash":"GENESIS",
        "evaluation_time":1,
        "prior_skg_digest":Value::Null,
    });
    let snapshot_digest = canonical_digest(&snapshot).expect("snapshot digest");
    let source = signer.sign(json!({
        "contract_id":"SBP_LEX_SKG_AUTHORITY_V2",
        "schema_status":"IMPLEMENTATION_DEFINED_V2_MECHANICS",
        "evaluator_id":"test-evaluator",
        "evaluator_version":"1",
        "authority_credential":{
            "credential_id":"test-credential",
            "authority_role":"SKG_CONSTITUTIONAL_AUTHORITY_EVALUATOR"
        },
        "stage":"skg_authority",
        "evaluation_sequence":1,
        "request_fingerprint":fingerprint(),
        "pre_evaluation_state_hash":"GENESIS",
        "evaluation_time":1,
        "prior_skg_digest":Value::Null,
        "snapshot_digest":snapshot_digest,
        "determination":{
            "result":"PASS",
            "content_class_results":Value::Object(class_results),
            "evidence_references":references.clone(),
            "authority_granted":false,
            "execution_authority_granted":false,
            "downstream_override_permitted":false,
        },
    }));
    let record = json!({
        "contract_id":"SBP_LEX_SKG_AUTHORITY_V2",
        "schema_status":"IMPLEMENTATION_DEFINED_V2_MECHANICS",
        "content_classes":classes,
        "stage":"skg_authority",
        "evaluation_sequence":1,
        "result":"PASS",
        "reason":"SKG_AUTHORITY_EVALUATION_COMPLETED",
        "evaluation_snapshot":snapshot,
        "evaluation_snapshot_digest":snapshot_digest,
        "evaluation_source_digest":canonical_digest(&source).expect("source digest"),
        "evaluation_source":source,
        "evidence_references":references,
        "authority_granted":false,
        "execution_authority_granted":false,
        "downstream_override_permitted":false,
    });
    let trace = json!([record]);
    let digest = canonical_digest(&trace).expect("skg trace digest");
    (trace, digest)
}

fn filed_framework_fixture(signer: &TestOnlySoftwareSigner) -> (Value, String) {
    let records = FRAMEWORK_ORDER
        .into_iter()
        .enumerate()
        .map(|(index, (framework, stage))| {
            let snapshot = json!({
                "framework":framework,
                "request_fingerprint":fingerprint(),
                "state_hash":digest_text('1'),
                "evaluation_time":1,
                "prior_framework_digest":Value::Null,
            });
            let source = signer.sign(json!({
                "evaluator_id":"test-evaluator",
                "evaluator_version":"1",
                "authority_credential":{
                    "credential_id":"test-credential",
                    "authority_role":"FILED_GOVERNANCE_FRAMEWORK_EVALUATOR"
                },
                "framework":framework,
                "stage":stage,
                "evaluation_sequence":index + 1,
                "request_fingerprint":fingerprint(),
                "pre_evaluation_state_hash":snapshot["state_hash"],
                "evaluation_time":snapshot["evaluation_time"],
                "prior_framework_digest":snapshot["prior_framework_digest"],
                "snapshot_digest":canonical_digest(&snapshot).expect("snapshot digest"),
                "determination":{"result":"PASS","evidence_references":evidence()},
            }));
            json!({
                "framework":framework,
                "stage":stage,
                "evaluation_sequence":index + 1,
                "result":"PASS",
                "reason":"verified",
                "evaluation_snapshot_digest":canonical_digest(&snapshot).expect("snapshot digest"),
                "evaluation_snapshot":snapshot,
                "evaluation_source_digest":canonical_digest(&source).expect("source digest"),
                "evaluation_source":source,
                "evidence_references":evidence(),
                "authority_granted":false,
                "execution_authority_granted":false,
            })
        })
        .collect::<Vec<_>>();
    let trace = Value::Array(records);
    let digest = canonical_digest(&trace).expect("framework trace digest");
    (trace, digest)
}

fn filed_lifecycle_fixture(signer: &TestOnlySoftwareSigner) -> (Value, String) {
    let records = LIFECYCLE_ORDER
        .into_iter()
        .enumerate()
        .map(|(index, (engine, engine_id, stage))| {
            let snapshot = json!({"engine":engine_id});
            let source = signer.sign(json!({"engine":engine_id}));
            json!({
                "schema_status":"IMPLEMENTATION_DEFINED_V2_MECHANICS_NOT_FILED_SCHEMA",
                "lifecycle_engine":engine,
                "lifecycle_engine_id":engine_id,
                "stage":stage,
                "evaluation_sequence":index + 1,
                "implementation_order_authority":"V2_IMPLEMENTATION_DEFINED_ORDER_NOT_FILED_ORDER",
                "result":"PASS",
                "reason":"verified",
                "evaluation_snapshot_digest":canonical_digest(&snapshot).expect("snapshot digest"),
                "evaluation_snapshot":snapshot,
                "evaluation_source_digest":canonical_digest(&source).expect("source digest"),
                "evaluation_source":source,
                "evidence_references":evidence(),
                "authority_granted":false,
                "execution_authority_granted":false,
                "licence_granted":false,
                "governance_superseded":false,
            })
        })
        .collect::<Vec<_>>();
    let trace = Value::Array(records);
    let digest = canonical_digest(&trace).expect("lifecycle trace digest");
    (trace, digest)
}

#[test]
fn deterministic_canonicalization_and_unicode_profile() {
    let left = json!({"z":"e\u{301}", "𐀀":1, "":2});
    let right = json!({"":2, "𐀀":1, "z":"é"});
    assert_eq!(
        canonical_assurance_bytes(&left).expect("canonical"),
        canonical_assurance_bytes(&right).expect("canonical")
    );
    assert_eq!(
        canonical_integrity_bytes(&json!({"n":1.25})).expect("integrity"),
        br#"{"n":{"exact_decimal":"1.25"}}"#
    );
    assert_eq!(
        canonical_assurance_bytes(&json!({"n":1.25})),
        Err(BoundaryError::Malformed("floating_point_forbidden"))
    );
}

#[test]
fn digest_stability() {
    assert_eq!(
        canonical_digest(&json!({"b":2,"a":1})),
        canonical_digest(&json!({"a":1,"b":2}))
    );
}

#[test]
fn sha512_digest_contract_rejects_legacy_sha256_width() {
    assert_eq!(
        sha512_hex(b"abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a".to_owned()
            + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    );
    assert!(is_sha512(&sha512_hex(b"abc")));
    assert!(!is_sha512(&"a".repeat(64)));
    assert!(!is_sha512(&"A".repeat(128)));
}

#[test]
fn every_signed_payload_field_mutation_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let signed = signer.sign(json!({"alpha":"a","beta":2,"gamma":true}));
    assert!(verify_signed_object(&signed, Some(&signer.expectation), false).is_ok());
    for field in ["alpha", "beta", "gamma"] {
        let mut mutated = signed.clone();
        mutated[field] = Value::Null;
        assert!(
            verify_signed_object(&mutated, Some(&signer.expectation), false).is_err(),
            "{field}"
        );
    }
    for field in [
        "provider_id",
        "algorithm",
        "suite_version",
        "verification_rule",
        "security_profile",
        "transition_policy",
        "lane_independence_required",
        "ml_dsa_87_key_id",
        "ed448_key_id",
        "ordered_key_set_digest",
        "custody_class",
        "ml_dsa_87_custody_record_sha512",
        "ed448_custody_record_sha512",
        "dual_custody_admission_sha512",
        "effect_authority",
        "authority_epoch",
        "purpose",
        "context_sha512",
        "ml_dsa_87_signature_b64",
        "ed448_signature_b64",
    ] {
        let mut mutated = signed.clone();
        mutated["signature"][field] = Value::Null;
        assert!(
            verify_signed_object(&mutated, Some(&signer.expectation), false).is_err(),
            "signature.{field}"
        );
    }
    for field in ["digest", "signature", "verified"] {
        let mut mutated = signed.clone();
        mutated[field] = Value::Null;
        assert!(
            verify_signed_object(&mutated, Some(&signer.expectation), false).is_err(),
            "{field}"
        );
    }
    let mut added = signed;
    added["added"] = json!(true);
    assert!(verify_signed_object(&added, Some(&signer.expectation), false).is_err());
}

#[test]
fn unproven_effect_authority_signer_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(true);
    let mut expectation = signer.expectation.clone();
    expectation.provider_id = "PRODUCTION-DUAL-CUSTODY-VERIFIER".to_owned();
    expectation.custody_class = PRODUCTION_DUAL_CUSTODY_CLASS.to_owned();
    expectation.dual_custody_admission_sha512 = digest_text('a');
    expectation.ml_dsa_87_custody.custody_class = "EXTERNAL_NON_EXPORTABLE".to_owned();
    expectation.ml_dsa_87_custody.external_custody_admitted = true;
    expectation.ml_dsa_87_custody.custody_admission_sha512 = digest_text('b');
    expectation.ml_dsa_87_custody.non_exportable = true;
    expectation.ed448_custody.custody_class = "EXTERNAL_NON_EXPORTABLE".to_owned();
    expectation.ed448_custody.external_custody_admitted = true;
    expectation.ed448_custody.custody_admission_sha512 = digest_text('c');
    expectation.ed448_custody.non_exportable = true;
    assert_eq!(
        verify_signed_object(&signer.sign(json!({"a":1})), Some(&expectation), true),
        Err(BoundaryError::Unsupported(
            Gap::HybridHardwareCustodyAndPinningUnavailable
        ))
    );
}

#[test]
fn shared_or_revoked_lane_custody_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let signed = signer.sign(json!({"a":1}));

    let mut shared_provider = signer.expectation.clone();
    shared_provider.ed448_custody.provider_id =
        shared_provider.ml_dsa_87_custody.provider_id.clone();
    assert_eq!(
        verify_signed_object(&signed, Some(&shared_provider), false),
        Err(BoundaryError::SignerMismatch)
    );

    let mut shared_reference = signer.expectation.clone();
    shared_reference.ed448_custody.custody_reference =
        shared_reference.ml_dsa_87_custody.custody_reference.clone();
    assert_eq!(
        verify_signed_object(&signed, Some(&shared_reference), false),
        Err(BoundaryError::SignerMismatch)
    );

    let mut revoked = signer.expectation.clone();
    revoked.ml_dsa_87_custody.lifecycle_status = "REVOKED".to_owned();
    revoked.ml_dsa_87_custody.revoked_at_epoch = Some(7);
    assert_eq!(
        verify_signed_object(&signed, Some(&revoked), false),
        Err(BoundaryError::SignerMismatch)
    );

    let mut invalid_rotation = signer.expectation.clone();
    invalid_rotation.ed448_custody.rotation_epoch = 0;
    assert_eq!(
        verify_signed_object(&signed, Some(&invalid_rotation), false),
        Err(BoundaryError::SignerMismatch)
    );

    let mut empty_context = signer.expectation.clone();
    empty_context.application_context.clear();
    assert_eq!(
        verify_signed_object(&signed, Some(&empty_context), false),
        Err(BoundaryError::SignerMismatch)
    );
}

#[test]
fn wrong_signer_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let wrong = SoftwareHybridSigningKey::from_seed_slices(&[0x33; 32], &[0xcc; 57]).unwrap();
    let public_key = wrong.public_key();
    let ml_dsa_87_key_id = sha512_hex(public_key.ml_dsa_87_bytes());
    let ed448_key_id = sha512_hex(public_key.ed448_bytes());
    let expectation = SignerExpectation {
        provider_id: "wrong".to_owned(),
        algorithm: SUITE_ID.to_owned(),
        ml_dsa_87_key_id: ml_dsa_87_key_id.clone(),
        ed448_key_id: ed448_key_id.clone(),
        ordered_key_set_digest: public_key_id(&public_key),
        custody_class: "wrong".to_owned(),
        dual_custody_admission_sha512: "wrong".to_owned(),
        ml_dsa_87_custody: LaneCustodyExpectation {
            algorithm: "ML-DSA-87".to_owned(),
            provider_id: "wrong-ml".to_owned(),
            key_id: ml_dsa_87_key_id,
            key_epoch: 7,
            rotation_epoch: 7,
            custody_class: "wrong".to_owned(),
            custody_reference: "wrong-ml-custody".to_owned(),
            lifecycle_status: "ACTIVE".to_owned(),
            revoked_at_epoch: None,
            external_custody_admitted: false,
            custody_admission_sha512: "NONE".to_owned(),
            non_exportable: false,
        },
        ed448_custody: LaneCustodyExpectation {
            algorithm: "Ed448".to_owned(),
            provider_id: "wrong-ed".to_owned(),
            key_id: ed448_key_id,
            key_epoch: 7,
            rotation_epoch: 7,
            custody_class: "wrong".to_owned(),
            custody_reference: "wrong-ed-custody".to_owned(),
            lifecycle_status: "ACTIVE".to_owned(),
            revoked_at_epoch: None,
            external_custody_admitted: false,
            custody_admission_sha512: "NONE".to_owned(),
            non_exportable: false,
        },
        effect_authority: false,
        authority_epoch: 7,
        purpose: "SECURITY_CORE_OBJECT".to_owned(),
        application_context: b"sbp.lex.security-core.test-context/2".to_vec(),
        public_key,
    };
    assert!(verify_signed_object(&signer.sign(json!({"a":1})), Some(&expectation), false).is_err());
}

#[test]
fn missing_signer_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    assert_eq!(
        verify_signed_object(&signer.sign(json!({"a":1})), None, false),
        Err(BoundaryError::SignerMissing)
    );
}

#[test]
fn malformed_signature_envelope_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let mut signed = signer.sign(json!({"a":1}));
    signed["signature"] = json!({"ml_dsa_87_signature_b64":"%%%"});
    assert!(verify_signed_object(&signed, Some(&signer.expectation), false).is_err());
}

#[test]
fn token_omission_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (mut tokens, trace, chain, order) = token_fixture(&signer);
    tokens.as_object_mut().expect("tokens").remove("skg");
    assert!(verify_token_stack(
        &tokens,
        &trace,
        &order,
        &chain,
        &fingerprint(),
        Some(&signer.expectation),
        false
    )
    .is_err());
}

#[test]
fn empty_required_token_vocabulary_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    assert!(verify_token_stack(
        &json!({}),
        &json!([]),
        &[],
        &json!([]),
        &fingerprint(),
        Some(&signer.expectation),
        false
    )
    .is_err());
}

#[test]
fn token_duplication_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (mut tokens, mut trace, chain, _) = token_fixture(&signer);
    tokens
        .as_object_mut()
        .expect("tokens")
        .insert("extra".to_owned(), json!({}));
    trace.as_array_mut().expect("trace")[1]["token"] = json!("authority");
    assert!(verify_token_stack(
        &tokens,
        &trace,
        &["authority", "authority"],
        &chain,
        &fingerprint(),
        Some(&signer.expectation),
        false
    )
    .is_err());
}

#[test]
fn token_substitution_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (mut tokens, trace, chain, order) = token_fixture(&signer);
    tokens["skg"]["issuer"] = json!("root_of_trust");
    assert!(verify_token_stack(
        &tokens,
        &trace,
        &order,
        &chain,
        &fingerprint(),
        Some(&signer.expectation),
        false
    )
    .is_err());
}

#[test]
fn token_reordering_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (tokens, mut trace, chain, order) = token_fixture(&signer);
    trace.as_array_mut().expect("trace").swap(0, 1);
    assert!(verify_token_stack(
        &tokens,
        &trace,
        &order,
        &chain,
        &fingerprint(),
        Some(&signer.expectation),
        false
    )
    .is_err());
}

#[test]
fn hash_chain_mutation_is_rejected() {
    let (mut value, state_hash) = chain(&["a", "b"]);
    value[0]["stage"] = json!("changed");
    assert!(verify_hash_chain(&value, &state_hash, &fingerprint()).is_err());
}

#[test]
fn validly_rehashed_unauthorised_suffix_is_rejected() {
    let (mut value, state_hash) = chain(&["a", "b"]);
    let suffix = build_entry(&state_hash, "unauthorised", &json!({"x":1})).expect("suffix");
    let suffix_hash = suffix["hash"].as_str().expect("hash").to_owned();
    value.as_array_mut().expect("chain").push(suffix);
    assert!(verify_exact_hash_chain(&value, &suffix_hash, &["a", "b"], &fingerprint()).is_err());
}

#[test]
fn licence_field_mismatch_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (trace, digest, mut bindings) = licence_fixture(&signer);
    bindings["identity"] = json!({"id":"substituted"});
    assert!(verify_licence(
        &trace,
        &digest,
        &bindings,
        "act",
        &fingerprint(),
        Some(&signer.expectation)
    )
    .is_err());
}

#[test]
fn licence_revocation_before_validation_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (mut trace, _, bindings) = licence_fixture(&signer);
    trace[1]["evaluation_source"]["determination"]["revocation_status"] = json!("REVOKED");
    let digest = canonical_digest(&trace).expect("digest");
    assert!(verify_licence(
        &trace,
        &digest,
        &bindings,
        "act",
        &fingerprint(),
        Some(&signer.expectation)
    )
    .is_err());
}

#[test]
fn licence_revocation_after_token_issuance_is_rejected() {
    let prior = RevocationState {
        status: "ACTIVE".to_owned(),
        sequence: 2,
    };
    let current = RevocationState {
        status: "REVOKED".to_owned(),
        sequence: 3,
    };
    assert_eq!(
        verify_monotonic_revocation(&prior, &current, &fingerprint()),
        Err(BoundaryError::Revoked)
    );
}

#[test]
fn revocation_immediately_before_effect_blocks_revalidation() {
    let proofs = all_pre_effect_proofs()
        .into_iter()
        .filter(|proof| proof.component() != Component::Revocation)
        .collect::<Vec<_>>();
    assert!(immediate_pre_effect_revalidation(&proofs, &fingerprint()).is_err());
}

#[test]
fn replay_is_rejected() {
    let mut store = TestReplayStore::default();
    assert!(claim_replay_slot(Some(&mut store), "permit", "p1", &fingerprint()).is_ok());
    assert_eq!(
        claim_replay_slot(Some(&mut store), "permit", "p1", &fingerprint()),
        Err(BoundaryError::Replay)
    );
}

#[test]
fn monotonic_sequence_rollback_is_rejected() {
    let prior = RevocationState {
        status: "ACTIVE".to_owned(),
        sequence: 4,
    };
    let current = RevocationState {
        status: "ACTIVE".to_owned(),
        sequence: 3,
    };
    assert_eq!(
        verify_monotonic_revocation(&prior, &current, &fingerprint()),
        Err(BoundaryError::Rollback)
    );
}

#[test]
fn missing_three_p_evidence_is_rejected() {
    assert!(
        verify_three_p_evidence(&Value::Null, &digest_text('a'), &fingerprint(), None).is_err()
    );
}

#[test]
fn missing_or_invalid_skg_evidence_is_rejected() {
    assert!(verify_skg_evidence(&json!([]), &digest_text('a'), &fingerprint(), None).is_err());
}

#[test]
fn filed_framework_failure_is_rejected() {
    assert!(verify_filed_frameworks(&json!([]), &digest_text('a'), &fingerprint(), None).is_err());
}

#[test]
fn filed_lifecycle_failure_is_rejected() {
    assert!(verify_filed_lifecycle(&json!([]), &digest_text('a'), &fingerprint(), None).is_err());
}

#[test]
fn audit_mutation_is_rejected() {
    let request = fingerprint();
    let (hash_chain, state_hash) = chain(&["audit"]);
    let mut live = json!({
        "request_fingerprint":request,"decision":"DENY","execution_result":"HALT","execution_reason":"denied",
        "governance_result":"DENY","governance_reason":"denied","governance_feedback":{},
        "three_p_core_digest":digest_text('1'),"three_p_trace_hash":digest_text('2'),
        "skg_authority_digest":digest_text('3'),"filed_framework_digest":digest_text('4'),
        "filed_lifecycle_digest":digest_text('5'),"filed_licence_digest":digest_text('6'),
        "licence_id":"l1","license_tier":"TIER_1_PERSONAL","licence_revocation_status":"ACTIVE",
        "licence_revocation_sequence":1,"effect_id":Value::Null,"effect_result":Value::Null,
        "hash_chain":hash_chain,"state_hash":state_hash,
    });
    let mut record = live.clone();
    let hash = canonical_digest(&record).expect("audit hash");
    let ledger_unsigned = json!({"previous_ledger_hash":"GENESIS","audit_hash":hash});
    let ledger = json!([{
        "previous_ledger_hash":"GENESIS","audit_hash":hash,
        "ledger_hash":canonical_digest(&ledger_unsigned).expect("ledger hash")
    }]);
    assert!(verify_terminal_audit(&record, &hash, &ledger, &live, &request).is_ok());
    let mut changed_live_hash = live.clone();
    changed_live_hash["state_hash"] = json!(digest_text('f'));
    assert!(verify_terminal_audit(&record, &hash, &ledger, &changed_live_hash, &request).is_err());
    let mut appended_live = live.clone();
    let suffix = build_entry(
        appended_live["state_hash"].as_str().expect("state hash"),
        "unauthorised_suffix",
        &json!({"mutation":true}),
    )
    .expect("suffix");
    appended_live["state_hash"] = suffix["hash"].clone();
    appended_live["hash_chain"]
        .as_array_mut()
        .expect("live hash chain")
        .push(suffix);
    assert!(verify_terminal_audit(&record, &hash, &ledger, &appended_live, &request).is_err());
    record["decision"] = json!("ALLOW");
    assert!(verify_terminal_audit(&record, &hash, &ledger, &live, &request).is_err());
    live["decision"] = json!("ALLOW");
}

#[test]
fn permit_mutation_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(true);
    let (permit, expected, chain) = permit_fixture(&signer);
    assert!(verify_effect_permit(
        &permit,
        &expected,
        &chain,
        150,
        100,
        &fingerprint(),
        Some(&signer.expectation)
    )
    .is_ok());
    assert!(verify_effect_permit(
        &permit,
        &json!({}),
        &chain,
        150,
        100,
        &fingerprint(),
        Some(&signer.expectation)
    )
    .is_err());
    let mut mutated = permit;
    mutated["effect_id"] = json!(digest_text('1'));
    assert!(verify_effect_permit(
        &mutated,
        &expected,
        &chain,
        150,
        100,
        &fingerprint(),
        Some(&signer.expectation)
    )
    .is_err());
}

#[test]
fn valid_paths_cover_each_structured_boundary_verifier() {
    let signer = TestOnlySoftwareSigner::new(false);
    let request = fingerprint();

    let (three_p, three_p_digest) = three_p_fixture(&signer);
    assert!(verify_three_p_evidence(
        &three_p,
        &three_p_digest,
        &request,
        Some(&signer.expectation)
    )
    .is_ok());

    let (skg, skg_digest) = skg_fixture(&signer);
    assert!(verify_skg_evidence(&skg, &skg_digest, &request, Some(&signer.expectation)).is_ok());

    let authority_state = json!({"authority":"bound"});
    assert!(verify_authority_binding(
        &authority_state,
        &canonical_digest(&authority_state).expect("authority digest"),
        &request,
        &request,
        "ALLOW"
    )
    .is_ok());
    assert!(verify_authority_binding(
        &authority_state,
        &canonical_digest(&authority_state).expect("authority digest"),
        &request,
        &request,
        "UNKNOWN"
    )
    .is_err());

    let (framework, framework_digest) = filed_framework_fixture(&signer);
    assert!(verify_filed_frameworks(
        &framework,
        &framework_digest,
        &request,
        Some(&signer.expectation)
    )
    .is_ok());

    let (lifecycle, lifecycle_digest) = filed_lifecycle_fixture(&signer);
    assert!(verify_filed_lifecycle(
        &lifecycle,
        &lifecycle_digest,
        &request,
        Some(&signer.expectation)
    )
    .is_ok());

    let (licence, licence_digest, bindings) = licence_fixture(&signer);
    assert!(verify_licence(
        &licence,
        &licence_digest,
        &bindings,
        "act",
        &request,
        Some(&signer.expectation)
    )
    .is_ok());

    let (tokens, trace, token_chain, required) = token_fixture(&signer);
    assert!(verify_token_stack(
        &tokens,
        &trace,
        &required,
        &token_chain,
        &request,
        Some(&signer.expectation),
        false
    )
    .is_ok());

    let (hash_chain, state_hash) = chain(&["one", "two"]);
    assert!(verify_hash_chain(&hash_chain, &state_hash, &request).is_ok());

    let active = RevocationState {
        status: "ACTIVE".to_owned(),
        sequence: 1,
    };
    assert!(verify_monotonic_revocation(&active, &active, &request).is_ok());
    let unknown = RevocationState {
        status: "UNKNOWN".to_owned(),
        sequence: 1,
    };
    assert_eq!(
        verify_monotonic_revocation(&active, &unknown, &request),
        Err(BoundaryError::UnknownValue("revocation_status"))
    );
}

#[test]
fn skg_snapshot_mutation_with_rehashed_trace_is_rejected() {
    let signer = TestOnlySoftwareSigner::new(false);
    let (mut trace, _) = skg_fixture(&signer);
    trace[0]["evaluation_snapshot"]["changed"] = json!(true);
    let digest = canonical_digest(&trace).expect("mutated trace digest");
    assert!(
        verify_skg_evidence(&trace, &digest, &fingerprint(), Some(&signer.expectation)).is_err()
    );
}

#[test]
fn tpm_unavailable_or_unsupported_fails_closed_without_fallback() {
    assert!(matches!(
        probe_platform_crypto_provider(),
        TpmProviderStatus::Unavailable
            | TpmProviderStatus::ProviderFailure(_)
            | TpmProviderStatus::UnsupportedPlatform
            | TpmProviderStatus::AvailableButHybridSuiteUnsupported
    ));
    assert_eq!(
        create_nonexportable_signing_key("key"),
        Err(BoundaryError::Unsupported(
            Gap::HybridHardwareCustodyAndPinningUnavailable
        ))
    );
    assert_eq!(
        sign_with_tpm("key", b"message"),
        Err(BoundaryError::Unsupported(
            Gap::HybridHardwareCustodyAndPinningUnavailable
        ))
    );
    assert_eq!(
        verify_with_tpm_public_key(&[], b"message", &[]),
        Err(BoundaryError::Unsupported(
            Gap::HybridHardwareCustodyAndPinningUnavailable
        ))
    );
}

#[test]
fn no_individual_token_or_component_can_grant_dispatch() {
    let token_only = Proof::new(Component::TokenStack, &fingerprint()).expect("proof");
    assert!(immediate_pre_effect_revalidation(&[token_only], &fingerprint()).is_err());
    let mut handler = CountingHandler::default();
    assert!(matches!(
        dispatch_existing_authorization(None, None, &fingerprint(), &mut handler),
        ClosedDecision::Deny(_)
    ));
    assert_eq!(handler.calls, 0);
}

#[test]
fn effect_handler_is_never_reached_after_any_failed_prerequisite() {
    let all = all_pre_effect_proofs();
    for omitted in all.iter().map(Proof::component) {
        let remaining = all
            .iter()
            .filter(|proof| proof.component() != omitted)
            .cloned()
            .collect::<Vec<_>>();
        let pre_effect = immediate_pre_effect_revalidation(&remaining, &fingerprint()).ok();
        let mut handler = CountingHandler::default();
        let replay = Proof::new(Component::Replay, &fingerprint()).expect("replay");
        assert!(matches!(
            dispatch_existing_authorization(
                pre_effect.as_ref(),
                Some(&replay),
                &fingerprint(),
                &mut handler
            ),
            ClosedDecision::Deny(_)
        ));
        assert_eq!(handler.calls, 0, "omitted {omitted:?}");
    }
}

#[test]
fn fully_proven_existing_authorization_reaches_handler_once() {
    let pre_effect = immediate_pre_effect_revalidation(&all_pre_effect_proofs(), &fingerprint())
        .expect("pre-effect");
    let replay = Proof::new(Component::Replay, &fingerprint()).expect("replay");
    let mut handler = CountingHandler::default();
    assert_eq!(
        dispatch_existing_authorization(
            Some(&pre_effect),
            Some(&replay),
            &fingerprint(),
            &mut handler
        ),
        ClosedDecision::PermitExistingAuthorization
    );
    assert_eq!(handler.calls, 1);
}

#[test]
fn request_fingerprint_mutation_is_rejected() {
    let request = json!({"request":"r-1"});
    let digest = canonical_digest(&request).expect("digest");
    assert!(verify_request_fingerprint(&request, &digest).is_ok());
    assert!(verify_request_fingerprint(&json!({"request":"r-2"}), &digest).is_err());
}

fn all_pre_effect_proofs() -> Vec<Proof> {
    [
        Component::Request,
        Component::ThreeP,
        Component::Skg,
        Component::Authority,
        Component::FiledFramework,
        Component::FiledLifecycle,
        Component::Licence,
        Component::TokenStack,
        Component::HashChain,
        Component::EffectPermit,
        Component::Revocation,
    ]
    .into_iter()
    .map(|component| Proof::new(component, &fingerprint()).expect("proof"))
    .collect()
}

#[derive(Default)]
struct TestReplayStore {
    claimed: HashSet<(String, String)>,
}

impl DurableReplayStore for TestReplayStore {
    fn claim_once(
        &mut self,
        namespace: &str,
        identifier: &str,
    ) -> Result<ClaimResult, BoundaryError> {
        if self
            .claimed
            .insert((namespace.to_owned(), identifier.to_owned()))
        {
            Ok(ClaimResult::Claimed)
        } else {
            Ok(ClaimResult::AlreadyClaimed)
        }
    }
}

#[derive(Default)]
struct CountingHandler {
    calls: usize,
}

impl EffectHandler for CountingHandler {
    fn dispatch(&mut self) -> Result<(), BoundaryError> {
        self.calls += 1;
        Ok(())
    }
}
