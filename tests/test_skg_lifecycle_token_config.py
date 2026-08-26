from __future__ import annotations

from copy import deepcopy

from sbp_lex.config.pipeline_config import (
    EXECUTION_GATE_REQUIRED_CHECKS,
    GOVERNANCE_TRAVERSAL_ORDER,
    HASH_CHAIN_REQUIRED_STAGES,
    PIPELINE_ORDER,
    build_pipeline_order,
)
from sbp_lex.governance.filed_lifecycle import (
    FILED_LIFECYCLE_AUTHORITY_ROLE,
    FILED_LIFECYCLE_ENGINE_IDS,
    FILED_LIFECYCLE_ORDER,
    FILED_LIFECYCLE_ORDER_AUTHORITY,
    FILED_LIFECYCLE_SCHEMA_STATUS,
    FILED_LIFECYCLE_STAGES,
    LIFECYCLE_PASS,
)
from sbp_lex.governance.filed_governance_integrity import (
    FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS,
    FILED_GOVERNANCE_INTEGRITY_ORDER,
    FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY,
    FILED_GOVERNANCE_INTEGRITY_STAGES,
    GOVERNANCE_INTEGRITY_PASS,
    evaluate_filed_governance_integrity,
    filed_governance_integrity_hash_payload,
    governance_integrity_revocation_binding,
)
from sbp_lex.governance.skg_authority import (
    SKG_AUTHORITY_ROLE,
    SKG_CONTENT_CLASSES,
    SKG_PASS,
    SKG_SATISFIED,
    SKG_SCHEMA_STATUS,
    SKG_V2_CONTRACT_ID,
    skg_authority_hash_payload,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.token_stack import (
    REQUIRED_CORE_TOKENS,
    _TOKEN_ISSUANCE_CONTRACTS,
    _expected_governance_integrity_token_payload,
    _expected_governance_token_payload,
    _expected_lifecycle_token_payload,
    _expected_skg_token_payload,
)
from tests.test_filed_governance_integrity import (
    GovernanceIntegrityEvaluator,
    GovernanceIntegrityProvider,
)


REQUEST_FINGERPRINT = canonical_integrity_hash({"request": "token-test"})
EVIDENCE_DIGEST = canonical_integrity_hash({"evidence": "exact"})
THREE_P_DIGEST = canonical_integrity_hash({"three_p": "record"})
THREE_P_TRACE_HASH = canonical_integrity_hash({"three_p": "trace"})


def _signature_envelope() -> dict:
    return {
        "provider_id": "ed25519-software:token-test",
        "algorithm": "Ed25519",
        "key_id": "token-test-key",
        "custody_class": "PROCESS_MEMORY_SOFTWARE_KEY",
        "effect_authority": False,
        "signature_b64": "AA==",
    }


def _complete_signed_source(source: dict) -> dict:
    source["digest"] = canonical_integrity_hash(source)
    source["signature"] = _signature_envelope()
    source["verified"] = False
    return source


def _skg_state() -> dict:
    pre_entry = build_hash_chain_entry(
        previous_hash=GENESIS_HASH,
        stage="three_p_core:skg_authority:constitutional_authority_substrate",
        payload={"three_p": "pre"},
    )
    snapshot = {
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "content_classes": list(SKG_CONTENT_CLASSES),
        "stage": "constitutional_authority_substrate",
        "evaluation_sequence": 1,
        "request_fingerprint": REQUEST_FINGERPRINT,
        "pre_evaluation_state_hash": pre_entry["hash"],
        "evaluation_time": 17,
        "prior_skg_digest": None,
    }
    evidence = [
        {
            "content_class": content_class,
            "evidence_id": f"skg-evidence-{index}",
            "source": "filed-authority-evidence",
            "digest": EVIDENCE_DIGEST,
        }
        for index, content_class in enumerate(SKG_CONTENT_CLASSES, start=1)
    ]
    determination = {
        "result": SKG_PASS,
        "content_class_results": {
            content_class: SKG_SATISFIED
            for content_class in SKG_CONTENT_CLASSES
        },
        "evidence_references": evidence,
        "authority_granted": False,
        "execution_authority_granted": False,
        "downstream_override_permitted": False,
    }
    source = _complete_signed_source({
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "evaluator_id": "test-skg-evaluator",
        "evaluator_version": "1",
        "authority_credential": {
            "credential_id": "test-skg-credential",
            "authority_role": SKG_AUTHORITY_ROLE,
        },
        "stage": snapshot["stage"],
        "evaluation_sequence": 1,
        "request_fingerprint": REQUEST_FINGERPRINT,
        "pre_evaluation_state_hash": pre_entry["hash"],
        "evaluation_time": 17,
        "prior_skg_digest": None,
        "snapshot_digest": canonical_integrity_hash(snapshot),
        "determination": determination,
    })
    record = {
        "contract_id": SKG_V2_CONTRACT_ID,
        "schema_status": SKG_SCHEMA_STATUS,
        "content_classes": list(SKG_CONTENT_CLASSES),
        "stage": snapshot["stage"],
        "evaluation_sequence": 1,
        "result": SKG_PASS,
        "reason": "SKG_AUTHORITY_EVALUATION_COMPLETED",
        "evaluation_snapshot": snapshot,
        "evaluation_snapshot_digest": canonical_integrity_hash(snapshot),
        "evaluation_source": source,
        "evaluation_source_digest": canonical_integrity_hash(source),
        "evidence_references": evidence,
        "authority_granted": False,
        "execution_authority_granted": False,
        "downstream_override_permitted": False,
    }
    state = {
        "request_fingerprint": REQUEST_FINGERPRINT,
        "evaluation_time": 17,
        "skg_authority_trace": [record],
        "skg_authority_record": record,
        "skg_authority_digest": canonical_integrity_hash(record),
        "skg_authority_trace_digest": canonical_integrity_hash([record]),
        "skg_authority_result": SKG_PASS,
        "skg_authority_reason": "SKG_AUTHORITY_EVALUATION_COMPLETED",
        "skg_authority_granted": False,
        "skg_execution_authority_granted": False,
        "skg_downstream_override_permitted": False,
    }
    entry = build_hash_chain_entry(
        previous_hash=pre_entry["hash"],
        stage="skg_authority:constitutional_authority_substrate",
        payload=skg_authority_hash_payload(state),
    )
    post_entry = build_hash_chain_entry(
        previous_hash=entry["hash"],
        stage=(
            "three_p_core:skg_authority:"
            "constitutional_authority_substrate:post"
        ),
        payload={"three_p": "post"},
    )
    state["hash_chain"] = [pre_entry, entry, post_entry]
    state["state_hash"] = post_entry["hash"]
    return state


def _lifecycle_state() -> tuple[dict, dict[str, int]]:
    state = _skg_state()
    state.update(
        {
            "governance_result": "ALLOW",
            "governance_reason": "governance_allow",
            "filed_framework_results": {
                "AJ-SAAF": "PASS",
                "GALA": "PASS",
                "ABEGF": "PASS",
            },
            "filed_framework_digest": canonical_integrity_hash(
                {"frameworks": "complete"}
            ),
            "filed_lifecycle_trace": [],
            "filed_lifecycle_results": {},
            "filed_lifecycle_digest": None,
        }
    )
    issued_indexes: dict[str, int] = {}
    for sequence, engine in enumerate(FILED_LIFECYCLE_ORDER, start=1):
        engine_id = FILED_LIFECYCLE_ENGINE_IDS[engine]
        stage = FILED_LIFECYCLE_STAGES[engine]
        pre_entry = build_hash_chain_entry(
            previous_hash=state["hash_chain"][-1]["hash"],
            stage=f"three_p_core:{stage}",
            payload={"three_p": "pre", "sequence": sequence},
        )
        state["hash_chain"].append(pre_entry)
        prior_digest = (
            canonical_integrity_hash(state["filed_lifecycle_trace"])
            if state["filed_lifecycle_trace"]
            else None
        )
        three_p_trace = [
            {
                "three_p_core_digest": THREE_P_DIGEST,
                "trace_hash": THREE_P_TRACE_HASH,
            }
        ]
        snapshot = {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "lifecycle_engine": engine,
            "lifecycle_engine_id": engine_id,
            "stage": stage,
            "evaluation_sequence": sequence,
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "implementation_order": list(FILED_LIFECYCLE_ORDER),
            "request_fingerprint": REQUEST_FINGERPRINT,
            "state_hash": pre_entry["hash"],
            "evaluation_time": 17,
            "prior_lifecycle_digest": prior_digest,
            "three_p_core_result": "PASS",
            "three_p_core_digest": THREE_P_DIGEST,
            "three_p_trace_hash": THREE_P_TRACE_HASH,
            "three_p_trace": three_p_trace,
            "skg_result": SKG_PASS,
            "skg_digest": state["skg_authority_digest"],
            "skg_record": deepcopy(state["skg_authority_record"]),
            "governance_result": "ALLOW",
        }
        evidence = [
            {
                "evidence_id": f"lifecycle-evidence-{sequence}",
                "source": "filed-lifecycle-evidence",
                "digest": EVIDENCE_DIGEST,
            }
        ]
        determination = {
            "result": LIFECYCLE_PASS,
            "transition_beyond_current_ai_paradigms_modelled": True,
            "full_lifecycle_governance_envelope_secured": True,
            "lawful_authority_continuity_preserved": True,
            "violent_or_coercive_interaction_prohibited": True,
            "bound_to_three_p": True,
            "bound_to_skg": True,
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
            "evidence_references": evidence,
        }
        source = _complete_signed_source({
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "evaluator_id": "test-lifecycle-evaluator",
            "evaluator_version": "1",
            "authority_credential": {
                "credential_id": "test-lifecycle-credential",
                "authority_role": FILED_LIFECYCLE_AUTHORITY_ROLE,
            },
            "lifecycle_engine": engine,
            "lifecycle_engine_id": engine_id,
            "stage": stage,
            "evaluation_sequence": sequence,
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "request_fingerprint": REQUEST_FINGERPRINT,
            "pre_evaluation_state_hash": pre_entry["hash"],
            "evaluation_time": 17,
            "prior_lifecycle_digest": prior_digest,
            "three_p_core_digest": THREE_P_DIGEST,
            "three_p_trace_hash": THREE_P_TRACE_HASH,
            "skg_digest": state["skg_authority_digest"],
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determination": determination,
        })
        reason = f"{engine_id}_EVALUATION_COMPLETED"
        record = {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "lifecycle_engine": engine,
            "lifecycle_engine_id": engine_id,
            "stage": stage,
            "evaluation_sequence": sequence,
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "result": LIFECYCLE_PASS,
            "reason": reason,
            "evaluation_snapshot": snapshot,
            "evaluation_snapshot_digest": canonical_integrity_hash(snapshot),
            "evaluation_source": source,
            "evaluation_source_digest": canonical_integrity_hash(source),
            "evidence_references": evidence,
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
        }
        state["filed_lifecycle_trace"].append(record)
        state["filed_lifecycle_results"][engine] = LIFECYCLE_PASS
        state["filed_lifecycle_digest"] = canonical_integrity_hash(
            state["filed_lifecycle_trace"]
        )
        payload = {
            "schema_status": FILED_LIFECYCLE_SCHEMA_STATUS,
            "lifecycle_engine": engine,
            "lifecycle_engine_id": engine_id,
            "stage": stage,
            "evaluation_sequence": sequence,
            "implementation_order_authority": FILED_LIFECYCLE_ORDER_AUTHORITY,
            "result": LIFECYCLE_PASS,
            "reason": reason,
            "record_digest": canonical_integrity_hash(record),
            "trace_digest": state["filed_lifecycle_digest"],
            "authority_granted": False,
            "execution_authority_granted": False,
            "licence_granted": False,
            "governance_superseded": False,
        }
        lifecycle_entry = build_hash_chain_entry(
            previous_hash=pre_entry["hash"],
            stage=stage,
            payload=payload,
        )
        state["hash_chain"].append(lifecycle_entry)
        post_entry = build_hash_chain_entry(
            previous_hash=lifecycle_entry["hash"],
            stage=f"three_p_core:{stage}:post",
            payload={"three_p": "post", "sequence": sequence},
        )
        state["hash_chain"].append(post_entry)
        token_name = engine_id.lower()
        issued_indexes[token_name] = len(state["hash_chain"]) - 1
    state["state_hash"] = state["hash_chain"][-1]["hash"]
    state["filed_lifecycle_record"] = deepcopy(
        state["filed_lifecycle_trace"][-1]
    )
    state["filed_lifecycle_result"] = LIFECYCLE_PASS
    state["filed_lifecycle_reason"] = state["filed_lifecycle_trace"][-1][
        "reason"
    ]
    return state, issued_indexes


def _governance_integrity_state() -> tuple[dict, dict[str, int]]:
    state, _ = _lifecycle_state()
    provider = GovernanceIntegrityProvider()
    evaluator = GovernanceIntegrityEvaluator(provider)
    context = provider.hybrid_verification_context(allow_test_only=True)
    state["filed_governance_integrity_revocation_binding"] = (
        governance_integrity_revocation_binding(
            status="ACTIVE",
            sequence=1,
        )
    )
    state["filed_governance_integrity_trace"] = []
    state["filed_governance_integrity_results"] = {}
    state["filed_governance_integrity_digest"] = None
    state["three_p_trace"] = []
    issued_indexes: dict[str, int] = {}
    for sequence, governance_function in enumerate(
        FILED_GOVERNANCE_INTEGRITY_ORDER,
        start=1,
    ):
        stage = FILED_GOVERNANCE_INTEGRITY_STAGES[
            governance_function
        ]
        state["three_p_core_result"] = "PASS"
        state["three_p_core_digest"] = canonical_integrity_hash(
            {"stage": stage, "sequence": sequence, "boundary": "pre"}
        )
        state["three_p_trace_hash"] = canonical_integrity_hash(
            {
                "prior": state.get("three_p_trace_hash"),
                "digest": state["three_p_core_digest"],
            }
        )
        state["three_p_trace"].append(
            {
                "three_p_core_digest": state["three_p_core_digest"],
                "trace_hash": state["three_p_trace_hash"],
            }
        )
        pre_entry = build_hash_chain_entry(
            previous_hash=state["hash_chain"][-1]["hash"],
            stage=f"three_p_core:{stage}",
            payload={"three_p": "pre", "sequence": sequence},
        )
        state["hash_chain"].append(pre_entry)
        state["state_hash"] = pre_entry["hash"]
        evaluate_filed_governance_integrity(
            state,
            governance_function,
            evaluator=evaluator,
            attestation_provider=provider,
            attestation_trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        )
        integrity_entry = build_hash_chain_entry(
            previous_hash=pre_entry["hash"],
            stage=stage,
            payload=filed_governance_integrity_hash_payload(state),
        )
        state["hash_chain"].append(integrity_entry)
        state["three_p_core_digest"] = canonical_integrity_hash(
            {"stage": stage, "sequence": sequence, "boundary": "post"}
        )
        state["three_p_trace_hash"] = canonical_integrity_hash(
            {
                "prior": state["three_p_trace_hash"],
                "digest": state["three_p_core_digest"],
            }
        )
        state["three_p_trace"].append(
            {
                "three_p_core_digest": state["three_p_core_digest"],
                "trace_hash": state["three_p_trace_hash"],
            }
        )
        post_entry = build_hash_chain_entry(
            previous_hash=integrity_entry["hash"],
            stage=f"three_p_core:{stage}:post",
            payload={"three_p": "post", "sequence": sequence},
        )
        state["hash_chain"].append(post_entry)
        state["state_hash"] = post_entry["hash"]
        token_name = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ].lower()
        issued_indexes[token_name] = len(state["hash_chain"]) - 1
    return state, issued_indexes


def test_required_token_order_and_issuance_contracts_are_exact() -> None:
    lifecycle_tokens = [
        FILED_LIFECYCLE_ENGINE_IDS[engine].lower()
        for engine in FILED_LIFECYCLE_ORDER
    ]
    governance_integrity_tokens = [
        FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ].lower()
        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
    ]
    assert REQUIRED_CORE_TOKENS == (
        "foundational",
        "authority_provenance",
        "authority",
        "skg",
        "procedural_truth",
        "ptodf",
        "classification",
        "licensing",
        "aj_saaf",
        "gala",
        "abegf",
        *lifecycle_tokens,
        *governance_integrity_tokens,
        "governance",
        "domain",
        "aurion",
        "execution_boundary",
        "execution_attestation",
    )
    assert _TOKEN_ISSUANCE_CONTRACTS["foundational"] == (
        "foundational_baseline",
        "foundational_baseline",
    )
    assert _TOKEN_ISSUANCE_CONTRACTS["authority_provenance"] == (
        "authority_provenance",
        "authority_provenance:admission",
    )
    assert _TOKEN_ISSUANCE_CONTRACTS["skg"] == (
        "skg_authority",
        "skg_authority",
    )
    for engine, token_name in zip(FILED_LIFECYCLE_ORDER, lifecycle_tokens):
        assert _TOKEN_ISSUANCE_CONTRACTS[token_name] == (
            FILED_LIFECYCLE_ENGINE_IDS[engine],
            FILED_LIFECYCLE_STAGES[engine],
        )
    for governance_function, token_name in zip(
        FILED_GOVERNANCE_INTEGRITY_ORDER,
        governance_integrity_tokens,
    ):
        assert _TOKEN_ISSUANCE_CONTRACTS[token_name] == (
            FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
                governance_function
            ],
            FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function],
        )


def test_pipeline_config_places_skg_and_lifecycle_in_exact_order() -> None:
    ordered_stages = [
        "root_of_trust",
        "skg_authority:constitutional_authority_substrate",
        "procedural_truth",
        "filed_framework:ptodf",
        "classification",
        "licensing",
        "filed_framework:aj_saaf",
        "filed_framework:gala",
        "filed_framework:abegf",
        *[FILED_LIFECYCLE_STAGES[engine] for engine in FILED_LIFECYCLE_ORDER],
        *[
            FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
            for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
        ],
        "governance",
        "domain_wrap",
        "aurion_runtime",
        "execution_gate",
    ]
    indexes = [PIPELINE_ORDER.index(stage) for stage in ordered_stages]
    assert indexes == sorted(indexes)
    assert GOVERNANCE_TRAVERSAL_ORDER == [
        "AJ-SAAF",
        "governance_engine",
        "GALA",
        "ABEGF",
        *FILED_LIFECYCLE_ORDER,
        *FILED_GOVERNANCE_INTEGRITY_ORDER,
    ]
    assert "hash_chain_presence_and_integrity" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    assert "three_p_core_constitutional_constraint" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    assert "authority_provenance_current_and_valid" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    assert "skg_authority_complete_and_valid" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    assert "filed_lifecycle_complete_and_valid" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    assert "filed_governance_integrity_complete_and_valid" in (
        EXECUTION_GATE_REQUIRED_CHECKS
    )
    for stage in [
        "skg_authority:constitutional_authority_substrate",
        *[FILED_LIFECYCLE_STAGES[engine] for engine in FILED_LIFECYCLE_ORDER],
        *[
            FILED_GOVERNANCE_INTEGRITY_STAGES[governance_function]
            for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
        ],
    ]:
        assert stage in HASH_CHAIN_REQUIRED_STAGES
    assert build_pipeline_order()[
        "lifecycle_implementation_order_authority"
    ] == FILED_LIFECYCLE_ORDER_AUTHORITY
    assert build_pipeline_order()[
        "governance_integrity_implementation_order_authority"
    ] == FILED_GOVERNANCE_INTEGRITY_ORDER_AUTHORITY


def test_skg_payload_is_exact_and_tamper_fails_closed() -> None:
    state = _skg_state()
    expected = skg_authority_hash_payload(state)
    assert _expected_skg_token_payload(state, 2) == expected

    tampered = deepcopy(state)
    tampered["skg_authority_record"]["schema_status"] = "FILED_SCHEMA"
    assert _expected_skg_token_payload(tampered, 2) is None

    tampered = deepcopy(state)
    tampered["skg_authority_record"]["evaluation_source"]["determination"][
        "authority_granted"
    ] = True
    assert _expected_skg_token_payload(tampered, 2) is None


def test_lifecycle_payloads_bind_each_exact_prefix_and_fail_closed() -> None:
    state, issued_indexes = _lifecycle_state()
    for sequence, engine in enumerate(FILED_LIFECYCLE_ORDER, start=1):
        token_name = FILED_LIFECYCLE_ENGINE_IDS[engine].lower()
        payload = _expected_lifecycle_token_payload(
            state, token_name, issued_indexes[token_name]
        )
        assert payload is not None
        assert payload["lifecycle_engine"] == engine
        assert payload["evaluation_sequence"] == sequence
        assert payload["trace_digest"] == canonical_integrity_hash(
            state["filed_lifecycle_trace"][:sequence]
        )
        assert payload["authority_granted"] is False
        assert payload["execution_authority_granted"] is False
        assert payload["licence_granted"] is False
        assert payload["governance_superseded"] is False

    final_token = FILED_LIFECYCLE_ENGINE_IDS[
        FILED_LIFECYCLE_ORDER[-1]
    ].lower()
    tampered = deepcopy(state)
    tampered["filed_lifecycle_trace"][-1]["evaluation_source"][
        "determination"
    ]["bound_to_skg"] = False
    assert (
        _expected_lifecycle_token_payload(
            tampered, final_token, issued_indexes[final_token]
        )
        is None
    )

    tampered = deepcopy(state)
    tampered["hash_chain"][issued_indexes[final_token] - 1]["stage"] = (
        "filed_lifecycle:wrong"
    )
    assert (
        _expected_lifecycle_token_payload(
            tampered, final_token, issued_indexes[final_token]
        )
        is None
    )


def test_governance_payload_binds_complete_lifecycle_and_integrity_state() -> None:
    state, _ = _governance_integrity_state()
    payload = _expected_governance_token_payload(state)
    assert payload is not None
    assert payload["filed_lifecycle_results"] == {
        engine: LIFECYCLE_PASS for engine in FILED_LIFECYCLE_ORDER
    }
    assert payload["filed_lifecycle_digest"] == state[
        "filed_lifecycle_digest"
    ]
    assert payload["lifecycle_implementation_order_authority"] == (
        FILED_LIFECYCLE_ORDER_AUTHORITY
    )
    assert payload["filed_governance_integrity_results"] == {
        governance_function: GOVERNANCE_INTEGRITY_PASS
        for governance_function in FILED_GOVERNANCE_INTEGRITY_ORDER
    }
    assert payload["filed_governance_integrity_digest"] == state[
        "filed_governance_integrity_digest"
    ]

    tampered = deepcopy(state)
    tampered["filed_lifecycle_results"][FILED_LIFECYCLE_ORDER[0]] = "DENY"
    assert _expected_governance_token_payload(tampered) is None


def test_governance_integrity_payloads_bind_each_exact_prefix() -> None:
    state, issued_indexes = _governance_integrity_state()
    for sequence, governance_function in enumerate(
        FILED_GOVERNANCE_INTEGRITY_ORDER,
        start=1,
    ):
        token_name = FILED_GOVERNANCE_INTEGRITY_FUNCTION_IDS[
            governance_function
        ].lower()
        payload = _expected_governance_integrity_token_payload(
            state,
            token_name,
            issued_indexes[token_name],
        )
        assert payload is not None
        assert payload["governance_integrity_function"] == (
            governance_function
        )
        assert payload["evaluation_sequence"] == sequence
        assert payload["authority_granted"] is False
        assert payload["licence_granted"] is False
        assert payload["execution_authority_granted"] is False
        assert payload["effect_granted"] is False
        assert payload["bypass_permitted"] is False
