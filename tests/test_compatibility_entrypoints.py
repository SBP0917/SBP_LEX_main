from __future__ import annotations

import ast
from pathlib import Path
from unittest.mock import patch

from sbp_lex.execution.engine import ExecutionEngine
from sbp_lex.response_controller.runner import run_pipeline


def test_main_canonical_entry_forwards_only_supplied_hybrid_trust_contexts() -> None:
    source = (Path(__file__).parents[1] / "main.py").read_text(encoding="utf-8")
    module = ast.parse(source)
    entry = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "run_v2"
    )
    parameter_defaults = dict(
        zip(entry.args.kwonlyargs, entry.args.kw_defaults, strict=True)
    )
    trust_parameter = next(
        parameter
        for parameter in entry.args.kwonlyargs
        if parameter.arg == "hybrid_trust_contexts"
    )
    assert isinstance(parameter_defaults[trust_parameter], ast.Constant)
    assert parameter_defaults[trust_parameter].value is None

    delegation = next(
        node
        for node in ast.walk(entry)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_pipeline_run_v2"
    )
    trust_keyword = next(
        keyword
        for keyword in delegation.keywords
        if keyword.arg == "hybrid_trust_contexts"
    )
    assert isinstance(trust_keyword.value, ast.Name)
    assert trust_keyword.value.id == "hybrid_trust_contexts"


def test_execution_engine_forwards_all_mandatory_dependencies() -> None:
    dependencies = {
        "signature_provider": object(),
        "signature_trust_context": object(),
        "signature_owner_pinned_context_digest": "signature-pin",
        "three_p_attestation_provider": object(),
        "three_p_attestation_trust_context": object(),
        "three_p_owner_pinned_context_digest": "three-p-pin",
        "skg_evaluator": object(),
        "skg_attestation_provider": object(),
        "skg_attestation_trust_context": object(),
        "skg_owner_pinned_context_digest": "skg-pin",
        "filed_framework_evaluator": object(),
        "filed_framework_attestation_provider": object(),
        "filed_framework_attestation_trust_context": object(),
        "filed_framework_owner_pinned_context_digest": "framework-pin",
        "filed_licence_evaluator": object(),
        "filed_licence_attestation_provider": object(),
        "filed_licence_attestation_trust_context": object(),
        "filed_licence_owner_pinned_context_digest": "licence-pin",
        "filed_lifecycle_evaluator": object(),
        "filed_lifecycle_attestation_provider": object(),
        "filed_lifecycle_attestation_trust_context": object(),
        "filed_lifecycle_owner_pinned_context_digest": "lifecycle-pin",
        "filed_governance_integrity_evaluator": object(),
        "filed_governance_integrity_attestation_provider": object(),
        "filed_governance_integrity_attestation_trust_context": object(),
        "filed_governance_integrity_owner_pinned_context_digest": (
            "governance-integrity-pin"
        ),
        "application_integrity_bundle": object(),
        "application_integrity_result": {"verified": True},
        "foundational_request_dependencies": object(),
    }
    engine = ExecutionEngine(**dependencies)
    state = {"request": "one"}

    with patch(
        "sbp_lex.execution.engine.run_execution_gate",
        return_value=state,
    ) as gate:
        assert engine.execute(state) is state

    gate.assert_called_once_with(state, **dependencies)


def test_response_controller_routes_only_through_complete_v2_pipeline() -> None:
    request = {"action": "review"}
    signals = {"intent_signal": "review"}
    dependencies = {
        "signature_provider": object(),
        "three_p_evaluator": object(),
        "three_p_attestation_provider": object(),
        "skg_evaluator": object(),
        "skg_attestation_provider": object(),
        "filed_framework_evaluator": object(),
        "filed_framework_attestation_provider": object(),
        "filed_licence_evaluator": object(),
        "filed_licence_attestation_provider": object(),
        "filed_lifecycle_evaluator": object(),
        "filed_lifecycle_attestation_provider": object(),
        "filed_governance_integrity_evaluator": object(),
        "filed_governance_integrity_attestation_provider": object(),
        "filed_governance_integrity_revocation_binding": object(),
        "application_integrity_bundle": object(),
        "foundational_request_dependencies": object(),
        "possession_proof": object(),
        "effect_adapter": object(),
        "effect_permit_ttl_ms": 500,
        "rust_authority_route": object(),
        "hybrid_trust_contexts": object(),
    }
    expected = {"decision": "DENY"}

    with patch(
        "sbp_lex.response_controller.runner.run_v2",
        return_value=expected,
    ) as full_pipeline:
        assert run_pipeline(request, signals, **dependencies) is expected

    full_pipeline.assert_called_once_with(request, signals, **dependencies)


def test_response_controller_forwards_missing_hybrid_context_as_none() -> None:
    with patch(
        "sbp_lex.response_controller.runner.run_v2",
        return_value={"decision": "DENY"},
    ) as full_pipeline:
        run_pipeline({"action": "review"})

    assert full_pipeline.call_args.kwargs["hybrid_trust_contexts"] is None
