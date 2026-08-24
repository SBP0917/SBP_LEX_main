from __future__ import annotations

from unittest.mock import patch

from main import SBPLexV2RequestEnvelope, app, evaluate_v2, health


def test_fastapi_app_is_the_canonical_v2_launcher() -> None:
    assert app.title == "SBP-LEX V2"
    assert app.version == "2.0.0"
    assert {route.path for route in app.routes} >= {"/health", "/v2/evaluate"}


def test_health_does_not_claim_production_admission() -> None:
    assert health() == {
        "service": "SBP-LEX V2",
        "process_status": "AVAILABLE",
        "production_authority_status": "NOT_ADMITTED",
        "production_ready": False,
    }


def test_evaluate_v2_routes_only_through_run_sbp_lex() -> None:
    envelope = SBPLexV2RequestEnvelope(
        request={"action": "review", "payload": {}, "context": {}},
        pre_context_signals={"intent_signal": "review"},
    )
    expected = {"decision": "DENY", "execution_result": "HALT"}

    with patch("main.run_sbp_lex", return_value=expected) as pipeline:
        assert evaluate_v2(envelope) is expected

    pipeline.assert_called_once_with(
        envelope.request,
        envelope.pre_context_signals,
    )
