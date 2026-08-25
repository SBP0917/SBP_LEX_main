from __future__ import annotations

from io import StringIO
import json
from unittest.mock import patch

import pytest

from main import cli, run_sbp_lex, run_v2


def test_run_v2_is_the_canonical_library_entrypoint() -> None:
    expected = {"decision": "DENY", "execution_result": "HALT"}
    request = {"action": "review", "payload": {}, "context": {}}
    signals = {"intent_signal": "review"}
    with patch("main._pipeline_run_v2", return_value=expected) as pipeline:
        assert run_v2(request, signals) is expected
    pipeline.assert_called_once()
    assert pipeline.call_args.args == (request, signals)


def test_run_sbp_lex_is_compatibility_only_and_delegates_to_run_v2() -> None:
    expected = {"decision": "DENY", "execution_result": "HALT"}
    request = {"action": "review", "payload": {}, "context": {}}
    with patch("main.run_v2", return_value=expected) as canonical:
        assert run_sbp_lex(request, possession_proof={"proof": "fixture"}) is expected
    canonical.assert_called_once_with(
        request,
        None,
        possession_proof={"proof": "fixture"},
    )


def test_cli_accepts_exact_json_objects_and_prints_canonical_result() -> None:
    expected = {"execution_result": "HALT", "decision": "DENY"}
    output = StringIO()
    with patch("main.run_v2", return_value=expected) as canonical:
        assert cli(
            [
                "--request-json",
                '{"action":"review","payload":{},"context":{}}',
                "--signals-json",
                '{"intent_signal":"review"}',
            ],
            stdout=output,
        ) == 0
    canonical.assert_called_once_with(
        {"action": "review", "payload": {}, "context": {}},
        {"intent_signal": "review"},
    )
    assert json.loads(output.getvalue()) == expected
    assert output.getvalue() == (
        '{"decision":"DENY","execution_result":"HALT"}\n'
    )


@pytest.mark.parametrize(
    "arguments",
    (
        [],
        ["--request-json", "[]"],
        ["--request-json", "{"],
        ["--request-json", "{}", "--request-file", "request.json"],
    ),
)
def test_cli_rejects_missing_non_object_malformed_or_ambiguous_input(
    arguments: list[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        cli(arguments)
    assert error.value.code == 2
