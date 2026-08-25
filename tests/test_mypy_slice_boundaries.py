from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from sbp_lex.baseline import foundational_baseline
from sbp_lex.compliance import australian_minor_access
from sbp_lex.provenance import digital_provenance
from tests import test_australian_minor_access as _minor_fixtures
from tests import test_digital_provenance as _provenance_fixtures


def test_compliance_deployment_composition_is_frozen(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        australian_minor_access,
        "_ACTIVE_COMPOSITION",
        None,
    )
    fixture = _minor_fixtures.Fixture()
    fixture.install()
    composition = australian_minor_access._composition()

    with pytest.raises(FrozenInstanceError):
        composition.context_id = "attacker-context"


@pytest.mark.parametrize("field", ("revocation_head", "clock_receipt"))
def test_compliance_verification_rejects_non_mapping_signed_records(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    monkeypatch.setattr(
        australian_minor_access,
        "_ACTIVE_COMPOSITION",
        None,
    )
    fixture = _minor_fixtures.Fixture()
    fixture.install()
    state = fixture.state()
    australian_minor_access.evaluate_australian_minor_access(
        state,
        stage="ACCOUNT_ADMISSION",
    )
    australian_minor_access.bind_australian_minor_access_hash(state)
    assert australian_minor_access.verify_australian_minor_access(state)

    state["australian_minor_access"][field] = None

    assert not australian_minor_access.verify_australian_minor_access(state)


def test_provenance_missing_durable_context_identity_denies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _provenance_fixtures.DigitalProvenanceTests(
        methodName="test_exact_lineage_receipt_is_deterministic_and_non_authorizing"
    )
    fixture.setUp()
    graph = fixture.graph()
    invalid_context = replace(fixture.trust_context, durable_context=object())
    monkeypatch.setattr(
        digital_provenance,
        "_deployment_context_error",
        lambda _context: None,
    )

    decision = fixture.verify(graph, trust_context=invalid_context)

    assert decision.result == digital_provenance.DENY
    assert decision.reason == "PROVENANCE_DEPLOYMENT_TRUST_CONTEXT_INVALID"


@pytest.mark.parametrize("record", (None, [], "malformed"))
def test_foundational_baseline_rejects_non_mapping_minor_record(
    record: object,
) -> None:
    assert not foundational_baseline._australian_minor_access_valid(
        {"australian_minor_access": record}
    )
