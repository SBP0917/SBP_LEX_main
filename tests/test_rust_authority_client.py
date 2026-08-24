from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import pytest

from sbp_lex.execution.rust_authority_client import (
    RustAuthorityClient,
    RustAuthorityRouteInDoubt,
    RustAuthorityRouteUnavailable,
)
from wire_protocol.v2.python import sbp_lex_wire_v2 as wire
from wire_protocol.v2.python.golden import (
    BASE_MS,
    build_transcript,
    fixture_admission,
)


class StaticTransport:
    def __init__(
        self,
        response: Iterable[bytes] | Exception,
        *,
        peer: str = "PINNED-PEER",
        binary: str = "PINNED-BINARY",
    ) -> None:
        self.response = response
        self.authenticated_peer_identity = peer
        self.binary_identity = binary
        self.calls = 0

    def exchange(
        self,
        request_frames: tuple[bytes, ...],
        *,
        deadline_ms: int,
    ) -> Iterable[bytes]:
        assert request_frames
        assert deadline_ms == 1_000
        self.calls += 1
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def client(
    transport: StaticTransport,
    *,
    request_messages: list[dict[str, object]],
    mode: str = "MODE_1",
    allow_test_only: bool = True,
) -> RustAuthorityClient:
    registry, _terminal = build_transcript(mode)
    admission = fixture_admission(registry, mode)
    return RustAuthorityClient(
        registry=registry,
        admission=admission,
        verifier=wire.fixture_verify,
        trusted_now_ms=lambda: BASE_MS + 5_000,
        request_builder=lambda _state: (
            wire.encode_frame(message) for message in request_messages
        ),
        state_binding_validator=lambda _state, pinned: pinned is admission,
        transport=transport,
        expected_peer_identity="PINNED-PEER",
        expected_binary_identity="PINNED-BINARY",
        session_deadline_ms=1_000,
        allow_test_only=allow_test_only,
    )


def external_messages(
    mode: str,
    messages: list[dict[str, object]],
) -> list[dict[str, object]]:
    indexes = {
        "MODE_1": (0, 2, 3, 4, 5, 7, 9, 13),
        "MODE_2": (0, 1, 2, 4, 6, 10),
        "MODE_3": (0, 1, 3, 5, 9),
    }[mode]
    return [messages[index] for index in indexes]


def test_complete_signed_terminal_is_validated_before_evidence_is_returned() -> None:
    _registry, messages = build_transcript("MODE_1")
    external = [messages[index] for index in (0, 2, 3, 4, 5, 7, 9, 13)]
    transport = StaticTransport(wire.encode_frame(message) for message in messages)
    evidence = client(transport, request_messages=external).execute({"request": "x"})

    assert evidence.outcome == "SUCCESS"
    assert evidence.frame_count == len(messages)
    assert evidence.terminal_transcript_digest == messages[-1]["transcript_digest"]
    assert evidence.audit_record()[
        "complete_signed_terminal_transcript_validated"
    ] is True
    assert evidence.audit_record()["route_admission_state"] == "NOT_ADMITTED"
    assert evidence.audit_record()["programme_success_eligible"] is False
    assert evidence.audit_record()["effect_authority_granted"] is False
    assert transport.calls == 1


@pytest.mark.parametrize("mode", ("MODE_2", "MODE_3"))
def test_mode2_and_mode3_complete_signed_transcripts_are_strictly_validated(
    mode: str,
) -> None:
    _registry, messages = build_transcript(mode)
    transport = StaticTransport(wire.encode_frame(message) for message in messages)
    evidence = client(
        transport,
        request_messages=external_messages(mode, messages),
        mode=mode,
    ).execute({"request": mode})

    assert evidence.outcome == "SUCCESS"
    assert evidence.frame_count == len(messages)
    assert evidence.terminal_transcript_digest == messages[-1]["transcript_digest"]
    assert evidence.permit_digest == messages[-5]["permit_digest"]
    assert evidence.receipt_digest == messages[-4]["receipt_digest"]
    assert evidence.watchdog_status == "HEALTHY"
    assert evidence.audit_record()["route_admission_state"] == "NOT_ADMITTED"
    assert evidence.audit_record()["programme_success_eligible"] is False
    assert evidence.audit_record()["effect_authority_granted"] is False
    assert transport.calls == 1


@pytest.mark.parametrize("mode", ("MODE_2", "MODE_3"))
@pytest.mark.parametrize(
    ("outcome", "timeout", "expected"),
    (
        ("FAILED", False, "FAILED"),
        ("UNKNOWN", False, "UNKNOWN"),
        ("SUCCEEDED", True, "TIMEOUT"),
    ),
)
def test_mode2_and_mode3_failure_unknown_and_timeout_tails_fail_closed(
    mode: str,
    outcome: str,
    timeout: bool,
    expected: str,
) -> None:
    _registry, messages = build_transcript(mode, outcome=outcome, timeout=timeout)
    evidence = client(
        StaticTransport(wire.encode_frame(message) for message in messages),
        request_messages=external_messages(mode, messages),
        mode=mode,
    ).execute({"request": mode})

    assert evidence.outcome == expected
    assert evidence.terminal_transcript_digest == messages[-1]["transcript_digest"]
    assert evidence.watchdog_status == ("TIMEOUT" if timeout else "STOP")
    assert evidence.audit_record()["route_admission_state"] == "NOT_ADMITTED"
    assert evidence.audit_record()["programme_success_eligible"] is False
    assert evidence.audit_record()["effect_authority_granted"] is False


@pytest.mark.parametrize("failure", (TimeoutError("timeout"), ConnectionError("closed")))
def test_timeout_or_disconnect_after_exchange_is_in_doubt(failure: Exception) -> None:
    _registry, messages = build_transcript("MODE_1")
    external = [messages[index] for index in (0, 2, 3, 4, 5, 7, 9, 13)]
    with pytest.raises(RustAuthorityRouteInDoubt):
        client(StaticTransport(failure), request_messages=external).execute({})


@pytest.mark.parametrize("response_kind", ("partial", "malformed"))
def test_partial_or_malformed_terminal_never_infers_no_effect(response_kind: str) -> None:
    _registry, messages = build_transcript("MODE_1")
    external = [messages[index] for index in (0, 2, 3, 4, 5, 7, 9, 13)]
    response = (
        [wire.encode_frame(message) for message in messages[:-1]]
        if response_kind == "partial"
        else [b"\x00\x00\x00\x03bad"]
    )
    with pytest.raises(RustAuthorityRouteInDoubt):
        client(StaticTransport(response), request_messages=external).execute({})


def test_wrong_authenticated_peer_is_rejected_before_exchange() -> None:
    _registry, messages = build_transcript("MODE_1")
    transport = StaticTransport([], peer="OTHER-PEER")
    with pytest.raises(RustAuthorityRouteUnavailable):
        client(transport, request_messages=[messages[0]]).execute({})
    assert transport.calls == 0


def test_test_only_registry_is_rejected_by_default() -> None:
    registry, messages = build_transcript("MODE_1")
    admission = fixture_admission(registry, "MODE_1")
    with pytest.raises(
        RustAuthorityRouteUnavailable,
        match="TEST_ONLY_RUST_AUTHORITY_ROUTE_REJECTED",
    ):
        RustAuthorityClient(
            registry=registry,
            admission=admission,
            verifier=wire.fixture_verify,
            trusted_now_ms=lambda: BASE_MS + 5_000,
            request_builder=lambda _state: [wire.encode_frame(messages[0])],
            state_binding_validator=lambda _state, _admission: True,
            transport=StaticTransport([]),
            expected_peer_identity="PINNED-PEER",
            expected_binary_identity="PINNED-BINARY",
            session_deadline_ms=1_000,
        )
