from __future__ import annotations

"""Fail-closed client boundary for the private Rust authority route.

This module deliberately does not choose or simulate an IPC mechanism, peer
credential, trust registry, trusted clock, HSM/TPM, replay service, watchdog,
interlock, audit store, or physical adapter. Those are injected by the owner
composition root. The client only bounds exact wire-v2 frames and independently
validates a complete signed terminal transcript before returning evidence.
"""

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
from typing import Any, Final, Protocol

from wire_protocol.v2.python import sbp_lex_wire_v2 as wire


RUST_AUTHORITY_ROUTE_NOT_ADMITTED: Final = "RUST_AUTHORITY_ROUTE_NOT_ADMITTED"
RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED: Final = "NOT_ADMITTED"
RUST_AUTHORITY_TERMINAL_SCHEMA: Final = (
    "SBP-LEX-RUST-AUTHORITY-VALIDATED-TERMINAL/1"
)
_MAX_EXTERNAL_FRAMES: Final = 8
_MAX_TERMINAL_FRAMES: Final = 21
_MAX_EXTERNAL_BYTES: Final = _MAX_EXTERNAL_FRAMES * (wire.MAX_FRAME_BYTES + 4)
_MAX_TERMINAL_BYTES: Final = _MAX_TERMINAL_FRAMES * (wire.MAX_FRAME_BYTES + 4)
_VALIDATION_SEAL = object()


class RustAuthorityRouteError(RuntimeError):
    """Base fail-closed route error."""


class RustAuthorityRouteUnavailable(RustAuthorityRouteError):
    """The route was rejected before an effect-capable exchange began."""


class RustAuthorityRouteInDoubt(RustAuthorityRouteError):
    """An exchange began but no complete valid terminal state was recovered."""


class RustAuthorityRoute(Protocol):
    def execute(self, state: Mapping[str, Any]) -> "RustAuthorityTerminalEvidence": ...


class RustAuthorityTransport(Protocol):
    """Deployment-provided authenticated transport.

    These identity properties are observations made by the deployment
    transport, not values accepted from request data.
    """

    @property
    def authenticated_peer_identity(self) -> str: ...

    @property
    def binary_identity(self) -> str: ...

    def exchange(
        self,
        request_frames: tuple[bytes, ...],
        *,
        deadline_ms: int,
    ) -> Iterable[bytes]: ...


@dataclass(frozen=True)
class RustAuthorityTerminalEvidence:
    outcome: str
    terminal_transcript_digest: str
    transcript_sha512: str
    frame_count: int
    authority_class: str
    authority_profile: str
    authority_build_id: str
    durable_consumption_digest: str
    adapter_digest: str
    effect_digest: str
    permit_digest: str | None
    receipt_digest: str | None
    watchdog_status: str | None
    _messages: tuple[dict[str, object], ...]
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _VALIDATION_SEAL:
            raise TypeError(
                "RustAuthorityTerminalEvidence requires independent wire validation"
            )

    def audit_record(self) -> dict[str, object]:
        """Return the bounded record Python may bind into its local audit."""

        return {
            "schema": RUST_AUTHORITY_TERMINAL_SCHEMA,
            "outcome": self.outcome,
            "terminal_transcript_digest": self.terminal_transcript_digest,
            "transcript_sha512": self.transcript_sha512,
            "frame_count": self.frame_count,
            "authority_class": self.authority_class,
            "authority_profile": self.authority_profile,
            "authority_build_id": self.authority_build_id,
            "durable_consumption_digest": self.durable_consumption_digest,
            "adapter_digest": self.adapter_digest,
            "effect_digest": self.effect_digest,
            "permit_digest": self.permit_digest,
            "receipt_digest": self.receipt_digest,
            "watchdog_status": self.watchdog_status,
            "complete_signed_terminal_transcript_validated": True,
            "route_admission_state": RUST_AUTHORITY_ROUTE_STATUS_NOT_ADMITTED,
            "programme_success_eligible": False,
            "effect_authority_granted": False,
        }

    def messages_for_diagnostics(self) -> tuple[dict[str, object], ...]:
        """Post-consumption audit evidence; never an effect-capability API."""

        return tuple(dict(message) for message in self._messages)


def _decode_bounded_frames(
    frames: Iterable[bytes],
    *,
    maximum_frames: int,
    maximum_bytes: int,
) -> tuple[tuple[bytes, ...], tuple[dict[str, object], ...]]:
    encoded: list[bytes] = []
    messages: list[dict[str, object]] = []
    total = 0
    for frame in frames:
        if type(frame) is not bytes:
            raise wire.WireError("frame must be immutable bytes")
        if len(encoded) >= maximum_frames:
            raise wire.WireError("session frame count")
        total += len(frame)
        if total > maximum_bytes:
            raise wire.WireError("session byte count")
        messages.append(wire.decode_frame(frame))
        encoded.append(frame)
    if not encoded:
        raise wire.WireError("empty session")
    return tuple(encoded), tuple(messages)


def _terminal_outcome(messages: Sequence[Mapping[str, object]]) -> str:
    final = messages[-1]
    if final.get("kind") != "watchdog_result":
        if final.get("decision") in {"DENY", "BLOCK"}:
            return "BLOCKED"
        raise wire.WireError("complete terminal result absent")
    receipt = next(
        (message for message in messages if message.get("kind") == "effect_receipt"),
        None,
    )
    watchdog = next(
        (message for message in messages if message.get("kind") == "watchdog_terminal"),
        None,
    )
    if watchdog is None:
        raise wire.WireError("signed watchdog terminal absent")
    status = watchdog.get("watchdog_status")
    if receipt is not None:
        outcome = receipt.get("effect_outcome")
        if outcome == "SUCCEEDED" and final.get("decision") == "ACK":
            return "SUCCESS"
        if outcome == "FAILED" and final.get("decision") == "BLOCK":
            return "FAILED"
        if outcome == "UNKNOWN" and final.get("decision") == "BLOCK":
            return "UNKNOWN"
        raise wire.WireError("terminal receipt disposition mismatch")
    if status == "TIMEOUT" and final.get("decision") == "BLOCK":
        return "TIMEOUT"
    if status == "STOP" and final.get("decision") == "BLOCK":
        return "UNKNOWN"
    raise wire.WireError("no-receipt terminal disposition mismatch")


class RustAuthorityClient:
    """Strict route assembled only from owner-pinned external dependencies."""

    def __init__(
        self,
        *,
        registry: wire.TrustRegistry,
        admission: wire.AdmissionPolicy,
        verifier: wire.Verifier,
        trusted_now_ms: Callable[[], int],
        request_builder: Callable[[Mapping[str, Any]], Iterable[bytes]],
        state_binding_validator: Callable[
            [Mapping[str, Any], wire.AdmissionPolicy], bool
        ],
        transport: RustAuthorityTransport,
        expected_peer_identity: str,
        expected_binary_identity: str,
        session_deadline_ms: int,
        allow_test_only: bool = False,
    ) -> None:
        if not expected_peer_identity or not expected_binary_identity:
            raise RustAuthorityRouteUnavailable(RUST_AUTHORITY_ROUTE_NOT_ADMITTED)
        if type(session_deadline_ms) is not int or session_deadline_ms <= 0:
            raise RustAuthorityRouteUnavailable(RUST_AUTHORITY_ROUTE_NOT_ADMITTED)
        if admission.authority_class == "TEST_ONLY" and not allow_test_only:
            raise RustAuthorityRouteUnavailable(
                "TEST_ONLY_RUST_AUTHORITY_ROUTE_REJECTED"
            )
        if admission.authority_class != "TEST_ONLY" and allow_test_only:
            raise RustAuthorityRouteUnavailable(
                "TEST_ONLY_FLAG_REJECTED_FOR_PRODUCTION_AUTHORITY"
            )
        self._registry = registry
        self._admission = admission
        self._verifier = verifier
        self._trusted_now_ms = trusted_now_ms
        self._request_builder = request_builder
        self._state_binding_validator = state_binding_validator
        self._transport = transport
        self._expected_peer_identity = expected_peer_identity
        self._expected_binary_identity = expected_binary_identity
        self._session_deadline_ms = session_deadline_ms

    def execute(self, state: Mapping[str, Any]) -> RustAuthorityTerminalEvidence:
        if (
            self._transport.authenticated_peer_identity
            != self._expected_peer_identity
            or self._transport.binary_identity != self._expected_binary_identity
        ):
            raise RustAuthorityRouteUnavailable(RUST_AUTHORITY_ROUTE_NOT_ADMITTED)
        if not self._state_binding_validator(state, self._admission):
            raise RustAuthorityRouteUnavailable(
                "RUST_AUTHORITY_STATE_BINDING_NOT_ADMITTED"
            )
        try:
            request_frames, _ = _decode_bounded_frames(
                self._request_builder(state),
                maximum_frames=_MAX_EXTERNAL_FRAMES,
                maximum_bytes=_MAX_EXTERNAL_BYTES,
            )
        except (TypeError, ValueError, wire.WireError) as error:
            raise RustAuthorityRouteUnavailable(
                "RUST_AUTHORITY_REQUEST_FRAMES_REJECTED"
            ) from error

        try:
            response_frames, messages = _decode_bounded_frames(
                self._transport.exchange(
                    request_frames,
                    deadline_ms=self._session_deadline_ms,
                ),
                maximum_frames=_MAX_TERMINAL_FRAMES,
                maximum_bytes=_MAX_TERMINAL_BYTES,
            )
            now = self._trusted_now_ms()
            if type(now) is not int or now < 0:
                raise wire.WireError("trusted time unavailable")
            wire.validate_transcript(
                messages,
                registry=self._registry,
                admission=self._admission,
                verifier=self._verifier,
                trusted_now_ms=now,
            )
            outcome = _terminal_outcome(messages)
        except Exception as error:
            # Once exchange begins, malformed, partial, timed-out, disconnected,
            # or unverifiable output can never establish that no effect occurred.
            raise RustAuthorityRouteInDoubt(
                "RUST_AUTHORITY_TERMINAL_STATE_UNVERIFIED"
            ) from error

        final = messages[-1]
        receipt = next(
            (message for message in messages if message.get("kind") == "effect_receipt"),
            None,
        )
        watchdog = next(
            (message for message in messages if message.get("kind") == "watchdog_terminal"),
            None,
        )
        permit = next(
            (message for message in messages if message.get("kind") == "effect_permit_result"),
            None,
        )
        return RustAuthorityTerminalEvidence(
            outcome=outcome,
            terminal_transcript_digest=str(final["transcript_digest"]),
            transcript_sha512=hashlib.sha512(b"".join(response_frames)).hexdigest(),
            frame_count=len(messages),
            authority_class=str(final["authority_class"]),
            authority_profile=str(final["authority_profile"]),
            authority_build_id=str(final["authority_build_id"]),
            durable_consumption_digest=str(final["durable_consumption_digest"]),
            adapter_digest=str(final["adapter_digest"]),
            effect_digest=str(final["effect_digest"]),
            permit_digest=(
                str(permit["permit_digest"]) if permit is not None else None
            ),
            receipt_digest=(
                str(receipt["receipt_digest"]) if receipt is not None else None
            ),
            watchdog_status=(
                str(watchdog["watchdog_status"]) if watchdog is not None else None
            ),
            _messages=tuple(dict(message) for message in messages),
            _seal=_VALIDATION_SEAL,
        )
