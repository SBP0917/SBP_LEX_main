from __future__ import annotations

import base64
import hashlib
import json
import unicodedata
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from typing import Any


ASSURANCE_ENVELOPE_VERSION = "sbp.v2.assurance-envelope/1"
GENESIS_DIGEST = "GENESIS"
CHECKPOINTS = frozenset(
    {
        "state_construction",
        "authority_first",
        "governance_grc",
        "domain_aurion_convergence",
        "execution_gate_input",
        "terminal_audit",
    }
)


class AssuranceContractError(ValueError):
    """Raised when decision-relevant data cannot be encoded canonically."""


def _normalise(value: Any, *, path: str = "$") -> Any:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise AssuranceContractError(
            f"floating-point value is forbidden in canonical assurance data at {path}"
        )
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        normalised_items: list[tuple[str, Any]] = []
        for key, child in value.items():
            if not isinstance(key, str):
                raise AssuranceContractError(
                    f"object key must be a string in canonical assurance data at {path}"
                )
            normalised_key = unicodedata.normalize("NFC", key)
            normalised_items.append(
                (normalised_key, _normalise(child, path=f"{path}.{normalised_key}"))
            )

        if len({key for key, _ in normalised_items}) != len(normalised_items):
            raise AssuranceContractError(
                f"Unicode normalisation produced duplicate object keys at {path}"
            )

        # RFC 8785 orders property names by UTF-16 code units. Python dicts retain
        # insertion order, so json.dumps can preserve the order established here.
        normalised_items.sort(key=lambda item: item[0].encode("utf-16-be"))
        return OrderedDict(normalised_items)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, memoryview)):
        return [_normalise(child, path=f"{path}[{index}]") for index, child in enumerate(value)]
    raise AssuranceContractError(
        f"unsupported canonical assurance type {type(value).__name__} at {path}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON for the restricted V2 assurance profile.

    The restricted profile deliberately excludes floating-point values. Exact
    decimal policy values must cross the boundary as scaled integers or strings.
    """

    normalised = _normalise(value)
    try:
        encoded = json.dumps(
            normalised,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError) as exc:
        raise AssuranceContractError("value is not valid canonical UTF-8 JSON") from exc
    return encoded


def _sha512_hex(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def _require_sha512_or_genesis(value: str, *, field: str) -> None:
    if value == GENESIS_DIGEST:
        return
    if len(value) != 128 or any(character not in "0123456789abcdef" for character in value):
        raise AssuranceContractError(f"{field} must be GENESIS or a lowercase SHA-512 hex digest")


def build_assurance_envelope(
    *,
    request_fingerprint: str,
    checkpoint: str,
    sequence: int,
    state_projection: Mapping[str, Any],
    previous_envelope_sha512: str = GENESIS_DIGEST,
) -> dict[str, Any]:
    """Build a versioned, digest-bound input for a veto-only verifier."""

    _require_sha512_or_genesis(request_fingerprint, field="request_fingerprint")
    if request_fingerprint == GENESIS_DIGEST:
        raise AssuranceContractError("request_fingerprint cannot be GENESIS")
    if checkpoint not in CHECKPOINTS:
        raise AssuranceContractError(f"unknown assurance checkpoint: {checkpoint}")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise AssuranceContractError("sequence must be a non-negative integer")
    _require_sha512_or_genesis(
        previous_envelope_sha512,
        field="previous_envelope_sha512",
    )

    canonical_state = canonical_json_bytes(state_projection)
    return {
        "schema_version": ASSURANCE_ENVELOPE_VERSION,
        "request_fingerprint": request_fingerprint,
        "checkpoint": checkpoint,
        "sequence": sequence,
        "previous_envelope_sha512": previous_envelope_sha512,
        "canonical_state_b64": base64.b64encode(canonical_state).decode("ascii"),
        "canonical_state_sha512": _sha512_hex(canonical_state),
    }


def assurance_envelope_digest(envelope: Mapping[str, Any]) -> str:
    """Digest the full envelope for chaining to the next checkpoint."""

    return _sha512_hex(canonical_json_bytes(envelope))
