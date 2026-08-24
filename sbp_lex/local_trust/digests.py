"""Detached implementation of the exact SBP-LEX V2 SHA-512 contract.

This module intentionally does not import the active runtime integrity package.
Its canonicalisation profile is byte-for-byte compatible with the V2 contract:
NFC strings/keys, UTF-16 key ordering, exact decimal wrappers for finite floats,
UTF-8 JSON without insignificant whitespace, and lowercase SHA-512 hex.
"""

from __future__ import annotations

import hmac
import json
import math
import unicodedata
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from decimal import Decimal
from hashlib import sha512
from typing import Any


MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_NODES = 1_000_000
MAX_CANONICAL_BYTES = 64 * 1024 * 1024


class IntegrityContractError(ValueError):
    """Raised when a value cannot cross the detached V2 integrity boundary."""


def exact_integrity_value(value: Any, *, path: str = "$") -> Any:
    """Convert JSON-like data to the exact V2 integrity number profile."""

    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IntegrityContractError(f"NONFINITE_NUMBER:{path}")
        decimal = Decimal(str(value)).normalize()
        if decimal == 0:
            decimal = Decimal(0)
        return {"exact_decimal": format(decimal, "f")}
    if type(value) is dict:
        converted: dict[str, Any] = {}
        for key, child in value.items():
            if type(key) is not str:
                raise IntegrityContractError(f"NONSTRING_KEY:{path}")
            converted[key] = exact_integrity_value(child, path=f"{path}.{key}")
        return converted
    if type(value) in {list, tuple}:
        return [
            exact_integrity_value(child, path=f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    raise IntegrityContractError(f"UNSUPPORTED_TYPE:{path}:{type(value).__name__}")


def _normalise(
    value: Any,
    *,
    path: str = "$",
    depth: int = 0,
    nodes: list[int] | None = None,
) -> Any:
    if depth > MAX_CANONICAL_DEPTH:
        raise IntegrityContractError(f"CANONICAL_DEPTH_EXCEEDED:{path}")
    counter = [0] if nodes is None else nodes
    counter[0] += 1
    if counter[0] > MAX_CANONICAL_NODES:
        raise IntegrityContractError("CANONICAL_NODE_LIMIT_EXCEEDED")
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        raise IntegrityContractError(f"FLOAT_NOT_EXACT:{path}")
    if type(value) is str:
        return unicodedata.normalize("NFC", value)
    if isinstance(value, Mapping):
        items: list[tuple[str, Any]] = []
        for key, child in value.items():
            if type(key) is not str:
                raise IntegrityContractError(f"NONSTRING_KEY:{path}")
            normalised_key = unicodedata.normalize("NFC", key)
            items.append(
                (
                    normalised_key,
                    _normalise(
                        child,
                        path=f"{path}.{normalised_key}",
                        depth=depth + 1,
                        nodes=counter,
                    ),
                )
            )
        if len({key for key, _ in items}) != len(items):
            raise IntegrityContractError(f"NORMALISED_KEY_COLLISION:{path}")
        items.sort(key=lambda item: item[0].encode("utf-16-be", errors="strict"))
        return OrderedDict(items)
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        return [
            _normalise(
                child,
                path=f"{path}[{index}]",
                depth=depth + 1,
                nodes=counter,
            )
            for index, child in enumerate(value)
        ]
    raise IntegrityContractError(f"UNSUPPORTED_TYPE:{path}:{type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    try:
        normalised = _normalise(exact_integrity_value(value))
        encoded = json.dumps(
            normalised,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except IntegrityContractError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, MemoryError) as exc:
        raise IntegrityContractError("CANONICAL_ENCODING_FAILED") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise IntegrityContractError("CANONICAL_DOCUMENT_TOO_LARGE")
    return encoded


def digest(value: Any) -> str:
    return sha512(canonical_bytes(value)).hexdigest()


def is_sha512(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def digest_equal(left: Any, right: Any) -> bool:
    return is_sha512(left) and is_sha512(right) and hmac.compare_digest(left, right)


__all__ = [
    "IntegrityContractError",
    "canonical_bytes",
    "digest",
    "digest_equal",
    "exact_integrity_value",
    "is_sha512",
]
