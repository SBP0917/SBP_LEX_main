"""Detached canonical JSON and SHA-512 primitives for V2 PVPL."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Any

from .constants import (
    MAX_DEPTH,
    MAX_DOCUMENT_BYTES,
    MAX_FIELDS,
    MAX_LIST_ITEMS,
    MAX_STRING_BYTES,
    MAX_TOTAL_NODES,
    SHA512_HEX_LENGTH,
)
from .errors import PVPLValidationError, reject


@dataclass
class _TraversalBudget:
    nodes_remaining: int = MAX_TOTAL_NODES
    string_bytes_remaining: int = MAX_DOCUMENT_BYTES

    def consume_node(self) -> None:
        self.nodes_remaining -= 1
        if self.nodes_remaining < 0:
            raise reject("CANONICAL_JSON_TOTAL_NODES_EXCEEDED")

    def consume_string(self, size: int) -> None:
        self.string_bytes_remaining -= size
        if self.string_bytes_remaining < 0:
            raise reject("CANONICAL_JSON_TOTAL_STRING_BYTES_EXCEEDED")


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="strict")


def _normalise(
    value: Any,
    *,
    depth: int = 0,
    budget: _TraversalBudget | None = None,
) -> Any:
    if budget is None:
        budget = _TraversalBudget()
    if depth > MAX_DEPTH:
        raise reject("CANONICAL_JSON_DEPTH_EXCEEDED")
    budget.consume_node()
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > 9_223_372_036_854_775_807:
            raise reject("CANONICAL_JSON_INTEGER_INVALID")
        return value
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise reject("CANONICAL_JSON_STRING_INVALID") from exc
        if (
            "\x00" in value
            or len(encoded) > MAX_STRING_BYTES
            or unicodedata.normalize("NFC", value) != value
        ):
            raise reject("CANONICAL_JSON_STRING_INVALID")
        budget.consume_string(len(encoded))
        return value
    if type(value) is list:
        if len(value) > MAX_LIST_ITEMS:
            raise reject("CANONICAL_JSON_LIST_TOO_LARGE")
        return [
            _normalise(item, depth=depth + 1, budget=budget) for item in value
        ]
    if type(value) is dict:
        if len(value) > MAX_FIELDS:
            raise reject("CANONICAL_JSON_OBJECT_TOO_LARGE")
        if any(type(key) is not str for key in value):
            raise reject("CANONICAL_JSON_KEY_INVALID")
        result: dict[str, Any] = {}
        for key in sorted(value, key=_utf16_key):
            normalised_key = _normalise(key, depth=depth + 1, budget=budget)
            if normalised_key in result:
                raise reject("CANONICAL_JSON_DUPLICATE_KEY")
            result[normalised_key] = _normalise(
                value[key], depth=depth + 1, budget=budget
            )
        return result
    raise reject("CANONICAL_JSON_TYPE_INVALID")


def canonical_bytes(value: Any) -> bytes:
    try:
        normalised = _normalise(value)
    except PVPLValidationError:
        raise
    except (KeyError, RuntimeError, UnicodeError, MemoryError) as exc:
        raise reject("CANONICAL_JSON_NORMALISATION_FAILED") from exc
    try:
        encoded = json.dumps(
            normalised,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise reject("CANONICAL_JSON_ENCODING_INVALID") from exc
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise reject("CANONICAL_JSON_DOCUMENT_TOO_LARGE")
    return encoded


def canonical_document_bytes(value: Any) -> bytes:
    encoded = canonical_bytes(value)
    if len(encoded) + 1 > MAX_DOCUMENT_BYTES:
        raise reject("CANONICAL_JSON_DOCUMENT_TOO_LARGE")
    return encoded + b"\n"


def canonical_sha512(value: Any) -> str:
    return hashlib.sha512(canonical_bytes(value)).hexdigest()


def require_sha512(value: Any, code: str = "SHA512_INVALID") -> str:
    if (
        type(value) is not str
        or len(value) != SHA512_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise reject(code)
    return value


def nonnegative_int(value: Any, code: str) -> int:
    if type(value) is not int or value < 0 or value > 9_223_372_036_854_775_807:
        raise reject(code)
    return value


def exact_fields(
    value: Any, expected: AbstractSet[str], code: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise reject(f"{code}_FIELDS_INVALID")
    return value


def _reject_float(_: str) -> Any:
    raise reject("CANONICAL_JSON_FLOAT_REJECTED")


def _reject_constant(_: str) -> Any:
    raise reject("CANONICAL_JSON_CONSTANT_REJECTED")


def _parse_integer(value: str) -> int:
    if len(value) > 20:
        raise reject("CANONICAL_JSON_INTEGER_INVALID")
    try:
        parsed = int(value, 10)
    except ValueError as exc:
        raise reject("CANONICAL_JSON_INTEGER_INVALID") from exc
    if abs(parsed) > 9_223_372_036_854_775_807:
        raise reject("CANONICAL_JSON_INTEGER_INVALID")
    return parsed


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise reject("CANONICAL_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def parse_canonical_document(data: bytes) -> dict[str, Any]:
    if type(data) is not bytes or not data or len(data) > MAX_DOCUMENT_BYTES:
        raise reject("JSON_DOCUMENT_BYTES_INVALID")
    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except PVPLValidationError:
        raise
    except UnicodeError as exc:
        raise reject("JSON_DOCUMENT_UTF8_INVALID") from exc
    except json.JSONDecodeError as exc:
        raise reject("JSON_DOCUMENT_INVALID") from exc
    except (RecursionError, MemoryError) as exc:
        raise reject("JSON_DOCUMENT_COMPLEXITY_INVALID") from exc
    except ValueError as exc:
        raise reject("JSON_DOCUMENT_VALUE_INVALID") from exc
    if type(value) is not dict or canonical_document_bytes(value) != data:
        raise reject("JSON_DOCUMENT_NOT_CANONICAL")
    return value


__all__ = [
    "canonical_bytes",
    "canonical_document_bytes",
    "canonical_sha512",
    "exact_fields",
    "nonnegative_int",
    "parse_canonical_document",
    "require_sha512",
]
