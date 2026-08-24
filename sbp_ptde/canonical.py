"""Strict canonical JSON, SHA-512, and canonical Git-path primitives."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import PurePosixPath
from typing import Any

from .constants import (
    MAX_INTEGER_ABSOLUTE,
    MAX_JSON_DEPTH,
    MAX_JSON_DOCUMENT_BYTES,
    MAX_JSON_LIST_ITEMS,
    MAX_JSON_OBJECT_FIELDS,
    MAX_JSON_STRING_BYTES,
    MAX_JSON_TOTAL_NODES,
    MAX_PATH_SEGMENT_UTF8_BYTES,
    MAX_PATH_UTF8_BYTES,
)
from .errors import PTDEVerificationError, reject


_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def sha512_hex(value: bytes) -> str:
    if type(value) is not bytes:
        raise reject("SHA512_INPUT_NOT_BYTES")
    return hashlib.sha512(value).hexdigest()


def require_sha512(value: Any, code: str = "SHA512_INVALID") -> str:
    if type(value) is not str or _SHA512_RE.fullmatch(value) is None:
        raise reject(code)
    return value


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be", errors="strict")


def _string_bytes(value: str, *, code: str) -> bytes:
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise reject(code) from exc
    if len(encoded) > MAX_JSON_STRING_BYTES:
        raise reject("CANONICAL_JSON_STRING_TOO_LARGE")
    return encoded


def _normalize(
    value: Any,
    path: str = "$",
    *,
    depth: int = 0,
    nodes: list[int] | None = None,
) -> Any:
    if depth > MAX_JSON_DEPTH:
        raise reject("CANONICAL_JSON_DEPTH_EXCEEDED")
    counter = [0] if nodes is None else nodes
    counter[0] += 1
    if counter[0] > MAX_JSON_TOTAL_NODES:
        raise reject("CANONICAL_JSON_NODE_LIMIT_EXCEEDED")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_INTEGER_ABSOLUTE:
            raise reject("CANONICAL_JSON_INTEGER_OUT_OF_RANGE")
        return value
    if type(value) is float:
        raise reject("CANONICAL_JSON_FLOAT_FORBIDDEN")
    if type(value) is str:
        if unicodedata.normalize("NFC", value) != value:
            raise reject("CANONICAL_JSON_STRING_NOT_NFC")
        _string_bytes(value, code="CANONICAL_JSON_STRING_ENCODING_INVALID")
        return value
    if type(value) is list:
        if len(value) > MAX_JSON_LIST_ITEMS:
            raise reject("CANONICAL_JSON_LIST_LIMIT_EXCEEDED")
        return [
            _normalize(item, f"{path}[]", depth=depth + 1, nodes=counter)
            for item in value
        ]
    if type(value) is dict:
        if len(value) > MAX_JSON_OBJECT_FIELDS:
            raise reject("CANONICAL_JSON_OBJECT_LIMIT_EXCEEDED")
        if any(type(key) is not str for key in value):
            raise reject("CANONICAL_JSON_KEY_INVALID")
        normalized: dict[str, Any] = {}
        for key in sorted(value, key=_utf16_key):
            if unicodedata.normalize("NFC", key) != key:
                raise reject("CANONICAL_JSON_KEY_INVALID")
            _string_bytes(key, code="CANONICAL_JSON_KEY_INVALID")
            normalized[key] = _normalize(
                value[key], f"{path}.{key}", depth=depth + 1, nodes=counter
            )
        return normalized
    raise reject("CANONICAL_JSON_TYPE_FORBIDDEN")


def canonical_json_bytes(value: Any) -> bytes:
    try:
        normalized = _normalize(value)
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=False,
        ).encode("utf-8", errors="strict")
        if len(encoded) > MAX_JSON_DOCUMENT_BYTES:
            raise reject("CANONICAL_JSON_DOCUMENT_TOO_LARGE")
        return encoded
    except PTDEVerificationError:
        raise
    except (TypeError, ValueError, UnicodeError, RecursionError, MemoryError) as exc:
        raise reject("CANONICAL_JSON_ENCODING_FAILED") from exc


def canonical_json_document_bytes(value: Any) -> bytes:
    encoded = canonical_json_bytes(value)
    if len(encoded) + 1 > MAX_JSON_DOCUMENT_BYTES:
        raise reject("CANONICAL_JSON_DOCUMENT_TOO_LARGE")
    return encoded + b"\n"


def canonical_sha512(value: Any) -> str:
    return sha512_hex(canonical_json_bytes(value))


def _precheck_json_nesting(data: bytes, *, code: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for byte in data:
        if in_string:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22:
                in_string = False
            continue
        if byte == 0x22:
            in_string = True
        elif byte in (0x5B, 0x7B):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise reject(f"{code}_DEPTH_EXCEEDED")
        elif byte in (0x5D, 0x7D):
            depth -= 1
            if depth < 0:
                raise reject(f"{code}_JSON_INVALID")


def strict_json_document(data: bytes, *, code: str) -> dict[str, Any]:
    if type(data) is not bytes:
        raise reject(f"{code}_NOT_BYTES")
    if len(data) > MAX_JSON_DOCUMENT_BYTES:
        raise reject(f"{code}_DOCUMENT_TOO_LARGE")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise reject(f"{code}_TERMINAL_LF_INVALID")
    if data.startswith(b"\xef\xbb\xbf") or b"\r" in data:
        raise reject(f"{code}_ENCODING_INVALID")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise reject(f"{code}_DUPLICATE_KEY")
            result[key] = value
        return result

    def reject_constant(_: str) -> Any:
        raise reject(f"{code}_NONFINITE_NUMBER")

    def parse_integer(raw: str) -> int:
        digits = raw[1:] if raw.startswith("-") else raw
        if len(digits) > 19:
            raise reject(f"{code}_INTEGER_OUT_OF_RANGE")
        value = int(raw, 10)
        if abs(value) > MAX_INTEGER_ABSOLUTE:
            raise reject(f"{code}_INTEGER_OUT_OF_RANGE")
        return value

    try:
        _precheck_json_nesting(data, code=code)
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
            parse_float=lambda _: (_ for _ in ()).throw(
                reject(f"{code}_FLOAT_FORBIDDEN")
            ),
            parse_int=parse_integer,
        )
    except PTDEVerificationError:
        raise
    except (
        UnicodeError,
        json.JSONDecodeError,
        ValueError,
        TypeError,
        RecursionError,
        MemoryError,
    ) as exc:
        raise reject(f"{code}_JSON_INVALID") from exc
    if type(value) is not dict or canonical_json_document_bytes(value) != data:
        raise reject(f"{code}_NOT_CANONICAL")
    return value


def canonical_path(value: Any, *, code: str = "PATH_INVALID") -> str:
    if type(value) is not str or not value:
        raise reject(code)
    if unicodedata.normalize("NFC", value) != value:
        raise reject(f"{code}_NFC")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise reject(f"{code}_ENCODING") from exc
    if len(encoded) > MAX_PATH_UTF8_BYTES:
        raise reject(f"{code}_TOO_LONG")
    if "\\" in value or "\x00" in value or any(ord(char) < 32 for char in value):
        raise reject(f"{code}_CHARACTER")
    candidate = PurePosixPath(value)
    if candidate.is_absolute() or candidate.as_posix() != value:
        raise reject(f"{code}_FORM")
    for part in candidate.parts:
        if len(part.encode("utf-8", errors="strict")) > MAX_PATH_SEGMENT_UTF8_BYTES:
            raise reject(f"{code}_SEGMENT_TOO_LONG")
        if part in {"", ".", ".."} or ":" in part or part.endswith((" ", ".")):
            raise reject(f"{code}_SEGMENT")
        if part.split(".", 1)[0].upper() in _WINDOWS_RESERVED:
            raise reject(f"{code}_RESERVED")
    return value


def campaign_id(value: Any) -> str:
    result = canonical_path(value, code="CAMPAIGN_ID_INVALID")
    if len(PurePosixPath(result).parts) != 1 or _IDENTIFIER_RE.fullmatch(result) is None:
        raise reject("CAMPAIGN_ID_INVALID")
    return result


def identifier(value: Any, *, code: str) -> str:
    if type(value) is not str or _IDENTIFIER_RE.fullmatch(value) is None:
        raise reject(code)
    return value


def environment_name(value: Any) -> str:
    if type(value) is not str or _ENVIRONMENT_NAME_RE.fullmatch(value) is None:
        raise reject("LANE_ENVIRONMENT_NAME_INVALID")
    return value


def exact_fields(value: Any, fields: set[str], *, code: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != fields:
        raise reject(f"{code}_FIELDS_INVALID")
    return value


def positive_int(value: Any, *, code: str, maximum: int | None = None) -> int:
    effective_maximum = MAX_INTEGER_ABSOLUTE if maximum is None else min(
        maximum, MAX_INTEGER_ABSOLUTE
    )
    if type(value) is not int or value <= 0 or value > effective_maximum:
        raise reject(code)
    return value


def nonnegative_int(value: Any, *, code: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_INTEGER_ABSOLUTE:
        raise reject(code)
    return value


__all__ = [
    "campaign_id",
    "canonical_json_bytes",
    "canonical_json_document_bytes",
    "canonical_path",
    "canonical_sha512",
    "environment_name",
    "exact_fields",
    "identifier",
    "nonnegative_int",
    "positive_int",
    "require_sha512",
    "sha512_hex",
    "strict_json_document",
]
