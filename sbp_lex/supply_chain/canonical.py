"""Supply-chain aliases for the frozen PTDE canonical contract."""

from __future__ import annotations

from typing import Any

from sbp_ptde.canonical import canonical_json_bytes, canonical_json_document_bytes, canonical_path, canonical_sha512, strict_json_document
from sbp_ptde.errors import PTDEVerificationError

CanonicalizationError = PTDEVerificationError
canonical_bytes = canonical_json_bytes
canonical_document_bytes = canonical_json_document_bytes
canonical_repository_path = canonical_path


def sha512_hex(value: bytes) -> str:
    from sbp_ptde.canonical import sha512_hex as frozen_sha512_hex

    return frozen_sha512_hex(value)


def require_sha512_digest(value: Any, field_name: str = "digest") -> str:
    from sbp_ptde.canonical import require_sha512

    return require_sha512(value, f"SUPPLY_CHAIN_{field_name.upper()}_INVALID")


def strict_json_loads(value: bytes) -> dict[str, Any]:
    return strict_json_document(value, code="SUPPLY_CHAIN_DOCUMENT")


def require_exact_fields(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    from sbp_ptde.canonical import exact_fields

    return exact_fields(value, fields, code=code)
