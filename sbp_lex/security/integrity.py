from __future__ import annotations

import math
from decimal import Decimal
from hashlib import sha512
from typing import Any

from sbp_lex.assurance.envelope import canonical_json_bytes


GENESIS_HASH = "GENESIS"


class IntegrityContractError(ValueError):
    """Raised when decision data cannot cross the integrity boundary exactly."""


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


def canonical_integrity_bytes(value: Any) -> bytes:
    return canonical_json_bytes(exact_integrity_value(value))


def canonical_integrity_hash(value: Any) -> str:
    return sha512(canonical_integrity_bytes(value)).hexdigest()


def is_sha512(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 128
        and all(character in "0123456789abcdef" for character in value)
    )


def build_hash_chain_entry(
    *,
    previous_hash: str,
    stage: str,
    payload: dict[str, Any],
) -> dict[str, str]:
    if previous_hash != GENESIS_HASH and not is_sha512(previous_hash):
        raise IntegrityContractError("PREVIOUS_HASH_INVALID")
    if type(stage) is not str or not stage:
        raise IntegrityContractError("HASH_CHAIN_STAGE_INVALID")
    if type(payload) is not dict:
        raise IntegrityContractError("HASH_CHAIN_PAYLOAD_INVALID")
    entry = {
        "stage": stage,
        "previous_hash": previous_hash,
        "payload_hash": canonical_integrity_hash(payload),
    }
    entry["hash"] = canonical_integrity_hash(entry)
    return entry


def verify_hash_chain_entries(chain: Any, state_hash: Any) -> bool:
    if type(chain) is not list or not chain:
        return False
    previous_hash = GENESIS_HASH
    for entry in chain:
        if type(entry) is not dict or set(entry) != {
            "stage",
            "previous_hash",
            "payload_hash",
            "hash",
        }:
            return False
        if type(entry["stage"]) is not str or not entry["stage"]:
            return False
        if entry["previous_hash"] != previous_hash:
            return False
        if not is_sha512(entry["payload_hash"]) or not is_sha512(entry["hash"]):
            return False
        unsigned_entry = {
            "stage": entry["stage"],
            "previous_hash": entry["previous_hash"],
            "payload_hash": entry["payload_hash"],
        }
        try:
            expected_hash = canonical_integrity_hash(unsigned_entry)
        except IntegrityContractError:
            return False
        if entry["hash"] != expected_hash:
            return False
        previous_hash = entry["hash"]
    return state_hash == previous_hash
