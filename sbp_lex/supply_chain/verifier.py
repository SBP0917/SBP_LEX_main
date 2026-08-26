"""Offline validation for unsigned, P-bound supply-chain source documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sbp_ptde.canonical import canonical_sha512, exact_fields, require_sha512
from sbp_ptde.constants import NO_AUTHORITY
from sbp_ptde.errors import PTDEVerificationError, reject

from .constants import P_SOURCE_INCOMPLETE, P_SOURCE_READY_NOT_ADMITTED, SCHEMA_ID, UNSIGNED_NOT_ADMITTED
from .source_binding import PObjectBinding, validate_p_binding_document


@dataclass(frozen=True, slots=True)
class VerificationReport:
    status: str
    reasons: tuple[str, ...]
    admitted: bool


_FIELDS = frozenset({
    "schema_id", "p_binding", "r2_inventories", "r2_inventories_sha512", "python_inputs_sha512",
    "rust_inputs_sha512", "toolchain_contract_sha512", "detached_boundary_sha512", "source_status",
    "host_observation_status", "no_authority", "admission_state", "limitations", "package_sha512",
})


def verify_p_source_package(value: Any, *, binding: PObjectBinding | None = None) -> VerificationReport:
    """Verify structure and P binding; success is always explicitly not admitted."""

    try:
        document = exact_fields(value, _FIELDS, code="SUPPLY_CHAIN_PACKAGE")
        if document["schema_id"] != SCHEMA_ID or document["no_authority"] != NO_AUTHORITY:
            raise reject("SUPPLY_CHAIN_PACKAGE_CONTRACT_INVALID")
        if document["admission_state"] != UNSIGNED_NOT_ADMITTED:
            raise reject("SUPPLY_CHAIN_UNSIGNED_ADMISSION_INVALID")
        if document["source_status"] not in {P_SOURCE_READY_NOT_ADMITTED, P_SOURCE_INCOMPLETE}:
            raise reject("SUPPLY_CHAIN_SOURCE_STATUS_INVALID")
        validate_p_binding_document(document["p_binding"])
        if document["r2_inventories_sha512"] != canonical_sha512(document["r2_inventories"]):
            raise reject("SUPPLY_CHAIN_R2_INVENTORY_DIGEST_INVALID")
        for field in (
            "python_inputs_sha512", "rust_inputs_sha512", "toolchain_contract_sha512", "detached_boundary_sha512",
        ):
            require_sha512(document[field], f"SUPPLY_CHAIN_{field.upper()}_INVALID")
        unsigned = {key: document[key] for key in document if key != "package_sha512"}
        if document["package_sha512"] != canonical_sha512(unsigned):
            raise reject("SUPPLY_CHAIN_PACKAGE_DIGEST_INVALID")
        if binding is not None and document["p_binding"] != binding.document():
            raise reject("SUPPLY_CHAIN_P_BINDING_MISMATCH")
    except PTDEVerificationError as error:
        return VerificationReport("P_SOURCE_INVALID", (str(error),), False)
    except (Exception, MemoryError) as error:
        return VerificationReport("P_SOURCE_INVALID", (type(error).__name__,), False)
    return VerificationReport(document["source_status"], (), False)
