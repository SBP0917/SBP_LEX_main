"""Assembly of an unsigned P-bound supply-chain source package."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sbp_ptde.canonical import canonical_sha512
from sbp_ptde.constants import NO_AUTHORITY

from .boundary import build_detached_boundary
from .constants import P_SOURCE_INCOMPLETE, P_SOURCE_READY_NOT_ADMITTED, R2_INVENTORY_CLASSES, SCHEMA_ID, UNSIGNED_NOT_ADMITTED
from .python_inventory import PYTHON_LOCK_PATH, build_python_dependency_inputs
from .rust_inventory import build_rust_dependency_inputs
from .source_binding import PObjectBinding
from .toolchain_inventory import build_toolchain_contract


@dataclass(frozen=True, slots=True)
class PSourcePackage:
    """Unsigned committed-source evidence to be carried into later PTDE stages."""

    document: dict[str, Any]
    binding: PObjectBinding
    python_inputs: dict[str, Any]
    rust_inputs: dict[str, Any]
    toolchain_contract: dict[str, Any]
    boundary: dict[str, Any]


def _r2_inventory(binding: PObjectBinding) -> dict[str, dict[str, Any]]:
    entries: dict[str, list[dict[str, Any]]] = {name: [] for name in R2_INVENTORY_CLASSES}
    for path in sorted(binding.tree):
        record = binding.tree[path].record()
        if path.startswith("sbp_lex/supply_chain/"):
            entries["detached_boundary"].append(record)
        elif path in {"requirements.txt", PYTHON_LOCK_PATH}:
            entries["python_dependency_input"].append(record)
        elif path.endswith("Cargo.toml") or path.endswith("Cargo.lock"):
            entries["rust_dependency_input"].append(record)
        elif path.startswith("tools/") or path.startswith("formal/") or path.startswith("docs/"):
            entries["reproducibility_contract"].append(record)
        else:
            entries["source"].append(record)
    return {
        name: {"entries": entries[name], "inventory_sha512": canonical_sha512(entries[name])}
        for name in R2_INVENTORY_CLASSES
    }


def assemble_p_source_package(binding: PObjectBinding) -> PSourcePackage:
    """Assemble source-only evidence from the verified P tree; no host facts are observed."""

    python_inputs = build_python_dependency_inputs(binding)
    rust_inputs = build_rust_dependency_inputs(binding)
    toolchain_contract = build_toolchain_contract(binding)
    boundary = build_detached_boundary(binding)
    inventories = _r2_inventory(binding)
    incomplete = (
        python_inputs["dependency_evidence_status"] != "COMPLETE"
        or any(item["lock_status"] != "COMMITTED_LOCK_PRESENT" for item in rust_inputs["workspaces"])
    )
    status = P_SOURCE_INCOMPLETE if incomplete else P_SOURCE_READY_NOT_ADMITTED
    unsigned = {
        "schema_id": SCHEMA_ID,
        "p_binding": binding.document(),
        "r2_inventories": inventories,
        "r2_inventories_sha512": canonical_sha512(inventories),
        "python_inputs_sha512": python_inputs["payload_sha512"],
        "rust_inputs_sha512": rust_inputs["payload_sha512"],
        "toolchain_contract_sha512": toolchain_contract["payload_sha512"],
        "detached_boundary_sha512": boundary["payload_sha512"],
        "source_status": status,
        "host_observation_status": "NOT_EXECUTED",
        "no_authority": dict(NO_AUTHORITY),
        "admission_state": UNSIGNED_NOT_ADMITTED,
        "limitations": [
            "This package is committed-source evidence only.",
            "No host dependency, toolchain, validation, deployment, or signature result is asserted.",
            "Local-trust admission and PTDE T/D/E evidence are separate work.",
        ],
    }
    document = {**unsigned, "package_sha512": canonical_sha512(unsigned)}
    return PSourcePackage(document, binding, python_inputs, rust_inputs, toolchain_contract, boundary)


def build_supply_chain_package(binding: PObjectBinding) -> PSourcePackage:
    """Compatibility-named entry point requiring an already verified P binding."""

    return assemble_p_source_package(binding)
