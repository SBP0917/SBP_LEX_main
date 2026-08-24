"""P-tree static detached-boundary inventory for the supply-chain lane."""

from __future__ import annotations

import ast
from typing import Any

from sbp_ptde.canonical import canonical_sha512
from sbp_ptde.constants import NO_AUTHORITY
from sbp_ptde.errors import reject

from .constants import FORBIDDEN_NETWORK_IMPORT_PREFIXES, FORBIDDEN_RUNTIME_IMPORT_PREFIXES, UNSIGNED_NOT_ADMITTED
from .source_binding import PObjectBinding, p_blob_content


def _imports_and_dynamic_calls(source: bytes, path: str) -> tuple[set[str], bool]:
    try:
        tree = ast.parse(source.decode("utf-8", errors="strict"), filename=path)
    except (UnicodeError, SyntaxError) as exc:
        raise reject("SUPPLY_CHAIN_BOUNDARY_SOURCE_INVALID") from exc
    imports: set[str] = set()
    dynamic = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                dynamic = True
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {"import_module", "exec", "eval"}:
                dynamic = True
    return imports, dynamic


def build_detached_boundary(binding: PObjectBinding) -> dict[str, Any]:
    """Prove against exact P blobs that the detached lane has no runtime attachment."""

    supply_paths = sorted(
        path for path in binding.tree if path.startswith("sbp_lex/supply_chain/") and path.endswith(".py")
    )
    runtime_paths = ["main.py"] + sorted(
        path for path in binding.tree
        if path.startswith("sbp_lex/")
        and path.endswith(".py")
        and not path.startswith("sbp_lex/supply_chain/")
        and not path.startswith("sbp_lex/local_trust/")
    )
    if not supply_paths or "main.py" not in binding.tree:
        raise reject("SUPPLY_CHAIN_BOUNDARY_P_INPUT_MISSING")
    runtime_attachment: list[str] = []
    forbidden_supply_imports: list[str] = []
    dynamic_imports: list[str] = []
    for path in runtime_paths:
        imports, dynamic = _imports_and_dynamic_calls(p_blob_content(binding, path), path)
        if dynamic:
            dynamic_imports.append(path)
        if any(name == "sbp_lex.supply_chain" or name.startswith("sbp_lex.supply_chain.") for name in imports):
            runtime_attachment.append(path)
    for path in supply_paths:
        imports, dynamic = _imports_and_dynamic_calls(p_blob_content(binding, path), path)
        if dynamic:
            dynamic_imports.append(path)
        for imported in imports:
            if imported.startswith(FORBIDDEN_RUNTIME_IMPORT_PREFIXES) or imported.startswith(FORBIDDEN_NETWORK_IMPORT_PREFIXES):
                forbidden_supply_imports.append(f"{path}:{imported}")
    failures = sorted(set(runtime_attachment + forbidden_supply_imports + dynamic_imports))
    payload = {
        "schema_id": "sbp.lex.v2.supply-chain.detached-boundary/1",
        "p_commit_oid": binding.commit.oid,
        "supply_chain_source_paths": supply_paths,
        "supply_chain_source_paths_sha512": canonical_sha512(supply_paths),
        "runtime_attachment": sorted(set(runtime_attachment)),
        "forbidden_supply_imports": sorted(set(forbidden_supply_imports)),
        "dynamic_import_or_execution_paths": sorted(set(dynamic_imports)),
        "boundary_status": "P_BOUNDARY_CLEAR" if not failures else "P_BOUNDARY_INVALID",
        "no_authority": dict(NO_AUTHORITY),
        "admission_state": UNSIGNED_NOT_ADMITTED,
    }
    payload["payload_sha512"] = canonical_sha512(payload)
    return payload
