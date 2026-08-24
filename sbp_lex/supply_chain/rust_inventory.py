"""Rust dependency inputs derived only from committed P blobs, never Cargo execution."""

from __future__ import annotations

import tomllib
from typing import Any

from sbp_ptde.canonical import canonical_sha512
from sbp_ptde.errors import reject

from .source_binding import PObjectBinding, p_blob_content


def _toml(binding: PObjectBinding, path: str) -> dict[str, Any]:
    try:
        return tomllib.loads(p_blob_content(binding, path).decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise reject("SUPPLY_CHAIN_RUST_TOML_INVALID") from exc


def build_rust_dependency_inputs(binding: PObjectBinding) -> dict[str, Any]:
    """Inventory all committed Cargo manifests/locks without live cargo metadata."""

    manifests = sorted(path for path in binding.tree if path.endswith("Cargo.toml"))
    workspaces: list[dict[str, Any]] = []
    for manifest_path in manifests:
        document = _toml(binding, manifest_path)
        package = document.get("package")
        if package is not None and type(package) is not dict:
            raise reject("SUPPLY_CHAIN_RUST_MANIFEST_INVALID")
        parent = manifest_path.rsplit("/", 1)[0] if "/" in manifest_path else ""
        lock_path = f"{parent}/Cargo.lock" if parent else "Cargo.lock"
        lock_record = binding.tree.get(lock_path)
        lock_packages: list[dict[str, Any]] = []
        if lock_record is not None:
            lock = _toml(binding, lock_path)
            raw_packages = lock.get("package", [])
            if type(raw_packages) is not list:
                raise reject("SUPPLY_CHAIN_RUST_LOCK_INVALID")
            seen: set[tuple[str, str, str]] = set()
            for raw in raw_packages:
                if type(raw) is not dict or type(raw.get("name")) is not str or type(raw.get("version")) is not str:
                    raise reject("SUPPLY_CHAIN_RUST_LOCK_PACKAGE_INVALID")
                source = raw.get("source") if type(raw.get("source")) is str else "LOCAL_OR_UNSPECIFIED"
                identity = (raw["name"].casefold(), raw["version"], source)
                if identity in seen:
                    raise reject("SUPPLY_CHAIN_RUST_LOCK_PACKAGE_DUPLICATE")
                seen.add(identity)
                dependencies = raw.get("dependencies", [])
                if type(dependencies) is not list or any(type(item) is not str for item in dependencies):
                    raise reject("SUPPLY_CHAIN_RUST_LOCK_DEPENDENCY_INVALID")
                checksum = raw.get("checksum")
                if checksum is not None and type(checksum) is not str:
                    raise reject("SUPPLY_CHAIN_RUST_LOCK_CHECKSUM_INVALID")
                lock_packages.append({
                    "name": raw["name"], "version": raw["version"], "source": source,
                    "checksum": checksum, "dependencies": sorted(dependencies),
                })
        workspaces.append({
            "manifest": binding.tree[manifest_path].record(),
            "crate": {
                "name": package.get("name") if type(package) is dict else None,
                "version": package.get("version") if type(package) is dict else None,
            },
            "lock": lock_record.record() if lock_record is not None else None,
            "lock_status": "COMMITTED_LOCK_PRESENT" if lock_record is not None else "COMMITTED_LOCK_MISSING",
            "packages": sorted(lock_packages, key=lambda item: (item["name"].casefold(), item["version"], item["source"])),
            "cargo_metadata_observation": "REQUIRES_DECLARED_T_OR_E_LANE",
        })
    payload = {
        "schema_id": "sbp.lex.v2.supply-chain.rust-inputs/1",
        "p_commit_oid": binding.commit.oid,
        "workspaces": workspaces,
        "workspace_inventory_sha512": canonical_sha512(workspaces),
        "network_access": "NOT_USED",
    }
    payload["payload_sha512"] = canonical_sha512(payload)
    return payload
