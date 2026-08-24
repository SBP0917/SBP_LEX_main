"""Committed host-observation contracts; this module does not inspect local tools."""

from __future__ import annotations

from typing import Any

from sbp_ptde.canonical import canonical_sha512

from .source_binding import PObjectBinding


def build_toolchain_contract(binding: PObjectBinding) -> dict[str, Any]:
    """Declare which host facts need later pinned T/D/E lanes, without observing them."""

    required = [
        "python_executable_and_version",
        "cryptography_distribution",
        "pytest_distribution",
        "pip_visibility",
        "powershell_version",
        "git_executable_and_version",
        "cargo_executable_and_version",
        "rustc_executable_and_version",
        "rustup_toolchains",
        "java_and_tlc_artifact",
        "gnat_and_spark_tooling",
    ]
    payload: dict[str, Any] = {
        "schema_id": "sbp.lex.v2.supply-chain.toolchain-contract/1",
        "p_commit_oid": binding.commit.oid,
        "required_observations": required,
        "observation_rule": "Each observation requires a pinned PTDE-compatible full-byte lane transcript.",
        "network_access": "NOT_USED",
        "payload_sha512": "0" * 128,
    }
    payload["payload_sha512"] = canonical_sha512({key: value for key, value in payload.items() if key != "payload_sha512"})
    return payload
