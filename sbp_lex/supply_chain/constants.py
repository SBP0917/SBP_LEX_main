"""Fixed detached supply-chain lane constants aligned to frozen V2 PTDE."""

from __future__ import annotations

from sbp_ptde.constants import MAX_STREAM_BYTE_COUNT

SCHEMA_ID = "sbp.lex.v2.supply-chain.p-source/1"
P_BINDING_SCHEMA_ID = "sbp.lex.v2.supply-chain.p-binding/2"
HOST_OBSERVATION_SCHEMA_ID = "sbp.lex.v2.supply-chain.host-observation/1"
UNSIGNED_NOT_ADMITTED = "UNSIGNED_NOT_ADMITTED"
P_SOURCE_READY_NOT_ADMITTED = "P_SOURCE_READY_NOT_ADMITTED"
P_SOURCE_INVALID = "P_SOURCE_INVALID"
P_SOURCE_INCOMPLETE = "P_SOURCE_INCOMPLETE"
P_SOURCE_UNAVAILABLE = "P_SOURCE_UNAVAILABLE"
P_SOURCE_DIRTY = "P_SOURCE_DIRTY"

SHA512_LABEL = "SHA-512"
SHA512_HEX_LENGTH = 128
MAX_SOURCE_BLOBS = 100_000
MAX_SOURCE_TOTAL_BYTES = 1_073_741_824
MAX_HOST_OUTPUT_BYTES = MAX_STREAM_BYTE_COUNT

REQUIRED_P_INPUTS = (
    "object_database",
    "p_oid",
    "expected_p_oid",
    "git_executable",
    "expected_git_executable_sha512",
    "ptde_accepted_attempt_history",
    "expected_ptde_accepted_attempt_history_sha512",
    "expected_local_trust_accepted_package_history_sequence",
    "expected_local_trust_accepted_package_history_sha512",
    "expected_python_dependency_prior_lock_sha512",
)

R2_INVENTORY_CLASSES = (
    "source",
    "python_dependency_input",
    "rust_dependency_input",
    "toolchain_contract",
    "reproducibility_contract",
    "detached_boundary",
)

FORBIDDEN_RUNTIME_IMPORT_PREFIXES = (
    "sbp_lex.pipeline",
    "sbp_lex.execution",
    "sbp_lex.audit",
    "sbp_lex.governance",
    "sbp_lex.licensing",
    "sbp_lex.security",
)

FORBIDDEN_NETWORK_IMPORT_PREFIXES = (
    "socket",
    "urllib",
    "http",
    "requests",
    "webbrowser",
    "boto3",
    "azure",
)
