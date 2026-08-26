"""Locked constants for the detached SBP-LEX V2 local-trust system."""

from __future__ import annotations

from pathlib import PurePosixPath
from types import MappingProxyType

CONTRACT_VERSION = "SBP_LEX_V2_LOCAL_TRUST_V2"
HYBRID_SIGNATURE_PROFILE = "SBP_LEX_V2_ML_DSA_87_ED448_AND_V1"
RETIRED_HYBRID_SIGNATURE_PROFILE = "ML_DSA_87_AND_ED448_REQUIRED_V1"
DUAL_SIGNATURE_VERIFICATION_RULE = "ALL_LANES_REQUIRED"
DUAL_SIGNATURE_TRANSITION_POLICY = (
    "NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK"
)
SIGNING_DOMAIN = b"SBP-LEX/V2/LOCAL-TRUST/STRICT-DUAL-SIGNATURE/1\x00"
GENESIS = "GENESIS"
SHA512_HEX_LENGTH = 128
PYTHON_DEPENDENCY_LOCK_SCHEMA = "sbp.lex.v2.python-dependency-lock/3"
PYTHON_DEPENDENCY_TARGET_ENVIRONMENT = MappingProxyType({
    "implementation": "CPython",
    "python_version": "3.12.13",
    "abi_tag": "cpython-312",
    "platform_tag": "win-amd64",
    "installed_scope": "assurance",
})
PYTHON_DEPENDENCY_ROLLBACK_FIELDS = frozenset(
    {
        "ptde_accepted_attempt_history_sequence",
        "ptde_accepted_attempt_history_sha512",
        "local_trust_accepted_package_history_sequence",
        "local_trust_accepted_package_history_sha512",
    }
)
EXTERNAL_EXECUTABLE_PIN_IDS = frozenset({"python", "cargo", "java", "alr", "git"})
MAX_EVIDENCE_FILES = 20_000
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
DEFAULT_COMMAND_TIMEOUT_SECONDS = 900

PRODUCTION = "PRODUCTION"
TEST_ONLY = "TEST_ONLY"
SIGNER_CLASSES = frozenset({PRODUCTION, TEST_ONLY})
ARTIFACT_SIGNING_PURPOSE = "LOCAL_TRUST_ARTIFACT"
CLOCK_SIGNING_PURPOSE = "TRUSTED_MONOTONIC_CLOCK"
HISTORY_SIGNING_PURPOSE = "ACCEPTED_PACKAGE_LIVE_HEAD"
SIGNING_PURPOSES = frozenset(
    {ARTIFACT_SIGNING_PURPOSE, CLOCK_SIGNING_PURPOSE, HISTORY_SIGNING_PURPOSE}
)

PASS = "PASS"
FAIL = "FAIL"
INCOMPLETE = "INCOMPLETE"
STALE = "STALE"
DIRTY = "DIRTY"

NO_AUTHORITY = MappingProxyType({
    "authority_granted": False,
    "decision_granted": False,
    "token_granted": False,
    "licence_granted": False,
    "governance_authority_granted": False,
    "execution_authority_granted": False,
    "effect_authority_granted": False,
    "publication_authority_granted": False,
    "audit_mutation_granted": False,
    "hash_chain_mutation_granted": False,
    "runtime_mutation_granted": False,
    "bypass_granted": False,
})

DETACHED_BOUNDARY = MappingProxyType({
    "local_only": True,
    "offline_verification_supported": True,
    "runtime_detached": True,
    "publication_active": False,
    "network_active": False,
    "cloud_active": False,
    "blockchain_active": False,
    "ledger_active": False,
})

DEPLOYMENT_LIMITS = MappingProxyType({
    "software_key_custody": "DEPLOYMENT_LIMITATION",
    "hardware_key_custody": "NOT_PROVEN",
    "tpm_binding": "NOT_PROVEN",
    "os_secure_boot": "NOT_PROVEN",
    "independent_validation": "NOT_PROVEN",
    "rust_tcb_active_in_python_runtime": "NOT_ACTIVE",
    "tla_formal_model_active_in_python_runtime": "NOT_ACTIVE",
    "durable_production_replay_revocation_audit_stores": "NOT_PROVEN",
    "effect_path_non_bypass": "NOT_PROVEN",
    "supply_chain_deployment": "NOT_PROVEN",
    "external_trust_and_time_authority": "NOT_PROVEN",
})

STAGE_ORDER = (
    "manifest",
    "execution_envelope",
    "evidence_chain",
    "regression_matrix",
    "constitutional_gates",
    "toolchain_guard",
    "capstone",
    "release_integrity",
    "adversarial_harness",
    "university_dossier",
)

STAGE_SCHEMAS = MappingProxyType(
    {
        stage: f"SBP_LEX_V2_LOCAL_TRUST_{stage.upper()}_V1"
        for stage in STAGE_ORDER
    }
)
TRUST_CONTEXT_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_STRICT_DUAL_PUBLIC_CONTEXT_V1"
TIME_EVIDENCE_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_TIME_EVIDENCE_V1"
ARTIFACT_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_SIGNED_ARTIFACT_V1"
ACCEPTED_HISTORY_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_ACCEPTED_PACKAGE_HISTORY_V1"
REPOSITORY_IDENTITY_SCHEMA = "SBP_LEX_V2_LOCAL_TRUST_REPOSITORY_IDENTITY_V1"

# Each required group must resolve to at least one safe regular file.  Optional
# groups are retained in the manifest with an explicit MISSING status.
EVIDENCE_GROUPS = (
    MappingProxyType({
        "group_id": "local_trust_source",
        "required": True,
        "roots": ("sbp_lex/local_trust",),
    }),
    MappingProxyType({
        "group_id": "python_security_integrity",
        "required": True,
        "paths": (
            "sbp_lex/security/integrity.py",
            "sbp_lex/security/signature_provider.py",
            "sbp_lex/security/application_integrity.py",
        ),
    }),
    MappingProxyType({
        "group_id": "foundational_controls",
        "required": True,
        "paths": (
            "sbp_lex/baseline/application_startup.py",
            "sbp_lex/baseline/foundational_baseline.py",
            "sbp_lex/baseline/request_controls.py",
        ),
    }),
    MappingProxyType({
        "group_id": "rust_security_core",
        "required": True,
        "roots": ("security_core",),
    }),
    MappingProxyType({
        "group_id": "wire_v2",
        "required": True,
        "roots": ("wire_protocol/v2",),
    }),
    MappingProxyType({
        "group_id": "cross_language_reconciliation",
        "required": True,
        "roots": ("cross_language_reconciliation",),
    }),
    MappingProxyType({
        "group_id": "formal_tla",
        "required": True,
        "paths": (
            "formal/tla/SBPLEXV2.tla",
            "formal/tla/SBPLEXV2.cfg",
            "formal/tla/README.md",
        ),
    }),
    MappingProxyType({
        "group_id": "spark_safety_monitor",
        "required": True,
        "roots": ("spark_safety_monitor/src", "spark_safety_monitor/config"),
        "paths": ("spark_safety_monitor/spark_safety_monitor.gpr",),
    }),
    MappingProxyType({
        "group_id": "validation_contracts",
        "required": True,
        "paths": (
            "tools/run_preexternal_validation.ps1",
            "tools/build_sha512_handover_snapshot.ps1",
            "docs/validation/SHA512_HANDOVER_STATUS.md",
            "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
            "docs/validation/V2_CANONICAL_STATUS.md",
            "docs/security/RUST_TCB_AND_TLA_VALIDATION.md",
            "runtime_artifacts/toolchains/tla2tools.jar",
        ),
    }),
    MappingProxyType({
        "group_id": "validation_logs_and_snapshot",
        "required": True,
        "roots": (
            "runtime_artifacts/sha512_handover",
        ),
    }),
)

DEPENDENCY_LOCK_PATHS = (
    "python-dependencies.lock.json",
    "requirements-production.lock.txt",
    "requirements-test.lock.txt",
    "runtime.txt",
    "hybrid_signature_rust/Cargo.lock",
    "independent_verifier_rust/Cargo.lock",
    "polyglot/rust/v2_assurance_kernel/Cargo.lock",
    "rust_authority_service/Cargo.lock",
    "security_core/Cargo.lock",
    "trusted_core_rust/Cargo.lock",
    "wire_protocol/rust/Cargo.lock",
    "wire_protocol/v2/rust/Cargo.lock",
    "spark_safety_monitor/alire/alire.lock",
    "runtime_artifacts/toolchains/tla2tools.jar",
)

_RUST_ASSURANCE_CRATES = (
    ("hybrid_signature_rust", "hybrid_signature_rust/Cargo.toml", ()),
    ("independent_verifier_rust", "independent_verifier_rust/Cargo.toml", ()),
    (
        "polyglot_v2_assurance_kernel",
        "polyglot/rust/v2_assurance_kernel/Cargo.toml",
        (),
    ),
    (
        "rust_authority_service",
        "rust_authority_service/Cargo.toml",
        ("--features", "evidence-only-fixtures"),
    ),
    ("security_core", "security_core/Cargo.toml", ()),
    ("trusted_core_rust", "trusted_core_rust/Cargo.toml", ()),
    ("wire_protocol_rust", "wire_protocol/rust/Cargo.toml", ()),
    ("wire_protocol_v2_rust", "wire_protocol/v2/rust/Cargo.toml", ()),
)
_RUST_ASSURANCE_COMMANDS = tuple(
    command
    for crate_id, manifest, feature_arguments in _RUST_ASSURANCE_CRATES
    for command in (
        (
            f"rust_{crate_id}_test",
            (
                "cargo", "test", "--offline", "--locked", "--manifest-path",
                manifest, *feature_arguments,
            ),
            True,
            ".",
        ),
        (
            f"rust_{crate_id}_check",
            (
                "cargo", "check", "--offline", "--locked", "--all-targets",
                "--manifest-path", manifest, *feature_arguments,
            ),
            True,
            ".",
        ),
        (
            f"rust_{crate_id}_clippy",
            (
                "cargo", "clippy", "--offline", "--locked", "--all-targets",
                "--manifest-path", manifest, *feature_arguments, "--", "-D", "warnings",
            ),
            True,
            ".",
        ),
        (
            f"rust_{crate_id}_fmt",
            ("cargo", "fmt", "--manifest-path", manifest, "--", "--check"),
            True,
            ".",
        ),
        (
            f"rust_{crate_id}_rustsec",
            (
                "cargo", "audit", "--no-fetch", "--deny", "warnings", "--file",
                str(PurePosixPath(manifest).parent / "Cargo.lock"),
            ),
            True,
            ".",
        ),
    )
)

COMMAND_POLICY = (
    ("python_tests", ("{python}", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"), True, "."),
    ("wire_v2_python", ("{python}", "wire_protocol/v2/run_python_tests.py"), True, "."),
    ("cross_language", ("{python}", "-m", "unittest", "discover", "-s", "cross_language_reconciliation"), True, "."),
    ("tool_python_version", ("{python}", "--version"), True, "."),
    ("tool_cargo_version", ("cargo", "--version"), True, "."),
    ("tool_java_version", ("java", "--version"), True, "."),
    ("tool_alr_version", ("alr", "--version"), True, "."),
    ("tool_git_version", ("git", "--version"), True, "."),
    *_RUST_ASSURANCE_COMMANDS,
    (
        "formal_tla_v2_tpm_disabled",
        (
            "java", "-Xmx4g", "-cp", "runtime_artifacts/toolchains/tla2tools.jar",
            "tlc2.TLC", "-config", "formal/tla/SBPLEXV2.cfg", "formal/tla/SBPLEXV2.tla",
        ),
        True,
        ".",
    ),
    (
        "formal_tla_v2_tpm_admitted",
        (
            "java", "-Xmx4g", "-cp", "runtime_artifacts/toolchains/tla2tools.jar",
            "tlc2.TLC", "-config", "formal/tla/SBPLEXV2_TPM_ADMITTED_NONVACUITY.cfg",
            "formal/tla/SBPLEXV2.tla",
        ),
        True,
        ".",
    ),
    (
        "formal_tla_authority",
        (
            "java", "-Xmx4g", "-cp", "runtime_artifacts/toolchains/tla2tools.jar",
            "tlc2.TLC", "-config", "formal/SBPLexAuthority.cfg",
            "formal/SBPLexAuthority.tla",
        ),
        True,
        ".",
    ),
    (
        "formal_python_explorer",
        ("{python}", "formal/check_model.py"),
        True,
        ".",
    ),
    (
        "spark_gnatprove_native",
        (
            "alr", "gnatprove", "-P", "spark_safety_monitor.gpr",
            "--mode=all", "--level=2", "--report=all",
        ),
        True,
        "spark_safety_monitor",
    ),
    (
        "spark_build_native",
        ("alr", "build"),
        True,
        "spark_safety_monitor",
    ),
    (
        "spark_assertion_harness",
        ("{python}", "spark_safety_monitor/tools/run_harness.py"),
        True,
        ".",
    ),
)

FORBIDDEN_SOURCE_IMPORTS = (
    "import main",
    "from main import",
    "sbp_lex.pipeline",
    "sbp_lex.runtime",
    "sbp_lex.execution",
    "sbp_lex.audit",
    "sbp_lex.security.token_stack",
)

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".pytest_cache",
        "__pycache__",
        "target",
        "obj",
        "bin",
    }
)
IGNORED_SUFFIXES = frozenset({".pyc", ".pyo"})


def stage_sequence(stage: str) -> int:
    """Return the locked one-based sequence for a local-trust stage."""

    return STAGE_ORDER.index(stage) + 1


def posix_path(value: str) -> str:
    return PurePosixPath(value).as_posix()
