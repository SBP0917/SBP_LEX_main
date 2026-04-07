from __future__ import annotations


# ─────────────────────────────────────────────
# V6 SECURITY CONFIG (LOCKED)
# ─────────────────────────────────────────────

PQC_ENABLED = True
PQC_PROVIDER_NAME = "LATTICE_BINDABLE"
PQC_STRICT_FAIL_CLOSED = True

SIGNATURE_REQUIRED = True
DIGEST_REQUIRED = True
HASH_CHAIN_REQUIRED = True

COLLECTIVE_SIGNAL_SIGNATURE_REQUIRED = True
COLLECTIVE_SIGNAL_DIGEST_REQUIRED = True
COLLECTIVE_SIGNAL_FRESHNESS_REQUIRED = True

TOKEN_SIGNATURE_REQUIRED = True
TOKEN_DIGEST_REQUIRED = True
TOKEN_STATE_HASH_BINDING_REQUIRED = True
TOKEN_REQUEST_FINGERPRINT_BINDING_REQUIRED = True
TOKEN_TIER_BINDING_REQUIRED = True

NON_REPEAT_ENFORCEMENT = True
FAIL_ON_IDENTICAL_DENIED_RESUBMISSION = True

EXECUTION_GATE_FAIL_CLOSED = True
HALT_ON_HASH_CHAIN_FAILURE = True
HALT_ON_TOKEN_FAILURE = True
HALT_ON_COLLECTIVE_SIGNAL_FAILURE = True

AUDIT_HASH_REQUIRED = True
AUDIT_LEDGER_REQUIRED = True

DEFAULT_SIGNATURE_ALGORITHM = "LATTICE_PQC_PLACEHOLDER"
DEFAULT_SIGNATURE_ENCODING = "BASE64_PLACEHOLDER"

DEFAULT_COLLECTIVE_SIGNAL_MAX_AGE_SECONDS = 300

REQUIRED_CORE_TOKENS = [
    "authority",
    "procedural_truth",
    "classification",
    "licensing",
    "governance",
    "domain",
    "aurion",
    "execution_boundary",
    "execution_attestation",
]

CONDITIONAL_THRESHOLD_TOKENS = [
    "consequentiality_threshold",
    "corroboration_threshold",
    "financial_threshold",
    "autonomy_boundary_threshold",
    "escalation_threshold",
]


# ─────────────────────────────────────────────
# BUILDERS
# ─────────────────────────────────────────────

def build_pqc_config() -> dict:
    return {
        "enabled": PQC_ENABLED,
        "provider_name": PQC_PROVIDER_NAME,
        "strict_fail_closed": PQC_STRICT_FAIL_CLOSED,
        "signature_algorithm": DEFAULT_SIGNATURE_ALGORITHM,
        "signature_encoding": DEFAULT_SIGNATURE_ENCODING,
    }


def build_token_requirements() -> dict:
    return {
        "required_core_tokens": list(REQUIRED_CORE_TOKENS),
        "conditional_threshold_tokens": list(CONDITIONAL_THRESHOLD_TOKENS),
        "signature_required": TOKEN_SIGNATURE_REQUIRED,
        "digest_required": TOKEN_DIGEST_REQUIRED,
        "state_hash_binding_required": TOKEN_STATE_HASH_BINDING_REQUIRED,
        "request_fingerprint_binding_required": TOKEN_REQUEST_FINGERPRINT_BINDING_REQUIRED,
        "tier_binding_required": TOKEN_TIER_BINDING_REQUIRED,
    }


def build_collective_signal_security() -> dict:
    return {
        "signature_required": COLLECTIVE_SIGNAL_SIGNATURE_REQUIRED,
        "digest_required": COLLECTIVE_SIGNAL_DIGEST_REQUIRED,
        "freshness_required": COLLECTIVE_SIGNAL_FRESHNESS_REQUIRED,
        "max_age_seconds": DEFAULT_COLLECTIVE_SIGNAL_MAX_AGE_SECONDS,
    }


def build_execution_gate_security() -> dict:
    return {
        "fail_closed": EXECUTION_GATE_FAIL_CLOSED,
        "halt_on_hash_chain_failure": HALT_ON_HASH_CHAIN_FAILURE,
        "halt_on_token_failure": HALT_ON_TOKEN_FAILURE,
        "halt_on_collective_signal_failure": HALT_ON_COLLECTIVE_SIGNAL_FAILURE,
        "hash_chain_required": HASH_CHAIN_REQUIRED,
    }


def build_audit_security() -> dict:
    return {
        "audit_hash_required": AUDIT_HASH_REQUIRED,
        "audit_ledger_required": AUDIT_LEDGER_REQUIRED,
    }


def build_security_config() -> dict:
    return {
        "pqc": build_pqc_config(),
        "tokens": build_token_requirements(),
        "collective_signals": build_collective_signal_security(),
        "execution_gate": build_execution_gate_security(),
        "audit": build_audit_security(),
        "non_repeat_enforcement": NON_REPEAT_ENFORCEMENT,
        "fail_on_identical_denied_resubmission": FAIL_ON_IDENTICAL_DENIED_RESUBMISSION,
        "signature_required": SIGNATURE_REQUIRED,
        "digest_required": DIGEST_REQUIRED,
        "hash_chain_required": HASH_CHAIN_REQUIRED,
}
