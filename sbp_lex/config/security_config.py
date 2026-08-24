from __future__ import annotations

from sbp_lex.security.hybrid_signature import (
    STRICT_DUAL_SIGNATURE_SUITE_ID,
    STRICT_DUAL_SIGNATURE_SUITE_VERSION,
    STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
    STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
)


# ─────────────────────────────────────────────
# V2 SECURITY CONFIG (FAIL-CLOSED PRE-ADMISSION)
# ─────────────────────────────────────────────

SIGNATURE_PROVIDER_REQUIRED = True
DEFAULT_SIGNATURE_PROVIDER = None
DEFAULT_SIGNATURE_ALGORITHM = STRICT_DUAL_SIGNATURE_SUITE_ID
DEFAULT_SIGNATURE_CUSTODY_CLASS = None
DEFAULT_SIGNATURE_EFFECT_AUTHORITY = False
SIGNATURE_SUITE_VERSION = STRICT_DUAL_SIGNATURE_SUITE_VERSION
SIGNATURE_VERIFICATION_RULE = STRICT_DUAL_SIGNATURE_VERIFICATION_RULE
SIGNATURE_REQUIRED_LANES = ("ML-DSA-87", "Ed448")
SIGNATURE_LANE_INDEPENDENT_CUSTODY_REQUIRED = True
SIGNATURE_SOFTWARE_SIGNING_PRODUCTION_ADMITTED = False
SIGNATURE_SUITE_TRANSITION_POLICY = STRICT_DUAL_SIGNATURE_TRANSITION_POLICY

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

DEFAULT_COLLECTIVE_SIGNAL_MAX_AGE_SECONDS = 300

REQUIRED_CORE_TOKENS = [
    "authority",
    "procedural_truth",
    "ptodf",
    "classification",
    "licensing",
    "aj_saaf",
    "gala",
    "abegf",
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

def build_signature_provider_config() -> dict:
    return {
        "required": SIGNATURE_PROVIDER_REQUIRED,
        "provider_name": DEFAULT_SIGNATURE_PROVIDER,
        "signature_algorithm": DEFAULT_SIGNATURE_ALGORITHM,
        "signature_suite_version": SIGNATURE_SUITE_VERSION,
        "verification_rule": SIGNATURE_VERIFICATION_RULE,
        "required_lanes": list(SIGNATURE_REQUIRED_LANES),
        "independent_lane_custody_required": (
            SIGNATURE_LANE_INDEPENDENT_CUSTODY_REQUIRED
        ),
        "software_signing_production_admitted": (
            SIGNATURE_SOFTWARE_SIGNING_PRODUCTION_ADMITTED
        ),
        "suite_transition_policy": SIGNATURE_SUITE_TRANSITION_POLICY,
        "custody_class": DEFAULT_SIGNATURE_CUSTODY_CLASS,
        "effect_authority": DEFAULT_SIGNATURE_EFFECT_AUTHORITY,
        "fallback_provider": None,
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
        "signature_provider": build_signature_provider_config(),
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
