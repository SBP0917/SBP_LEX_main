from __future__ import annotations


# ─────────────────────────────────────────────
# V6 PIPELINE CONFIG (LOCKED)
# ─────────────────────────────────────────────

PIPELINE_NAME = "SBP_LEX_V6"
PIPELINE_MODE = "FAIL_CLOSED"
PIPELINE_EXTERNALITY = "STRUCTURALLY_EXTERNAL"
PIPELINE_SUPERIORITY = "HIERARCHICALLY_SUPERIOR"
PIPELINE_NON_BYPASS = True


# ─────────────────────────────────────────────
# LOCKED PIPELINE ORDER
# ─────────────────────────────────────────────

PIPELINE_ORDER = [
    "entry",
    "state_construction",
    "collective_attach",
    "root_of_trust",
    "classification",
    "licensing",
    "governance",
    "grc",
    "domain_wrap",
    "aurion_candidate",
    "aurion_runtime",
    "execution_gate",
    "audit",
]


# ─────────────────────────────────────────────
# ROOT OF TRUST
# ─────────────────────────────────────────────

ROOT_OF_TRUST_STAGES = [
    "anchor_validation",
    "attestation",
    "attestation_consensus",
    "truth_anchor",
    "truth_continuity",
    "truth_expiry",
    "truth_revocation",
    "procedural_truth",
]


# ─────────────────────────────────────────────
# AURION LOOP CONTROL
# ─────────────────────────────────────────────

AURION_MAX_CANDIDATE_ATTEMPTS = 12
AURION_REQUIRE_NEXT_CANDIDATE_RESULT = "require_next_candidate"
AURION_PASS_RESULT = "pass"
AURION_FAIL_RESULT = "fail"
AURION_ESCALATE_RESULT = "escalate"


# ─────────────────────────────────────────────
# DOMAIN RESULTS
# ─────────────────────────────────────────────

DOMAIN_PASS_RESULT = "pass"
DOMAIN_FAIL_RESULT = "fail"
DOMAIN_ESCALATE_RESULT = "escalate"


# ─────────────────────────────────────────────
# EXECUTION RESULTS
# ─────────────────────────────────────────────

EXECUTION_APPROVED = "APPROVED"
EXECUTION_DENIED = "DENY"
EXECUTION_ESCALATED = "ESCALATE"

EXECUTION_RESULT_EXECUTE = "EXECUTE"
EXECUTION_RESULT_HALT = "HALT"


# ─────────────────────────────────────────────
# GOVERNANCE RESULTS
# ─────────────────────────────────────────────

GOVERNANCE_ALLOW = "ALLOW"
GOVERNANCE_DENY = "DENY"
GOVERNANCE_ESCALATE = "ESCALATE"


# ─────────────────────────────────────────────
# PROCEDURAL TRUTH RESULTS
# ─────────────────────────────────────────────

PROCEDURAL_TRUTH_PASS = "PASS"
PROCEDURAL_TRUTH_FAIL = "FAIL"
PROCEDURAL_TRUTH_ESCALATE = "ESCALATE"


# ─────────────────────────────────────────────
# CLASSIFICATION / LICENSING RESULTS
# ─────────────────────────────────────────────

CLASSIFICATION_ALLOW = "ALLOW"
CLASSIFICATION_DENY = "DENY"
CLASSIFICATION_ESCALATE = "ESCALATE"

LICENSING_ALLOW = "ALLOW"
LICENSING_DENY = "DENY"
LICENSING_ESCALATE = "ESCALATE"


# ─────────────────────────────────────────────
# RE-ENTRY / GRC CONTROL
# ─────────────────────────────────────────────

ALLOW_IDENTICAL_DENIED_RESUBMISSION = False
ALLOW_DIRECT_EXECUTION_BYPASS = False
ALLOW_UNGOVERNED_REENTRY = False

VALID_POST_DENIAL_ACTIONS = [
    "materially_changed_request",
    "fallback_request",
    "escalation_request",
    "safe_state",
    "abandon_request",
]


# ─────────────────────────────────────────────
# EXECUTION GATE REQUIRED CHECKS
# ─────────────────────────────────────────────

EXECUTION_GATE_REQUIRED_CHECKS = [
    "hash_chain_presence",
    "governance_allow",
    "procedural_truth_pass",
    "corroboration_threshold_satisfied",
    "domain_pass",
    "aurion_pass",
    "required_tokens_present",
    "token_digest_valid",
    "token_signature_valid",
    "request_fingerprint_match",
    "state_hash_match",
    "tier_consistency",
    "execution_boundary_clear",
    "execution_attestation_clear",
    "collective_signal_consistency",
]


# ─────────────────────────────────────────────
# HASH CHAIN STAGES
# ─────────────────────────────────────────────

HASH_CHAIN_REQUIRED_STAGES = [
    "collective_attach",
    "root_of_trust",
    "classification",
    "licensing",
    "governance",
    "domain_wrap",
    "aurion_candidate",
    "aurion_runtime",
    "execution_gate",
    "audit",
]


# ─────────────────────────────────────────────
# BUILDERS
# ─────────────────────────────────────────────

def build_pipeline_identity() -> dict:
    return {
        "name": PIPELINE_NAME,
        "mode": PIPELINE_MODE,
        "externality": PIPELINE_EXTERNALITY,
        "superiority": PIPELINE_SUPERIORITY,
        "non_bypass": PIPELINE_NON_BYPASS,
    }


def build_pipeline_order() -> dict:
    return {
        "order": list(PIPELINE_ORDER),
        "root_of_trust_stages": list(ROOT_OF_TRUST_STAGES),
        "hash_chain_required_stages": list(HASH_CHAIN_REQUIRED_STAGES),
    }


def build_aurion_config() -> dict:
    return {
        "max_candidate_attempts": AURION_MAX_CANDIDATE_ATTEMPTS,
        "pass_result": AURION_PASS_RESULT,
        "fail_result": AURION_FAIL_RESULT,
        "escalate_result": AURION_ESCALATE_RESULT,
        "require_next_candidate_result": AURION_REQUIRE_NEXT_CANDIDATE_RESULT,
    }


def build_reentry_config() -> dict:
    return {
        "allow_identical_denied_resubmission": ALLOW_IDENTICAL_DENIED_RESUBMISSION,
        "allow_direct_execution_bypass": ALLOW_DIRECT_EXECUTION_BYPASS,
        "allow_ungoverned_reentry": ALLOW_UNGOVERNED_REENTRY,
        "valid_post_denial_actions": list(VALID_POST_DENIAL_ACTIONS),
    }


def build_execution_gate_config() -> dict:
    return {
        "required_checks": list(EXECUTION_GATE_REQUIRED_CHECKS),
        "execute_result": EXECUTION_RESULT_EXECUTE,
        "halt_result": EXECUTION_RESULT_HALT,
        "approved_decision": EXECUTION_APPROVED,
        "denied_decision": EXECUTION_DENIED,
        "escalated_decision": EXECUTION_ESCALATED,
    }


def build_result_constants() -> dict:
    return {
        "governance": {
            "allow": GOVERNANCE_ALLOW,
            "deny": GOVERNANCE_DENY,
            "escalate": GOVERNANCE_ESCALATE,
        },
        "procedural_truth": {
            "pass": PROCEDURAL_TRUTH_PASS,
            "fail": PROCEDURAL_TRUTH_FAIL,
            "escalate": PROCEDURAL_TRUTH_ESCALATE,
        },
        "classification": {
            "allow": CLASSIFICATION_ALLOW,
            "deny": CLASSIFICATION_DENY,
            "escalate": CLASSIFICATION_ESCALATE,
        },
        "licensing": {
            "allow": LICENSING_ALLOW,
            "deny": LICENSING_DENY,
            "escalate": LICENSING_ESCALATE,
        },
        "domain": {
            "pass": DOMAIN_PASS_RESULT,
            "fail": DOMAIN_FAIL_RESULT,
            "escalate": DOMAIN_ESCALATE_RESULT,
        },
        "aurion": {
            "pass": AURION_PASS_RESULT,
            "fail": AURION_FAIL_RESULT,
            "escalate": AURION_ESCALATE_RESULT,
            "require_next_candidate": AURION_REQUIRE_NEXT_CANDIDATE_RESULT,
        },
        "execution": {
            "execute": EXECUTION_RESULT_EXECUTE,
            "halt": EXECUTION_RESULT_HALT,
            "approved": EXECUTION_APPROVED,
            "deny": EXECUTION_DENIED,
            "escalate": EXECUTION_ESCALATED,
        },
    }


def build_pipeline_config() -> dict:
    return {
        "identity": build_pipeline_identity(),
        "structure": build_pipeline_order(),
        "aurion": build_aurion_config(),
        "reentry": build_reentry_config(),
        "execution_gate": build_execution_gate_config(),
        "results": build_result_constants(),
}
