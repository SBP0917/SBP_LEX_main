from __future__ import annotations

from typing import Dict, Any, List

from sbp_lex.security.pqc import build_signed_object, verify_signed_object


# ─────────────────────────────────────────────
# LOCKED TOKEN NAMES
# ─────────────────────────────────────────────

REQUIRED_CORE_TOKENS: List[str] = [
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

CONDITIONAL_THRESHOLD_TOKENS: List[str] = [
    "consequentiality_threshold",
    "corroboration_threshold",
    "financial_threshold",
    "autonomy_boundary_threshold",
    "escalation_threshold",
]


# ─────────────────────────────────────────────
# STATE INITIALISATION
# ─────────────────────────────────────────────

def ensure_token_state(state: Dict[str, Any]) -> Dict[str, Any]:
    state.setdefault("tokens", {})
    state.setdefault("token_stack_valid", False)
    state.setdefault("token_verification_failures", [])
    state.setdefault("token_trace", [])
    return state


# ─────────────────────────────────────────────
# TOKEN BUILD / ISSUE
# ─────────────────────────────────────────────

def build_token(
    *,
    token_name: str,
    state: Dict[str, Any],
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
    key_id: str = "default_key",
) -> Dict[str, Any]:
    token_body = {
        "name": token_name,
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash"),
        "tier": state.get("safety_profile", {}).get("computed_tier"),
        "corroboration_required": state.get("corroboration_required"),
        "issuer": issuer,
        "issued_at_stage": issued_at_stage,
        "payload": payload,
    }

    signed = build_signed_object(token_body, key_id=key_id)
    return signed


def issue_token(
    state: Dict[str, Any],
    *,
    token_name: str,
    issuer: str,
    issued_at_stage: str,
    payload: Dict[str, Any],
    key_id: str = "default_key",
) -> Dict[str, Any]:
    state = ensure_token_state(state)

    token = build_token(
        token_name=token_name,
        state=state,
        issuer=issuer,
        issued_at_stage=issued_at_stage,
        payload=payload,
        key_id=key_id,
    )

    state["tokens"][token_name] = token
    state["token_trace"].append(
        {
            "event": "issued",
            "token": token_name,
            "issuer": issuer,
            "stage": issued_at_stage,
        }
    )
    return state


# ─────────────────────────────────────────────
# TOKEN VERIFICATION
# ─────────────────────────────────────────────

def verify_token(
    state: Dict[str, Any],
    token_name: str,
) -> bool:
    token = state.get("tokens", {}).get(token_name)
    if not token:
        return False

    if not verify_signed_object(token):
        return False

    if token.get("request_fingerprint") != state.get("request_fingerprint"):
        return False

    if token.get("state_hash") != state.get("state_hash"):
        return False

    if token.get("tier") != state.get("safety_profile", {}).get("computed_tier"):
        return False

    if token.get("corroboration_required") != state.get("corroboration_required"):
        return False

    return True


def verify_required_tokens(
    state: Dict[str, Any],
    *,
    required_threshold_tokens: List[str] | None = None,
) -> Dict[str, Any]:
    state = ensure_token_state(state)

    failures: List[str] = []
    token_names = list(REQUIRED_CORE_TOKENS)

    if required_threshold_tokens:
        token_names.extend(required_threshold_tokens)

    for token_name in token_names:
        passed = verify_token(state, token_name)
        state["token_trace"].append(
            {
                "event": "verified",
                "token": token_name,
                "passed": passed,
            }
        )
        if not passed:
            failures.append(token_name)

    state["token_verification_failures"] = failures
    state["token_stack_valid"] = len(failures) == 0
    return state


# ─────────────────────────────────────────────
# THRESHOLD TOKEN HELPERS
# ─────────────────────────────────────────────

def get_required_threshold_tokens(state: Dict[str, Any]) -> List[str]:
    required: List[str] = []

    if state.get("safety_profile", {}).get("computed_tier"):
        required.append("consequentiality_threshold")

    if state.get("corroboration_required") is not None:
        required.append("corroboration_threshold")

    if state.get("financial_amount") is not None:
        required.append("financial_threshold")

    if state.get("autonomy_boundary_required") is True:
        required.append("autonomy_boundary_threshold")

    if state.get("escalation_threshold_required") is True:
        required.append("escalation_threshold")

    return required
