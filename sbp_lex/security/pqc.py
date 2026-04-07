from __future__ import annotations

from typing import Dict, Any
from hashlib import sha256
import base64
import json


# ─────────────────────────────────────────────
# PQC PLACEHOLDER (V6 LOCKED)
# ─────────────────────────────────────────────

def compute_digest(payload: Dict[str, Any]) -> str:
    """
    Deterministic digest for tokens and signals.
    """
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return sha256(encoded).hexdigest()


def sign_payload(payload: Dict[str, Any], key_id: str = "default_key") -> Dict[str, Any]:
    """
    Placeholder PQC signing (lattice-ready hook).
    """
    digest = compute_digest(payload)

    signature_data = base64.b64encode(digest.encode()).decode()

    return {
        "provider": "LATTICE_PQC_PLACEHOLDER",
        "algorithm": "DILITHIUM_PLACEHOLDER",
        "key_id": key_id,
        "signature_data": signature_data,
    }


def verify_signature(payload: Dict[str, Any], signature: Dict[str, Any]) -> bool:
    """
    Placeholder verification.
    """
    if not signature:
        return False

    expected_digest = compute_digest(payload)
    expected_sig = base64.b64encode(expected_digest.encode()).decode()

    return signature.get("signature_data") == expected_sig


def build_signed_object(payload: Dict[str, Any], key_id: str = "default_key") -> Dict[str, Any]:
    """
    Attach digest + signature.
    """
    digest = compute_digest(payload)
    signature = sign_payload(payload, key_id=key_id)

    return {
        **payload,
        "digest": digest,
        "signature": signature,
        "verified": False,
    }


def verify_signed_object(obj: Dict[str, Any]) -> bool:
    """
    Verify digest + signature.
    """
    if "digest" not in obj or "signature" not in obj:
        return False

    payload = {k: v for k, v in obj.items() if k not in ["digest", "signature", "verified"]}

    expected_digest = compute_digest(payload)
    if obj["digest"] != expected_digest:
        return False

    return verify_signature(payload, obj["signature"])
