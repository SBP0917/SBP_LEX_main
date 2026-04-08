from __future__ import annotations

from typing import Dict, Any
from hashlib import sha256
import json


# ─────────────────────────────────────────────
# SBP-LEX V6 AUDIT LEDGER (LOCKED)
# ─────────────────────────────────────────────

def record_audit(state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Append audit record to immutable ledger chain.
    """

    state.setdefault("audit_ledger", [])

    audit_record = state.get("audit_record", {})
    audit_hash = state.get("audit_hash")

    if not audit_record or not audit_hash:
        return state

    previous_ledger_hash = (
        state["audit_ledger"][-1]["ledger_hash"]
        if state["audit_ledger"]
        else "GENESIS"
    )

    entry = {
        "previous_ledger_hash": previous_ledger_hash,
        "audit_hash": audit_hash,
    }

    entry["ledger_hash"] = _compute_digest(entry)

    state["audit_ledger"].append(entry)

    return state


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def _compute_digest(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
    return sha256(encoded).hexdigest()
