from __future__ import annotations

from typing import Dict, Any

from sbp_lex.pipeline.runner import run_v6


# ─────────────────────────────────────────────
# SBP-LEX V6 ENTRY POINT (LOCKED)
# ─────────────────────────────────────────────

def run_sbp_lex(
    request: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    External entry point for SBP-LEX V6.

    Accepts:
    - request (action, payload, context)
    - optional pre_context_signals (DTN/SKG output)

    Delegates execution to the deterministic pipeline.
    """
    return run_v6(request, pre_context_signals)


# ─────────────────────────────────────────────
# LOCAL TEST ENTRY (OPTIONAL)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    test_request = {
        "action": "test_action",
        "payload": {},
        "context": {},
    }

    result = run_sbp_lex(test_request)
    print(result)
