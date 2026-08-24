from __future__ import annotations

from copy import deepcopy
import unittest

from main import run_sbp_lex
from sbp_lex.audit.audit_ledger import verify_audit_ledger, verify_audit_record


class TerminalAuditIntegrityTests(unittest.TestCase):
    def result(self) -> dict:
        return run_sbp_lex({"action": "review"})

    def test_terminal_audit_remains_valid_after_chain_append(self) -> None:
        result = self.result()

        self.assertTrue(verify_audit_record(result))
        self.assertTrue(verify_audit_ledger(result))

    def test_legacy_observation_tamper_invalidates_audit(self) -> None:
        result = self.result()
        tampered = deepcopy(result)
        tampered.setdefault("legacy_admission_trace", []).append(
            {"engine_id": "tampered"}
        )

        self.assertFalse(verify_audit_record(tampered))

    def test_legacy_reconciliation_tamper_invalidates_audit(self) -> None:
        result = self.result()
        tampered = deepcopy(result)
        tampered.setdefault("legacy_admission_reconciliation_trace", []).append(
            {"engine_id": "tampered"}
        )

        self.assertFalse(verify_audit_record(tampered))

    def test_three_p_tamper_invalidates_audit(self) -> None:
        result = self.result()
        tampered = deepcopy(result)
        tampered["three_p_core_digest"] = "0" * 128

        self.assertFalse(verify_audit_record(tampered))

    def test_terminal_authorization_field_tamper_invalidates_audit(self) -> None:
        result = self.result()
        mutations = {
            "decision": "APPROVED",
            "execution_result": "EXECUTE",
            "execution_reason": "changed",
            "governance_result": "ALLOW",
            "governance_reason": "changed",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                tampered = deepcopy(result)
                tampered[field] = value
                self.assertFalse(verify_audit_record(tampered))

    def test_live_hash_chain_tamper_invalidates_audit(self) -> None:
        result = self.result()
        tampered = deepcopy(result)
        tampered["hash_chain"][-1]["stage"] = "changed"

        self.assertFalse(verify_audit_record(tampered))


if __name__ == "__main__":
    unittest.main()
