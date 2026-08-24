from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import sys
from types import ModuleType
import unittest
from unittest.mock import patch

from sbp_lex.legacy_admission import contracts as contract_module
from sbp_lex.legacy_admission import runtime
from sbp_lex.legacy_admission.contracts import (
    LEGACY_ENGINE_CONTRACTS,
    validate_legacy_contracts,
)
from sbp_lex.pipeline.runner import _run_legacy_phase
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.types import EngineResult


class LegacyAdmissionTests(unittest.TestCase):
    def fixture(self, decision: str = "APPROVED") -> dict:
        return {
            "action": "review",
            "payload": {"output": {"fact_verified_ratio": 1.0}},
            "context": {},
            "resolved_authority": "owner",
            "jurisdiction": "AU",
            "authority": {
                "primary_authority": "owner",
                "authorized_scope": ["review"],
            },
            "anchors": {
                "procedural_truth": True,
                "sovereign_knowledge_graph": True,
                "digital_twin_network": True,
                "planetary_population_constraints": True,
            },
            "constraints": {},
            "evaluation_time": 0,
            "collective_signal_status": "attached",
            "collective_signals": {},
            "authority_first_result": "ALLOW",
            "governance_result": "ALLOW",
            "domain_result": "pass",
            "aurion15_result": "pass",
            "execution_result": "EXECUTE",
            "decision": decision,
            "candidate_attempt_count": 1,
            "current_candidate": {"name": "review_primary"},
            "tokens": {},
            "hash_chain": [],
            "state_hash": "",
        }

    def test_exact_inventory_is_initial_shadow_only(self) -> None:
        validate_legacy_contracts()
        self.assertEqual(len(LEGACY_ENGINE_CONTRACTS), 45)
        self.assertEqual(
            len({contract.engine_id for contract in LEGACY_ENGINE_CONTRACTS}),
            45,
        )
        self.assertEqual(
            len({contract.position for contract in LEGACY_ENGINE_CONTRACTS}),
            45,
        )
        for contract in LEGACY_ENGINE_CONTRACTS:
            self.assertEqual(contract.role, "shadow_only")
            self.assertEqual(contract.failure_policy, "record_only")
            self.assertEqual(contract.allowed_writes, ())
            self.assertEqual(contract.promotion_evidence, ())

    def test_nonimportable_sources_are_quarantined(self) -> None:
        quarantined = [
            contract for contract in LEGACY_ENGINE_CONTRACTS if not contract.runnable
        ]
        self.assertEqual(len(quarantined), 2)
        for contract in quarantined:
            self.assertEqual(contract.kind, "quarantined_source")
            self.assertTrue(Path(contract.source_path).is_file())
            self.assertFalse(contract.module)
            self.assertFalse(contract.callable_name)

    def test_real_fixture_never_changes_active_outcome(self) -> None:
        active_keys = (
            "authority_first_result",
            "governance_result",
            "domain_result",
            "aurion15_result",
            "execution_result",
            "decision",
        )
        for decision in ("APPROVED", "DENY", "ESCALATE"):
            with self.subTest(decision=decision):
                state = self.fixture(decision)
                before = {key: deepcopy(state[key]) for key in active_keys}
                for phase in (
                    "collective",
                    "authority",
                    "governance",
                    "domain",
                    "candidate",
                    "pre_execution",
                    "audit",
                ):
                    runtime.run_legacy_admission_phase(
                        state,
                        phase,
                        run_id="1" if phase == "candidate" else None,
                    )
                self.assertEqual(
                    {key: state[key] for key in active_keys},
                    before,
                )
                self.assertNotIn("legacy_admission_context", state)
                self.assertEqual(len(state["legacy_admission_trace"]), 45)
                self.assertTrue(
                    all(
                        record["authority_granted"] is False
                        for record in state["legacy_admission_trace"]
                    )
                )

    def test_candidate_attempts_are_separate(self) -> None:
        state = self.fixture()
        runtime.run_legacy_admission_phase(state, "candidate", run_id="1")
        runtime.run_legacy_admission_phase(state, "candidate", run_id="2")

        records = [
            record
            for record in state["legacy_admission_trace"]
            if record["phase"] == "candidate"
        ]
        self.assertEqual(len(records), 12)
        self.assertEqual({record["run_id"] for record in records}, {"1", "2"})

    def test_reconciliation_preserves_observation_records(self) -> None:
        state = self.fixture()
        runtime.run_legacy_admission_phase(state, "collective")
        before = canonical_integrity_hash(state["legacy_admission_trace"])

        runtime.reconcile_legacy_comparisons(state)

        self.assertEqual(
            canonical_integrity_hash(state["legacy_admission_trace"]),
            before,
        )
        self.assertEqual(
            len(state["legacy_admission_reconciliation_trace"]),
            len(state["legacy_admission_trace"]),
        )
        statuses = {
            record["comparison"]["status"]
            for record in state["legacy_admission_reconciliation_trace"]
        }
        self.assertIn("INCOMPARABLE_UNVERIFIED_ADAPTER", statuses)

    def test_shadow_infrastructure_failure_has_no_authority_effect(self) -> None:
        state = self.fixture("APPROVED")
        with patch(
            "sbp_lex.pipeline.runner.run_legacy_admission_phase",
            side_effect=RuntimeError("fixture failure"),
        ):
            state, terminal = _run_legacy_phase(state, "collective")

        self.assertFalse(terminal)
        self.assertEqual(state["decision"], "APPROVED")
        self.assertEqual(
            state["legacy_admission_infrastructure_errors"][0]["authority_effect"],
            "NONE",
        )

    def test_declared_reads_and_isolated_outputs_are_enforced(self) -> None:
        module_name = "legacy_contract_test_module"
        module = ModuleType(module_name)
        observed: dict[str, object] = {}

        def reader(payload: dict) -> EngineResult:
            observed["secret"] = payload.get("secret")
            return EngineResult(True, "fixture", "read complete", {})

        def undeclared_writer(state: dict) -> dict:
            state["undeclared"] = True
            return state

        module.reader = reader
        module.undeclared_writer = undeclared_writer
        sys.modules[module_name] = module
        try:
            base = LEGACY_ENGINE_CONTRACTS[0]
            reader_contract = replace(
                base,
                module=module_name,
                callable_name="reader",
                reads=("allowed",),
                deterministic=True,
            )
            runtime._invoke(
                reader_contract,
                {"allowed": "visible", "secret": "hidden"},
            )
            self.assertIsNone(observed["secret"])

            writer_contract = replace(
                base,
                module=module_name,
                callable_name="undeclared_writer",
                kind="state_function",
                reads=("allowed",),
                isolated_outputs=("declared",),
                deterministic=True,
            )
            with self.assertRaisesRegex(
                TypeError,
                "LEGACY_UNDECLARED_ISOLATED_OUTPUTS",
            ):
                runtime._invoke(writer_contract, {"allowed": True})
        finally:
            sys.modules.pop(module_name, None)

    def test_unmet_dependency_is_contract_failure(self) -> None:
        contract = replace(
            LEGACY_ENGINE_CONTRACTS[0],
            dependencies=("missing.engine",),
        )
        state = self.fixture()
        with patch.object(runtime, "LEGACY_ENGINE_CONTRACTS", (contract,)):
            runtime.run_legacy_admission_phase(state, contract.phase)

        self.assertEqual(
            state["legacy_admission_trace"][0]["status"],
            "CONTRACT_FAILURE",
        )

    def test_promotion_evidence_cannot_exist_during_initial_admission(self) -> None:
        promoted = replace(
            LEGACY_ENGINE_CONTRACTS[0],
            promotion_evidence=("fixture",),
        )
        with patch.object(
            contract_module,
            "LEGACY_ENGINE_CONTRACTS",
            (promoted,),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "LEGACY_UNADMITTED_PROMOTION_EVIDENCE",
            ):
                contract_module.validate_legacy_contracts()


if __name__ == "__main__":
    unittest.main()
