import importlib
import pkgutil
import unittest

import sbp_lex
from sbp_lex.aurion15.core import (
    EXTERNAL_ENGINE_DEPENDENCIES,
    load_aurion_catalog,
)


IMPORTED_ENGINE_NAMES = {
    "crisis_recognition_engine",
    "ecological_constraint_engine",
    "legal_conflict_resolution_engine",
    "policy_simulation_engine",
}


class AurionEngineImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = load_aurion_catalog()

    def test_all_sbp_lex_modules_import(self):
        failures = []
        module_names = sorted(
            module.name
            for module in pkgutil.walk_packages(
                sbp_lex.__path__,
                sbp_lex.__name__ + ".",
            )
        )

        for module_name in module_names:
            try:
                importlib.import_module(module_name)
            except Exception as exc:  # pragma: no cover - reported in assertion
                failures.append(f"{module_name}: {type(exc).__name__}: {exc}")

        self.assertEqual([], failures)

    def test_four_imported_engines_are_registered(self):
        self.assertTrue(IMPORTED_ENGINE_NAMES.issubset(self.registry.names()))

    def test_catalog_has_no_unresolved_dependencies(self):
        self.assertEqual(
            {},
            self.registry.unresolved_dependencies(EXTERNAL_ENGINE_DEPENDENCIES),
        )

    def test_known_convergence_group_is_reported(self):
        cycles = [set(group) for group in self.registry.dependency_cycles()]
        self.assertIn(
            {
                "demographic_monitoring_engine",
                "ecological_constraint_engine",
                "economic_signal_engine",
                "resource_allocation_engine",
                "societal_stability_engine",
            },
            cycles,
        )

    def test_imported_engine_outputs_match_v2_consumers(self):
        cases = {
            "crisis_recognition_engine": (
                {"payload": {}, "current_candidate": {}, "risk_level": "low"},
                "crisis_recognition_status",
                "stable",
            ),
            "ecological_constraint_engine": (
                {
                    "payload": {"ecological_constraint_score": 0.8},
                    "current_candidate": {},
                    "risk_level": "low",
                    "demographic_monitoring_status": "stable",
                },
                "ecological_constraint_status",
                "within_limits",
            ),
            "legal_conflict_resolution_engine": (
                {
                    "payload": {"legal_conflicts": []},
                    "current_candidate": {},
                    "jurisdiction": "test-jurisdiction",
                    "resolved_authority": "test-authority",
                    "governance_compliance_status": "compliant",
                },
                "legal_conflict_resolution_status",
                "resolved",
            ),
            "policy_simulation_engine": (
                {
                    "governance_compliance_status": "compliant",
                    "resource_allocation_status": "balanced",
                    "legal_conflict_resolution_status": "resolved",
                    "ethical_constraint_status": "aligned",
                },
                "policy_simulation_status",
                "viable",
            ),
        }

        for engine_name, (state, result_key, expected) in cases.items():
            with self.subTest(engine=engine_name):
                result = self.registry.get(engine_name).execute(state)
                self.assertEqual(expected, result[result_key])
                self.assertEqual("pass", result["candidate_action"])


if __name__ == "__main__":
    unittest.main()
