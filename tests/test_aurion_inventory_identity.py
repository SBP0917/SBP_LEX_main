from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.aurion15.core.catalog import (
    AURION_ENGINE_MODULES,
    EXTERNAL_ENGINE_DEPENDENCIES,
    load_aurion_catalog,
)
from sbp_lex.aurion15.core.contracts import ENGINE_CONTRACTS
from sbp_lex.aurion15.core.inventory import (
    AURION_CURRENT_COUNT,
    AURION_NON_COUNTING_ALIASES,
    AURION_NON_COUNTING_EXTERNAL_DEPENDENCIES,
    AURION_PROVISIONAL_ENGINES,
    CognitiveInventoryError,
    PROVISIONAL_CURRENT,
    build_cognitive_engine_inventory,
    validate_cognitive_engine_inventory,
)


class AurionInventoryIdentityTests(unittest.TestCase):
    def test_exact_current_source_identity_is_locked(self) -> None:
        registry = load_aurion_catalog()
        self.assertEqual(len(AURION_PROVISIONAL_ENGINES), AURION_CURRENT_COUNT)
        self.assertEqual(
            tuple(engine.module for engine in AURION_PROVISIONAL_ENGINES),
            AURION_ENGINE_MODULES,
        )
        self.assertEqual(
            {engine.canonical_name for engine in AURION_PROVISIONAL_ENGINES},
            set(registry.names()),
        )
        self.assertEqual(
            {engine.canonical_name for engine in AURION_PROVISIONAL_ENGINES},
            set(ENGINE_CONTRACTS),
        )

        for expected in AURION_PROVISIONAL_ENGINES:
            with self.subTest(engine=expected.canonical_name):
                actual = registry.get(expected.canonical_name)
                self.assertEqual(actual.name, expected.canonical_name)
                self.assertEqual(type(actual).__module__, expected.module)
                self.assertEqual(type(actual).__name__, expected.class_name)
                self.assertEqual(actual.stage, expected.stage)
                self.assertEqual(tuple(actual.depends_on), expected.dependencies)

    def test_aliases_and_external_dependencies_are_exact_and_non_counting(self) -> None:
        registry = load_aurion_catalog()
        self.assertEqual(
            AURION_NON_COUNTING_ALIASES,
            (
                ("legitimacy_engine", "legitimacy_verification_engine"),
                ("jurisdiction_determination_engine", "jurisdiction_engine"),
            ),
        )
        for alias, target in AURION_NON_COUNTING_ALIASES:
            self.assertEqual(registry.resolve_name(alias), target)
        self.assertEqual(
            set(AURION_NON_COUNTING_EXTERNAL_DEPENDENCIES),
            set(EXTERNAL_ENGINE_DEPENDENCIES),
        )

        aurion = build_cognitive_engine_inventory()["layers"][0]
        self.assertEqual(aurion["status"], PROVISIONAL_CURRENT)
        self.assertEqual(aurion["admitted_count"], AURION_CURRENT_COUNT)
        self.assertTrue(all(engine["counted"] for engine in aurion["engines"]))
        self.assertTrue(all(not alias["counted"] for alias in aurion["aliases"]))
        self.assertTrue(
            all(not item["counted"] for item in aurion["external_dependencies"])
        )

    def assert_rejected(self, manifest: dict) -> None:
        with self.assertRaises(CognitiveInventoryError):
            validate_cognitive_engine_inventory(manifest)

    def test_duplicate_reorder_unknown_and_case_variant_are_rejected(self) -> None:
        for mutation in ("duplicate", "reorder", "unknown", "case"):
            with self.subTest(mutation=mutation):
                manifest = build_cognitive_engine_inventory()
                engines = manifest["layers"][0]["engines"]
                if mutation == "duplicate":
                    engines[1] = deepcopy(engines[0])
                elif mutation == "reorder":
                    engines[0], engines[1] = engines[1], engines[0]
                elif mutation == "unknown":
                    engines[0]["canonical_name"] = "unknown_engine"
                else:
                    engines[0]["canonical_name"] = engines[0][
                        "canonical_name"
                    ].upper()
                self.assert_rejected(manifest)

    def test_dependency_module_stage_class_count_and_status_tamper_are_rejected(self) -> None:
        mutations = {
            "dependency": lambda manifest: manifest["layers"][0]["engines"][0][
                "dependencies"
            ].append("unknown_engine"),
            "module": lambda manifest: manifest["layers"][0]["engines"][0].update(
                module="sbp_lex.domains.risk_detection_engine"
            ),
            "stage": lambda manifest: manifest["layers"][0]["engines"][0].update(
                stage=2
            ),
            "class": lambda manifest: manifest["layers"][0]["engines"][0].update(
                class_name="UnknownEngine"
            ),
            "count": lambda manifest: manifest["layers"][0].update(
                admitted_count=32
            ),
            "filed_count": lambda manifest: manifest["layers"][0].update(
                filed_count=37
            ),
            "unavailable_count": lambda manifest: manifest["layers"][0].update(
                unavailable_name_count=6
            ),
            "status": lambda manifest: manifest["layers"][0].update(
                status="AUTHORITATIVE"
            ),
            "engine_status": lambda manifest: manifest["layers"][0]["engines"][
                0
            ].update(status="AUTHORITATIVE"),
            "engine_counted": lambda manifest: manifest["layers"][0]["engines"][
                0
            ].update(counted=False),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                manifest = build_cognitive_engine_inventory()
                mutate(manifest)
                self.assert_rejected(manifest)


if __name__ == "__main__":
    unittest.main()
