from __future__ import annotations

from copy import deepcopy
import unittest

from sbp_lex.aurion15.core.inventory import (
    AUTHORITATIVE_SOURCE_UNAVAILABLE,
    CognitiveInventoryError,
    build_cognitive_engine_inventory,
    validate_cognitive_engine_inventory,
)


class CognitiveLayerSeparationTests(unittest.TestCase):
    def assert_rejected(self, manifest: dict) -> None:
        with self.assertRaises(CognitiveInventoryError):
            validate_cognitive_engine_inventory(manifest)

    def test_ckc_and_ngk_have_zero_admitted_names_and_exact_unavailable_sets(self) -> None:
        manifest = build_cognitive_engine_inventory()
        ckc, ngk = manifest["layers"][1:]
        for layer, count in ((ckc, 26), (ngk, 32)):
            self.assertEqual(layer["status"], AUTHORITATIVE_SOURCE_UNAVAILABLE)
            self.assertEqual(layer["filed_count"], count)
            self.assertEqual(layer["unavailable_name_count"], count)
            self.assertEqual(layer["admitted_count"], 0)
            self.assertEqual(layer["engines"], [])
            self.assertEqual(layer["aliases"], [])
            self.assertEqual(layer["external_dependencies"], [])

        self.assertEqual(
            ckc["unavailable_sets"],
            [
                "ALL_26_CANONICAL_ENGINE_NAMES",
                "FOUR_NAMED_LONG_HORIZON_FUNCTION_NAMES",
            ],
        )
        self.assertEqual(
            ngk["unavailable_sets"],
            [
                "ALL_32_CANONICAL_ENGINE_NAMES",
                "CONDITIONAL_TAG_AND_CLASSIFICATION_VOCABULARY",
            ],
        )

    def test_alias_external_and_legacy_inflation_are_rejected(self) -> None:
        for source in ("alias", "external", "legacy"):
            with self.subTest(source=source):
                manifest = build_cognitive_engine_inventory()
                aurion = manifest["layers"][0]
                if source == "alias":
                    inflated = deepcopy(aurion["engines"][0])
                    inflated["canonical_name"] = aurion["aliases"][0]["alias"]
                elif source == "external":
                    inflated = deepcopy(aurion["engines"][0])
                    inflated["canonical_name"] = aurion[
                        "external_dependencies"
                    ][0]["name"]
                else:
                    inflated = deepcopy(aurion["engines"][0])
                    inflated["canonical_name"] = "legacy_shadow_engine"
                aurion["engines"].append(inflated)
                aurion["admitted_count"] += 1
                self.assert_rejected(manifest)

    def test_non_counting_metadata_and_order_tamper_are_rejected(self) -> None:
        mutations = {
            "alias_counted": lambda aurion: aurion["aliases"][0].update(
                counted=True
            ),
            "external_counted": lambda aurion: aurion[
                "external_dependencies"
            ][0].update(counted=True),
            "alias_reorder": lambda aurion: aurion["aliases"].reverse(),
            "external_reorder": lambda aurion: aurion[
                "external_dependencies"
            ].reverse(),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                manifest = build_cognitive_engine_inventory()
                mutate(manifest["layers"][0])
                self.assert_rejected(manifest)

    def test_ckc_ngk_placeholder_entries_are_rejected(self) -> None:
        for layer_index in (1, 2):
            with self.subTest(layer_index=layer_index):
                manifest = build_cognitive_engine_inventory()
                layer = manifest["layers"][layer_index]
                layer["engines"] = [
                    {
                        "canonical_name": "placeholder_engine",
                        "module": "placeholder.engine",
                        "class_name": "PlaceholderEngine",
                        "implementation_type": "AURION_ENGINE_CLASS",
                        "status": "PROVISIONAL_CURRENT",
                        "stage": 1,
                        "dependencies": [],
                        "counted": True,
                    }
                ]
                layer["admitted_count"] = 1
                self.assert_rejected(manifest)

    def test_cross_layer_and_dtn_substitution_are_rejected(self) -> None:
        for layer_index, substituted_name in (
            (1, "risk_detection_engine"),
            (2, "risk_detection_engine"),
            (1, "digital_twin_network_engine"),
            (2, "digital_twin_network_engine"),
        ):
            with self.subTest(
                layer_index=layer_index,
                substituted_name=substituted_name,
            ):
                manifest = build_cognitive_engine_inventory()
                substituted = deepcopy(manifest["layers"][0]["engines"][0])
                substituted["canonical_name"] = substituted_name
                manifest["layers"][layer_index]["engines"] = [substituted]
                manifest["layers"][layer_index]["admitted_count"] = 1
                self.assert_rejected(manifest)

    def test_no_layer_count_can_be_inflated(self) -> None:
        for layer_index, field in (
            (0, "filed_count"),
            (0, "admitted_count"),
            (0, "unavailable_name_count"),
            (1, "filed_count"),
            (1, "admitted_count"),
            (1, "unavailable_name_count"),
            (2, "filed_count"),
            (2, "admitted_count"),
            (2, "unavailable_name_count"),
        ):
            with self.subTest(layer_index=layer_index, field=field):
                manifest = build_cognitive_engine_inventory()
                manifest["layers"][layer_index][field] += 1
                self.assert_rejected(manifest)

    def test_layer_duplicate_reorder_unknown_case_and_status_tamper_are_rejected(self) -> None:
        for mutation in ("duplicate", "reorder", "unknown", "case", "status"):
            with self.subTest(mutation=mutation):
                manifest = build_cognitive_engine_inventory()
                if mutation == "duplicate":
                    manifest["layers"][2] = deepcopy(manifest["layers"][1])
                elif mutation == "reorder":
                    manifest["layers"][1], manifest["layers"][2] = (
                        manifest["layers"][2],
                        manifest["layers"][1],
                    )
                elif mutation == "unknown":
                    manifest["layers"][1]["layer_id"] = "UNKNOWN"
                elif mutation == "case":
                    manifest["layers"][1]["layer_id"] = "ckc"
                else:
                    manifest["layers"][1]["status"] = "PROVISIONAL_CURRENT"
                self.assert_rejected(manifest)

    def test_no_canonical_name_is_shared_across_layers(self) -> None:
        manifest = build_cognitive_engine_inventory()
        names_by_layer = [
            {entry["canonical_name"] for entry in layer["engines"]}
            for layer in manifest["layers"]
        ]
        for index, names in enumerate(names_by_layer):
            for other in names_by_layer[index + 1 :]:
                self.assertTrue(names.isdisjoint(other))


if __name__ == "__main__":
    unittest.main()
