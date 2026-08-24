from __future__ import annotations

import json
from pathlib import Path
import unittest

from sbp_lex.aurion15.core.inventory import (
    COGNITIVE_ENGINE_INVENTORY_SCHEMA_VERSION,
    COGNITIVE_ENGINE_INVENTORY_STATUS,
    build_cognitive_engine_inventory,
    validate_cognitive_engine_inventory,
)


SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "contracts"
    / "v2"
    / "cognitive-engine-inventory.schema.json"
)


class CognitiveInventorySchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_schema_is_strict_draft_2020_12(self) -> None:
        self.assertEqual(
            self.schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema",
        )
        self.assertFalse(self.schema["additionalProperties"])
        self.assertEqual(
            set(self.schema["required"]),
            {
                "schema_version",
                "inventory_status",
                "authority_effect",
                "runtime_activation",
                "layer_order",
                "layers",
            },
        )

    def test_schema_identity_and_non_authority_match_manifest(self) -> None:
        properties = self.schema["properties"]
        self.assertEqual(
            properties["schema_version"]["const"],
            COGNITIVE_ENGINE_INVENTORY_SCHEMA_VERSION,
        )
        self.assertEqual(
            properties["inventory_status"]["const"],
            COGNITIVE_ENGINE_INVENTORY_STATUS,
        )
        self.assertEqual(properties["authority_effect"]["const"], "NONE")
        self.assertFalse(properties["runtime_activation"]["const"])
        self.assertEqual(
            properties["layer_order"]["const"],
            ["AURION_15", "CKC", "NGK"],
        )
        validate_cognitive_engine_inventory(build_cognitive_engine_inventory())

    def test_schema_locks_counts_and_prohibits_ckc_ngk_placeholders(self) -> None:
        definitions = self.schema["$defs"]
        aurion = definitions["aurionLayer"]["properties"]
        self.assertEqual(aurion["filed_count"]["const"], 38)
        self.assertEqual(aurion["admitted_count"]["const"], 31)
        self.assertEqual(aurion["unavailable_name_count"]["const"], 7)
        self.assertEqual(aurion["engines"]["minItems"], 31)
        self.assertEqual(aurion["engines"]["maxItems"], 31)

        common = definitions["unavailableLayerCommon"]["properties"]
        self.assertEqual(common["engines"]["maxItems"], 0)
        self.assertEqual(common["aliases"]["maxItems"], 0)
        self.assertEqual(common["external_dependencies"]["maxItems"], 0)

        ckc = definitions["ckcLayer"]["allOf"][1]["properties"]
        ngk = definitions["ngkLayer"]["allOf"][1]["properties"]
        self.assertEqual(ckc["filed_count"]["const"], 26)
        self.assertEqual(ckc["unavailable_name_count"]["const"], 26)
        self.assertEqual(ngk["filed_count"]["const"], 32)
        self.assertEqual(ngk["unavailable_name_count"]["const"], 32)

    def test_schema_locks_non_counting_aliases_and_external_dependencies(self) -> None:
        aurion = self.schema["$defs"]["aurionLayer"]["properties"]
        aliases = aurion["aliases"]["const"]
        external = aurion["external_dependencies"]["const"]
        self.assertEqual(len(aliases), 2)
        self.assertEqual(len(external), 6)
        self.assertTrue(all(item["counted"] is False for item in aliases))
        self.assertTrue(all(item["counted"] is False for item in external))

    def test_manifest_fields_and_locked_values_match_schema(self) -> None:
        manifest = build_cognitive_engine_inventory()
        definitions = self.schema["$defs"]
        self.assertEqual(set(manifest), set(self.schema["required"]))

        aurion = manifest["layers"][0]
        aurion_schema = definitions["aurionLayer"]
        self.assertEqual(set(aurion), set(aurion_schema["required"]))
        self.assertEqual(
            aurion["aliases"],
            aurion_schema["properties"]["aliases"]["const"],
        )
        self.assertEqual(
            aurion["external_dependencies"],
            aurion_schema["properties"]["external_dependencies"]["const"],
        )
        for engine in aurion["engines"]:
            self.assertEqual(set(engine), set(definitions["engine"]["required"]))

        for layer, definition_name in zip(
            manifest["layers"][1:],
            ("ckcLayer", "ngkLayer"),
            strict=True,
        ):
            locked = definitions[definition_name]["allOf"][1]["properties"]
            self.assertEqual(layer["layer_id"], locked["layer_id"]["const"])
            self.assertEqual(layer["filed_count"], locked["filed_count"]["const"])
            self.assertEqual(
                layer["unavailable_sets"],
                locked["unavailable_sets"]["const"],
            )
            self.assertEqual(
                layer["horizon_years"],
                locked["horizon_years"]["const"],
            )


if __name__ == "__main__":
    unittest.main()
