from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence, MutableSet
from typing import Any, cast

import pytest

from sbp_ptde import policy as policy_module
from sbp_ptde import policy_document_bytes, preparation, schemas, trust, verifier
from sbp_ptde.constants import (
    ASSURANCE_LIMITS,
    CALLABLE_ALLOWED_SET,
    NO_AUTHORITY,
    assurance_limits_document,
)


def test_ptde_policy_mappings_resist_in_process_mutation() -> None:
    policy_before = policy_document_bytes()

    for policy, key, hostile_value in (
        (NO_AUTHORITY, "authority", True),
        (ASSURANCE_LIMITS, "production_admitted", True),
        (
            cast(dict[str, Any], ASSURANCE_LIMITS["resource_maxima"]),
            "lane_timeout_seconds",
            0,
        ),
        (CALLABLE_ALLOWED_SET[0], "source_path", "hostile.py"),
    ):
        with pytest.raises(TypeError):
            cast(MutableMapping[str, Any], policy)[key] = hostile_value

    assert policy_document_bytes() == policy_before


def test_assurance_document_is_a_detached_plain_json_copy() -> None:
    first = assurance_limits_document()
    maxima = cast(dict[str, object], first["resource_maxima"])
    maxima["lane_timeout_seconds"] = 0
    first["production_admitted"] = True

    second = assurance_limits_document()
    assert type(second) is dict
    assert type(second["resource_maxima"]) is dict
    assert second["production_admitted"] is False
    assert cast(dict[str, object], second["resource_maxima"])[
        "lane_timeout_seconds"
    ] != 0


@pytest.mark.parametrize(
    "field_set",
    tuple(
        getattr(module, name)
        for module, names in (
            (policy_module, ("_POLICY_FIELDS",)),
            (
                preparation,
                (
                    "_P_PACKET_FIELDS",
                    "_LOCAL_HISTORY_BINDING_FIELDS",
                    "_PYTHON_BINDING_FIELDS",
                    "_TREE_BLOB_FIELDS",
                    "_E_INPUT_FIELDS",
                    "_OBJECT_BINDING_FIELDS",
                    "_FIXED_E_MANIFEST_BINDING_FIELDS",
                    "_LANE_INPUT_FIELDS",
                    "_D_FINGERPRINT_FIELDS",
                    "_SCRIPT_GIT_SUFFIXES",
                ),
            ),
            (
                schemas,
                (
                    "_INVENTORY_ENTRY_FIELDS",
                    "_INVENTORY_FIELDS",
                    "_T_FIELDS",
                    "_LANE_FIELDS",
                    "_STREAM_CONTRACT_FIELDS",
                    "_ARTIFACT_CONTRACT_FIELDS",
                    "_D_FIELDS",
                    "_CALLABLE_FIELDS",
                    "_E_FIELDS",
                    "_LANE_RESULT_FIELDS",
                    "_TRANSCRIPT_FIELDS",
                ),
            ),
            (trust, ("_HISTORY_FIELDS", "_RECORD_FIELDS")),
            (verifier, ("_RESULT_FIELDS", "_OBJECT_BINDING_FIELDS")),
        )
        for name in names
    ),
)
def test_ptde_schema_field_sets_are_immutable(field_set: object) -> None:
    assert type(field_set) is frozenset
    with pytest.raises(AttributeError):
        cast(MutableSet[str], field_set).add("hostile")


def test_required_external_result_sequence_is_immutable() -> None:
    fields = preparation._REQUIRED_EXTERNAL_RESULT_FIELDS
    assert type(fields) is tuple
    with pytest.raises(TypeError):
        cast(MutableSequence[str], fields)[0] = "hostile"
