from __future__ import annotations

from collections.abc import MutableMapping, MutableSet
from typing import Any, cast

import pytest

from sbp_lex.local_trust import (
    artifact,
    evidence_chain,
    execution_envelope,
    history,
    history_preparation,
    manifest,
    pipeline,
    pqc_channel,
    pqc_wrapper,
    signing,
    toolchain_guard,
)
from sbp_lex.local_trust.constants import EVIDENCE_GROUPS, STAGE_SCHEMAS


def test_local_trust_policy_maps_resist_in_process_mutation() -> None:
    original_manifest_schema = STAGE_SCHEMAS["manifest"]
    with pytest.raises(TypeError):
        cast(MutableMapping[str, str], STAGE_SCHEMAS)["manifest"] = "hostile"
    assert STAGE_SCHEMAS["manifest"] == original_manifest_schema

    group = EVIDENCE_GROUPS[0]
    with pytest.raises(TypeError):
        cast(MutableMapping[str, Any], group)["required"] = False
    assert group["required"] is True

    with pytest.raises(TypeError):
        cast(MutableMapping[str, str], toolchain_guard._TOOL_VERSION_COMMANDS)[
            "git"
        ] = "hostile"


@pytest.mark.parametrize(
    "field_set",
    tuple(
        getattr(module, name)
        for module, names in (
            (
                artifact,
                (
                    "_TIME_UNSIGNED_FIELDS",
                    "_TIME_FIELDS",
                    "_UNSIGNED_FIELDS",
                    "_ARTIFACT_FIELDS",
                ),
            ),
            (history, ("_RECORD_FIELDS", "_UNSIGNED_FIELDS", "_HISTORY_FIELDS")),
            (pipeline, ("_PACKAGE_UNSIGNED_FIELDS", "_PACKAGE_FIELDS")),
            (signing, ("_SIGNATURE_FIELDS", "_LANE_FIELDS")),
            (
                pqc_wrapper,
                (
                    "_WRAPPER_FIELDS",
                    "_ENVELOPE_FIELDS",
                    "_DESCRIPTOR_FIELDS",
                    "_SIGNATURE_LANE_FIELDS",
                ),
            ),
            (execution_envelope, ("_PAYLOAD_FIELDS",)),
            (evidence_chain, ("_PAYLOAD_FIELDS",)),
            (manifest, ("_PAYLOAD_FIELDS",)),
            (pqc_channel, ("_FIELDS",)),
            (
                history_preparation,
                (
                    "_PTDE_PREPARATION_FIELDS",
                    "_CUSTODY_METADATA_FIELDS",
                    "_UNSIGNED_HISTORY_FIELDS",
                    "_SIGNING_REQUEST_FIELDS",
                    "_LANE_CUSTODY_FIELDS",
                ),
            ),
        )
        for name in names
    ),
)
def test_local_trust_exact_schema_sets_are_immutable(field_set: object) -> None:
    assert type(field_set) is frozenset
    with pytest.raises(AttributeError):
        cast(MutableSet[str], field_set).add("hostile")
