from __future__ import annotations

import ast
import hashlib
import importlib
import json
import operator
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

import sbp_pvpl.file_io as pvpl_file_io
from sbp_pvpl.canonical import (
    canonical_bytes,
    canonical_document_bytes,
    canonical_sha512,
    parse_canonical_document,
)
from sbp_pvpl.constants import (
    ADMISSION_STATE,
    CLAIM_RESULT,
    CLAIM_SCHEMA_ID,
    CLAIM_SCOPE,
    CONTRACT_VERSION,
    EXTERNAL_PINS_SCHEMA_ID,
    HISTORY_SCHEMA_ID,
    MAX_LIST_ITEMS,
    MAX_STRING_BYTES,
    NO_AUTHORITY,
    PUBLICATION_STATE,
    RECEIPT_SCHEMA_ID,
    SOURCE_OUTCOMES,
    SOURCE_RESULT_SCHEMA_ID,
    SOURCE_RESULT_SCHEMAS,
)
from sbp_pvpl.errors import PVPLValidationError
from sbp_pvpl.file_io import read_canonical_file, write_exclusive_canonical_file
from sbp_pvpl.verifier import (
    build_publication_claim,
    validate_accepted_history,
    validate_detached_receipt,
    validate_external_pins,
    validate_publication_claim,
    validate_redacted_source_result,
)


def _hash(label: str) -> str:
    return hashlib.sha512(label.encode("ascii")).hexdigest()


def _finish(value: dict, field: str) -> dict:
    result = deepcopy(value)
    result[field] = canonical_sha512(result)
    return result


def _source(kind: str, sequence: int = 10) -> dict:
    return _finish(
        {
            "schema_id": SOURCE_RESULT_SCHEMA_ID,
            "contract_version": CONTRACT_VERSION,
            "source_kind": kind,
            "source_result_schema_id": SOURCE_RESULT_SCHEMAS[kind],
            "source_result_sha512": _hash(f"{kind}:full-result"),
            "source_evidence_head_sha512": _hash(f"{kind}:evidence-head"),
            "source_history_sha512": _hash(f"{kind}:history"),
            "source_history_sequence": sequence,
            "source_current_head_sha512": _hash(f"{kind}:current-head"),
            "verification_outcome": SOURCE_OUTCOMES[kind],
            "claim_scope": CLAIM_SCOPE,
            "admission_state": ADMISSION_STATE,
            "runtime_attachment": "NONE",
            "no_authority": dict(NO_AUTHORITY),
        },
        "source_artifact_sha512",
    )


def _receipt(source: dict, trust_label: str) -> dict:
    value = {
        "schema_id": RECEIPT_SCHEMA_ID,
        "contract_version": CONTRACT_VERSION,
        "receipt_kind": "DETACHED_INDEPENDENT_VERIFICATION",
        "source_kind": source["source_kind"],
        "verification_status": "VERIFIED",
        "verification_scope": "CANONICAL_SOURCE_RESULT_AND_REQUIRED_BINDINGS",
        "source_artifact_sha512": source["source_artifact_sha512"],
        "source_result_sha512": source["source_result_sha512"],
        "source_evidence_head_sha512": source["source_evidence_head_sha512"],
        "source_history_sha512": source["source_history_sha512"],
        "source_history_sequence": source["source_history_sequence"],
        "source_current_head_sha512": source["source_current_head_sha512"],
        "verifier_trust_root_sha512": _hash(trust_label),
    }
    bindings = {
        key: value[key]
        for key in (
            "source_kind",
            "source_artifact_sha512",
            "source_result_sha512",
            "source_evidence_head_sha512",
            "source_history_sha512",
            "source_history_sequence",
            "source_current_head_sha512",
            "verifier_trust_root_sha512",
        )
    }
    value["bindings_sha512"] = canonical_sha512(bindings)
    return _finish(value, "receipt_sha512")


def _history(
    claims: list[str] | None = None,
    sources: list[str] | None = None,
    receipts: list[str] | None = None,
) -> dict:
    claim_items = list(claims or [])
    value = {
        "schema_id": HISTORY_SCHEMA_ID,
        "contract_version": CONTRACT_VERSION,
        "sequence": len(claim_items),
        "current_head_sha512": claim_items[-1] if claim_items else "0" * 128,
        "accepted_claim_sha512": claim_items,
        "accepted_source_artifact_sha512": list(sources or []),
        "accepted_receipt_sha512": list(receipts or []),
    }
    return _finish(value, "history_sha512")


def _pins(sources: list[dict], receipts: list[dict], history: dict) -> dict:
    source_pins = []
    for source, receipt in zip(sources, receipts):
        source_pins.append(
            {
                "source_kind": source["source_kind"],
                "expected_source_artifact_sha512": source["source_artifact_sha512"],
                "expected_receipt_sha512": receipt["receipt_sha512"],
                "expected_verifier_trust_root_sha512": receipt[
                    "verifier_trust_root_sha512"
                ],
                "expected_source_result_sha512": source["source_result_sha512"],
                "expected_source_evidence_head_sha512": source[
                    "source_evidence_head_sha512"
                ],
                "expected_source_history_sha512": source["source_history_sha512"],
                "minimum_source_history_sequence": source["source_history_sequence"],
                "expected_source_current_head_sha512": source[
                    "source_current_head_sha512"
                ],
            }
        )
    return _finish(
        {
            "schema_id": EXTERNAL_PINS_SCHEMA_ID,
            "contract_version": CONTRACT_VERSION,
            "source_pins": source_pins,
            "publication_history_pin": {
                "expected_history_sha512": history["history_sha512"],
                "expected_sequence": history["sequence"],
                "expected_current_head_sha512": history["current_head_sha512"],
            },
        },
        "pins_sha512",
    )


@pytest.fixture
def material() -> dict:
    sources = [_source("PTDE", 21), _source("LOCAL_TRUST", 34)]
    receipts = [_receipt(sources[0], "ptde-root"), _receipt(sources[1], "lt-root")]
    history = _history()
    pins = _pins(sources, receipts, history)
    return {"sources": sources, "receipts": receipts, "history": history, "pins": pins}


def _claim(material: dict) -> dict:
    return build_publication_claim(
        material["sources"],
        material["receipts"],
        material["pins"],
        material["history"],
    )


def test_valid_v2_claim_is_deterministic_redacted_and_non_authorizing(material: dict) -> None:
    first = _claim(material)
    second = _claim(material)
    assert first == second
    assert first["schema_id"] == CLAIM_SCHEMA_ID
    assert first["result"] == CLAIM_RESULT
    assert first["admission_state"] == "NOT_ADMITTED"
    assert first["publication_state"] == PUBLICATION_STATE == "NOT_ACTIVATED"
    assert first["no_authority"] == NO_AUTHORITY
    assert all(value is False for value in first["no_authority"].values())
    assert first["claim_sha512"] == canonical_sha512(
        {key: value for key, value in first.items() if key != "claim_sha512"}
    )
    encoded = canonical_document_bytes(first).decode("utf-8")
    for leaked in ("C:\\", "email", "runtime_fingerprint", "private_key", "campaign_id"):
        assert leaked not in encoded


@pytest.mark.parametrize(
    ("validator", "key"),
    [
        (validate_redacted_source_result, "source_artifact_sha512"),
        (validate_detached_receipt, "receipt_sha512"),
        (validate_external_pins, "pins_sha512"),
        (validate_accepted_history, "history_sha512"),
    ],
)
def test_canonical_digest_tamper_fails_closed(material: dict, validator, key: str) -> None:
    lookup = {
        "source_artifact_sha512": material["sources"][0],
        "receipt_sha512": material["receipts"][0],
        "pins_sha512": material["pins"],
        "history_sha512": material["history"],
    }
    changed = deepcopy(lookup[key])
    changed[key] = "f" * 128
    with pytest.raises(PVPLValidationError):
        validator(changed)


@pytest.mark.parametrize(
    "leak",
    [
        {"secret": "hidden"},
        {"repository_path": "C:\\private\\repo"},
        {"user_identity": "person@example.test"},
        {"runtime_fingerprint": "f" * 128},
        {"privacy_payload": "-----BEGIN PRIVATE KEY-----"},
    ],
)
def test_redaction_allowlist_rejects_secret_path_identity_and_fingerprint(
    material: dict, leak: dict
) -> None:
    changed = deepcopy(material["sources"][0])
    changed.update(leak)
    with pytest.raises(PVPLValidationError):
        validate_redacted_source_result(changed)


def test_unpinned_receipt_and_unverified_package_claim_are_rejected(material: dict) -> None:
    changed_receipt = deepcopy(material["receipts"][0])
    changed_receipt["verifier_trust_root_sha512"] = _hash("attacker-root")
    bindings = {
        key: changed_receipt[key]
        for key in (
            "source_kind",
            "source_artifact_sha512",
            "source_result_sha512",
            "source_evidence_head_sha512",
            "source_history_sha512",
            "source_history_sequence",
            "source_current_head_sha512",
            "verifier_trust_root_sha512",
        )
    }
    changed_receipt["bindings_sha512"] = canonical_sha512(bindings)
    changed_receipt["receipt_sha512"] = canonical_sha512(
        {key: value for key, value in changed_receipt.items() if key != "receipt_sha512"}
    )
    receipts = [changed_receipt, material["receipts"][1]]
    with pytest.raises(PVPLValidationError, match="SOURCE_EXTERNAL_PIN_MISMATCH"):
        build_publication_claim(
            material["sources"], receipts, material["pins"], material["history"]
        )

    raw_package_claim = {"package_status": "PASS", "package_digest": _hash("package")}
    with pytest.raises(PVPLValidationError):
        build_publication_claim(
            [raw_package_claim, material["sources"][1]],
            material["receipts"],
            material["pins"],
            material["history"],
        )


def test_stale_source_and_changed_current_head_are_rejected(material: dict) -> None:
    stale_pins = deepcopy(material["pins"])
    stale_pins["source_pins"][0]["minimum_source_history_sequence"] += 1
    stale_pins["pins_sha512"] = canonical_sha512(
        {key: value for key, value in stale_pins.items() if key != "pins_sha512"}
    )
    with pytest.raises(PVPLValidationError, match="SOURCE_RESULT_STALE"):
        build_publication_claim(
            material["sources"], material["receipts"], stale_pins, material["history"]
        )

    changed_pins = deepcopy(material["pins"])
    changed_pins["source_pins"][0]["expected_source_current_head_sha512"] = _hash(
        "new-head"
    )
    changed_pins["pins_sha512"] = canonical_sha512(
        {key: value for key, value in changed_pins.items() if key != "pins_sha512"}
    )
    with pytest.raises(PVPLValidationError, match="SOURCE_EXTERNAL_PIN_MISMATCH"):
        build_publication_claim(
            material["sources"], material["receipts"], changed_pins, material["history"]
        )


def test_publication_history_rollback_and_replay_are_rejected(material: dict) -> None:
    first = _claim(material)
    advanced = _history(
        [first["claim_sha512"]],
        [item["source_artifact_sha512"] for item in material["sources"]],
        [item["receipt_sha512"] for item in material["receipts"]],
    )
    advanced_pins = _pins(material["sources"], material["receipts"], advanced)
    with pytest.raises(PVPLValidationError, match="SOURCE_RESULT_REPLAYED"):
        build_publication_claim(
            material["sources"], material["receipts"], advanced_pins, advanced
        )

    rollback_pins = deepcopy(material["pins"])
    rollback_pins["publication_history_pin"]["expected_sequence"] = 1
    rollback_pins["pins_sha512"] = canonical_sha512(
        {key: value for key, value in rollback_pins.items() if key != "pins_sha512"}
    )
    with pytest.raises(PVPLValidationError, match="PUBLICATION_HISTORY_ROLLBACK"):
        build_publication_claim(
            material["sources"], material["receipts"], rollback_pins, material["history"]
        )


def test_unknown_missing_extra_fields_and_claim_tamper_fail_closed(material: dict) -> None:
    source = deepcopy(material["sources"][0])
    del source["claim_scope"]
    with pytest.raises(PVPLValidationError):
        validate_redacted_source_result(source)
    claim = _claim(material)
    claim["new_field"] = True
    with pytest.raises(PVPLValidationError):
        validate_publication_claim(claim)
    claim = _claim(material)
    claim["publication_state"] = "ACTIVATED"
    with pytest.raises(PVPLValidationError):
        validate_publication_claim(claim)


def test_canonical_parser_rejects_noncanonical_duplicate_and_float() -> None:
    with pytest.raises(PVPLValidationError):
        parse_canonical_document(b'{"b":1,"a":2}\n')
    with pytest.raises(PVPLValidationError):
        parse_canonical_document(b'{"a":1,"a":1}\n')
    with pytest.raises(PVPLValidationError):
        parse_canonical_document(b'{"a":1.0}\n')
    with pytest.raises(PVPLValidationError, match="CANONICAL_JSON_INTEGER_INVALID"):
        parse_canonical_document(b'{"a":999999999999999999999999999999999999}\n')


def test_canonical_normalisation_wraps_hostile_unicode_key() -> None:
    with pytest.raises(
        PVPLValidationError, match="CANONICAL_JSON_NORMALISATION_FAILED"
    ):
        canonical_bytes({"\ud800": 1})


def test_canonical_parser_fails_closed_on_hostile_nesting() -> None:
    hostile = b'{"x":' + (b"[" * 10_000) + b"0" + (b"]" * 10_000) + b"}\n"
    with pytest.raises(PVPLValidationError):
        parse_canonical_document(hostile)


def test_canonical_normalisation_bounds_aliased_container_amplification() -> None:
    repeated_string = ["x" * MAX_STRING_BYTES]
    hostile = {"items": [repeated_string] * MAX_LIST_ITEMS}
    with pytest.raises(
        PVPLValidationError,
        match="CANONICAL_JSON_TOTAL_STRING_BYTES_EXCEEDED",
    ):
        canonical_bytes(hostile)


def test_validators_detach_results_from_caller_owned_containers(material: dict) -> None:
    source = deepcopy(material["sources"][0])
    checked = validate_redacted_source_result(source)
    source["no_authority"]["runtime_authority"] = True
    assert checked["no_authority"]["runtime_authority"] is False


@pytest.mark.parametrize(
    ("mapping", "key", "value"),
    [
        (NO_AUTHORITY, "runtime_authority", True),
        (SOURCE_RESULT_SCHEMAS, "PTDE", "attacker-schema"),
        (SOURCE_OUTCOMES, "PTDE", "attacker-outcome"),
    ],
)
def test_exported_contract_policy_mappings_are_immutable(
    mapping: object, key: str, value: object
) -> None:
    with pytest.raises(TypeError):
        operator.setitem(mapping, key, value)


def test_exclusive_export_never_overwrites(tmp_path: Path, material: dict) -> None:
    claim = _claim(material)
    target = tmp_path / "claim.json"
    write_exclusive_canonical_file(claim, target)
    assert target.read_bytes() == canonical_document_bytes(claim)
    with pytest.raises(PVPLValidationError, match="OUTPUT_ALREADY_EXISTS"):
        write_exclusive_canonical_file(claim, target)
    assert target.read_bytes() == canonical_document_bytes(claim)


def test_file_boundary_rejects_hardlinked_input(tmp_path: Path, material: dict) -> None:
    original = tmp_path / "source.json"
    alias = tmp_path / "source-alias.json"
    original.write_bytes(canonical_document_bytes(material["sources"][0]))
    try:
        os.link(original, alias)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    with pytest.raises(PVPLValidationError, match="INPUT_FILE_INVALID"):
        read_canonical_file(original)


def test_failed_exclusive_export_leaves_fail_closed_tombstone(
    tmp_path: Path, material: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "partial.json"
    monkeypatch.setattr(pvpl_file_io.os, "write", lambda _descriptor, _data: 0)
    with pytest.raises(PVPLValidationError, match="OUTPUT_WRITE_INCOMPLETE"):
        write_exclusive_canonical_file(_claim(material), target)
    assert target.exists()
    with pytest.raises(PVPLValidationError):
        read_canonical_file(target)
    with pytest.raises(PVPLValidationError, match="OUTPUT_ALREADY_EXISTS"):
        write_exclusive_canonical_file(_claim(material), target)


def test_exclusive_export_verifies_exact_persisted_bytes(
    tmp_path: Path, material: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "persisted.json"
    monkeypatch.setattr(
        pvpl_file_io.os,
        "read",
        lambda _descriptor, size: b"x" * size,
    )
    with pytest.raises(PVPLValidationError, match="OUTPUT_PERSISTED_CONTENT_MISMATCH"):
        write_exclusive_canonical_file(_claim(material), target)


def test_relative_output_is_anchored_before_cwd_can_change(
    tmp_path: Path, material: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = tmp_path / "original"
    alternate = tmp_path / "alternate"
    original.mkdir()
    alternate.mkdir()
    monkeypatch.chdir(original)
    open_held_directory = pvpl_file_io._open_held_directory

    def switch_cwd(
        path: Path, code: str, *, writable: bool = False
    ) -> tuple[os.stat_result, int | None, int | None]:
        result = open_held_directory(path, code, writable=writable)
        os.chdir(alternate)
        return result

    monkeypatch.setattr(pvpl_file_io, "_open_held_directory", switch_cwd)
    try:
        write_exclusive_canonical_file(_claim(material), "claim.json")
    finally:
        os.chdir(original)
    assert (original / "claim.json").is_file()
    assert not (alternate / "claim.json").exists()


def test_resource_cleanup_attempts_every_descriptor_before_rejecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    windows_closed: list[int] = []

    def close_descriptor(descriptor: int) -> None:
        closed.append(descriptor)
        if descriptor == 101:
            raise OSError("simulated close failure")

    monkeypatch.setattr(pvpl_file_io.os, "close", close_descriptor)
    monkeypatch.setattr(
        pvpl_file_io,
        "_close_windows_handle",
        windows_closed.append,
    )
    with pytest.raises(PVPLValidationError, match="HANDLE_CLOSE_FAILED"):
        pvpl_file_io._close_resources((101, 202), 303, "HANDLE_CLOSE_FAILED")
    assert closed == [101, 202]
    assert windows_closed == [303]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle semantics")
def test_windows_held_parent_denies_directory_rebinding(tmp_path: Path) -> None:
    parent = tmp_path / "held"
    moved = tmp_path / "moved"
    parent.mkdir()
    _, descriptor, windows_handle = pvpl_file_io._open_held_directory(
        parent,
        "TEST_PARENT_INVALID",
        writable=True,
    )
    assert descriptor is None
    assert windows_handle is not None
    try:
        with pytest.raises(OSError):
            parent.rename(moved)
    finally:
        pvpl_file_io._close_resources(
            (descriptor,), windows_handle, "TEST_HANDLE_CLOSE_FAILED"
        )
    parent.rename(moved)
    assert moved.is_dir()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle semantics")
def test_windows_native_close_failure_is_not_silenced() -> None:
    with pytest.raises(OSError):
        pvpl_file_io._close_windows_handle(0)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows handle semantics")
def test_windows_output_handle_denies_concurrent_mutation(
    tmp_path: Path, material: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "share-denied.json"
    original_write = pvpl_file_io.os.write
    sharing_errors: list[OSError] = []

    def adversarial_write(descriptor: int, data: bytes | memoryview) -> int:
        if not sharing_errors:
            try:
                with target.open("r+b") as attacker:
                    attacker.write(b"attacker")
            except OSError as exc:
                sharing_errors.append(exc)
            else:
                raise AssertionError("exclusive output handle allowed concurrent mutation")
        return original_write(descriptor, data)

    monkeypatch.setattr(pvpl_file_io.os, "write", adversarial_write)
    write_exclusive_canonical_file(_claim(material), target)
    assert sharing_errors
    assert target.read_bytes() == canonical_document_bytes(_claim(material))


@pytest.mark.parametrize("name", ["..", "line\nbreak.json"])
def test_output_rejects_ambiguous_path_components(
    tmp_path: Path, material: dict, name: str
) -> None:
    target = tmp_path / "child" / name / "claim.json"
    with pytest.raises(PVPLValidationError, match="OUTPUT_PATH_INVALID"):
        write_exclusive_canonical_file(_claim(material), target)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows path semantics")
@pytest.mark.parametrize(
    "name",
    [
        "claim.json:stream",
        "NUL.json",
        "claim.json.",
        "COM¹.txt",
        "LPT³.txt",
        "CONIN$",
        "CONOUT$",
    ],
)
def test_output_rejects_windows_alias_and_alternate_stream_paths(
    tmp_path: Path, material: dict, name: str
) -> None:
    with pytest.raises(PVPLValidationError, match="OUTPUT_PATH_INVALID"):
        write_exclusive_canonical_file(_claim(material), tmp_path / name)


def _write(path: Path, value: dict) -> None:
    path.write_bytes(canonical_document_bytes(value))


def test_pvpl_main_module_is_import_safe() -> None:
    assert importlib.import_module("sbp_pvpl.__main__") is not None


def test_cli_validate_show_and_export_redacted_only(
    tmp_path: Path, material: dict
) -> None:
    paths = {}
    documents = {
        "ptde-result": material["sources"][0],
        "ptde-receipt": material["receipts"][0],
        "local-trust-result": material["sources"][1],
        "local-trust-receipt": material["receipts"][1],
        "external-pins": material["pins"],
        "accepted-history": material["history"],
    }
    arguments: list[str] = []
    for name, document in documents.items():
        path = tmp_path / f"{name}.json"
        _write(path, document)
        paths[name] = path
        arguments.extend((f"--{name}", str(path)))
    for command in ("validate", "show"):
        completed = subprocess.run(
            [sys.executable, "-m", "sbp_pvpl", command, *arguments],
            check=False,
            capture_output=True,
            cwd=Path(__file__).resolve().parents[2],
        )
        assert completed.returncode == 0, completed.stdout.decode()
        assert parse_canonical_document(completed.stdout)
        assert completed.stderr == b""
    target = tmp_path / "redacted-claim.json"
    command = [
        sys.executable,
        "-m",
        "sbp_pvpl",
        "export-redacted",
        *arguments,
        "--output",
        str(target),
    ]
    first = subprocess.run(command, check=False, capture_output=True, cwd=Path(__file__).resolve().parents[2])
    assert first.returncode == 0
    exported = parse_canonical_document(target.read_bytes())
    assert exported == _claim(material)
    second = subprocess.run(command, check=False, capture_output=True, cwd=Path(__file__).resolve().parents[2])
    assert second.returncode == 2
    assert json.loads(second.stdout)["error_code"] == "OUTPUT_ALREADY_EXISTS"
    assert parse_canonical_document(target.read_bytes()) == exported


def test_python_boundary_has_no_active_runtime_network_or_mutation_hooks() -> None:
    root = Path(__file__).resolve().parents[2] / "sbp_pvpl"
    forbidden_imports = {
        "sbp_lex",
        "sbp_ptde",
        "requests",
        "urllib",
        "http",
        "socket",
        "fastapi",
    }
    forbidden_function_fragments = (
        "runner",
        "gate",
        "token",
        "adapter",
        "ledger",
        "activate",
        "publish_external",
    )
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(item.name.split(".")[0] not in forbidden_imports for item in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden_imports
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lowered = node.name.casefold()
                assert not any(fragment in lowered for fragment in forbidden_function_fragments)
