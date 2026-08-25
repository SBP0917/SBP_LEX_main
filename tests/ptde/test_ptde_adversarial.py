from __future__ import annotations

import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

import pytest

from sbp_ptde import (
    GENESIS_SHA512,
    AcceptedAttemptHistory,
    AcceptedAttemptRecord,
    PTDEVerificationError,
    SUCCESS_CLAIM_TEXT,
    SUCCESS_RESULT,
    accepted_attempt_history_from_document,
    expected_policy,
    policy_document_bytes,
    validate_verification_result,
    verify_ptde_chain,
    verify_ptde_result,
)
from sbp_ptde.canonical import canonical_json_document_bytes
from sbp_ptde.cli import _read_accepted_attempt_history_file, main as ptde_cli_main
from sbp_ptde import git_objects as git_objects_module


def _verify(chain: Any, **overrides: Any) -> dict[str, Any]:
    return verify_ptde_chain(
        chain.object_database,
        **chain.arguments(**overrides),
        git_executable=chain.git_executable,
    )


def _init_bare(path: Path) -> None:
    completed = subprocess.run(
        ["git", "init", "--bare", str(path)],
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr.decode(errors="replace"))


def test_git_timeout_terminates_descendant_process_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "escaped.txt"
    ready = tmp_path / "ready.txt"
    child_code = (
        "import pathlib,sys,time;"
        "time.sleep(1.5);"
        "pathlib.Path(sys.argv[1]).write_text('escaped', encoding='utf-8')"
    )
    parent_code = (
        "import pathlib,subprocess,sys,time;"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]);"
        "pathlib.Path(sys.argv[3]).write_text('ready', encoding='utf-8');"
        "time.sleep(30)"
    )
    real_popen = subprocess.Popen

    def launch_descendant_tree(
        _command: Any, **options: Any
    ) -> subprocess.Popen[bytes]:
        return real_popen(
            [
                sys.executable,
                "-c",
                parent_code,
                child_code,
                str(marker),
                str(ready),
            ],
            **options,
        )

    database: Any = object.__new__(git_objects_module.GitObjectDatabase)
    database._git_executable = Path(sys.executable)
    database._git_dir = tmp_path
    database._expected_git_executable_sha512 = "0" * 128
    database._git_executable_measurement = object()
    database._environment = os.environ.copy
    monkeypatch.setattr(
        git_objects_module,
        "_verify_pinned_executable",
        lambda _path, _digest, baseline: baseline,
    )
    monkeypatch.setattr(git_objects_module.subprocess, "Popen", launch_descendant_tree)
    monkeypatch.setattr(git_objects_module, "MAX_GIT_SUBPROCESS_SECONDS", 1)

    with pytest.raises(PTDEVerificationError, match="GIT_OBJECT_READ_TIMEOUT"):
        database._run("version")

    assert ready.read_text(encoding="utf-8") == "ready"
    time.sleep(0.75)
    assert not marker.exists()


def test_fixed_policy_and_success_claim_are_exact() -> None:
    policy = expected_policy()
    assert policy["schema_id"] == "sbp.lex.v2.ptde.policy/1"
    assert policy["json_schemas"] == {
        "d": "sbp.lex.v2.ptde.runtime-descriptor/1",
        "e": "sbp.lex.v2.ptde.evidence-commit/1",
        "result": "sbp.lex.v2.ptde.verification-result/1",
        "t": "sbp.lex.v2.ptde.test-subject/1",
        "transcript": "sbp.lex.v2.ptde.lane-transcript/1",
    }
    assert policy["lane_contract"]["maximum_timeout_seconds"] == 7200
    assert policy["lane_contract"]["timeout_status"] == "TIMEOUT_FAIL_CLOSED"
    assert policy["lane_contract"]["pass_requires_command_executed"] is True
    assert policy["lane_contract"]["pass_requires_untruncated_full_stream_bytes"] is True
    assert policy["resource_maxima"] == {
        "artifact_file_count": 10_000,
        "artifact_total_byte_count": 134_217_728,
        "argument_utf8_bytes": 32_768,
        "argv_items": 4_096,
        "blob_count": 100_000,
        "commit_parent_count": 16,
        "environment_names": 4_096,
        "evidence_entries": 100_000,
        "git_executable_bytes": 268_435_456,
        "git_object_bytes": 134_217_728,
        "git_subprocess_metadata_bytes": 1_048_576,
        "git_subprocess_seconds": 120,
        "integer_absolute": 9_223_372_036_854_775_807,
        "inventory_entries": 100_000,
        "json_depth": 64,
        "json_document_bytes": 16_777_216,
        "json_list_items": 100_000,
        "json_object_fields": 4_096,
        "json_string_bytes": 1_048_576,
        "json_total_nodes": 1_000_000,
        "lanes": 1_024,
        "lane_timeout_seconds": 7_200,
        "path_segment_utf8_bytes": 255,
        "path_utf8_bytes": 4_096,
        "stream_byte_count": 134_217_728,
        "total_git_object_bytes": 1_073_741_824,
        "transcript_byte_count": 1_048_576,
        "tree_count": 100_000,
        "tree_depth": 64,
        "tree_entry_count": 100_000,
    }
    assert policy["success"] == {
        "claim_text": SUCCESS_CLAIM_TEXT,
        "result": SUCCESS_RESULT,
    }
    assert policy_document_bytes().endswith(b"\n")
    assert not policy_document_bytes().endswith(b"\n\n")
    assert json.loads(policy_document_bytes()) == policy


def test_cli_history_file_rejects_links_and_uses_bounded_same_file_read(
    tmp_path: Path,
    valid_chain: Any,
) -> None:
    history_path = tmp_path / "accepted-history.json"
    history_path.write_bytes(
        canonical_json_document_bytes(valid_chain.accepted_attempt_history.as_dict())
    )
    assert _read_accepted_attempt_history_file(str(history_path)).endswith(b"\n")

    hardlink = tmp_path / "accepted-history-hardlink.json"
    try:
        os.link(history_path, hardlink)
    except OSError:
        pass
    else:
        with pytest.raises(PTDEVerificationError):
            _read_accepted_attempt_history_file(str(hardlink))

    alias = tmp_path / "history-alias"
    try:
        alias.symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pass
    else:
        with pytest.raises(PTDEVerificationError):
            _read_accepted_attempt_history_file(str(alias / history_path.name))

    with pytest.raises(PTDEVerificationError):
        _read_accepted_attempt_history_file("../accepted-history.json")
    with pytest.raises(PTDEVerificationError):
        _read_accepted_attempt_history_file("accepted-history.json:alternate")

    source = Path("sbp_ptde/cli.py").read_text(encoding="utf-8")
    assert ".read_bytes()" not in source
    assert 'getattr(os, "O_NOFOLLOW", 0)' in source
    assert "os.fstat(descriptor)" in source


def test_cli_show_policy_is_ascii_safe_and_preserves_exact_claim(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert ptde_cli_main(["show-policy"]) == 0
    captured = capsys.readouterr().out
    assert captured.isascii()
    assert json.loads(captured)["success"]["claim_text"] == SUCCESS_CLAIM_TEXT


def test_ptde_main_module_is_import_safe() -> None:
    assert importlib.import_module("sbp_ptde.__main__") is not None


def test_valid_chain_is_deterministic_narrow_and_non_authorising(valid_chain: Any) -> None:
    first = _verify(valid_chain)
    second = _verify(valid_chain)
    assert first == second
    assert first["result"] == "PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED"
    assert first["claim_text"] == SUCCESS_CLAIM_TEXT
    assert first["admission_state"] == "NOT_ADMITTED"
    assert first["no_authority"] == expected_policy()["no_authority"]
    assert all(
        value is False
        for key, value in first["no_authority"].items()
        if key != "runtime_attachment"
    )
    assert first["no_authority"]["runtime_attachment"] == "NONE"
    assert first["assurance_limits"]["production_admitted"] is False
    assert first["assurance_limits"]["external_validation"] is False
    assert first["assurance_limits"]["deployment_admitted"] is False
    assert first["assurance_limits"]["accepted_attempt_history_persistence"] == (
        "EXTERNAL_DURABLE_DEPENDENCY"
    )
    assert first["assurance_limits"]["git_executable_point_of_use_immutability"] == (
        "WINDOWS_SAME_HANDLE_EXECUTION_NOT_PROVEN"
    )
    assert first["assurance_limits"]["resource_maxima"] == expected_policy()[
        "resource_maxima"
    ]
    assert first["git_executable_sha512"] == valid_chain.git_executable_sha512
    assert first["accepted_attempt_history_id"] == valid_chain.accepted_attempt_history.history_id
    assert first["accepted_attempt_history_sequence"] == 0
    assert first["accepted_attempt_history_sha512"] == (
        valid_chain.accepted_attempt_history.sha512()
    )
    assert validate_verification_result(first) == first
    assert verify_ptde_result(
        first,
        valid_chain.object_database,
        **valid_chain.arguments(),
        git_executable=valid_chain.git_executable,
    ) == first


def test_git_executable_pin_is_mandatory_and_exact(valid_chain: Any) -> None:
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain, expected_git_executable_sha512="0" * 128)


def test_accepted_history_pin_is_mandatory_and_exact(valid_chain: Any) -> None:
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain, expected_attempt_history_sha512="0" * 128)


def test_whole_consistent_history_substitution_fails_against_external_pin(
    valid_chain: Any,
) -> None:
    substituted = AcceptedAttemptHistory(
        history_id="attacker-history",
        sequence=0,
        prior_history_sha512=GENESIS_SHA512,
        records=(),
    )
    with pytest.raises(PTDEVerificationError):
        _verify(
            valid_chain,
            accepted_attempt_history=substituted,
            expected_attempt_history_sha512=valid_chain.accepted_attempt_history.sha512(),
        )


def test_history_document_is_canonical_strict_and_non_authorising(valid_chain: Any) -> None:
    history = valid_chain.accepted_attempt_history
    document = (
        json.dumps(
            history.as_dict(),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    assert accepted_attempt_history_from_document(document) == history
    malformed = document[:-2] + b',"authority":true}\n'
    with pytest.raises(PTDEVerificationError):
        accepted_attempt_history_from_document(malformed)


def test_history_sequence_predecessor_and_record_shape_fail_closed(valid_chain: Any) -> None:
    malformed = AcceptedAttemptHistory(
        history_id="ptde-test-history",
        sequence=1,
        prior_history_sha512=GENESIS_SHA512,
        records=(),
    )
    with pytest.raises(PTDEVerificationError):
        _verify(
            valid_chain,
            accepted_attempt_history=malformed,
            expected_attempt_history_sha512=malformed.sha512(),
        )
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain, accepted_attempt_history={})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("result", "PASS"),
        ("claim_text", "broader claim"),
        ("admission_state", "ADMITTED"),
        ("schema_id", "sbp.lex.v2.ptde.verification-result/2"),
    ],
)
def test_result_contract_rejects_broader_or_changed_claims(
    valid_chain: Any,
    field: str,
    value: str,
) -> None:
    result = _verify(valid_chain)
    result[field] = value
    with pytest.raises(PTDEVerificationError):
        validate_verification_result(result)


def test_result_cannot_grant_any_authority(valid_chain: Any) -> None:
    result = _verify(valid_chain)
    result["no_authority"]["execution"] = True
    with pytest.raises(PTDEVerificationError):
        validate_verification_result(result)


def test_result_must_be_reverified_against_exact_objects(valid_chain: Any) -> None:
    result = _verify(valid_chain)
    result["campaign_id"] = "different-campaign"
    with pytest.raises(PTDEVerificationError):
        verify_ptde_result(
            result,
            valid_chain.object_database,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("p_oid", "HEAD"),
        ("p_oid", "0" * 8),
        ("p_oid", "A" * 40),
        ("expected_p_oid", "0" * 40),
    ],
)
def test_refs_abbreviations_uppercase_and_wrong_p_pin_fail_closed(
    valid_chain: Any,
    override: str,
    value: str,
) -> None:
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain, **{override: value})


def test_duplicate_or_reordered_stage_oids_fail_closed(valid_chain: Any) -> None:
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain, t_oid=valid_chain.p_oid)
    with pytest.raises(PTDEVerificationError):
        _verify(
            valid_chain,
            t_oid=valid_chain.d_oid,
            d_oid=valid_chain.t_oid,
        )


def test_working_tree_root_is_not_an_object_database(valid_chain: Any) -> None:
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            valid_chain.worktree,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


@pytest.mark.parametrize(
    ("stage", "extra_files"),
    [
        ("T", {"main.py": b'def run_sbp_lex():\n    return "changed at T"\n'}),
        ("D", {"config/profile.txt": b"changed-at-D\n"}),
        ("E", {"main.py": b'def run_sbp_lex():\n    return "changed at E"\n'}),
    ],
)
def test_application_or_configuration_change_at_t_d_or_e_is_rejected(
    chain_factory: Callable[..., Any],
    stage: str,
    extra_files: dict[str, bytes],
) -> None:
    keyword = {f"{stage.lower()}_extra_files": extra_files}
    chain = chain_factory(**keyword)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_e_addition_outside_declared_campaign_subtree_is_rejected(
    chain_factory: Callable[..., Any],
) -> None:
    chain = chain_factory(e_extra_files={"outside-evidence.bin": b"not admitted"})
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_p_resource_policy_tamper_is_rejected(chain_factory: Callable[..., Any]) -> None:
    policy = expected_policy()
    policy["resource_maxima"]["json_depth"] += 1
    tampered = (
        json.dumps(
            policy,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )
    chain = chain_factory(policy_bytes=tampered)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_t_inventory_omission_is_rejected(chain_factory: Callable[..., Any]) -> None:
    def omit_source(profile: dict[str, Any]) -> None:
        profile["inventories"]["source"]["entries"].pop()

    chain = chain_factory(t_mutator=omit_source)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_d_callable_substitution_is_rejected(chain_factory: Callable[..., Any]) -> None:
    def substitute(descriptor: dict[str, Any]) -> None:
        descriptor["single_pipeline_callables"][0]["function_ast_sha512"] = "0" * 128

    chain = chain_factory(d_mutator=substitute)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_e_evidence_digest_tamper_is_rejected(chain_factory: Callable[..., Any]) -> None:
    def tamper(manifest: dict[str, Any]) -> None:
        manifest["lane_results"][0]["stdout_sha512"] = "0" * 128

    chain = chain_factory(e_mutator=tamper)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


@pytest.mark.parametrize("mutation", ["elapsed_limit", "timeout_flag", "timeout_status"])
def test_timeout_cannot_be_relabelled_as_successful_evidence(
    chain_factory: Callable[..., Any],
    mutation: str,
) -> None:
    def mutate(result: dict[str, Any]) -> None:
        if mutation == "elapsed_limit":
            result["finished_at_unix_ms"] = result["started_at_unix_ms"] + 7_200_000
            result["wall_clock_milliseconds"] = 7_200_000
        elif mutation == "timeout_flag":
            result["timed_out"] = True
        else:
            result["timeout_status"] = "TIMEOUT_FAIL_CLOSED"

    chain = chain_factory(lane_result_mutator=mutate)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


@pytest.mark.parametrize(
    "field",
    [
        "source_mutation_observed",
        "ledger_mutation_observed",
        "authority_mutation_observed",
    ],
)
def test_lane_with_source_ledger_or_authority_mutation_is_rejected(
    chain_factory: Callable[..., Any],
    field: str,
) -> None:
    def mutate(result: dict[str, Any]) -> None:
        result[field] = True

    chain = chain_factory(lane_result_mutator=mutate)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_alternative_e_child_cannot_launder_same_attempt_and_transcript(
    chain_factory: Callable[..., Any],
) -> None:
    chain = chain_factory(replay_e_child=True)
    assert chain.replay_e_oid is not None
    assert chain.transcript_sha512 is not None
    _verify(chain)
    accepted = AcceptedAttemptHistory(
        history_id=chain.accepted_attempt_history.history_id,
        sequence=1,
        prior_history_sha512=chain.accepted_attempt_history.sha512(),
        records=(
            AcceptedAttemptRecord(
                campaign_id="campaign-1",
                lane_id="unit",
                attempt_id="attempt-1",
                transcript_sha512=chain.transcript_sha512,
                e_commit_oid=chain.e_oid,
            ),
        ),
    )
    with pytest.raises(PTDEVerificationError):
        _verify(
            chain,
            e_oid=chain.replay_e_oid,
            accepted_attempt_history=accepted,
            expected_attempt_history_sha512=accepted.sha512(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("command_executed", False),
        ("setup_completed", False),
        ("stdout_full_bytes", False),
        ("stderr_full_bytes", False),
        ("output_truncated", True),
        ("lane_contract_sha512", "0" * 128),
        ("attempt_id", "different-attempt"),
        ("d_commit_oid", "0" * 40),
        ("cleanup_completed", False),
        ("source_mutation_observed", True),
        ("ledger_mutation_observed", True),
        ("authority_mutation_observed", True),
    ],
)
def test_fabricated_or_truncated_transcript_cannot_be_admitted(
    chain_factory: Callable[..., Any],
    field: str,
    value: bool,
) -> None:
    def mutate(transcript: dict[str, Any]) -> None:
        transcript[field] = value

    chain = chain_factory(transcript_mutator=mutate)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_shallow_object_database_marker_is_rejected(
    valid_chain: Any,
    copy_object_database: Callable[[Any, str], Path],
) -> None:
    shallow = copy_object_database(valid_chain, "shallow.git")
    (shallow / "shallow").write_text(valid_chain.p_oid + "\n", encoding="ascii")
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            shallow,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


def test_commondir_object_database_is_rejected(
    valid_chain: Any,
    copy_object_database: Callable[[Any, str], Path],
) -> None:
    common = copy_object_database(valid_chain, "commondir.git")
    (common / "commondir").write_text(".\n", encoding="ascii")
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            common,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


@pytest.mark.parametrize("variable", ["GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"])
def test_inherited_git_object_redirection_cannot_substitute_database(
    valid_chain: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
) -> None:
    empty = tmp_path / f"empty-{variable}.git"
    _init_bare(empty)
    monkeypatch.setenv(variable, str(valid_chain.object_database / "objects"))
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            empty,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


@pytest.mark.parametrize("source", ["GIT_CONFIG_GLOBAL", "HOME"])
def test_hostile_inherited_git_configuration_fails_closed(
    valid_chain: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    if source == "GIT_CONFIG_GLOBAL":
        malformed = tmp_path / "malformed.gitconfig"
        malformed.write_text("[malformed\n", encoding="ascii")
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(malformed))
    else:
        hostile_home = tmp_path / "hostile-home"
        hostile_home.mkdir()
        (hostile_home / ".gitconfig").write_text("[malformed\n", encoding="ascii")
        monkeypatch.setenv("HOME", str(hostile_home))
    with pytest.raises(PTDEVerificationError):
        _verify(valid_chain)


@pytest.mark.skipif(os.name != "nt", reason="Windows command wrapper substitution case")
def test_caller_supplied_fake_git_executable_is_rejected(
    valid_chain: Any,
    tmp_path: Path,
) -> None:
    real_git = shutil.which("git")
    assert real_git is not None
    wrapper = tmp_path / "git-substitute.cmd"
    wrapper.write_text(f'@echo off\r\n"{real_git}" %*\r\n', encoding="utf-8")
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            valid_chain.object_database,
            **valid_chain.arguments(),
            git_executable=str(wrapper),
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows junction/reparse case")
def test_junction_object_database_path_is_rejected(
    valid_chain: Any,
    tmp_path: Path,
) -> None:
    junction = tmp_path / "object-junction.git"
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(valid_chain.object_database)],
        capture_output=True,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        pytest.skip("junction creation unavailable in this test environment")
    with pytest.raises(PTDEVerificationError):
        verify_ptde_chain(
            junction,
            **valid_chain.arguments(),
            git_executable=valid_chain.git_executable,
        )


def test_deep_json_resource_exhaustion_is_structured_fail_closed(
    tmp_path: Path,
    deep_json_chain_factory: Callable[..., Any],
) -> None:
    chain = deep_json_chain_factory(tmp_path / "deep-json")
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_unbounded_integer_metadata_is_rejected(
    chain_factory: Callable[..., Any],
) -> None:
    chain = chain_factory(started_at_unix_ms=10**1_000)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)


def test_unbounded_stream_and_artifact_caps_are_rejected(
    chain_factory: Callable[..., Any],
) -> None:
    chain = chain_factory(maximum_byte_count=10**1_000)
    with pytest.raises(PTDEVerificationError):
        _verify(chain)
