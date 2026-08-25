from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import pytest

from sbp_ptde import (
    GENESIS_SHA512,
    TRANSCRIPT_SCHEMA_ID,
    AcceptedAttemptHistory,
    expected_policy,
    policy_document_bytes,
)


INVENTORY_CLASSES = (
    "source",
    "contract",
    "architecture",
    "configuration",
    "test",
    "dependency_build",
    "detached_verifier",
)


@dataclass(frozen=True)
class PTDEChain:
    worktree: Path
    object_database: Path
    p_oid: str
    t_oid: str
    d_oid: str
    e_oid: str
    git_executable: str
    git_executable_sha512: str
    accepted_attempt_history: AcceptedAttemptHistory
    replay_e_oid: str | None = None
    transcript_sha512: str | None = None

    def arguments(self, **overrides: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "p_oid": self.p_oid,
            "t_oid": self.t_oid,
            "d_oid": self.d_oid,
            "e_oid": self.e_oid,
            "expected_p_oid": self.p_oid,
            "expected_git_executable_sha512": self.git_executable_sha512,
            "accepted_attempt_history": self.accepted_attempt_history,
            "expected_attempt_history_sha512": self.accepted_attempt_history.sha512(),
        }
        values.update(overrides)
        return values


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> bytes:
    completed = subprocess.run(
        command,
        cwd=cwd,
        input=input_bytes,
        capture_output=True,
        check=False,
        shell=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: {command!r}\n"
            f"stdout={completed.stdout!r}\nstderr={completed.stderr!r}"
        )
    return completed.stdout


def _git(repository: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return _run(
        ["git", "-C", str(repository), *arguments],
        input_bytes=input_bytes,
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _document(value: dict[str, Any]) -> bytes:
    return _canonical_bytes(value) + b"\n"


def _canonical_sha512(value: Any) -> str:
    return hashlib.sha512(_canonical_bytes(value)).hexdigest()


def _raw_sha512(object_type: str, content: bytes) -> str:
    raw = f"{object_type} {len(content)}\0".encode("ascii") + content
    return hashlib.sha512(raw).hexdigest()


def _git_trust() -> tuple[str, str]:
    located = shutil.which("git")
    if located is None:
        raise AssertionError("git executable is unavailable")
    executable = Path(located).resolve(strict=True)
    return str(executable), hashlib.sha512(executable.read_bytes()).hexdigest()


def _genesis_history() -> AcceptedAttemptHistory:
    return AcceptedAttemptHistory(
        history_id="ptde-test-history",
        sequence=0,
        prior_history_sha512=GENESIS_SHA512,
        records=(),
    )


def _assurance_limits() -> dict[str, Any]:
    return {
        "production_admitted": False,
        "external_validation": False,
        "deployment_admitted": False,
        "external_trust_custody": "NOT_PROVEN",
        "durable_replay_or_rollback_head": "NOT_PROVEN",
        "effect_path_non_bypass": "NOT_PROVEN",
        "accepted_attempt_history_persistence": "EXTERNAL_DURABLE_DEPENDENCY",
        "git_executable_point_of_use_immutability": "WINDOWS_SAME_HANDLE_EXECUTION_NOT_PROVEN",
        "transcript_assertion_scope": "COMMITTED_BYTES_ONLY_NOT_EXTERNAL_COMMAND_ATTESTATION",
        "resource_maxima": expected_policy()["resource_maxima"],
    }


def _write(repository: Path, relative: str, content: bytes) -> None:
    target = repository / Path(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)


def _commit(repository: Path, message: str) -> str:
    _git(repository, "add", "--all")
    _git(repository, "commit", "--no-gpg-sign", "-m", message)
    return _git(repository, "rev-parse", "HEAD").decode("ascii").strip()


def _object_content(repository: Path, object_type: str, oid: str) -> bytes:
    return _git(repository, "cat-file", object_type, oid)


def _commit_record(repository: Path, oid: str) -> dict[str, str]:
    commit_content = _object_content(repository, "commit", oid)
    tree_oid = _git(repository, "rev-parse", f"{oid}^{{tree}}").decode("ascii").strip()
    tree_content = _object_content(repository, "tree", tree_oid)
    return {
        "commit_oid": oid,
        "tree_oid": tree_oid,
        "commit_raw_sha512": _raw_sha512("commit", commit_content),
        "tree_raw_sha512": _raw_sha512("tree", tree_content),
    }


def _tree_records(repository: Path, commit_oid: str) -> dict[str, dict[str, Any]]:
    output = _git(repository, "ls-tree", "-r", "-z", "--full-tree", commit_oid)
    records: dict[str, dict[str, Any]] = {}
    for raw_entry in output.split(b"\0"):
        if not raw_entry:
            continue
        header, path_bytes = raw_entry.split(b"\t", 1)
        mode, object_type, oid_bytes = header.split(b" ", 2)
        path = path_bytes.decode("utf-8")
        oid = oid_bytes.decode("ascii")
        content = _object_content(repository, object_type.decode("ascii"), oid)
        records[path] = {
            "path": path,
            "mode": mode.decode("ascii"),
            "blob_oid": oid,
            "blob_sha512": hashlib.sha512(content).hexdigest(),
            "blob_raw_sha512": _raw_sha512(object_type.decode("ascii"), content),
            "byte_count": len(content),
        }
    return records


def _inventory(records: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    assignments = {
        "contracts/ptde/PTDE_POLICY_V1.json": "contract",
        "main.py": "source",
        "sbp_lex/pipeline/runner.py": "source",
        "docs/architecture.txt": "architecture",
        "config/profile.txt": "configuration",
        "tests/p_subject.txt": "test",
        "requirements.lock": "dependency_build",
        "detached_verifier.txt": "detached_verifier",
    }
    inventories: dict[str, dict[str, Any]] = {}
    for inventory_class in INVENTORY_CLASSES:
        entries = [
            records[path]
            for path in sorted(records)
            if assignments.get(path) == inventory_class
        ]
        inventories[inventory_class] = {
            "entries": entries,
            "inventory_sha512": _canonical_sha512(entries),
        }
    if set(assignments) != set(records):
        raise AssertionError(f"fixture P inventory mismatch: {set(records) ^ set(assignments)}")
    return inventories


def _lane(*, timeout_seconds: int = 7200, maximum_byte_count: int = 4096) -> dict[str, Any]:
    environment_names = ["CI"]
    return {
        "lane_id": "unit",
        "order": 1,
        "executable_id": "python",
        "argv": ["python", "-m", "pytest"],
        "cwd_rule": "P_ROOT",
        "environment_name_allowlist": environment_names,
        "environment_name_allowlist_sha512": _canonical_sha512(environment_names),
        "timeout_seconds": timeout_seconds,
        "expected_exit_codes": [0],
        "stdout_contract": {
            "capture": "FULL_BYTES",
            "relative_path": "unit/stdout.bin",
            "maximum_byte_count": maximum_byte_count,
        },
        "stderr_contract": {
            "capture": "FULL_BYTES",
            "relative_path": "unit/stderr.bin",
            "maximum_byte_count": maximum_byte_count,
        },
        "produced_artifact_contract": {
            "required_relative_paths": ["unit/report.json"],
            "optional_relative_paths": [],
            "maximum_file_count": 1,
            "maximum_total_byte_count": maximum_byte_count,
        },
    }


def _callable_record(
    repository: Path,
    tree_records: dict[str, dict[str, Any]],
    *,
    qualified_name: str,
    source_path: str,
) -> dict[str, str]:
    source_record = tree_records[source_path]
    source = _object_content(repository, "blob", source_record["blob_oid"])
    module = ast.parse(source.decode("utf-8"))
    name = qualified_name.rsplit(".", 1)[-1]
    matches = [
        node
        for node in module.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError("fixture callable definition is not exact")
    function_ast = ast.dump(matches[0], annotate_fields=True, include_attributes=False)
    return {
        "qualified_name": qualified_name,
        "source_path": source_path,
        "source_blob_oid": source_record["blob_oid"],
        "source_blob_sha512": source_record["blob_sha512"],
        "function_ast_sha512": hashlib.sha512(function_ast.encode("utf-8")).hexdigest(),
    }


def _evidence_record(repository: Path, path: str, content: bytes) -> dict[str, Any]:
    oid = _git(repository, "hash-object", "-w", "--stdin", input_bytes=content).decode("ascii").strip()
    return {
        "path": path,
        "mode": "100644",
        "blob_oid": oid,
        "blob_sha512": hashlib.sha512(content).hexdigest(),
        "blob_raw_sha512": _raw_sha512("blob", content),
        "byte_count": len(content),
    }


def build_chain(
    root: Path,
    *,
    t_mutator: Callable[[dict[str, Any]], None] | None = None,
    d_mutator: Callable[[dict[str, Any]], None] | None = None,
    e_mutator: Callable[[dict[str, Any]], None] | None = None,
    lane_result_mutator: Callable[[dict[str, Any]], None] | None = None,
    transcript_mutator: Callable[[dict[str, Any]], None] | None = None,
    t_extra_files: dict[str, bytes] | None = None,
    d_extra_files: dict[str, bytes] | None = None,
    e_extra_files: dict[str, bytes] | None = None,
    timeout_seconds: int = 7200,
    maximum_byte_count: int = 4096,
    started_at_unix_ms: int = 1_000,
    evidence_contents: dict[str, bytes] | None = None,
    replay_e_child: bool = False,
    policy_bytes: bytes | None = None,
) -> PTDEChain:
    repository = root / "work"
    bare = root / "objects.git"
    repository.mkdir(parents=True)
    _git(repository, "init")
    _git(repository, "config", "user.name", "PTDE Test")
    _git(repository, "config", "user.email", "ptde@example.invalid")
    _git(repository, "config", "core.autocrlf", "false")

    p_files = {
        "contracts/ptde/PTDE_POLICY_V1.json": (
            policy_document_bytes() if policy_bytes is None else policy_bytes
        ),
        "main.py": b'def run_sbp_lex():\n    return "ok"\n',
        "sbp_lex/pipeline/runner.py": (
            b'def run_v2():\n    return "v2"\n\n'
            b'def run_v2_pipeline():\n    return "pipeline"\n'
        ),
        "docs/architecture.txt": b"single pipeline\n",
        "config/profile.txt": b"profile=v2\n",
        "tests/p_subject.txt": b"P subject test inventory\n",
        "requirements.lock": b"pytest==1\n",
        "detached_verifier.txt": b"detached verifier subject\n",
    }
    for path, content in p_files.items():
        _write(repository, path, content)
    p_oid = _commit(repository, "P")
    p_commit = _commit_record(repository, p_oid)
    p_tree = _tree_records(repository, p_oid)
    inventories = _inventory(p_tree)
    lane = _lane(
        timeout_seconds=timeout_seconds,
        maximum_byte_count=maximum_byte_count,
    )
    policy_record = p_tree["contracts/ptde/PTDE_POLICY_V1.json"]
    profile: dict[str, Any] = {
        "schema_id": "sbp.lex.v2.ptde.test-subject/1",
        "policy_blob_oid": policy_record["blob_oid"],
        "policy_sha512": policy_record["blob_sha512"],
        "policy_blob_raw_sha512": policy_record["blob_raw_sha512"],
        "p_commit_oid": p_oid,
        "p_tree_oid": p_commit["tree_oid"],
        "p_commit_raw_sha512": p_commit["commit_raw_sha512"],
        "p_tree_raw_sha512": p_commit["tree_raw_sha512"],
        "inventories": inventories,
        "p_inventory_sha512": _canonical_sha512(inventories),
        "test_profile_id": "v2-test-profile",
        "lanes": [lane],
        "lanes_sha512": _canonical_sha512([lane]),
        "no_authority": expected_policy()["no_authority"],
        "runtime_attachment": "NONE",
    }
    if t_mutator is not None:
        t_mutator(profile)
    _write(repository, "ptde_subjects/T_TEST_BUILD_PROFILE.json", _document(profile))
    for path, content in (t_extra_files or {}).items():
        _write(repository, path, content)
    t_oid = _commit(repository, "T")
    t_commit = _commit_record(repository, t_oid)
    t_tree = _tree_records(repository, t_oid)
    t_profile_record = t_tree["ptde_subjects/T_TEST_BUILD_PROFILE.json"]

    callables = [
        _callable_record(
            repository,
            t_tree,
            qualified_name="main.run_sbp_lex",
            source_path="main.py",
        ),
        _callable_record(
            repository,
            t_tree,
            qualified_name="sbp_lex.pipeline.runner.run_v2",
            source_path="sbp_lex/pipeline/runner.py",
        ),
        _callable_record(
            repository,
            t_tree,
            qualified_name="sbp_lex.pipeline.runner.run_v2_pipeline",
            source_path="sbp_lex/pipeline/runner.py",
        ),
    ]
    descriptor: dict[str, Any] = {
        "schema_id": "sbp.lex.v2.ptde.runtime-descriptor/1",
        "campaign_id": "campaign-1",
        "p_commit_oid": p_oid,
        "p_tree_oid": p_commit["tree_oid"],
        "p_commit_raw_sha512": p_commit["commit_raw_sha512"],
        "p_tree_raw_sha512": p_commit["tree_raw_sha512"],
        "t_commit_oid": t_oid,
        "t_tree_oid": t_commit["tree_oid"],
        "t_commit_raw_sha512": t_commit["commit_raw_sha512"],
        "t_tree_raw_sha512": t_commit["tree_raw_sha512"],
        "t_profile_path": "ptde_subjects/T_TEST_BUILD_PROFILE.json",
        "t_profile_blob_oid": t_profile_record["blob_oid"],
        "t_profile_sha512": t_profile_record["blob_sha512"],
        "t_profile_blob_raw_sha512": t_profile_record["blob_raw_sha512"],
        "policy_sha512": profile["policy_sha512"],
        "p_inventory_sha512": profile["p_inventory_sha512"],
        "p_contract_inventory_sha512": inventories["contract"]["inventory_sha512"],
        "p_architecture_inventory_sha512": inventories["architecture"]["inventory_sha512"],
        "p_configuration_inventory_sha512": inventories["configuration"]["inventory_sha512"],
        "os_fingerprint_sha512": hashlib.sha512(b"os").hexdigest(),
        "build_fingerprint_sha512": hashlib.sha512(b"build").hexdigest(),
        "architecture_fingerprint_sha512": hashlib.sha512(b"architecture").hexdigest(),
        "runtime_fingerprint_sha512": hashlib.sha512(b"runtime").hexdigest(),
        "toolchain_fingerprint_sha512": hashlib.sha512(b"toolchain").hexdigest(),
        "lanes": profile["lanes"],
        "lanes_sha512": profile["lanes_sha512"],
        "single_pipeline_callables": callables,
        "no_authority": expected_policy()["no_authority"],
        "assurance_limits": _assurance_limits(),
    }
    if d_mutator is not None:
        d_mutator(descriptor)
    _write(repository, "ptde_subjects/D_RUNTIME_DESCRIPTOR.json", _document(descriptor))
    for path, content in (d_extra_files or {}).items():
        _write(repository, path, content)
    d_oid = _commit(repository, "D")
    d_commit = _commit_record(repository, d_oid)
    d_tree = _tree_records(repository, d_oid)
    d_descriptor_record = d_tree["ptde_subjects/D_RUNTIME_DESCRIPTOR.json"]

    campaign_prefix = "evidence/ptde/campaign-1"
    contents = evidence_contents or {
        "unit/stdout.bin": b"ok\n",
        "unit/stderr.bin": b"",
        "unit/report.json": b'{"passed":true}\n',
    }
    if "unit/transcript.json" in contents:
        raise AssertionError("use transcript_mutator for transcript counterexamples")
    finish = started_at_unix_ms + 1_000
    lane_result = {
        "lane_id": "unit",
        "attempt_id": "attempt-1",
        "status": "LANE_PASS",
        "argv": lane["argv"],
        "d_commit_oid": d_oid,
        "d_descriptor_sha512": d_descriptor_record["blob_sha512"],
        "exit_status": 0,
        "started_at_unix_ms": started_at_unix_ms,
        "finished_at_unix_ms": finish,
        "wall_clock_milliseconds": 1_000,
        "timeout_seconds": timeout_seconds,
        "timed_out": False,
        "timeout_status": "NOT_TIMED_OUT",
        "cleanup_completed": True,
        "process_tree_terminated": False,
        "stdout_path": f"{campaign_prefix}/unit/stdout.bin",
        "stdout_byte_count": len(contents["unit/stdout.bin"]),
        "stdout_sha512": hashlib.sha512(contents["unit/stdout.bin"]).hexdigest(),
        "stderr_path": f"{campaign_prefix}/unit/stderr.bin",
        "stderr_byte_count": len(contents["unit/stderr.bin"]),
        "stderr_sha512": hashlib.sha512(contents["unit/stderr.bin"]).hexdigest(),
        "transcript_path": f"{campaign_prefix}/unit/transcript.json",
        "transcript_byte_count": 0,
        "transcript_sha512": "0" * 128,
        "error": None,
        "produced_artifacts": [f"{campaign_prefix}/unit/report.json"],
        "source_mutation_observed": False,
        "ledger_mutation_observed": False,
        "authority_mutation_observed": False,
    }
    if lane_result_mutator is not None:
        lane_result_mutator(lane_result)
    transcript = {
        "schema_id": TRANSCRIPT_SCHEMA_ID,
        "campaign_id": "campaign-1",
        "lane_id": lane_result["lane_id"],
        "attempt_id": lane_result["attempt_id"],
        "lane_contract_sha512": _canonical_sha512(lane),
        "d_commit_oid": lane_result["d_commit_oid"],
        "d_descriptor_sha512": lane_result["d_descriptor_sha512"],
        "command_executed": True,
        "setup_completed": True,
        "status": lane_result["status"],
        "exit_status": lane_result["exit_status"],
        "started_at_unix_ms": lane_result["started_at_unix_ms"],
        "finished_at_unix_ms": lane_result["finished_at_unix_ms"],
        "wall_clock_milliseconds": lane_result["wall_clock_milliseconds"],
        "timeout_seconds": lane_result["timeout_seconds"],
        "timed_out": lane_result["timed_out"],
        "timeout_status": lane_result["timeout_status"],
        "cleanup_completed": lane_result["cleanup_completed"],
        "process_tree_terminated": lane_result["process_tree_terminated"],
        "stdout_path": lane_result["stdout_path"],
        "stdout_byte_count": lane_result["stdout_byte_count"],
        "stdout_sha512": lane_result["stdout_sha512"],
        "stdout_full_bytes": True,
        "stderr_path": lane_result["stderr_path"],
        "stderr_byte_count": lane_result["stderr_byte_count"],
        "stderr_sha512": lane_result["stderr_sha512"],
        "stderr_full_bytes": True,
        "output_truncated": False,
        "error": lane_result["error"],
        "produced_artifacts": lane_result["produced_artifacts"],
        "source_mutation_observed": lane_result["source_mutation_observed"],
        "ledger_mutation_observed": lane_result["ledger_mutation_observed"],
        "authority_mutation_observed": lane_result["authority_mutation_observed"],
        "no_authority": expected_policy()["no_authority"],
    }
    if transcript_mutator is not None:
        transcript_mutator(transcript)
    transcript_bytes = _document(transcript)
    contents["unit/transcript.json"] = transcript_bytes
    lane_result["transcript_byte_count"] = len(transcript_bytes)
    lane_result["transcript_sha512"] = hashlib.sha512(transcript_bytes).hexdigest()
    evidence_records: list[dict[str, Any]] = []
    for relative, content in contents.items():
        full_path = f"{campaign_prefix}/{relative}"
        _write(repository, full_path, content)
        evidence_records.append(_evidence_record(repository, full_path, content))
    evidence_records.sort(key=lambda item: item["path"])
    manifest: dict[str, Any] = {
        "schema_id": "sbp.lex.v2.ptde.evidence-commit/1",
        "campaign_id": "campaign-1",
        "p_commit_oid": p_oid,
        "p_tree_oid": p_commit["tree_oid"],
        "t_commit_oid": t_oid,
        "t_tree_oid": t_commit["tree_oid"],
        "d_commit_oid": d_oid,
        "d_tree_oid": d_commit["tree_oid"],
        "d_descriptor_path": "ptde_subjects/D_RUNTIME_DESCRIPTOR.json",
        "d_descriptor_blob_oid": d_descriptor_record["blob_oid"],
        "d_descriptor_sha512": d_descriptor_record["blob_sha512"],
        "d_descriptor_blob_raw_sha512": d_descriptor_record["blob_raw_sha512"],
        "policy_sha512": descriptor["policy_sha512"],
        "t_profile_sha512": descriptor["t_profile_sha512"],
        "p_inventory_sha512": descriptor["p_inventory_sha512"],
        "lanes_sha512": descriptor["lanes_sha512"],
        "approved_lane_order": ["unit"],
        "lane_results": [lane_result],
        "evidence_inventory": evidence_records,
        "evidence_inventory_sha512": _canonical_sha512(evidence_records),
        "limitations": descriptor["assurance_limits"],
        "no_authority": expected_policy()["no_authority"],
    }
    if e_mutator is not None:
        e_mutator(manifest)
    manifest_path = f"{campaign_prefix}/E_EVIDENCE_MANIFEST.json"
    _write(repository, manifest_path, _document(manifest))
    for path, content in (e_extra_files or {}).items():
        _write(repository, path, content)
    e_oid = _commit(repository, "E")
    replay_e_oid: str | None = None
    if replay_e_child:
        _git(repository, "branch", "e-first", e_oid)
        _git(repository, "reset", "--hard", d_oid)
        for relative, content in contents.items():
            _write(repository, f"{campaign_prefix}/{relative}", content)
        _write(repository, manifest_path, _document(manifest))
        replay_e_oid = _commit(repository, "E replay with identical attempt and transcript")
        _git(repository, "branch", "e-replay", replay_e_oid)

    _run(["git", "clone", "--bare", str(repository), str(bare)])
    git_executable, git_executable_sha512 = _git_trust()
    return PTDEChain(
        worktree=repository,
        object_database=bare,
        p_oid=p_oid,
        t_oid=t_oid,
        d_oid=d_oid,
        e_oid=e_oid,
        git_executable=git_executable,
        git_executable_sha512=git_executable_sha512,
        accepted_attempt_history=_genesis_history(),
        replay_e_oid=replay_e_oid,
        transcript_sha512=lane_result["transcript_sha512"],
    )


def build_deep_json_chain(root: Path, *, depth: int = 2_000) -> PTDEChain:
    repository = root / "work"
    bare = root / "objects.git"
    repository.mkdir(parents=True)
    _git(repository, "init")
    _git(repository, "config", "user.name", "PTDE Test")
    _git(repository, "config", "user.email", "ptde@example.invalid")
    _git(repository, "config", "core.autocrlf", "false")
    _write(repository, "contracts/ptde/PTDE_POLICY_V1.json", policy_document_bytes())
    p_oid = _commit(repository, "P")
    deep = b'{"a":' + (b"[" * depth) + b"0" + (b"]" * depth) + b"}\n"
    _write(repository, "ptde_subjects/T_TEST_BUILD_PROFILE.json", deep)
    t_oid = _commit(repository, "T deep JSON")
    _write(repository, "ptde_subjects/D_RUNTIME_DESCRIPTOR.json", b"{}\n")
    d_oid = _commit(repository, "D")
    _write(repository, "evidence/ptde/campaign-1/evidence.bin", b"x")
    _write(repository, "evidence/ptde/campaign-1/E_EVIDENCE_MANIFEST.json", b"{}\n")
    e_oid = _commit(repository, "E")
    _run(["git", "clone", "--bare", str(repository), str(bare)])
    git_executable, git_executable_sha512 = _git_trust()
    return PTDEChain(
        repository,
        bare,
        p_oid,
        t_oid,
        d_oid,
        e_oid,
        git_executable,
        git_executable_sha512,
        _genesis_history(),
    )


@pytest.fixture(scope="module")
def valid_chain(tmp_path_factory: pytest.TempPathFactory) -> PTDEChain:
    return build_chain(tmp_path_factory.mktemp("ptde-valid"))


@pytest.fixture
def chain_factory(tmp_path: Path) -> Callable[..., PTDEChain]:
    counter = 0

    def factory(**kwargs: Any) -> PTDEChain:
        nonlocal counter
        counter += 1
        return build_chain(tmp_path / f"chain-{counter}", **kwargs)

    return factory


@pytest.fixture
def deep_json_chain_factory() -> Callable[..., PTDEChain]:
    return build_deep_json_chain


@pytest.fixture
def copy_object_database(tmp_path: Path) -> Callable[[PTDEChain, str], Path]:
    def copy(chain: PTDEChain, name: str) -> Path:
        target = tmp_path / name
        shutil.copytree(chain.object_database, target)
        return target

    return copy


__all__ = [
    "PTDEChain",
    "build_chain",
    "build_deep_json_chain",
]
