from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from sbp_ptde.canonical import canonical_json_document_bytes, canonical_sha512, strict_json_document
from sbp_ptde.errors import PTDEVerificationError
from sbp_ptde.trust import AcceptedAttemptHistory

from sbp_lex.supply_chain.boundary import build_detached_boundary
from sbp_lex.supply_chain.build_provenance import execute_host_lane
from sbp_lex.supply_chain.constants import P_SOURCE_INCOMPLETE, P_SOURCE_READY_NOT_ADMITTED, UNSIGNED_NOT_ADMITTED
from sbp_lex.supply_chain.package import assemble_p_source_package
from sbp_lex.supply_chain.python_inventory import (
    PYTHON_LOCK_INVALID,
    PYTHON_LOCK_MISSING,
    PYTHON_LOCK_SCHEMA,
    evaluate_python_dependency_evidence,
)
from sbp_lex.supply_chain.rust_inventory import build_rust_dependency_inputs
from sbp_lex.supply_chain.source_binding import bind_p_object
from sbp_lex.supply_chain.verifier import verify_p_source_package


class PObjectFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = Path(tempfile.mkdtemp(prefix="supply-chain-p-"))
        self.addCleanup(lambda: shutil.rmtree(self.temp, ignore_errors=True))
        self.work = self.temp / "work"
        self.bare = self.temp / "objects.git"
        self.git = shutil.which("git")
        if not self.git:
            self.skipTest("git unavailable")
        self.git_digest = hashlib.sha512(Path(self.git).read_bytes()).hexdigest()
        self._run("init", str(self.work))
        self._run("-C", str(self.work), "config", "user.email", "test@example.invalid")
        self._run("-C", str(self.work), "config", "user.name", "Supply Chain Test")
        self._run("-C", str(self.work), "config", "core.autocrlf", "false")
        self._run("-C", str(self.work), "config", "core.eol", "lf")
        self.history = AcceptedAttemptHistory("history", 0, "0" * 128, ())
        self._write_p_tree()
        self._run("-C", str(self.work), "add", ".")
        self._run("-C", str(self.work), "commit", "-m", "P")
        self._run("clone", "--bare", str(self.work), str(self.bare))
        self.p_oid = self._output("-C", str(self.work), "rev-parse", "HEAD")
        self._home = self.temp / "empty-home"
        self._home.mkdir()

    def _run(self, *arguments: str) -> None:
        subprocess.run([self.git, *arguments], check=True, shell=False, capture_output=True)

    def _output(self, *arguments: str) -> str:
        return subprocess.run([self.git, *arguments], check=True, shell=False, capture_output=True, text=True).stdout.strip()

    def _write(self, relative: str, content: str) -> None:
        path = self.work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="")

    def _python_lock(self) -> dict:
        requirements = [{
            "identity": "cryptography",
            "version": "50.0.0",
            "source_requirement": "cryptography==50.0.0",
        }]
        return {
            "schema_id": PYTHON_LOCK_SCHEMA,
            "lock_sequence": 1,
            "prior_lock_sha512": "GENESIS",
            "requirements_sha512": canonical_sha512(requirements),
            "target_environment": {
                "implementation": "CPython",
                "python_version": "3.13.0",
                "abi_tag": "cp313",
                "platform_tag": "test_platform",
            },
            "rollback_guard": {
                "accepted_attempt_history_sequence": self.history.sequence,
                "accepted_attempt_history_sha512": self.history.sha512(),
            },
            "packages": [{
                "name": "cryptography",
                "version": "50.0.0",
                "hashes": ["sha256:" + "1" * 64],
                "scopes": ["production"],
                "direct": True,
                "dependencies": [],
            }],
        }

    def _write_p_tree(self, *, main: str = "def main():\n    return None\n", requirement: str = "cryptography==50.0.0\n", lock: bool = True, checksum: str = "one", python_lock: bool = True) -> None:
        self._write("main.py", main)
        self._write("requirements.txt", requirement)
        if python_lock:
            self._write(
                "python-dependencies.lock.json",
                canonical_json_document_bytes(self._python_lock()).decode("utf-8"),
            )
        self._write("sbp_lex/supply_chain/__init__.py", "\"\"\"detached\"\"\"\n")
        self._write("Cargo.toml", "[package]\nname='p-test'\nversion='1.0.0'\n")
        if lock:
            self._write("Cargo.lock", f"version=3\n[[package]]\nname='dep'\nversion='1.0.0'\nchecksum='{checksum}'\n")

    def bind(self):
        environment = {"HOME": str(self._home)}
        previous = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(environment)
            return bind_p_object(
                self.bare,
                p_oid=self.p_oid,
                expected_p_oid=self.p_oid,
                git_executable=self.git,
                expected_git_executable_sha512=self.git_digest,
                accepted_attempt_history=self.history,
                expected_attempt_history_sha512=self.history.sha512(),
            )
        finally:
            os.environ.clear()
            os.environ.update(previous)

    def test_real_committed_p_binding_is_unsigned_not_admitted(self) -> None:
        binding = self.bind()
        package = assemble_p_source_package(binding)
        report = verify_p_source_package(package.document, binding=binding)
        self.assertEqual(report.status, P_SOURCE_READY_NOT_ADMITTED)
        self.assertFalse(report.admitted)
        self.assertEqual(package.document["admission_state"], UNSIGNED_NOT_ADMITTED)

    def test_p_substitution_is_rejected(self) -> None:
        with self.assertRaises(PTDEVerificationError):
            previous = dict(os.environ)
            try:
                os.environ.clear()
                os.environ["HOME"] = str(self._home)
                bind_p_object(
                    self.bare, p_oid=self.p_oid, expected_p_oid="0" * len(self.p_oid), git_executable=self.git,
                    expected_git_executable_sha512=self.git_digest, accepted_attempt_history=self.history,
                    expected_attempt_history_sha512=self.history.sha512(),
                )
            finally:
                os.environ.clear()
                os.environ.update(previous)

    def test_history_pin_is_required(self) -> None:
        with self.assertRaises(PTDEVerificationError):
            previous = dict(os.environ)
            try:
                os.environ.clear()
                os.environ["HOME"] = str(self._home)
                bind_p_object(
                    self.bare, p_oid=self.p_oid, expected_p_oid=self.p_oid, git_executable=self.git,
                    expected_git_executable_sha512=self.git_digest, accepted_attempt_history=self.history,
                    expected_attempt_history_sha512="a" * 128,
                )
            finally:
                os.environ.clear()
                os.environ.update(previous)

    def test_mutable_checkout_is_not_consulted_after_p_binding(self) -> None:
        binding = self.bind()
        before = assemble_p_source_package(binding).document["package_sha512"]
        self._write("uncommitted.py", "mutated = True\n")
        after = assemble_p_source_package(binding).document["package_sha512"]
        self.assertEqual(before, after)

    def test_missing_committed_lock_is_incomplete(self) -> None:
        missing = self.temp / "missing"
        missing.mkdir()
        self.work = missing / "work"
        self.bare = missing / "objects.git"
        self._run("init", str(self.work))
        self._run("-C", str(self.work), "config", "user.email", "test@example.invalid")
        self._run("-C", str(self.work), "config", "user.name", "Supply Chain Test")
        self._run("-C", str(self.work), "config", "core.autocrlf", "false")
        self._run("-C", str(self.work), "config", "core.eol", "lf")
        self._write_p_tree(lock=False)
        self._run("-C", str(self.work), "add", ".")
        self._run("-C", str(self.work), "commit", "-m", "P missing lock")
        self._run("clone", "--bare", str(self.work), str(self.bare))
        self.p_oid = self._output("-C", str(self.work), "rev-parse", "HEAD")
        package = assemble_p_source_package(self.bind())
        self.assertEqual(package.document["source_status"], P_SOURCE_INCOMPLETE)

    def test_missing_python_lock_is_incomplete(self) -> None:
        self._run("-C", str(self.work), "rm", "python-dependencies.lock.json")
        self._run("-C", str(self.work), "commit", "-m", "P missing Python lock")
        self._run("-C", str(self.work), "push", str(self.bare), "HEAD:master")
        previous = self.p_oid
        self.p_oid = self._output("-C", str(self.work), "rev-parse", "HEAD")
        try:
            package = assemble_p_source_package(self.bind())
            self.assertEqual(package.document["source_status"], P_SOURCE_INCOMPLETE)
            self.assertEqual(package.python_inputs["lock_status"], PYTHON_LOCK_MISSING)
        finally:
            self.p_oid = previous

    def test_python_lock_hostile_variants_fail_closed(self) -> None:
        requirements = b"cryptography==50.0.0\n"
        valid = self._python_lock()
        expected_environment = valid["target_environment"]
        common = {
            "expected_environment": expected_environment,
            "expected_history_sequence": self.history.sequence,
            "expected_history_sha512": self.history.sha512(),
        }
        complete = evaluate_python_dependency_evidence(requirements, valid, **common)
        self.assertEqual(complete["dependency_evidence_status"], "COMPLETE")

        mutations = {
            "unhashed": lambda value: value["packages"][0].update(hashes=[]),
            "mismatched": lambda value: value["packages"][0].update(version="49.0.0"),
            "case_variant": lambda value: value["packages"][0].update(name="Cryptography"),
            "duplicate": lambda value: value["packages"].append(deepcopy(value["packages"][0])),
            "extra": lambda value: value["packages"].append({
                "name": "orphan", "version": "1.0.0", "hashes": ["sha256:" + "2" * 64],
                "scopes": ["development"], "direct": False, "dependencies": [],
            }),
            "scope": lambda value: value["packages"][0].update(scopes=[]),
            "rollback": lambda value: value.update(lock_sequence=2),
            "environment": lambda value: value["target_environment"].update(abi_tag="cp312"),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                hostile = deepcopy(valid)
                mutation(hostile)
                result = evaluate_python_dependency_evidence(requirements, hostile, **common)
                self.assertEqual(result["lock_status"], PYTHON_LOCK_INVALID)
                self.assertEqual(result["dependency_evidence_status"], "INCOMPLETE")

        unpinned = evaluate_python_dependency_evidence(b"cryptography>=50\n", valid, **common)
        self.assertEqual(unpinned["lock_status"], PYTHON_LOCK_INVALID)
        self.assertEqual(unpinned["requirements_status"], "INVALID_OR_UNPINNED")

    def test_runtime_import_attachment_in_p_is_rejected(self) -> None:
        self._write("main.py", "import sbp_lex.supply_chain\n")
        self._run("-C", str(self.work), "add", "main.py")
        self._run("-C", str(self.work), "commit", "-m", "hostile runtime import")
        self._run("-C", str(self.work), "push", str(self.bare), "HEAD:master")
        previous = self.p_oid
        self.p_oid = self._output("-C", str(self.work), "rev-parse", "HEAD")
        try:
            self.assertEqual(build_detached_boundary(self.bind())["boundary_status"], "P_BOUNDARY_INVALID")
        finally:
            self.p_oid = previous

    def test_rust_checksum_mutation_changes_committed_inventory(self) -> None:
        first = build_rust_dependency_inputs(self.bind())["payload_sha512"]
        self._write("Cargo.lock", "version=3\n[[package]]\nname='dep'\nversion='1.0.0'\nchecksum='two'\n")
        self._run("-C", str(self.work), "add", "Cargo.lock")
        self._run("-C", str(self.work), "commit", "-m", "checksum")
        self._run("-C", str(self.work), "push", str(self.bare), "HEAD:master")
        second_oid = self._output("-C", str(self.work), "rev-parse", "HEAD")
        previous = self.p_oid
        self.p_oid = second_oid
        try:
            second = build_rust_dependency_inputs(self.bind())["payload_sha512"]
        finally:
            self.p_oid = previous
        self.assertNotEqual(first, second)

    def test_package_mutation_is_invalid(self) -> None:
        binding = self.bind()
        package = assemble_p_source_package(binding).document
        package["source_status"] = P_SOURCE_INCOMPLETE
        self.assertEqual(verify_p_source_package(package, binding=binding).status, "P_SOURCE_INVALID")

    def test_ptde_canonical_terminal_lf_is_required(self) -> None:
        document = {"value": "x"}
        self.assertTrue(canonical_json_document_bytes(document).endswith(b"\n"))

    def test_host_lane_emits_full_ptde_transcript_without_admission(self) -> None:
        environment = {
            key: os.environ[key]
            for key in ("COMSPEC", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        names = sorted(environment)
        lane = {
            "lane_id": "git_version",
            "order": 1,
            "executable_id": "git",
            "argv": ["git", "--version"],
            "cwd_rule": "CLEAN_SOURCE_CHECKOUT",
            "environment_name_allowlist": names,
            "environment_name_allowlist_sha512": canonical_sha512(names),
            "timeout_seconds": 10,
            "expected_exit_codes": [0],
            "stdout_contract": {"capture": "FULL_BYTES", "relative_path": "streams/stdout.log", "maximum_byte_count": 1_048_576},
            "stderr_contract": {"capture": "FULL_BYTES", "relative_path": "streams/stderr.log", "maximum_byte_count": 1_048_576},
            "produced_artifact_contract": {"required_relative_paths": [], "optional_relative_paths": [], "maximum_file_count": 0, "maximum_total_byte_count": 1},
        }
        evidence = self.temp / "evidence"
        clean_environment = {
            key: os.environ[key]
            for key in ("COMSPEC", "SYSTEMROOT", "TEMP", "TMP", "WINDIR")
            if key in os.environ
        }
        clean_environment.update({
            "GIT_CONFIG_COUNT": "0",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
        })
        clean_status = subprocess.run(
            [self.git, "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=self.work,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            env=clean_environment,
        )
        self.assertEqual(clean_status.returncode, 0, clean_status.stderr.decode("utf-8", "replace"))
        self.assertEqual(clean_status.stdout, b"", clean_status.stdout.decode("utf-8", "replace"))
        result = execute_host_lane(
            lane=lane,
            executable_path=self.git,
            expected_executable_sha512=self.git_digest,
            git_executable=self.git,
            expected_git_executable_sha512=self.git_digest,
            source_checkout=self.work,
            evidence_root=evidence,
            campaign_id="supply",
            attempt_id="attempt1",
            d_commit_oid=self.p_oid,
            d_descriptor_sha512="d" * 128,
            environment=environment,
        )
        transcript = strict_json_document((evidence / result["transcript_path"]).read_bytes(), code="TEST_TRANSCRIPT")
        self.assertEqual(transcript["schema_id"], "sbp.lex.v2.ptde.lane-transcript/1")
        self.assertTrue(transcript["stdout_full_bytes"])
        self.assertFalse(transcript["output_truncated"])
        self.assertEqual(result["admission_state"], UNSIGNED_NOT_ADMITTED)

    def test_timeout_fails_closed_with_process_tree_termination(self) -> None:
        environment = {
            key: os.environ[key]
            for key in ("COMSPEC", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        python_digest = hashlib.sha512(Path(sys.executable).read_bytes()).hexdigest()
        lane = {
            "lane_id": "timeout_probe",
            "order": 1,
            "executable_id": "python",
            "argv": ["python", "-c", "import time; time.sleep(10)"],
            "cwd_rule": "CLEAN_SOURCE_CHECKOUT",
            "environment_name_allowlist": sorted(environment),
            "environment_name_allowlist_sha512": canonical_sha512(sorted(environment)),
            "timeout_seconds": 1,
            "expected_exit_codes": [0],
            "stdout_contract": {"capture": "FULL_BYTES", "relative_path": "streams/timeout.stdout.log", "maximum_byte_count": 1_048_576},
            "stderr_contract": {"capture": "FULL_BYTES", "relative_path": "streams/timeout.stderr.log", "maximum_byte_count": 1_048_576},
            "produced_artifact_contract": {"required_relative_paths": [], "optional_relative_paths": [], "maximum_file_count": 0, "maximum_total_byte_count": 1},
        }
        result = execute_host_lane(
            lane=lane,
            executable_path=sys.executable,
            expected_executable_sha512=python_digest,
            git_executable=self.git,
            expected_git_executable_sha512=self.git_digest,
            source_checkout=self.work,
            evidence_root=self.temp / "timeout-evidence",
            campaign_id="supply",
            attempt_id="timeout1",
            d_commit_oid=self.p_oid,
            d_descriptor_sha512="d" * 128,
            environment=environment,
        )
        transcript = result["pinned_host_lane"]
        self.assertEqual(transcript["status"], "LANE_FAIL")
        self.assertTrue(transcript["timed_out"])
        self.assertEqual(transcript["timeout_status"], "TIMEOUT_FAIL_CLOSED")
        self.assertTrue(transcript["process_tree_terminated"])
        self.assertEqual(result["admission_state"], UNSIGNED_NOT_ADMITTED)

    def test_dirty_checkout_is_rejected_before_lane_execution(self) -> None:
        self._write("uncommitted-hostile-input.txt", "dirty\n")
        environment = {
            key: os.environ[key]
            for key in ("COMSPEC", "SYSTEMROOT", "WINDIR")
            if key in os.environ
        }
        lane = {
            "lane_id": "dirty_probe",
            "order": 1,
            "executable_id": "git",
            "argv": ["git", "--version"],
            "cwd_rule": "CLEAN_SOURCE_CHECKOUT",
            "environment_name_allowlist": sorted(environment),
            "environment_name_allowlist_sha512": canonical_sha512(sorted(environment)),
            "timeout_seconds": 10,
            "expected_exit_codes": [0],
            "stdout_contract": {"capture": "FULL_BYTES", "relative_path": "streams/dirty.stdout.log", "maximum_byte_count": 1_048_576},
            "stderr_contract": {"capture": "FULL_BYTES", "relative_path": "streams/dirty.stderr.log", "maximum_byte_count": 1_048_576},
            "produced_artifact_contract": {"required_relative_paths": [], "optional_relative_paths": [], "maximum_file_count": 0, "maximum_total_byte_count": 1},
        }
        with self.assertRaises(PTDEVerificationError):
            execute_host_lane(
                lane=lane,
                executable_path=self.git,
                expected_executable_sha512=self.git_digest,
                git_executable=self.git,
                expected_git_executable_sha512=self.git_digest,
                source_checkout=self.work,
                evidence_root=self.temp / "dirty-evidence",
                campaign_id="supply",
                attempt_id="dirty1",
                d_commit_oid=self.p_oid,
                d_descriptor_sha512="d" * 128,
                environment=environment,
            )


if __name__ == "__main__":
    unittest.main()
