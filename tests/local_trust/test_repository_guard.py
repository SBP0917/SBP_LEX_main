from __future__ import annotations

import hashlib
import json
import operator
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sbp_lex.local_trust import repository_guard
from sbp_lex.local_trust.repository_guard import verify_repository_guard

ROOT = Path(__file__).resolve().parents[2]
PTDE_HISTORY_SEQUENCE = 0
PTDE_HISTORY_DIGEST = "a" * 128
LOCAL_TRUST_HISTORY_SEQUENCE = 0
LOCAL_TRUST_HISTORY_DIGEST = "b" * 128
PRIOR_LOCK_SHA512 = "GENESIS"
GIT_EXECUTABLE = shutil.which("git")
if GIT_EXECUTABLE is None:
    raise RuntimeError("git required for repository guard tests")
GIT_SHA512 = hashlib.sha512(Path(GIT_EXECUTABLE).read_bytes()).hexdigest()


def _verify(root: Path, *, scope: str = "test") -> dict:
    return verify_repository_guard(
        root,
        scope=scope,
        expected_ptde_accepted_attempt_history_sequence=PTDE_HISTORY_SEQUENCE,
        expected_ptde_accepted_attempt_history_digest=PTDE_HISTORY_DIGEST,
        expected_local_trust_accepted_package_history_sequence=(
            LOCAL_TRUST_HISTORY_SEQUENCE
        ),
        expected_local_trust_accepted_package_history_digest=(
            LOCAL_TRUST_HISTORY_DIGEST
        ),
        expected_python_dependency_prior_lock_sha512=PRIOR_LOCK_SHA512,
        git_executable=GIT_EXECUTABLE,
        expected_git_executable_sha512=GIT_SHA512,
    )


def _write_canonical_lock(path: Path, value: dict) -> None:
    path.write_bytes(
        (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
    )


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=SBP-LEX Test",
            "-c",
            "user.email=sbp-lex-test@example.invalid",
            *arguments,
        ),
        cwd=root,
        check=True,
        capture_output=True,
        shell=False,
    )


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    (root / "sbp_lex").mkdir(parents=True)
    (root / "main.py").write_text("def run_v2():\n    return None\n", encoding="utf-8")
    (root / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (root / "requirements.txt").write_bytes((ROOT / "requirements.txt").read_bytes())
    (root / "requirements-production.lock.txt").write_bytes(
        (ROOT / "requirements-production.lock.txt").read_bytes()
    )
    (root / "requirements-test.lock.txt").write_bytes(
        (ROOT / "requirements-test.lock.txt").read_bytes()
    )
    (root / "runtime.txt").write_bytes((ROOT / "runtime.txt").read_bytes())
    (root / "sbp_lex" / "__init__.py").write_text("VERSION = 2\n", encoding="utf-8")
    governed_fixture_files = {
        "tests/test_smoke.py": b"def test_smoke():\n    assert True\n",
        "tools/verify.py": b"raise SystemExit(0)\n",
        "fixture_rust/Cargo.toml": b"[package]\nname='fixture'\nversion='0.1.0'\n",
        "formal/tla/Fixture.tla": b"---- MODULE Fixture ----\n====\n",
        "spark_safety_monitor/src/fixture.ads": b"package Fixture is end Fixture;\n",
    }
    for relative, content in governed_fixture_files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)
    for relative in repository_guard.DEPENDENCY_LOCK_PATHS:
        destination = root / relative
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(f"fixture:{relative}\n".encode())
    production_lock = repository_guard._parse_lock(
        root, "requirements-production.lock.txt"
    )
    assurance_lock = repository_guard._parse_lock(
        root, "requirements-test.lock.txt"
    )
    dependencies = {
        "cffi": ["pycparser"],
        "colorama": [],
        "cryptography": ["cffi"],
        "iniconfig": [],
        "packaging": [],
        "pluggy": [],
        "pycparser": [],
        "pygments": [],
        "pytest": ["colorama", "iniconfig", "packaging", "pluggy", "pygments"],
    }
    packages = []
    for name, (version, package_hash) in sorted(assurance_lock.items()):
        scopes = ["assurance"]
        if name in production_lock:
            scopes.append("production")
        direct_scopes = []
        if name == "cryptography":
            direct_scopes = ["assurance", "production"]
        elif name == "pytest":
            direct_scopes = ["assurance"]
        packages.append(
            {
                "name": name,
                "version": version,
                "hashes": [f"sha256:{package_hash}"],
                "scopes": scopes,
                "direct_scopes": direct_scopes,
                "dependencies": dependencies[name],
            }
        )
    requirements = [
        {
            "identity": "cryptography",
            "version": "50.0.0",
            "source_requirement": "cryptography==50.0.0",
        }
    ]
    (root / "python-dependencies.lock.json").write_bytes(
        (
            json.dumps(
            {
                "schema_id": "sbp.lex.v2.python-dependency-lock/3",
                "lock_sequence": 1,
                "prior_lock_sha512": "GENESIS",
                "requirements_sha512": repository_guard.digest(requirements),
                "production_hash_lock_sha512": repository_guard.sha512(
                    (root / "requirements-production.lock.txt").read_bytes()
                ).hexdigest(),
                "assurance_hash_lock_sha512": repository_guard.sha512(
                    (root / "requirements-test.lock.txt").read_bytes()
                ).hexdigest(),
                "target_environment": {
                    "implementation": "CPython",
                    "python_version": "3.12.13",
                    "abi_tag": "cpython-312",
                    "platform_tag": "win-amd64",
                    "installed_scope": "assurance",
                },
                "rollback_guard": {
                    "ptde_accepted_attempt_history_sequence": (
                        PTDE_HISTORY_SEQUENCE
                    ),
                    "ptde_accepted_attempt_history_sha512": PTDE_HISTORY_DIGEST,
                    "local_trust_accepted_package_history_sequence": (
                        LOCAL_TRUST_HISTORY_SEQUENCE
                    ),
                    "local_trust_accepted_package_history_sha512": (
                        LOCAL_TRUST_HISTORY_DIGEST
                    ),
                },
                "packages": packages,
            },
            sort_keys=True,
            separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8"),
    )
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "core.eol", "lf")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "fixture")
    return root


@pytest.fixture
def exact_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(repository_guard, "_installed_versions", lambda: dict(repository_guard.TEST_PACKAGES))
    monkeypatch.setattr(repository_guard, "_pip_check", lambda root: True)


def test_clean_committed_known_good_repository_passes(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    observed_status = repository_guard.PinnedGit(
        GIT_EXECUTABLE, GIT_SHA512
    ).run(root, "status", "--porcelain=v1", "--untracked-files=all")
    assert observed_status == b"", observed_status
    result = _verify(root, scope="test")
    assert result["status"] == "PASS", (result["failures"], result["checks"])
    assert result["failures"] == []
    assert result["checks"] == {
        "working_tree_clean": True,
        "critical_inventory_matches_commit": True,
        "git_executable_measured": True,
        "known_good_runtime": True,
        "dependency_locks": True,
        "governed_python_lock_binding": True,
        "installed_environment": True,
        "lifecycle_change_control": True,
    }
    assert all(value is False for value in result["no_authority"].values())
    assert result["accepted_history_created"] is False
    assert result["self_referential_hash_manifest_created"] is False


def test_dependency_validator_truth_is_immutable() -> None:
    for policy in (
        repository_guard.DIRECT_REQUIREMENTS,
        repository_guard.PRODUCTION_PACKAGES,
        repository_guard.TEST_PACKAGES,
    ):
        with pytest.raises(TypeError):
            operator.setitem(policy, "hostile", "0.0.0")


def test_dirty_and_untracked_trees_fail_closed(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    (root / "sbp_lex" / "__init__.py").write_text("VERSION = 3\n", encoding="utf-8")
    (root / "untracked-critical.py").write_text("pass\n", encoding="utf-8")
    result = _verify(root)
    assert result["status"] == "FAIL"
    assert "working_tree_not_clean" in result["failures"]
    assert "untracked_files_present" in result["failures"]
    assert result["checks"]["critical_inventory_matches_commit"] is False


def test_guard_disables_hostile_repository_fsmonitor(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "guard-fsmonitor-executed.txt"
    helper = tmp_path / "guard-hostile-fsmonitor.py"
    helper.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    helper_command = (
        f'"{Path(sys.executable).as_posix()}" "{helper.as_posix()}"'
    )
    _git(root, "config", "core.fsmonitor", helper_command)

    result = _verify(root)

    assert result["status"] == "PASS", result["failures"]
    assert not marker.exists()


def test_repository_inventory_path_count_is_bounded(
    tmp_path: Path,
    exact_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    monkeypatch.setattr(repository_guard, "MAX_TRACKED_PATHS", 1)

    result = _verify(root)

    assert result["status"] == "FAIL"
    assert "critical_inventory_path_limit" in result["failures"]


def test_malformed_lock_and_environment_drift_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    (root / "requirements-test.lock.txt").write_text(
        "--only-binary=:all:\npytest==9.1.1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(repository_guard, "_installed_versions", lambda: {"pytest": "0.0.0"})
    monkeypatch.setattr(repository_guard, "_pip_check", lambda path: True)
    result = _verify(root)
    assert result["status"] == "FAIL"
    assert "dependency_lock_validation_failed" in result["failures"]
    assert "installed_environment_not_exact_lock_closure" in result["failures"]


def test_change_control_requires_classified_checks_and_rollback(
    tmp_path: Path,
    exact_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    invalid = repository_guard.change_control_policy_document()
    invalid["change_classes"]["trust_boundary"]["rollback_plan_required"] = False
    monkeypatch.setattr(repository_guard, "CHANGE_CONTROL_POLICY", invalid)
    result = _verify(root)
    assert result["status"] == "FAIL"
    assert "lifecycle_change_control_invalid" in result["failures"]


def test_runtime_and_scope_mismatch_fail_closed(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    (root / "runtime.txt").write_text("python-3.12.12\n", encoding="ascii")
    result = _verify(root, scope="invalid")
    assert result["status"] == "FAIL"
    assert "known_good_runtime_mismatch" in result["failures"]
    assert "verification_scope_invalid" in result["failures"]


def test_repository_guard_requires_external_v3_rollback_pins(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    with pytest.raises(TypeError):
        verify_repository_guard(root)
    substituted = verify_repository_guard(
        root,
        expected_ptde_accepted_attempt_history_sequence=0,
        expected_ptde_accepted_attempt_history_digest="f" * 128,
        expected_local_trust_accepted_package_history_sequence=0,
        expected_local_trust_accepted_package_history_digest=(
            LOCAL_TRUST_HISTORY_DIGEST
        ),
        expected_python_dependency_prior_lock_sha512=PRIOR_LOCK_SHA512,
        git_executable=GIT_EXECUTABLE,
        expected_git_executable_sha512=GIT_SHA512,
    )
    assert substituted["checks"]["governed_python_lock_binding"] is False
    assert "governed_python_lock_binding_invalid" in substituted["failures"]


def test_repository_guard_rejects_v2_and_non_genesis_transition(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    lock_path = root / "python-dependencies.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["schema_id"] = "sbp.lex.v2.python-dependency-lock/2"
    lock["rollback_guard"] = {
        "accepted_attempt_history_sequence": 0,
        "accepted_attempt_history_sha512": PTDE_HISTORY_DIGEST,
    }
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    legacy = _verify(root)
    assert legacy["checks"]["governed_python_lock_binding"] is False

    lock["schema_id"] = "sbp.lex.v2.python-dependency-lock/3"
    lock["lock_sequence"] = 2
    lock["prior_lock_sha512"] = "GENESIS"
    lock["rollback_guard"] = {
        "ptde_accepted_attempt_history_sequence": 1,
        "ptde_accepted_attempt_history_sha512": PTDE_HISTORY_DIGEST,
        "local_trust_accepted_package_history_sequence": 0,
        "local_trust_accepted_package_history_sha512": LOCAL_TRUST_HISTORY_DIGEST,
    }
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    invalid_transition = verify_repository_guard(
        root,
        expected_ptde_accepted_attempt_history_sequence=1,
        expected_ptde_accepted_attempt_history_digest=PTDE_HISTORY_DIGEST,
        expected_local_trust_accepted_package_history_sequence=0,
        expected_local_trust_accepted_package_history_digest=(
            LOCAL_TRUST_HISTORY_DIGEST
        ),
        expected_python_dependency_prior_lock_sha512="c" * 128,
        git_executable=GIT_EXECUTABLE,
        expected_git_executable_sha512=GIT_SHA512,
    )
    assert invalid_transition["checks"]["governed_python_lock_binding"] is False


@pytest.mark.parametrize(
    "mutation",
    (
        "arbitrary_prior",
        "fake_source_digest",
        "fake_hash_lock_digest",
        "fake_package_graph",
        "dependency_cycle",
    ),
)
def test_repository_guard_recomputes_entire_governed_lock(
    tmp_path: Path,
    exact_environment: None,
    mutation: str,
) -> None:
    root = _repository(tmp_path)
    lock_path = root / "python-dependencies.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    expected_prior = PRIOR_LOCK_SHA512
    if mutation == "arbitrary_prior":
        lock["prior_lock_sha512"] = "c" * 128
        expected_prior = "c" * 128
    elif mutation == "fake_source_digest":
        lock["requirements_sha512"] = "f" * 128
    elif mutation == "fake_hash_lock_digest":
        lock["production_hash_lock_sha512"] = "f" * 128
    elif mutation == "fake_package_graph":
        cryptography = next(
            item for item in lock["packages"] if item["name"] == "cryptography"
        )
        cryptography["dependencies"] = []
    else:
        cffi = next(item for item in lock["packages"] if item["name"] == "cffi")
        cffi["dependencies"] = ["cryptography"]
    _write_canonical_lock(lock_path, lock)
    result = verify_repository_guard(
        root,
        expected_ptde_accepted_attempt_history_sequence=PTDE_HISTORY_SEQUENCE,
        expected_ptde_accepted_attempt_history_digest=PTDE_HISTORY_DIGEST,
        expected_local_trust_accepted_package_history_sequence=(
            LOCAL_TRUST_HISTORY_SEQUENCE
        ),
        expected_local_trust_accepted_package_history_digest=(
            LOCAL_TRUST_HISTORY_DIGEST
        ),
        expected_python_dependency_prior_lock_sha512=expected_prior,
        git_executable=GIT_EXECUTABLE,
        expected_git_executable_sha512=GIT_SHA512,
    )
    assert result["checks"]["governed_python_lock_binding"] is False
    assert "governed_python_lock_binding_invalid" in result["failures"]


def test_subprocess_output_overflow_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(
        repository_guard.RepositoryGuardError,
        match="command_output_limit",
    ):
        repository_guard._run_bounded(
            (sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"),
            cwd=tmp_path,
            env={
                "PATH": str(Path(sys.executable).resolve().parent),
                "SYSTEMROOT": repository_guard.os.environ.get("SYSTEMROOT", ""),
                "WINDIR": repository_guard.os.environ.get("WINDIR", ""),
            },
            timeout_seconds=10,
            max_output_bytes=64,
        )
