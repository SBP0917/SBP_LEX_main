from __future__ import annotations

import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from sbp_lex.local_trust import repository_guard
from sbp_lex.local_trust.repository_guard import verify_repository_guard

ROOT = Path(__file__).resolve().parents[2]


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
    _git(root, "init", "-q")
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
    result = verify_repository_guard(_repository(tmp_path), scope="test")
    assert result["status"] == "PASS", (result["failures"], result["checks"])
    assert result["failures"] == []
    assert result["checks"] == {
        "working_tree_clean": True,
        "critical_inventory_matches_commit": True,
        "git_executable_measured": True,
        "known_good_runtime": True,
        "dependency_locks": True,
        "installed_environment": True,
        "lifecycle_change_control": True,
    }
    assert all(value is False for value in result["no_authority"].values())
    assert result["accepted_history_created"] is False
    assert result["self_referential_hash_manifest_created"] is False


def test_dirty_and_untracked_trees_fail_closed(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    (root / "sbp_lex" / "__init__.py").write_text("VERSION = 3\n", encoding="utf-8")
    (root / "untracked-critical.py").write_text("pass\n", encoding="utf-8")
    result = verify_repository_guard(root)
    assert result["status"] == "FAIL"
    assert "working_tree_not_clean" in result["failures"]
    assert "untracked_files_present" in result["failures"]
    assert result["checks"]["critical_inventory_matches_commit"] is False


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
    result = verify_repository_guard(root)
    assert result["status"] == "FAIL"
    assert "dependency_lock_validation_failed" in result["failures"]
    assert "installed_environment_not_exact_lock_closure" in result["failures"]


def test_change_control_requires_classified_checks_and_rollback(
    tmp_path: Path,
    exact_environment: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    invalid = deepcopy(repository_guard.CHANGE_CONTROL_POLICY)
    invalid["change_classes"]["trust_boundary"]["rollback_plan_required"] = False
    monkeypatch.setattr(repository_guard, "CHANGE_CONTROL_POLICY", invalid)
    result = verify_repository_guard(root)
    assert result["status"] == "FAIL"
    assert "lifecycle_change_control_invalid" in result["failures"]


def test_runtime_and_scope_mismatch_fail_closed(
    tmp_path: Path,
    exact_environment: None,
) -> None:
    root = _repository(tmp_path)
    (root / "runtime.txt").write_text("python-3.12.12\n", encoding="ascii")
    result = verify_repository_guard(root, scope="invalid")
    assert result["status"] == "FAIL"
    assert "known_good_runtime_mismatch" in result["failures"]
    assert "verification_scope_invalid" in result["failures"]


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
