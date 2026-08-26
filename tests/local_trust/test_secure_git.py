from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from sbp_lex.local_trust.repository import (
    RepositoryEvidenceError,
    collect_repository_provenance,
)
from sbp_lex.local_trust.secure_git import PinnedGit, SecureGitError

GIT_EXECUTABLE = shutil.which("git")
if GIT_EXECUTABLE is None:
    raise RuntimeError("git required for secure Git tests")
GIT_SHA512 = hashlib.sha512(Path(GIT_EXECUTABLE).read_bytes()).hexdigest()


def _git(root: Path, *arguments: str) -> None:
    subprocess.run(
        (
            GIT_EXECUTABLE,
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
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    _git(root, "config", "core.eol", "lf")
    (root / "tracked.txt").write_bytes(b"fixed\n")
    _git(root, "add", "tracked.txt")
    _git(root, "commit", "-q", "-m", "fixture")
    return root


def test_provenance_uses_exact_pinned_git_and_ignores_hostile_fsmonitor(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    marker = tmp_path / "fsmonitor-executed.txt"
    helper = tmp_path / "hostile-fsmonitor.py"
    helper.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    helper_command = (
        f'"{Path(sys.executable).as_posix()}" "{helper.as_posix()}"'
    )
    _git(root, "config", "core.fsmonitor", helper_command)

    result = collect_repository_provenance(
        root,
        git_executable=GIT_EXECUTABLE,
        expected_git_executable_sha512=GIT_SHA512,
    )

    assert result["working_tree_clean"] is True
    assert result["git_executable_sha512"] == GIT_SHA512
    assert not marker.exists()


def test_wrong_pin_and_scripted_path_git_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _repository(tmp_path)
    with pytest.raises(RepositoryEvidenceError, match="git_evidence_unavailable"):
        collect_repository_provenance(
            root,
            git_executable=GIT_EXECUTABLE,
            expected_git_executable_sha512="0" * 128,
        )

    fake_directory = tmp_path / "fake-bin"
    fake_directory.mkdir()
    fake_git = fake_directory / ("git.cmd" if os.name == "nt" else "git")
    fake_git.write_text(
        "@exit /b 0\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n",
        encoding="utf-8",
    )
    if os.name != "nt":
        fake_git.chmod(0o700)
    monkeypatch.setenv("PATH", str(fake_directory))
    fake_digest = hashlib.sha512(fake_git.read_bytes()).hexdigest()
    with pytest.raises(SecureGitError, match="git_executable_script_rejected"):
        PinnedGit("git", fake_digest)


def test_git_output_is_bounded_before_it_can_be_trusted(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    payload = b"x" * 4096
    (root / "large.bin").write_bytes(payload)
    _git(root, "add", "large.bin")
    _git(root, "commit", "-q", "-m", "large")
    runner = PinnedGit(GIT_EXECUTABLE, GIT_SHA512)

    with pytest.raises(SecureGitError, match="git_command_output_limit"):
        runner.run(root, "show", "HEAD:large.bin", maximum_output_bytes=64)


def test_alternate_hardlink_and_changed_repository_root_fail_closed(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    alternate = tmp_path / "git-hardlink.exe"
    try:
        os.link(GIT_EXECUTABLE, alternate)
    except OSError:
        pass
    else:
        with pytest.raises(SecureGitError, match="git_executable_hard_link_rejected"):
            PinnedGit(alternate, GIT_SHA512)

    runner = PinnedGit(GIT_EXECUTABLE, GIT_SHA512)
    runner.run(root, "rev-parse", "--verify", "HEAD")
    moved = tmp_path / "moved-repository"
    root.rename(moved)
    root.mkdir()
    with pytest.raises(SecureGitError, match="git_repository_root_changed"):
        runner.run(root, "rev-parse", "--verify", "HEAD")


def test_git_argument_count_is_bounded(tmp_path: Path) -> None:
    runner = PinnedGit(GIT_EXECUTABLE, GIT_SHA512)
    with pytest.raises(SecureGitError, match="git_command_invalid"):
        runner.run(_repository(tmp_path), *("x" for _ in range(257)))
