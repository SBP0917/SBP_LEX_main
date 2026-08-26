"""Repository and evidence provenance collection without runtime attachment."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .constants import EVIDENCE_GROUPS
from .digests import digest
from .paths import collect_group_files, validated_root
from .secure_git import PinnedGit, SecureGitError

MAX_TRACKED_PATHS = 100_000
MAX_TRACKED_PATH_INDEX_BYTES = 16_777_216


class RepositoryEvidenceError(ValueError):
    pass


def _git(runner: PinnedGit, root: Path, *arguments: str) -> str:
    try:
        stdout = runner.run(root, *arguments, timeout_seconds=120)
    except SecureGitError as exc:
        raise RepositoryEvidenceError("git_evidence_unavailable") from exc
    try:
        return stdout.decode("utf-8", errors="strict").rstrip("\r\n")
    except UnicodeError as exc:
        raise RepositoryEvidenceError("git_evidence_encoding_invalid") from exc


def collect_repository_provenance(
    repository_root: str | Path,
    *,
    expected_git_executable_sha512: str,
    git_executable: str = "git",
) -> dict[str, Any]:
    root = validated_root(repository_root)
    try:
        runner = PinnedGit(git_executable, expected_git_executable_sha512)
    except SecureGitError as exc:
        raise RepositoryEvidenceError("git_evidence_unavailable") from exc
    commit = _git(runner, root, "rev-parse", "HEAD")
    branch = _git(runner, root, "branch", "--show-current")
    status = _git(
        runner, root, "status", "--porcelain=v1", "--untracked-files=all"
    )
    tracked = _git(runner, root, "ls-files", "-z").split("\x00")
    tracked = sorted(path for path in tracked if path)
    if (
        len(tracked) > MAX_TRACKED_PATHS
        or sum(len(path.encode("utf-8")) for path in tracked)
        > MAX_TRACKED_PATH_INDEX_BYTES
    ):
        raise RepositoryEvidenceError("git_tracked_path_limit")
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RepositoryEvidenceError("git_commit_invalid")
    if not branch:
        raise RepositoryEvidenceError("git_detached_head_rejected")
    return {
        "git_commit": commit,
        "git_branch": branch,
        "git_executable_sha512": runner.executable_sha512,
        "working_tree_clean": status == "",
        "working_tree_status_digest": digest({"porcelain_v1": status}),
        "working_tree_status_entry_count": len(status.splitlines()) if status else 0,
        "tracked_path_count": len(tracked),
        "tracked_path_index_digest": digest({"tracked_paths": tracked}),
    }


def collect_v2_evidence_inventory(repository_root: str | Path) -> dict[str, Any]:
    root = validated_root(repository_root)
    groups: list[dict[str, Any]] = []
    all_files: dict[str, dict[str, Any]] = {}
    required_missing: list[str] = []
    optional_missing: list[str] = []
    for spec in EVIDENCE_GROUPS:
        group_id = spec.get("group_id")
        required = spec.get("required")
        if type(group_id) is not str or type(required) is not bool:
            raise RepositoryEvidenceError("evidence_group_specification_invalid")
        records, missing = collect_group_files(root, dict(spec))
        group_status = "PRESENT" if records and not missing else "MISSING"
        group = {
            "group_id": group_id,
            "required": required,
            "status": group_status,
            "missing_requirements": missing,
            "file_count": len(records),
            "files_digest": digest({"files": records}),
            "files": records,
        }
        groups.append(group)
        for record in records:
            existing = all_files.get(record["path"])
            if existing is not None and existing != record:
                raise RepositoryEvidenceError("evidence_path_measurement_conflict")
            all_files[record["path"]] = record
        if group_status == "MISSING":
            target = required_missing if required else optional_missing
            target.append(group_id)
    files = [all_files[path] for path in sorted(all_files)]
    return {
        "inventory_schema": "SBP_LEX_V2_LOCAL_TRUST_EVIDENCE_INVENTORY_V1",
        "groups": groups,
        "files": files,
        "file_count": len(files),
        "inventory_digest": digest({"groups": groups, "files": files}),
        "required_missing_groups": sorted(required_missing),
        "optional_missing_groups": sorted(optional_missing),
    }


__all__ = [
    "RepositoryEvidenceError",
    "collect_repository_provenance",
    "collect_v2_evidence_inventory",
]
