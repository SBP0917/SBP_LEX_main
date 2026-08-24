"""Repository and evidence provenance collection without runtime attachment."""

from __future__ import annotations

import os
import subprocess
import threading
from time import monotonic
from pathlib import Path
from typing import Any

from .constants import EVIDENCE_GROUPS, MAX_COMMAND_OUTPUT_BYTES
from .digests import digest
from .paths import collect_group_files, validated_root


class RepositoryEvidenceError(ValueError):
    pass


def _git(root: Path, *arguments: str) -> str:
    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()

    def reader(stream: Any, target: bytearray) -> None:
        try:
            while not overflow.is_set():
                chunk = stream.read(64 * 1024)
                if not chunk:
                    return
                if len(target) + len(chunk) > MAX_COMMAND_OUTPUT_BYTES:
                    overflow.set()
                    return
                target.extend(chunk)
        finally:
            stream.close()

    try:
        process = subprocess.Popen(
            ("git", *arguments),
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=os.name != "nt",
            creationflags=(
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                if os.name == "nt" else 0
            ),
        )
        assert process.stdout is not None and process.stderr is not None
        readers = (
            threading.Thread(target=reader, args=(process.stdout, stdout), daemon=True),
            threading.Thread(target=reader, args=(process.stderr, stderr), daemon=True),
        )
        for thread in readers:
            thread.start()
        deadline = monotonic() + 120
        while process.poll() is None and not overflow.is_set() and monotonic() < deadline:
            overflow.wait(0.05)
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        for thread in readers:
            thread.join(timeout=5)
        if overflow.is_set() or any(thread.is_alive() for thread in readers):
            raise RepositoryEvidenceError("git_evidence_output_limit")
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        raise RepositoryEvidenceError("git_evidence_unavailable") from exc
    if process.returncode != 0 or stderr:
        raise RepositoryEvidenceError("git_evidence_failed")
    try:
        return bytes(stdout).decode("utf-8", errors="strict").rstrip("\r\n")
    except UnicodeError as exc:
        raise RepositoryEvidenceError("git_evidence_encoding_invalid") from exc


def collect_repository_provenance(repository_root: str | Path) -> dict[str, Any]:
    root = validated_root(repository_root)
    commit = _git(root, "rev-parse", "HEAD")
    branch = _git(root, "branch", "--show-current")
    status = _git(root, "status", "--porcelain=v1", "--untracked-files=all")
    tracked = _git(root, "ls-files", "-z").split("\x00")
    tracked = sorted(path for path in tracked if path)
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise RepositoryEvidenceError("git_commit_invalid")
    if not branch:
        raise RepositoryEvidenceError("git_detached_head_rejected")
    return {
        "git_commit": commit,
        "git_branch": branch,
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
        records, missing = collect_group_files(root, dict(spec))
        group_status = "PRESENT" if records and not missing else "MISSING"
        group = {
            "group_id": spec["group_id"],
            "required": spec["required"],
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
            target = required_missing if spec["required"] else optional_missing
            target.append(spec["group_id"])
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
