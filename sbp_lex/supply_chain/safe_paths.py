"""Bounded regular-file helpers for detached host-lane evidence only."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from sbp_ptde.canonical import canonical_path
from sbp_ptde.errors import reject


@dataclass(frozen=True, slots=True)
class FileMeasurement:
    relative_path: str
    byte_count: int
    sha512: str


def _is_link_or_reparse(value: os.stat_result) -> bool:
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(value.st_mode) or bool(getattr(value, "st_file_attributes", 0) & reparse)


def _identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns


def _regular_before_open(path: Path, *, maximum_bytes: int) -> os.stat_result:
    value = path.lstat()
    if (
        not stat.S_ISREG(value.st_mode)
        or _is_link_or_reparse(value)
        or value.st_nlink != 1
        or value.st_size < 0
        or value.st_size > maximum_bytes
    ):
        raise reject("SUPPLY_CHAIN_EVIDENCE_FILE_INVALID")
    return value


def measure_regular_file(root: Path, relative_path: str, *, maximum_bytes: int) -> FileMeasurement:
    """Read one relative regular file once, with no link following or race tolerance."""

    relative = canonical_path(relative_path, code="SUPPLY_CHAIN_EVIDENCE_PATH_INVALID")
    if type(maximum_bytes) is not int or maximum_bytes < 0:
        raise reject("SUPPLY_CHAIN_EVIDENCE_LIMIT_INVALID")
    root_stat = root.lstat()
    if not stat.S_ISDIR(root_stat.st_mode) or _is_link_or_reparse(root_stat):
        raise reject("SUPPLY_CHAIN_EVIDENCE_ROOT_INVALID")
    path = root.joinpath(*relative.split("/"))
    current = root
    for segment in relative.split("/"):
        current = current / segment
        if _is_link_or_reparse(current.lstat()):
            raise reject("SUPPLY_CHAIN_EVIDENCE_LINK_REJECTED")
    before = _regular_before_open(path, maximum_bytes=maximum_bytes)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise reject("SUPPLY_CHAIN_EVIDENCE_IDENTITY_CHANGED")
        digest = hashlib.sha512()
        observed = 0
        while True:
            chunk = os.read(descriptor, min(1_048_576, maximum_bytes + 1 - observed))
            if not chunk:
                break
            observed += len(chunk)
            if observed > maximum_bytes:
                raise reject("SUPPLY_CHAIN_EVIDENCE_SIZE_LIMIT_EXCEEDED")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    after = _regular_before_open(path, maximum_bytes=maximum_bytes)
    if _identity(before) != _identity(after) or observed != before.st_size:
        raise reject("SUPPLY_CHAIN_EVIDENCE_CHANGED_DURING_MEASUREMENT")
    return FileMeasurement(relative, observed, digest.hexdigest())


def ensure_output_relative_path(value: str) -> str:
    return canonical_path(value, code="SUPPLY_CHAIN_OUTPUT_PATH_INVALID")
