"""Deterministic immutable package persistence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .paths import strict_load_json, validated_root, write_json_exclusive


PACKAGE_FILENAME = "LOCAL_TRUST_PACKAGE.json"
REPORT_FILENAME = "LOCAL_TRUST_REPORT.md"


def write_local_trust_package(package: dict[str, Any], output_directory: str | Path) -> dict[str, Path]:
    directory = validated_root(Path(output_directory))
    package_path = write_json_exclusive(package, directory / PACKAGE_FILENAME)
    return {"package": package_path}


def load_local_trust_package(path: str | Path) -> dict[str, Any]:
    value = strict_load_json(Path(path))
    if type(value) is not dict:
        raise ValueError("local_trust_package_not_object")
    return value


__all__ = [
    "PACKAGE_FILENAME", "REPORT_FILENAME",
    "load_local_trust_package", "write_local_trust_package",
]
