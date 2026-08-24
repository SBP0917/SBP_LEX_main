#!/usr/bin/env python3
"""Run the locally built SPARK assertion harness without a shell.

This helper is intentionally narrow: it accepts no path or command-line
selection, resolves the single project-defined executable beneath ``bin/``,
rejects link/reparse and hard-link substitutions, and propagates the harness
exit status.  It is an assurance check, not an authority-bearing component.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXECUTABLE = ROOT / "bin" / (
    "spark_safety_monitor.exe" if os.name == "nt" else "spark_safety_monitor"
)


def _is_reparse(path: Path) -> bool:
    status = os.lstat(path)
    attributes = getattr(status, "st_file_attributes", 0)
    return stat.S_ISLNK(status.st_mode) or bool(attributes & 0x400)


def main() -> int:
    if len(sys.argv) != 1:
        raise SystemExit("SPARK_HARNESS_ARGUMENTS_PROHIBITED")
    try:
        executable = EXECUTABLE.resolve(strict=True)
        executable.relative_to((ROOT / "bin").resolve(strict=True))
        status = os.lstat(executable)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"SPARK_HARNESS_EXECUTABLE_INVALID:{type(exc).__name__}") from exc
    if (
        _is_reparse(executable)
        or not stat.S_ISREG(status.st_mode)
        or status.st_nlink != 1
    ):
        raise SystemExit("SPARK_HARNESS_EXECUTABLE_LINK_STATE_INVALID")
    completed = subprocess.run(
        [str(executable)],
        cwd=ROOT,
        env=dict(os.environ),
        stdin=subprocess.DEVNULL,
        shell=False,
        check=False,
    )
    return int(completed.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
