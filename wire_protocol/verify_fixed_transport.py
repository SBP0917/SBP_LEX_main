#!/usr/bin/env python3
"""Verify the fixed, non-authorizing SBP-LEX wire-v1 byte identities."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXPECTED = {
    "SPEC.md": "f084a52597df0db1466ef9681273deb7513fa1818b41060f443802aafa8db76c",
    "rust/Cargo.toml": "394fec6a7dcb1909f9b6e02dcb1652e6dc07dd84bb7827eaaeaf66fef79b09c0",
    "rust/src/lib.rs": "ef17d5bb811d93e1cd156dbec636160eae48492c50ce97cd6068878db4f36943",
    "vectors/adversarial_cases.txt": "946f45cc9f7f95e19e90b76056a2a09a260b27095d1a589231fb4ba32a7c9132",
    "vectors/golden_transcript.jsonl": "2c91bffb4eab4890f36d27bc63cb926b37a1f24d4f7bfff6846723424ec420e0",
}


def _is_reparse(path: Path) -> bool:
    status = os.lstat(path)
    attributes = getattr(status, "st_file_attributes", 0)
    return stat.S_ISLNK(status.st_mode) or bool(attributes & 0x400)


def main() -> int:
    if len(sys.argv) != 1:
        raise SystemExit("FIXED_TRANSPORT_ARGUMENTS_PROHIBITED")
    actual: dict[str, str] = {}
    for relative, expected in sorted(EXPECTED.items()):
        path = ROOT / relative
        status = os.lstat(path)
        if (
            _is_reparse(path)
            or not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
        ):
            raise SystemExit(f"FIXED_TRANSPORT_LINK_STATE_INVALID:{relative}")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected:
            raise SystemExit(f"FIXED_TRANSPORT_HASH_MISMATCH:{relative}")
        actual[relative] = digest
    print(
        json.dumps(
            {
                "schema": "SBP_LEX_FIXED_TRANSPORT_V1_VERIFICATION",
                "status": "PASS_NON_AUTHORIZING_TRANSPORT_BYTES_ONLY",
                "files": actual,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
