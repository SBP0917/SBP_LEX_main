from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

def main(argv: Sequence[str] | None = None) -> int:
    from sbp_lex.local_trust.repository_guard import verify_repository_guard

    parser = argparse.ArgumentParser(description="Verify the SBP-LEX V2 repository guard")
    parser.add_argument("repository", nargs="?", default=str(Path.cwd()))
    parser.add_argument("--scope", choices=("production", "test"), default="test")
    args = parser.parse_args(argv)
    result = verify_repository_guard(args.repository, scope=args.scope)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
