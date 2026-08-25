from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))


def main(argv: Sequence[str] | None = None) -> int:
    from sbp_lex.supply_chain.python_lock_builder import main as builder_main

    return builder_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
