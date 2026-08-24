"""Static proof that the package remains detached from V2 runtime imports."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .constants import FAIL, PASS
from .digests import digest
from .paths import LocalTrustPathError, inventory_root, resolve_safe_path, validated_root


_FORBIDDEN_MODULE_PREFIXES = (
    "main",
    "sbp_lex",
)
_RUNTIME_SCAN_ROOTS = (
    "main.py",
    "sbp_lex/pipeline",
    "sbp_lex/runtime",
    "sbp_lex/execution",
    "sbp_lex/audit",
    "sbp_lex/security/token_stack.py",
)


def _imports(path: Path) -> list[tuple[str, int]]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise LocalTrustPathError("boundary_source_unreadable") from exc
    result: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            result.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            result.append((node.module, node.lineno))
    return result


def check_runtime_detachment(repository_root: str | Path) -> dict[str, Any]:
    root = validated_root(repository_root)
    failures: list[str] = []
    local_paths = inventory_root(root, "sbp_lex/local_trust")
    for relative in local_paths:
        if not relative.endswith(".py"):
            continue
        path = resolve_safe_path(root, relative)
        for imported, line in _imports(path):
            if any(imported == prefix or imported.startswith(prefix + ".") for prefix in _FORBIDDEN_MODULE_PREFIXES):
                failures.append(f"forbidden_import:{relative}:{line}:{imported}")
    for scan_target in _RUNTIME_SCAN_ROOTS:
        candidate = root / Path(scan_target)
        if not candidate.exists():
            continue
        paths = (
            inventory_root(root, scan_target)
            if candidate.is_dir()
            else [scan_target]
        )
        for relative in paths:
            if not relative.endswith(".py"):
                continue
            try:
                text = resolve_safe_path(root, relative).read_text(encoding="utf-8")
            except (OSError, UnicodeError) as exc:
                raise LocalTrustPathError("boundary_source_unreadable") from exc
            if "sbp_lex.local_trust" in text:
                failures.append(f"runtime_imports_local_trust:{relative}")
    return {
        "status": PASS if not failures else FAIL,
        "validation_failures": sorted(set(failures)),
        "scanned_local_source_count": sum(path.endswith(".py") for path in local_paths),
        "boundary_digest": digest({"failures": sorted(set(failures)), "local_paths": local_paths}),
    }


__all__ = ["check_runtime_detachment"]
