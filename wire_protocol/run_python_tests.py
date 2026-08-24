"""Install-free isolated-mode runner for the SBP-LEX wire Python tests."""

from __future__ import annotations

import importlib.util
import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parent
PACKAGE = "sbp_lex_wire_contract"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


package = types.ModuleType(PACKAGE)
package.__path__ = [str(ROOT / "python")]
package.__package__ = PACKAGE
sys.modules[PACKAGE] = package
_load(f"{PACKAGE}.sbp_lex_wire", ROOT / "python" / "sbp_lex_wire.py")
_load(f"{PACKAGE}.golden", ROOT / "python" / "golden.py")
tests = _load(f"{PACKAGE}.test_contract", ROOT / "python" / "test_contract.py")

result = unittest.TextTestRunner(verbosity=2).run(
    unittest.defaultTestLoader.loadTestsFromModule(tests)
)
raise SystemExit(0 if result.wasSuccessful() else 1)

