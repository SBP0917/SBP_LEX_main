"""Install-free isolated-mode test runner for the v2 Python codec."""

from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
REPOSITORY_ROOT = ROOT.parent.parent
sys.path.insert(0, str(REPOSITORY_ROOT))
sys.path.insert(0, str(ROOT))

suite = unittest.defaultTestLoader.loadTestsFromName("python.test_contract")
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
