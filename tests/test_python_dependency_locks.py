from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

import pytest


ROOT = Path(__file__).resolve().parents[1]
LOCK_LINE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9-]*)==(?P<version>[0-9]+(?:\.[0-9]+)+) "
    r"--hash=sha256:(?P<digest>[0-9a-f]{64})$"
)
DIRECT_REQUIREMENTS = {
    "cryptography": "50.0.0",
}
TEST_ONLY = {
    "iniconfig": "2.3.0",
    "packaging": "26.3",
    "pluggy": "1.6.0",
    "pygments": "2.21.0",
    "pytest": "9.1.1",
}


def _requirements() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        name, version = line.split("==", maxsplit=1)
        result[name] = version
    return result


def _lock(name: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for line in (ROOT / name).read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#") or line.startswith("--"):
            continue
        matched = LOCK_LINE.fullmatch(line)
        assert matched is not None
        package = matched.group("name")
        assert package not in result
        digest = matched.group("digest")
        assert len(set(digest)) >= 8
        result[package] = (matched.group("version"), digest)
    assert list(result) == sorted(result)
    return result


def test_production_lock_is_exact_hashed_and_matches_direct_imports() -> None:
    assert _requirements() == DIRECT_REQUIREMENTS
    production = _lock("requirements-production.lock.txt")
    assert len(production) == 3
    assert {
        package: production[package][0]
        for package in DIRECT_REQUIREMENTS
    } == DIRECT_REQUIREMENTS


def test_test_lock_is_exact_hashed_production_superset() -> None:
    production = _lock("requirements-production.lock.txt")
    test = _lock("requirements-test.lock.txt")
    assert len(test) == 9
    assert {package: test[package] for package in production} == production
    assert {
        package: test[package][0]
        for package in TEST_ONLY
    } == TEST_ONLY


@pytest.mark.parametrize(
    ("lock_name", "wheelhouse_name"),
    (
        (
            "requirements-production.lock.txt",
            "python31213-production-wheelhouse",
        ),
        ("requirements-test.lock.txt", "python31213-test-wheelhouse"),
    ),
)
def test_downloaded_target_wheels_match_locked_hashes(
    lock_name: str,
    wheelhouse_name: str,
) -> None:
    wheelhouse = ROOT / "runtime_artifacts" / wheelhouse_name
    if not wheelhouse.is_dir():
        pytest.skip("resolution wheelhouse is an uncommitted validation input")
    wheels = list(wheelhouse.glob("*.whl"))
    for package, (version, expected_digest) in _lock(lock_name).items():
        filename_prefix = f"{package.replace('-', '_')}-{version}-"
        matches = [
            wheel
            for wheel in wheels
            if wheel.name.casefold().startswith(filename_prefix.casefold())
        ]
        assert len(matches) == 1
        assert sha256(matches[0].read_bytes()).hexdigest() == expected_digest
