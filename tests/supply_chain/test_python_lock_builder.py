from __future__ import annotations

import hashlib
import shutil
import stat
import struct
import tempfile
import unittest
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import cast
from unittest import mock

from sbp_lex.local_trust.toolchain_guard import _local_python_dependency_evidence
from sbp_lex.supply_chain import python_lock_builder
from sbp_lex.supply_chain.python_inventory import (
    GOVERNED_PYTHON_ENVIRONMENT,
    PYTHON_LOCK_SCHEMA,
    validate_python_lock_document,
)
from sbp_lex.supply_chain.python_lock_builder import (
    build_python_lock_document,
    write_python_lock_document_exclusive,
)
from sbp_ptde.canonical import (
    canonical_json_document_bytes,
    canonical_sha512,
    strict_json_document,
)
from sbp_ptde.errors import PTDEVerificationError


class PythonLockBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="python-lock-v3-"))
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.production = self.root / "production-wheelhouse"
        self.assurance = self.root / "assurance-wheelhouse"
        self.production.mkdir()
        self.assurance.mkdir()
        self.ptde_digest = "a" * 128
        self.local_digest = "b" * 128
        cryptography = self._wheel_bytes("cryptography", "50.0.0")
        pytest = self._wheel_bytes("pytest", "9.1.1")
        (self.production / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            cryptography
        )
        (self.assurance / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            cryptography
        )
        (self.assurance / "pytest-9.1.1-py3-none-any.whl").write_bytes(pytest)
        self._write_inputs(cryptography=cryptography, pytest=pytest)

    def _wheel_bytes(
        self,
        name: str,
        version: str,
        *,
        dependencies: tuple[str, ...] = (),
    ) -> bytes:
        wheel = self.root / f"{name}-{version}-fixture.whl"
        metadata = [
            "Metadata-Version: 2.4",
            f"Name: {name}",
            f"Version: {version}",
            "Requires-Python: >=3.12,<3.13",
        ]
        metadata.extend(f"Requires-Dist: {item}" for item in dependencies)
        dist_info = f"{name}-{version}.dist-info"
        with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(f"{dist_info}/METADATA", "\n".join(metadata) + "\n")
            archive.writestr(
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\n"
                "Tag: py3-none-any\n",
            )
        content = wheel.read_bytes()
        wheel.unlink()
        return content

    def _write_inputs(self, *, cryptography: bytes, pytest: bytes) -> None:
        (self.root / "requirements.txt").write_bytes(b"cryptography==50.0.0\n")
        production = (
            "--only-binary=:all:\n"
            "--require-hashes\n\n"
            f"cryptography==50.0.0 --hash=sha256:{hashlib.sha256(cryptography).hexdigest()}\n"
        )
        assurance = production + (
            f"pytest==9.1.1 --hash=sha256:{hashlib.sha256(pytest).hexdigest()}\n"
        )
        (self.root / "requirements-production.lock.txt").write_text(
            production,
            encoding="utf-8",
            newline="",
        )
        (self.root / "requirements-test.lock.txt").write_text(
            assurance,
            encoding="utf-8",
            newline="",
        )

    def _install_cryptography_wheel(self, content: bytes) -> None:
        (self.production / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            content
        )
        (self.assurance / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            content
        )
        pytest_content = (
            self.assurance / "pytest-9.1.1-py3-none-any.whl"
        ).read_bytes()
        self._write_inputs(cryptography=content, pytest=pytest_content)

    def _custom_cryptography_wheel(
        self,
        *,
        compression: int = zipfile.ZIP_DEFLATED,
        extra: zipfile.ZipInfo | tuple[str, bytes] | None = None,
    ) -> bytes:
        wheel = self.root / "custom-cryptography.whl"
        dist_info = "cryptography-50.0.0.dist-info"
        with zipfile.ZipFile(wheel, "w", compression=compression) as archive:
            archive.writestr(
                f"{dist_info}/METADATA",
                "Metadata-Version: 2.4\n"
                "Name: cryptography\n"
                "Version: 50.0.0\n"
                "Requires-Python: >=3.12,<3.13\n",
            )
            archive.writestr(
                f"{dist_info}/WHEEL",
                "Wheel-Version: 1.0\nGenerator: fixture\n"
                "Root-Is-Purelib: true\nTag: py3-none-any\n",
            )
            if isinstance(extra, zipfile.ZipInfo):
                archive.writestr(extra, b"target")
            elif extra is not None:
                archive.writestr(extra[0], extra[1])
        content = wheel.read_bytes()
        wheel.unlink()
        return content

    def _build(
        self,
        *,
        ptde_sequence: int = 0,
        local_sequence: int = 0,
        ptde_digest: str | None = None,
        prior: bytes | None = None,
        expected_prior: str = "GENESIS",
    ) -> dict:
        return build_python_lock_document(
            self.root,
            production_wheelhouse=self.production,
            assurance_wheelhouse=self.assurance,
            expected_environment=GOVERNED_PYTHON_ENVIRONMENT,
            ptde_accepted_attempt_history_sequence=ptde_sequence,
            ptde_accepted_attempt_history_sha512=ptde_digest or self.ptde_digest,
            local_trust_accepted_package_history_sequence=local_sequence,
            local_trust_accepted_package_history_sha512=self.local_digest,
            prior_lock_document=prior,
            expected_python_dependency_prior_lock_sha512=expected_prior,
        )

    def test_genesis_build_is_deterministic_canonical_and_not_admitting(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_id"], PYTHON_LOCK_SCHEMA)
        self.assertEqual(first["lock_sequence"], 1)
        self.assertEqual(first["prior_lock_sha512"], "GENESIS")
        self.assertNotIn("authority_granted", first)
        self.assertNotIn("admitted", first)

        output = self.root / "python-dependencies.lock.json"
        digest = write_python_lock_document_exclusive(first, output)
        persisted = output.read_bytes()
        self.assertEqual(persisted, canonical_json_document_bytes(first))
        self.assertTrue(persisted.endswith(b"\n"))
        self.assertFalse(persisted.endswith(b"\n\n"))
        self.assertEqual(strict_json_document(persisted, code="TEST_LOCK"), first)
        self.assertEqual(digest, hashlib.sha512(persisted).hexdigest())
        with self.assertRaises(PTDEVerificationError):
            write_python_lock_document_exclusive(first, output)

    def test_non_genesis_requires_exact_canonical_predecessor_pin(self) -> None:
        genesis = self._build()
        predecessor = canonical_json_document_bytes(genesis)
        predecessor_digest = canonical_sha512(genesis)
        successor = self._build(
            ptde_sequence=1,
            ptde_digest="c" * 128,
            prior=predecessor,
            expected_prior=predecessor_digest,
        )
        self.assertEqual(successor["lock_sequence"], 2)
        self.assertEqual(successor["prior_lock_sha512"], predecessor_digest)
        arbitrary_prior = dict(successor)
        arbitrary_prior["prior_lock_sha512"] = "d" * 128
        with self.assertRaises(PTDEVerificationError) as arbitrary:
            validate_python_lock_document(
                arbitrary_prior,
                requirements=[{
                    "identity": "cryptography",
                    "version": "50.0.0",
                    "source_requirement": "cryptography==50.0.0",
                }],
                production_hash_lock_content=(
                    self.root / "requirements-production.lock.txt"
                ).read_bytes(),
                assurance_hash_lock_content=(
                    self.root / "requirements-test.lock.txt"
                ).read_bytes(),
                expected_environment=GOVERNED_PYTHON_ENVIRONMENT,
                expected_ptde_accepted_attempt_history_sequence=1,
                expected_ptde_accepted_attempt_history_sha512="c" * 128,
                expected_local_trust_accepted_package_history_sequence=0,
                expected_local_trust_accepted_package_history_sha512=(
                    self.local_digest
                ),
                expected_python_dependency_prior_lock_sha512=(
                    predecessor_digest
                ),
            )
        self.assertEqual(
            arbitrary.exception.code,
            "SUPPLY_CHAIN_PYTHON_LOCK_PRIOR_MISMATCH",
        )
        with self.assertRaises(PTDEVerificationError):
            self._build(
                ptde_sequence=1,
                ptde_digest="c" * 128,
                prior=predecessor,
                expected_prior="d" * 128,
            )
        with self.assertRaises(PTDEVerificationError):
            self._build(
                ptde_sequence=1,
                ptde_digest="c" * 128,
                prior=None,
                expected_prior=predecessor_digest,
            )

    def test_schema_two_and_copied_history_lane_are_rejected(self) -> None:
        document = self._build()
        requirements = [{
            "identity": "cryptography",
            "version": "50.0.0",
            "source_requirement": "cryptography==50.0.0",
        }]
        common = {
            "requirements": requirements,
            "production_hash_lock_content": (
                self.root / "requirements-production.lock.txt"
            ).read_bytes(),
            "assurance_hash_lock_content": (
                self.root / "requirements-test.lock.txt"
            ).read_bytes(),
            "expected_environment": GOVERNED_PYTHON_ENVIRONMENT,
            "expected_ptde_accepted_attempt_history_sequence": 0,
            "expected_ptde_accepted_attempt_history_sha512": self.ptde_digest,
            "expected_local_trust_accepted_package_history_sequence": 0,
            "expected_local_trust_accepted_package_history_sha512": self.local_digest,
            "expected_python_dependency_prior_lock_sha512": "GENESIS",
        }
        downgraded = dict(document)
        downgraded["schema_id"] = "sbp.lex.v2.python-dependency-lock/2"
        with self.assertRaises(PTDEVerificationError):
            validate_python_lock_document(downgraded, **common)
        copied = dict(document)
        copied["rollback_guard"] = dict(document["rollback_guard"])
        copied["rollback_guard"][
            "local_trust_accepted_package_history_sha512"
        ] = self.ptde_digest
        common["expected_local_trust_accepted_package_history_sha512"] = (
            self.ptde_digest
        )
        with self.assertRaises(PTDEVerificationError):
            validate_python_lock_document(copied, **common)

    def test_direct_validator_rejects_missing_or_alternate_environment(self) -> None:
        document = self._build()
        requirements = [{
            "identity": "cryptography",
            "version": "50.0.0",
            "source_requirement": "cryptography==50.0.0",
        }]
        common = {
            "requirements": requirements,
            "production_hash_lock_content": (
                self.root / "requirements-production.lock.txt"
            ).read_bytes(),
            "assurance_hash_lock_content": (
                self.root / "requirements-test.lock.txt"
            ).read_bytes(),
            "expected_ptde_accepted_attempt_history_sequence": 0,
            "expected_ptde_accepted_attempt_history_sha512": self.ptde_digest,
            "expected_local_trust_accepted_package_history_sequence": 0,
            "expected_local_trust_accepted_package_history_sha512": self.local_digest,
            "expected_python_dependency_prior_lock_sha512": "GENESIS",
        }
        with self.assertRaises(PTDEVerificationError) as missing:
            validate_python_lock_document(
                document,
                expected_environment=cast(dict[str, str], None),
                **common,
            )
        self.assertEqual(
            missing.exception.code,
            "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_ENVIRONMENT_INVALID",
        )

        alternate = dict(GOVERNED_PYTHON_ENVIRONMENT)
        alternate["python_version"] = "3.12.12"
        alternate_document = deepcopy(document)
        alternate_document["target_environment"] = alternate
        with self.assertRaises(PTDEVerificationError) as substituted:
            validate_python_lock_document(
                alternate_document,
                expected_environment=alternate,
                **common,
            )
        self.assertEqual(
            substituted.exception.code,
            "SUPPLY_CHAIN_PYTHON_LOCK_EXPECTED_ENVIRONMENT_INVALID",
        )

    def test_built_lock_passes_both_supply_chain_and_local_trust_contracts(self) -> None:
        document = self._build()
        evidence = _local_python_dependency_evidence(
            (self.root / "requirements.txt").read_bytes(),
            (self.root / "requirements-production.lock.txt").read_bytes(),
            (self.root / "requirements-test.lock.txt").read_bytes(),
            document,
            [
                {"name": "cryptography", "version": "50.0.0"},
                {"name": "pytest", "version": "9.1.1"},
            ],
            expected_ptde_accepted_attempt_history_sequence=0,
            expected_ptde_accepted_attempt_history_digest=self.ptde_digest,
            expected_local_trust_accepted_package_history_sequence=0,
            expected_local_trust_accepted_package_history_digest=self.local_digest,
            expected_python_dependency_prior_lock_sha512="GENESIS",
        )
        self.assertEqual(evidence["dependency_evidence_status"], "COMPLETE")
        self.assertFalse(evidence["authority_granted"])

    def test_extra_tampered_and_cyclic_wheels_fail_closed(self) -> None:
        extra = self.assurance / "orphan-1.0.0-py3-none-any.whl"
        extra.write_bytes(self._wheel_bytes("orphan", "1.0.0"))
        with self.assertRaises(PTDEVerificationError):
            self._build()
        extra.unlink()

        cryptography_path = self.production / "cryptography-50.0.0-py3-none-any.whl"
        cryptography_path.write_bytes(cryptography_path.read_bytes() + b"tampered")
        with self.assertRaises(PTDEVerificationError):
            self._build()

        cryptography = self._wheel_bytes(
            "cryptography",
            "50.0.0",
            dependencies=("pytest==9.1.1",),
        )
        pytest = self._wheel_bytes(
            "pytest",
            "9.1.1",
            dependencies=("cryptography==50.0.0",),
        )
        cryptography_path.write_bytes(cryptography)
        (self.assurance / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            cryptography
        )
        (self.assurance / "pytest-9.1.1-py3-none-any.whl").write_bytes(pytest)
        self._write_inputs(cryptography=cryptography, pytest=pytest)
        with self.assertRaises(PTDEVerificationError) as raised:
            self._build()
        self.assertEqual(
            raised.exception.code,
            "SUPPLY_CHAIN_PYTHON_WHEEL_DEPENDENCY_UNSATISFIED",
        )

    def test_wheel_archive_complexity_compression_and_special_files_fail_closed(
        self,
    ) -> None:
        bzip2_wheel = self._custom_cryptography_wheel(
            compression=zipfile.ZIP_BZIP2
        )
        self._install_cryptography_wheel(bzip2_wheel)
        with self.assertRaises(PTDEVerificationError) as unsupported:
            self._build()
        self.assertEqual(
            unsupported.exception.code,
            "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID",
        )

        symlink = zipfile.ZipInfo("cryptography/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        linked_wheel = self._custom_cryptography_wheel(extra=symlink)
        self._install_cryptography_wheel(linked_wheel)
        with self.assertRaises(PTDEVerificationError) as special:
            self._build()
        self.assertEqual(
            special.exception.code,
            "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID",
        )

        extra_member = self._custom_cryptography_wheel(
            extra=("cryptography/extra.txt", b"extra")
        )
        self._install_cryptography_wheel(extra_member)
        with (
            mock.patch.object(python_lock_builder, "_MAX_WHEEL_MEMBERS", 2),
            self.assertRaises(PTDEVerificationError) as member_limit,
        ):
            self._build()
        self.assertEqual(
            member_limit.exception.code,
            "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID",
        )

    def test_wheel_full_stream_crc_is_checked_not_only_metadata(self) -> None:
        content = bytearray(
            self._custom_cryptography_wheel(
                compression=zipfile.ZIP_STORED,
                extra=("cryptography/payload.bin", b"payload-for-crc"),
            )
        )
        crc_source = self.root / "crc-source.whl"
        crc_source.write_bytes(content)
        with zipfile.ZipFile(crc_source) as archive:
            info = archive.getinfo("cryptography/payload.bin")
            offset = info.header_offset
            fields = struct.unpack_from("<4s5H3L2H", content, offset)
            name_size = fields[-2]
            extra_size = fields[-1]
            data_offset = offset + 30 + name_size + extra_size
        crc_source.unlink()
        content[data_offset] ^= 0x01
        corrupted = bytes(content)
        self._install_cryptography_wheel(corrupted)

        with self.assertRaises(PTDEVerificationError) as crc_failure:
            self._build()
        self.assertEqual(
            crc_failure.exception.code,
            "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID",
        )

    def test_wheel_dot_and_windows_device_members_fail_closed(self) -> None:
        for name in (".", "cryptography/NUL.txt", "cryptography/payload. "):
            with self.subTest(name=name):
                hostile = self._custom_cryptography_wheel(
                    extra=(name, b"hostile")
                )
                self._install_cryptography_wheel(hostile)
                with self.assertRaises(PTDEVerificationError) as raised:
                    self._build()
                self.assertEqual(
                    raised.exception.code,
                    "SUPPLY_CHAIN_PYTHON_WHEEL_ARCHIVE_INVALID",
                )


if __name__ == "__main__":
    unittest.main()
