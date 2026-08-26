from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sbp_lex.assurance.envelope import (
    ASSURANCE_ENVELOPE_VERSION,
    AssuranceContractError,
    assurance_envelope_digest,
    build_assurance_envelope,
    canonical_json_bytes,
)
from sbp_lex.assurance.verifier import (
    MAX_VERIFIER_OUTPUT_BYTES,
    AssuranceMode,
    invoke_veto_verifier,
    mode_requires_denial,
    verifier_command_digest,
)

REQUEST_FINGERPRINT = "1" * 128
PYTHON_EXECUTABLE_SHA512 = hashlib.sha512(Path(sys.executable).read_bytes()).hexdigest()


class PolyglotAssuranceContractTests(unittest.TestCase):
    def _invoke(
        self,
        envelope: dict,
        command: tuple[Path | str, ...],
        *,
        timeout_seconds: float = 2.0,
    ):
        return invoke_veto_verifier(
            envelope,
            command=command,
            expected_executable_sha512=PYTHON_EXECUTABLE_SHA512,
            expected_command_sha512=verifier_command_digest(command),
            timeout_seconds=timeout_seconds,
        )

    def test_canonical_json_is_order_independent(self) -> None:
        left = {"z": [3, 2, 1], "a": {"b": True, "a": None}}
        right = {"a": {"a": None, "b": True}, "z": [3, 2, 1]}
        self.assertEqual(canonical_json_bytes(left), canonical_json_bytes(right))

    def test_canonical_json_normalises_unicode(self) -> None:
        decomposed = {"label": "Cafe\u0301"}
        composed = {"label": "Caf\u00e9"}
        self.assertEqual(canonical_json_bytes(decomposed), canonical_json_bytes(composed))

    def test_floating_point_values_are_rejected(self) -> None:
        with self.assertRaises(AssuranceContractError):
            canonical_json_bytes({"risk": 0.1})

    def test_envelope_binds_canonical_state(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe", "risk_basis_points": 1250},
        )

        decoded = base64.b64decode(envelope["canonical_state_b64"], validate=True)
        self.assertEqual(envelope["schema_version"], ASSURANCE_ENVELOPE_VERSION)
        self.assertEqual(hashlib.sha512(decoded).hexdigest(), envelope["canonical_state_sha512"])
        self.assertEqual(json.loads(decoded), {"action": "observe", "risk_basis_points": 1250})
        self.assertEqual(len(assurance_envelope_digest(envelope)), 128)

    def test_unknown_checkpoint_fails_closed(self) -> None:
        with self.assertRaises(AssuranceContractError):
            build_assurance_envelope(
                request_fingerprint=REQUEST_FINGERPRINT,
                checkpoint="unregistered_stage",
                sequence=0,
                state_projection={},
            )

    def test_verifier_adapter_accepts_consistent_success(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        verdict = {
            "schema_version": "sbp.v2.assurance-verdict/1",
            "verifier_version": "test/1",
            "accepted": True,
            "reason_code": "VERIFIED",
            "request_fingerprint": envelope["request_fingerprint"],
            "checkpoint": envelope["checkpoint"],
            "observed_state_sha512": envelope["canonical_state_sha512"],
            "envelope_sha512": assurance_envelope_digest(envelope),
        }
        verifier = (
            Path(sys.executable),
            "-c",
            f"import json; print(json.dumps({verdict!r}))",
        )
        invocation = self._invoke(envelope, verifier)
        self.assertEqual(invocation.status, "VERIFIED")
        self.assertFalse(mode_requires_denial(AssuranceMode.REQUIRED, invocation))

    def test_verifier_adapter_rejects_exit_status_contradiction(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        verifier = (
            Path(sys.executable),
            "-c",
            (
                "import json; print(json.dumps({"
                "'schema_version':'sbp.v2.assurance-verdict/1',"
                "'verifier_version':'test/1',"
                "'accepted':False,"
                "'reason_code':'STATE_DIGEST_MISMATCH'}))"
            ),
        )
        invocation = self._invoke(envelope, verifier)
        self.assertEqual(invocation.reason_code, "VERDICT_EXIT_STATUS_CONTRADICTION")
        self.assertTrue(mode_requires_denial(AssuranceMode.REQUIRED, invocation))
        self.assertFalse(mode_requires_denial(AssuranceMode.SHADOW, invocation))

    def test_verifier_adapter_rejects_success_bound_to_another_envelope(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        verdict = {
            "schema_version": "sbp.v2.assurance-verdict/1",
            "verifier_version": "test/1",
            "accepted": True,
            "reason_code": "VERIFIED",
            "request_fingerprint": envelope["request_fingerprint"],
            "checkpoint": envelope["checkpoint"],
            "observed_state_sha512": "0" * 128,
            "envelope_sha512": assurance_envelope_digest(envelope),
        }
        verifier = (
            Path(sys.executable),
            "-c",
            f"import json; print(json.dumps({verdict!r}))",
        )
        invocation = self._invoke(envelope, verifier)
        self.assertEqual(invocation.reason_code, "VERDICT_BINDING_MISMATCH")
        self.assertTrue(mode_requires_denial(AssuranceMode.REQUIRED, invocation))

    def test_verifier_adapter_rejects_duplicate_verdict_keys(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        verifier = (
            Path(sys.executable),
            "-c",
            (
                "print('{\"schema_version\":\"sbp.v2.assurance-verdict/1\",'"
                "'\"verifier_version\":\"test/1\",\"accepted\":true,'"
                "'\"accepted\":true,\"reason_code\":\"VERIFIED\"}')"
            ),
        )
        invocation = self._invoke(envelope, verifier)
        self.assertEqual(invocation.reason_code, "VERIFIER_OUTPUT_MALFORMED")

    def test_verifier_adapter_bounds_stdout_and_stderr_while_running(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        for stream, reason in (
            ("stdout", "VERIFIER_OUTPUT_TOO_LARGE"),
            ("stderr", "VERIFIER_ERROR_OUTPUT_TOO_LARGE"),
        ):
            with self.subTest(stream=stream):
                verifier = (
                    Path(sys.executable),
                    "-c",
                    (
                        "import sys,time;"
                        f"sys.{stream}.buffer.write("
                        f"b'x'*{MAX_VERIFIER_OUTPUT_BYTES + 1});"
                        f"sys.{stream}.buffer.flush();"
                        "time.sleep(10)"
                    ),
                )
                invocation = self._invoke(
                    envelope,
                    verifier,
                    timeout_seconds=2,
                )
                self.assertEqual(invocation.reason_code, reason)
                self.assertFalse(invocation.accepted)

    def test_verifier_timeout_terminates_descendants(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            started = root / "child-started"
            survived = root / "child-survived"
            child_script = (
                "import pathlib,time;"
                f"pathlib.Path({str(started)!r}).write_text('started');"
                "time.sleep(1.5);"
                f"pathlib.Path({str(survived)!r}).write_text('survived')"
            )
            parent_script = (
                "import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c',"
                f"{child_script!r}]);"
                "time.sleep(10)"
            )
            invocation = self._invoke(
                envelope,
                (Path(sys.executable), "-c", parent_script),
                timeout_seconds=0.75,
            )
            self.assertEqual(invocation.reason_code, "VERIFIER_TIMEOUT")
            self.assertTrue(started.is_file())
            time.sleep(1.0)
            self.assertFalse(survived.exists())

    def test_verifier_requires_independent_executable_and_command_pins(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        command = (Path(sys.executable), "-c", "raise SystemExit(99)")
        wrong_executable = invoke_veto_verifier(
            envelope,
            command=command,
            expected_executable_sha512="0" * 128,
            expected_command_sha512=verifier_command_digest(command),
        )
        wrong_command = invoke_veto_verifier(
            envelope,
            command=command,
            expected_executable_sha512=PYTHON_EXECUTABLE_SHA512,
            expected_command_sha512="0" * 128,
        )

        self.assertEqual(
            wrong_executable.reason_code,
            "VERIFIER_EXECUTABLE_PIN_MISMATCH",
        )
        self.assertEqual(
            wrong_command.reason_code,
            "VERIFIER_COMMAND_PIN_MISMATCH",
        )

    def test_verifier_drops_inherited_python_injection_environment(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "sitecustomize-executed.txt"
            (root / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            command = (
                Path(sys.executable),
                "-c",
                "raise SystemExit(2)",
            )
            with mock.patch.dict(
                os.environ,
                {
                    "PYTHONPATH": str(root),
                    "PYTHONSTARTUP": str(root / "sitecustomize.py"),
                },
            ):
                invocation = self._invoke(envelope, command)

            self.assertEqual(invocation.exit_code, 2)
            self.assertFalse(marker.exists())

    def test_script_or_hardlinked_verifier_executable_is_rejected(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "verifier.py"
            script.write_text("raise SystemExit(0)\n", encoding="utf-8")
            script_command = (script,)
            scripted = invoke_veto_verifier(
                envelope,
                command=script_command,
                expected_executable_sha512=hashlib.sha512(
                    script.read_bytes()
                ).hexdigest(),
                expected_command_sha512=verifier_command_digest(script_command),
            )
            self.assertEqual(
                scripted.reason_code,
                "VERIFIER_EXECUTABLE_INVALID",
            )

            hardlink = root / "python-hardlink.exe"
            try:
                os.link(sys.executable, hardlink)
            except OSError:
                return
            hardlink_command = (hardlink, "-c", "raise SystemExit(0)")
            linked = invoke_veto_verifier(
                envelope,
                command=hardlink_command,
                expected_executable_sha512=PYTHON_EXECUTABLE_SHA512,
                expected_command_sha512=verifier_command_digest(
                    hardlink_command
                ),
            )
            self.assertEqual(
                linked.reason_code,
                "VERIFIER_EXECUTABLE_INVALID",
            )

    def test_verifier_script_argument_is_bound_and_rechecked(self) -> None:
        envelope = build_assurance_envelope(
            request_fingerprint=REQUEST_FINGERPRINT,
            checkpoint="state_construction",
            sequence=0,
            state_projection={"action": "observe"},
        )
        verdict = {
            "schema_version": "sbp.v2.assurance-verdict/1",
            "verifier_version": "test/1",
            "accepted": True,
            "reason_code": "VERIFIED",
            "request_fingerprint": envelope["request_fingerprint"],
            "checkpoint": envelope["checkpoint"],
            "observed_state_sha512": envelope["canonical_state_sha512"],
            "envelope_sha512": assurance_envelope_digest(envelope),
        }
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "verifier.py"
            script.write_text(
                "import json\n"
                "from pathlib import Path\n"
                f"verdict = {verdict!r}\n"
                "Path(__file__).write_text('mutated\\n', encoding='utf-8')\n"
                "print(json.dumps(verdict))\n",
                encoding="utf-8",
            )
            command = (Path(sys.executable), "-I", script)
            expected_command = verifier_command_digest(command)

            invocation = invoke_veto_verifier(
                envelope,
                command=command,
                expected_executable_sha512=PYTHON_EXECUTABLE_SHA512,
                expected_command_sha512=expected_command,
            )

            self.assertEqual(
                invocation.reason_code,
                "VERIFIER_COMMAND_ARGUMENT_FILE_CHANGED",
            )
            self.assertNotEqual(verifier_command_digest(command), expected_command)


if __name__ == "__main__":
    unittest.main()
