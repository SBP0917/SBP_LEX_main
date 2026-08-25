from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

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
)

REQUEST_FINGERPRINT = "1" * 128


class PolyglotAssuranceContractTests(unittest.TestCase):
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
        invocation = invoke_veto_verifier(envelope, command=verifier)
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
            "import json; print(json.dumps({"
            "'schema_version':'sbp.v2.assurance-verdict/1',"
            "'verifier_version':'test/1',"
            "'accepted':False,"
            "'reason_code':'STATE_DIGEST_MISMATCH'}))",
        )
        invocation = invoke_veto_verifier(envelope, command=verifier)
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
        invocation = invoke_veto_verifier(envelope, command=verifier)
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
            "print('{\"schema_version\":\"sbp.v2.assurance-verdict/1\",'"
            "'\"verifier_version\":\"test/1\",\"accepted\":true,'"
            "'\"accepted\":true,\"reason_code\":\"VERIFIED\"}')",
        )
        invocation = invoke_veto_verifier(envelope, command=verifier)
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
                invocation = invoke_veto_verifier(
                    envelope,
                    command=verifier,
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
            invocation = invoke_veto_verifier(
                envelope,
                command=(Path(sys.executable), "-c", parent_script),
                timeout_seconds=0.75,
            )
            self.assertEqual(invocation.reason_code, "VERIFIER_TIMEOUT")
            self.assertTrue(started.is_file())
            time.sleep(1.0)
            self.assertFalse(survived.exists())


if __name__ == "__main__":
    unittest.main()
