"""Adversarial tests for semantic reconciliation and its detached verifier."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import reconcile  # noqa: E402
import verify_report  # noqa: E402
from native_output_adapters import (  # noqa: E402
    NativeOutputAdapterError,
    RAW_TOOL_BUNDLE_SCHEMA,
    RAW_TOOL_OPEN_STATUS,
    SCHEMA as NATIVE_WIRE_SCHEMA,
    parse_raw_native_tool_output_bundle,
)
from wire_protocol.v2.python import sbp_lex_wire_v2 as wire_v2  # noqa: E402


class ReconciliationTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="c10-reconcile-test-", dir=ROOT / "runtime_artifacts",
        )
        self.base = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> Path:
        report = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=None,
        )
        report_path, _ = reconcile.write_report(self.base / "report", report)
        return report_path

    @staticmethod
    def rewrite(path: Path, report: dict[str, object]) -> None:
        data = reconcile.canonical_bytes(report)
        path.write_bytes(data)
        path.with_name(reconcile.REPORT_SIDECAR).write_text(
            f"{hashlib.sha512(data).hexdigest()}  {reconcile.REPORT_NAME}\n",
            encoding="ascii",
            newline="\n",
        )

    @staticmethod
    def bound_blob(data: bytes) -> dict[str, object]:
        return {
            "bytes_hex": data.hex(),
            "sha512": hashlib.sha512(data).hexdigest(),
            "size": len(data),
        }

    def raw_tool_bundle(
        self,
        baseline: dict[str, object],
        lane: str,
    ) -> dict[str, object]:
        tools = {
            "spark_safety_monitor": "gnatprove",
            "formal_model": "tlc2.TLC",
        }
        subject = baseline["subject"]
        aggregates = baseline["component_aggregate_sha512"]
        assert isinstance(subject, dict) and isinstance(aggregates, dict)
        return {
            "candidate": {
                "commit": subject["commit"],
                "source_aggregate_sha512": aggregates[lane],
                "tree": subject["tree"],
            },
            "execution": {
                "exit_status": 0,
                "stderr": self.bound_blob(b""),
                "stdout": self.bound_blob(f"raw complete output for {lane}\n".encode("ascii")),
            },
            "lane": lane,
            "producer": {
                "claimed_binary_sha512": "a" * 128,
                "identity_attestation": "UNAVAILABLE",
                "tool": tools[lane],
                "tool_identity_output": self.bound_blob(
                    f"{tools[lane]} native version output\n".encode("ascii")
                ),
            },
            "schema": RAW_TOOL_BUNDLE_SCHEMA,
            "termination": "COMPLETE_UNTRUNCATED",
        }

    def test_baseline_report_verifies_and_remains_non_evidentiary_open(self) -> None:
        report_path = self.build()
        report = verify_report.verify(report_path)
        self.assertEqual(report["report_class"], "NON_EVIDENTIARY_SYNTHETIC_LOCAL_ASSURANCE")
        self.assertEqual(report["overall_status"], "OPEN_CROSS_LANGUAGE_REFINEMENT_INCOMPLETE")
        self.assertFalse(report["evidence_execution_ready"])

    def test_equal_case_count_cannot_mask_semantic_mismatch(self) -> None:
        catalog = reconcile.load_catalog()
        _, observations = reconcile.run_python_cases(catalog)
        matrix_ids = list(catalog["matrix_case_ids"])
        items = [
            {"case_id": case_id, "observation": copy.deepcopy(observations[case_id])}
            for case_id in matrix_ids
        ]
        items[0]["observation"]["final_decision"] = "BLOCK"
        observation_set = {
            "case_catalog_sha512": reconcile.sha512_file(reconcile.CATALOG_PATH),
            "implementation": "TEST-MISMATCH-SAME-COUNT",
            "observations": items,
            "schema": reconcile.OBSERVATION_SET_SCHEMA,
        }
        capture = self.base / "rust-observations.json"
        capture.write_bytes(reconcile.canonical_bytes(observation_set))
        capture_relative = capture.relative_to(ROOT).as_posix()
        manifest = {
            "lanes": {
                "wire_v2_rust": {
                    "declared_result": "PASS",
                    "format": "canonical_observation_set",
                    "path": capture_relative,
                    "sha512": reconcile.sha512_file(capture),
                },
            },
            "schema": reconcile.CAPTURE_SCHEMA,
        }
        manifest_path = self.base / "captures.json"
        manifest_path.write_bytes(reconcile.canonical_bytes(manifest))
        report = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=manifest_path,
        )
        lane = next(item for item in report["lane_results"] if item["lane"] == "wire_v2_rust")
        self.assertEqual(lane["status"], "FAIL_SEMANTIC_MISMATCH")
        self.assertEqual(lane["semantic_mismatches"], [matrix_ids[0]])
        self.assertEqual(len(items), 12)

        items[0]["observation"]["final_decision"] = observations[matrix_ids[0]]["final_decision"]
        capture.write_bytes(reconcile.canonical_bytes(observation_set))
        manifest["lanes"]["wire_v2_rust"]["sha512"] = reconcile.sha512_file(capture)
        manifest_path.write_bytes(reconcile.canonical_bytes(manifest))
        matching = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=manifest_path,
        )
        matching_lane = next(
            item for item in matching["lane_results"] if item["lane"] == "wire_v2_rust"
        )
        self.assertEqual(
            matching_lane["status"], "OPEN_MATCH_NOT_DERIVED_BY_NATIVE_OUTPUT_ADAPTER",
        )

    def test_native_raw_frame_adapter_derives_semantics_but_stays_unattested(self) -> None:
        catalog = reconcile.load_catalog()
        matrix_ids = list(catalog["matrix_case_ids"])
        cases = {case["id"]: case for case in catalog["cases"]}
        lines = [
            NATIVE_WIRE_SCHEMA,
            "IMPLEMENTATION rust_authority_service",
            f"BINARY_SHA512 {'a' * 128}",
        ]
        for case_id in matrix_ids:
            messages = reconcile.load_vector(cases[case_id]["source"])
            frames = [wire_v2.encode_frame(message) for message in messages]
            lines.append(f"CASE {case_id} {len(frames)}")
            lines.extend(f"FRAME {frame.hex()}" for frame in frames)
        lines.append("END")
        capture = self.base / "native-rust-authority.txt"
        capture.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
        manifest = {
            "lanes": {
                "rust_authority_service": {
                    "declared_result": "PASS",
                    "format": "native_wire_v2_framed_transcripts",
                    "path": capture.relative_to(ROOT).as_posix(),
                    "sha512": reconcile.sha512_file(capture),
                },
            },
            "schema": reconcile.CAPTURE_SCHEMA,
        }
        manifest_path = self.base / "native-captures.json"
        manifest_path.write_bytes(reconcile.canonical_bytes(manifest))
        report = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=manifest_path,
        )
        lane = next(
            item
            for item in report["lane_results"]
            if item["lane"] == "rust_authority_service"
        )
        self.assertEqual(
            lane["status"],
            "OPEN_NATIVE_OUTPUT_ADAPTER_BINARY_IDENTITY_UNATTESTED",
        )
        self.assertFalse(lane["native_producer"]["binary_identity_attested"])
        report_path, _sidecar = reconcile.write_report(
            self.base / "native-report", report
        )
        verified = verify_report.verify(report_path)
        self.assertEqual(verified["lane_results"], report["lane_results"])

        capture.write_text(
            "\n".join(lines[:-2] + ["END"]) + "\n",
            encoding="ascii",
            newline="\n",
        )
        manifest["lanes"]["rust_authority_service"]["sha512"] = (
            reconcile.sha512_file(capture)
        )
        manifest_path.write_bytes(reconcile.canonical_bytes(manifest))
        with self.assertRaisesRegex(
            reconcile.ReconciliationError,
            "native output adapter rejected",
        ):
            reconcile.build_report(
                evidentiary=False,
                expected_commit=None,
                expected_tree=None,
                capture_manifest_path=manifest_path,
            )

    def test_spark_and_formal_raw_bundles_are_bound_but_remain_open(self) -> None:
        baseline = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=None,
        )
        captures: dict[str, dict[str, object]] = {}
        for lane in ("spark_safety_monitor", "formal_model"):
            bundle = self.raw_tool_bundle(baseline, lane)
            path = self.base / f"{lane}-native-output.json"
            path.write_bytes(reconcile.canonical_bytes(bundle))
            captures[lane] = {
                "declared_result": "PASS",
                "format": "native_tool_raw_output_bundle",
                "path": path.relative_to(ROOT).as_posix(),
                "sha512": reconcile.sha512_file(path),
            }
        manifest_path = self.base / "raw-tool-captures.json"
        manifest_path.write_bytes(
            reconcile.canonical_bytes(
                {"lanes": captures, "schema": reconcile.CAPTURE_SCHEMA}
            )
        )
        report = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=manifest_path,
        )
        for lane_name in captures:
            lane = next(
                item for item in report["lane_results"] if item["lane"] == lane_name
            )
            self.assertEqual(lane["status"], RAW_TOOL_OPEN_STATUS)
            self.assertFalse(lane["native_output"]["binary_identity_attested"])
            self.assertEqual(
                lane["native_output"]["semantic_observation_contract"],
                "UNAVAILABLE",
            )
        self.assertEqual(
            report["overall_status"],
            "OPEN_CROSS_LANGUAGE_REFINEMENT_INCOMPLETE",
        )
        report_path, _sidecar = reconcile.write_report(self.base / "raw-report", report)
        verified = verify_report.verify(report_path)
        self.assertEqual(verified["lane_results"], report["lane_results"])

    def test_raw_tool_bundle_hostile_inputs_fail_closed(self) -> None:
        baseline = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=None,
        )
        lane = "spark_safety_monitor"
        subject = baseline["subject"]
        aggregates = baseline["component_aggregate_sha512"]
        assert isinstance(subject, dict) and isinstance(aggregates, dict)
        expected = {
            "expected_lane": lane,
            "expected_candidate_commit": str(subject["commit"]),
            "expected_candidate_tree": str(subject["tree"]),
            "expected_source_aggregate_sha512": str(aggregates[lane]),
        }
        baseline_bundle = self.raw_tool_bundle(baseline, lane)
        mutations: dict[str, object] = {}

        truncated = copy.deepcopy(baseline_bundle)
        truncated["execution"]["stdout"]["bytes_hex"] = truncated["execution"]["stdout"]["bytes_hex"][:-2]
        mutations["truncated"] = truncated
        wrong_digest = copy.deepcopy(baseline_bundle)
        wrong_digest["execution"]["stdout"]["sha512"] = "b" * 128
        mutations["raw digest"] = wrong_digest
        wrong_source = copy.deepcopy(baseline_bundle)
        wrong_source["candidate"]["source_aggregate_sha512"] = "b" * 128
        mutations["source binding"] = wrong_source
        asserted_attestation = copy.deepcopy(baseline_bundle)
        asserted_attestation["producer"]["identity_attestation"] = "ATTESTED"
        mutations["unverifiable attestation"] = asserted_attestation
        empty_identity = copy.deepcopy(baseline_bundle)
        empty_identity["producer"]["tool_identity_output"] = self.bound_blob(b"")
        mutations["missing identity"] = empty_identity
        empty_output = copy.deepcopy(baseline_bundle)
        empty_output["execution"]["stdout"] = self.bound_blob(b"")
        mutations["missing raw output"] = empty_output
        incomplete = copy.deepcopy(baseline_bundle)
        incomplete["termination"] = "TRUNCATED"
        mutations["incomplete termination"] = incomplete
        extra = copy.deepcopy(baseline_bundle)
        extra["invented"] = False
        mutations["extra field"] = extra

        for label, mutation in mutations.items():
            with self.subTest(label=label):
                data = reconcile.canonical_bytes(mutation)
                with self.assertRaises(NativeOutputAdapterError):
                    parse_raw_native_tool_output_bundle(data, **expected)
                with self.assertRaises(verify_report.VerificationError):
                    verify_report.parse_raw_native_tool_output_bundle(data, **expected)

        noncanonical = json.dumps(baseline_bundle, sort_keys=False).encode("ascii")
        with self.assertRaises(NativeOutputAdapterError):
            parse_raw_native_tool_output_bundle(noncanonical, **expected)
        with self.assertRaises(verify_report.VerificationError):
            verify_report.parse_raw_native_tool_output_bundle(noncanonical, **expected)

    def test_omitted_and_extra_case_are_rejected(self) -> None:
        for mutation in ("omit", "extra"):
            with self.subTest(mutation=mutation):
                output = self.base / mutation
                report = reconcile.build_report(
                    evidentiary=False,
                    expected_commit=None,
                    expected_tree=None,
                    capture_manifest_path=None,
                )
                path, _ = reconcile.write_report(output, report)
                changed = copy.deepcopy(report)
                if mutation == "omit":
                    changed["case_results"] = changed["case_results"][:-1]
                else:
                    changed["case_results"].append(copy.deepcopy(changed["case_results"][-1]))
                self.rewrite(path, changed)
                with self.assertRaisesRegex(verify_report.VerificationError, "case result"):
                    verify_report.verify(path)

    def test_altered_vector_result_and_hash_are_rejected(self) -> None:
        source = ROOT / "wire_protocol" / "v2" / "vectors" / "mode1_golden.jsonl"
        altered = self.base / "altered-vector.jsonl"
        data = bytearray(source.read_bytes())
        position = data.find(b'"decision":"ALLOW"')
        self.assertGreater(position, 0)
        data[position + len('"decision":"')] = ord("D")
        altered.write_bytes(bytes(data))
        with self.assertRaises(verify_report.VerificationError):
            verify_report.load_vector(altered)

        report_path = self.build()
        report = json.loads(report_path.read_text(encoding="ascii"))
        report["case_results"][0]["source_sha512"] = "f" * 128
        self.rewrite(report_path, report)
        with self.assertRaisesRegex(verify_report.VerificationError, "binding mismatch"):
            verify_report.verify(report_path)

        report_path.with_name(reconcile.REPORT_SIDECAR).write_text(
            f"{'0' * 128}  {reconcile.REPORT_NAME}\n", encoding="ascii", newline="\n",
        )
        with self.assertRaisesRegex(verify_report.VerificationError, "sidecar"):
            verify_report.verify(report_path)

    def test_half_open_deadline_equality_is_not_success(self) -> None:
        messages = verify_report.load_vector(
            ROOT / "wire_protocol" / "v2" / "vectors" / "mode1_golden.jsonl"
        )
        receipt = next(item for item in messages if item["kind"] == "effect_receipt")
        receipt["message_time_ms"] = next(
            item["permit_deadline_ms"] for item in messages if item["kind"] == "effect_permit_result"
        )
        with self.assertRaisesRegex(verify_report.VerificationError, "half-open"):
            verify_report.derive_observation(messages)

    def test_failed_effect_cannot_be_relabelled_allow(self) -> None:
        report_path = self.build()
        report = json.loads(report_path.read_text(encoding="ascii"))
        failure = next(item for item in report["case_results"] if item["case_id"] == "mode1_failure")
        failure["observation"]["final_decision"] = "ACK"
        failure["observation"]["effect_disposition"] = "EFFECT_RECORDED"
        self.rewrite(report_path, report)
        # Other agents share the worktree and may change a separately bound
        # component during this test. Pin this test's inventory snapshot so it
        # reaches, and specifically exercises, the deny-vs-allow comparison.
        with mock.patch.object(
            verify_report, "expected_inventory", return_value=report["source_inventory"],
        ):
            with self.assertRaisesRegex(verify_report.VerificationError, "normalized lifecycle mismatch"):
                verify_report.verify(report_path)

    def test_extra_output_path_and_noncanonical_reparse_are_rejected(self) -> None:
        report_path = self.build()
        extra = report_path.parent / "extra.txt"
        extra.write_text("unexpected\n", encoding="ascii")
        with self.assertRaisesRegex(verify_report.VerificationError, "path set"):
            verify_report.verify(report_path)
        extra.unlink()

        data = report_path.read_text(encoding="ascii")
        noncanonical = data.replace('{"authority_effect":', '{"authority_effect":"NONE","authority_effect":', 1)
        report_path.write_text(noncanonical, encoding="ascii", newline="\n")
        report_path.with_name(reconcile.REPORT_SIDECAR).write_text(
            f"{hashlib.sha512(noncanonical.encode('ascii')).hexdigest()}  {reconcile.REPORT_NAME}\n",
            encoding="ascii",
            newline="\n",
        )
        with self.assertRaisesRegex(verify_report.VerificationError, "duplicate JSON key"):
            verify_report.verify(report_path)

    def test_dirty_evidentiary_mode_refuses_before_claim(self) -> None:
        responses = {
            ("rev-parse", "--verify", "HEAD^{commit}"): "a" * 40,
            ("rev-parse", "--verify", "HEAD^{tree}"): "b" * 40,
            ("status", "--porcelain=v1", "--untracked-files=all"): " M mutable.py",
        }
        with mock.patch.object(reconcile, "_git", side_effect=lambda *args: responses[args]):
            with self.assertRaisesRegex(reconcile.ReconciliationError, "dirty worktree"):
                reconcile.subject_record(
                    evidentiary=True,
                    expected_commit="a" * 40,
                    expected_tree="b" * 40,
                )

    def test_clean_but_incomplete_evidentiary_mode_also_refuses(self) -> None:
        responses = {
            ("rev-parse", "--verify", "HEAD^{commit}"): "a" * 40,
            ("rev-parse", "--verify", "HEAD^{tree}"): "b" * 40,
            ("status", "--porcelain=v1", "--untracked-files=all"): "",
        }
        with mock.patch.object(reconcile, "_git", side_effect=lambda *args: responses[args]):
            with self.assertRaisesRegex(
                reconcile.ReconciliationError, "every external lane",
            ):
                reconcile.build_report(
                    evidentiary=True,
                    expected_commit="a" * 40,
                    expected_tree="b" * 40,
                    capture_manifest_path=None,
                )

    def test_independent_verifier_text_adapter_is_bounded_and_open_scope(self) -> None:
        trace = (
            "SBP-LEX-INDEPENDENT-EVIDENCE-V1\n"
            "REQUEST x=y\n"
            "STATE x=y\n"
            "CONVERGENCE x=y\n"
            "ENVELOPE decision=BLOCK\n"
            "RECEIPT x=y\n"
            "WATCHDOG x=y\n"
            "END events=6\n"
        ).encode("ascii")
        expected = {
            "decision": "BLOCK",
            "event_count": 6,
            "profile": "SBP-LEX-INDEPENDENT-EVIDENCE-V1",
            "record_kinds": [
                "REQUEST", "STATE", "CONVERGENCE", "ENVELOPE",
                "RECEIPT", "WATCHDOG", "END",
            ],
            "verification_scope": "STRUCTURAL_TEXT_ONLY_SIGNATURES_NOT_REVERIFIED",
        }
        self.assertEqual(reconcile._parse_independent_trace(trace), expected)
        self.assertEqual(verify_report.parse_independent_trace(trace), expected)
        extra = trace.replace(b"RECEIPT x=y\n", b"COMMIT x=y\nRECEIPT x=y\n")
        with self.assertRaisesRegex(reconcile.ReconciliationError, "record order"):
            reconcile._parse_independent_trace(extra)
        with self.assertRaisesRegex(verify_report.VerificationError, "record order"):
            verify_report.parse_independent_trace(extra)

    def test_capture_hash_and_unknown_or_extra_capture_fail_closed(self) -> None:
        capture = self.base / "opaque.json"
        capture.write_bytes(b"{}\n")
        relative = capture.relative_to(ROOT).as_posix()
        baseline = {
            "lanes": {
                "formal_model": {
                    "declared_result": "PASS",
                    "format": "opaque_result",
                    "path": relative,
                    "sha512": "0" * 128,
                }
            },
            "schema": reconcile.CAPTURE_SCHEMA,
        }
        manifest = self.base / "capture-hash.json"
        manifest.write_bytes(reconcile.canonical_bytes(baseline))
        with self.assertRaisesRegex(reconcile.ReconciliationError, "SHA-512 mismatch"):
            reconcile.build_report(
                evidentiary=False,
                expected_commit=None,
                expected_tree=None,
                capture_manifest_path=manifest,
            )

        baseline["lanes"] = {"extra_implementation": baseline["lanes"]["formal_model"]}
        manifest.write_bytes(reconcile.canonical_bytes(baseline))
        with self.assertRaisesRegex(reconcile.ReconciliationError, "unknown capture"):
            reconcile.build_report(
                evidentiary=False,
                expected_commit=None,
                expected_tree=None,
                capture_manifest_path=manifest,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
