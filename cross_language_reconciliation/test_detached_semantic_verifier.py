"""Focused hostile tests for the copied-report detached semantic verifier."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))

import detached_semantic_verifier as detached  # noqa: E402
import reconcile  # noqa: E402
import verify_report  # noqa: E402


def _bound_blob(data: bytes) -> dict[str, object]:
    return {
        "bytes_hex": data.hex(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "size": len(data),
    }


def _raw_tool_bundle(
    baseline: dict[str, object], lane: str
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
            "stderr": _bound_blob(b""),
            "stdout": _bound_blob(f"complete {lane} raw output\n".encode("ascii")),
        },
        "lane": lane,
        "producer": {
            "claimed_binary_sha512": "a" * 128,
            "identity_attestation": "UNAVAILABLE",
            "tool": tools[lane],
            "tool_identity_output": _bound_blob(
                f"{tools[lane]} identity output\n".encode("ascii")
            ),
        },
        "schema": verify_report.RAW_TOOL_BUNDLE_SCHEMA,
        "termination": "COMPLETE_UNTRUNCATED",
    }


class DetachedSemanticVerifierTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(
            prefix="c10-detached-reconciliation-", dir=ROOT / "runtime_artifacts"
        )
        cls.base = Path(cls.temporary.name)
        baseline = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=None,
        )
        captures: dict[str, dict[str, str]] = {}
        for index, lane in enumerate(detached.REQUIRED_EXTERNAL_LANES):
            path = cls.base / f"{index:02d}-{lane}.capture"
            if lane in {"spark_safety_monitor", "formal_model"}:
                path.write_bytes(reconcile.canonical_bytes(_raw_tool_bundle(baseline, lane)))
                capture_format = "native_tool_raw_output_bundle"
            else:
                path.write_bytes(
                    f"opaque non-authorizing observation for {lane}\n".encode("ascii")
                )
                capture_format = "opaque_result"
            relative = path.relative_to(ROOT).as_posix()
            captures[lane] = {
                "declared_result": "PASS",
                "format": capture_format,
                "path": relative,
                "sha512": hashlib.sha512(path.read_bytes()).hexdigest(),
            }
        manifest = {"lanes": captures, "schema": reconcile.CAPTURE_SCHEMA}
        manifest_path = cls.base / "capture-manifest.json"
        manifest_path.write_bytes(reconcile.canonical_bytes(manifest))
        cls.report = reconcile.build_report(
            evidentiary=False,
            expected_commit=None,
            expected_tree=None,
            capture_manifest_path=manifest_path,
        )
        cls.report_bytes, cls.sidecar_bytes = cls._serialize(cls.report)
        subject = cls.report["subject"]
        assert isinstance(subject, dict)
        cls.commit = str(subject["commit"])
        cls.tree = str(subject["tree"])
        cls.sources = {
            str(entry["path"]): ROOT.joinpath(*str(entry["path"]).split("/")).read_bytes()
            for entry in cls.report["source_inventory"]
        }
        cls.captures = {
            str(entry["path"]): ROOT.joinpath(*str(entry["path"]).split("/")).read_bytes()
            for entry in cls.report["capture_inventory"]
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    @staticmethod
    def _serialize(report: dict[str, object]) -> tuple[bytes, bytes]:
        data = reconcile.canonical_bytes(report)
        sidecar = (
            f"{hashlib.sha512(data).hexdigest()}  {reconcile.REPORT_NAME}\n".encode("ascii")
        )
        return data, sidecar

    def resolver(
        self,
        *,
        sources: dict[str, bytes] | None = None,
        captures: dict[str, bytes] | None = None,
    ) -> detached.MappingContentResolver:
        return detached.MappingContentResolver(
            self.sources if sources is None else sources,
            self.captures if captures is None else captures,
        )

    def verify(
        self,
        report: dict[str, object] | None = None,
        *,
        resolver: detached.MappingContentResolver | None = None,
        commit: str | None = None,
        tree: str | None = None,
    ) -> detached.DetachedVerificationResult:
        data, sidecar = (
            (self.report_bytes, self.sidecar_bytes)
            if report is None
            else self._serialize(report)
        )
        return detached.verify_detached_report(
            data,
            sidecar,
            expected_commit=self.commit if commit is None else commit,
            expected_tree=self.tree if tree is None else tree,
            resolver=self.resolver() if resolver is None else resolver,
        )

    def test_complete_resolved_report_is_verified_but_remains_observation_only(self) -> None:
        result = self.verify()
        self.assertEqual(result.status, "OPEN_OBSERVATION_ONLY")
        self.assertTrue(result.report_verified)
        self.assertFalse(result.readiness_satisfied)
        self.assertFalse(result.production_or_live_authority)
        self.assertEqual(result.missing_bytes, ())
        self.assertEqual(
            result.reason,
            "REPORT_VERIFIED_BUT_NATIVE_CROSS_LANGUAGE_REFINEMENT_REMAINS_OPEN",
        )

    def test_current_copied_capture_only_closure_returns_exact_missing_bytes(self) -> None:
        result = self.verify(
            resolver=detached.MappingContentResolver({}, self.captures)
        )
        self.assertEqual(result.status, "OPEN_OBSERVATION_ONLY")
        self.assertFalse(result.report_verified)
        self.assertFalse(result.readiness_satisfied)
        self.assertEqual(
            {item.path for item in result.missing_bytes}, set(self.sources)
        )
        self.assertIn(detached.CATALOG_PATH, {item.path for item in result.missing_bytes})
        self.assertIn(
            detached.OBSERVATION_SCHEMA_PATH,
            {item.path for item in result.missing_bytes},
        )

    def test_zero_capture_or_zero_case_shallow_report_is_rejected(self) -> None:
        for field in ("capture_inventory", "case_results"):
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report[field] = []
                with self.assertRaises(detached.DetachedVerificationError):
                    self.verify(report)

    def test_self_consistent_minimal_source_inventory_is_rejected(self) -> None:
        report = copy.deepcopy(self.report)
        report["source_inventory"] = [
            item
            for item in report["source_inventory"]
            if item["path"]
            in {detached.CATALOG_PATH, detached.OBSERVATION_SCHEMA_PATH}
        ]
        report["component_aggregate_sha512"] = verify_report.aggregate_inventory(
            report["source_inventory"]
        )
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "every canonical component"
        ):
            self.verify(report)

    def test_explicit_subject_identity_never_follows_head(self) -> None:
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "explicit expected commit/tree"
        ):
            self.verify(commit="f" * len(self.commit))

    def test_sidecar_extra_root_field_and_authority_widening_are_rejected(self) -> None:
        with self.assertRaisesRegex(detached.DetachedVerificationError, "sidecar"):
            detached.verify_detached_report(
                self.report_bytes,
                f"{'0' * 128}  {reconcile.REPORT_NAME}\n".encode("ascii"),
                expected_commit=self.commit,
                expected_tree=self.tree,
                resolver=self.resolver(),
            )
        for mutation in ("extra", "authority", "schema"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(self.report)
                if mutation == "extra":
                    report["invented"] = "field"
                elif mutation == "authority":
                    report["authority_effect"] = "EXECUTE"
                else:
                    report["schema"] = "SBP-LEX-C10-SEMANTIC-RECONCILIATION-REPORT/2"
                with self.assertRaises(detached.DetachedVerificationError):
                    self.verify(report)

    def test_self_consistent_replacement_of_fixed_catalog_or_schema_is_rejected(self) -> None:
        for logical_path, binding_field in (
            (detached.CATALOG_PATH, "case_catalog"),
            (detached.OBSERVATION_SCHEMA_PATH, "normalized_observation_schema"),
        ):
            with self.subTest(path=logical_path):
                report = copy.deepcopy(self.report)
                changed = self.sources[logical_path][:-1] + b" \n"
                digest = hashlib.sha512(changed).hexdigest()
                report[binding_field]["sha512"] = digest
                entry = next(
                    item for item in report["source_inventory"] if item["path"] == logical_path
                )
                entry["sha512"] = digest
                entry["size"] = len(changed)
                report["component_aggregate_sha512"] = verify_report.aggregate_inventory(
                    report["source_inventory"]
                )
                changed_sources = dict(self.sources)
                changed_sources[logical_path] = changed
                with self.assertRaisesRegex(
                    detached.DetachedVerificationError, "fixed Candidate 10|fixed normalized"
                ):
                    self.verify(report, resolver=self.resolver(sources=changed_sources))

    def test_present_but_mutated_source_or_capture_is_a_hard_failure(self) -> None:
        source_path = next(
            path for path in self.sources if path.endswith("mode1_golden.jsonl")
        )
        changed_sources = dict(self.sources)
        changed_sources[source_path] += b"x"
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "source inventory"
        ):
            self.verify(resolver=self.resolver(sources=changed_sources))

        capture_path = next(iter(self.captures))
        changed_captures = dict(self.captures)
        changed_captures[capture_path] += b"x"
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "capture bytes"
        ):
            self.verify(resolver=self.resolver(captures=changed_captures))

    def test_self_consistent_hostile_raw_tool_capture_is_rejected(self) -> None:
        raw_entry = next(
            item
            for item in self.report["capture_inventory"]
            if item["lane"] == "spark_safety_monitor"
        )
        path = str(raw_entry["path"])
        original = json.loads(self.captures[path].decode("ascii"))
        mutations: list[dict[str, object]] = []

        wrong_source = copy.deepcopy(original)
        wrong_source["candidate"]["source_aggregate_sha512"] = "b" * 128
        mutations.append(wrong_source)
        truncated = copy.deepcopy(original)
        truncated["execution"]["stdout"]["bytes_hex"] = truncated["execution"]["stdout"]["bytes_hex"][:-2]
        mutations.append(truncated)
        attested = copy.deepcopy(original)
        attested["producer"]["identity_attestation"] = "ATTESTED"
        mutations.append(attested)

        for mutation in mutations:
            with self.subTest(mutation=mutation):
                changed = reconcile.canonical_bytes(mutation)
                report = copy.deepcopy(self.report)
                entry = next(
                    item
                    for item in report["capture_inventory"]
                    if item["lane"] == "spark_safety_monitor"
                )
                entry["sha512"] = hashlib.sha512(changed).hexdigest()
                entry["size"] = len(changed)
                captures = dict(self.captures)
                captures[path] = changed
                with self.assertRaisesRegex(
                    detached.DetachedVerificationError,
                    "native raw tool adapter",
                ):
                    self.verify(report, resolver=self.resolver(captures=captures))

    def test_omitted_capture_lane_and_extra_resolver_capture_are_rejected(self) -> None:
        report = copy.deepcopy(self.report)
        report["capture_inventory"] = report["capture_inventory"][:-1]
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "each required external lane"
        ):
            self.verify(report)

        extra_captures = dict(self.captures)
        extra_captures["runtime_artifacts/unbound.capture"] = b"extra\n"
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "resolver path set"
        ):
            self.verify(resolver=self.resolver(captures=extra_captures))

    def test_case_lane_overall_and_readiness_claims_are_recomputed(self) -> None:
        mutations: list[tuple[str, object]] = [
            ("overall_status", "CLOSED_ALL_DECLARED_IMPLEMENTATIONS_SEMANTICALLY_MATCH"),
            ("evidence_execution_ready", True),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                report = copy.deepcopy(self.report)
                report[field] = value
                with self.assertRaisesRegex(
                    detached.DetachedVerificationError, "readiness/overall"
                ):
                    self.verify(report)

        report = copy.deepcopy(self.report)
        report["case_results"][0]["observation"]["final_decision"] = "BLOCK"
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "normalized case semantics"
        ):
            self.verify(report)

        report = copy.deepcopy(self.report)
        report["lane_results"][1]["status"] = "CLOSED_SEMANTIC_MATCH"
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "lane results"
        ):
            self.verify(report)

        report = copy.deepcopy(self.report)
        report["report_class"] = "EVIDENTIARY_RECONCILIATION_CANDIDATE"
        report["subject"]["clean"] = True
        report["subject"]["fixed_subject_verified"] = True
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "every external semantic lane"
        ):
            self.verify(report)

    def test_casefold_ambiguous_paths_are_rejected(self) -> None:
        report = copy.deepcopy(self.report)
        duplicate = copy.deepcopy(report["source_inventory"][0])
        duplicate["path"] = str(duplicate["path"]).upper()
        report["source_inventory"].append(duplicate)
        report["source_inventory"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(
            detached.DetachedVerificationError, "case-fold"
        ):
            self.verify(report)

    def test_resolver_bytes_are_snapshotted_once(self) -> None:
        class ChangingResolver:
            def __init__(self, sources: dict[str, bytes], captures: dict[str, bytes]) -> None:
                self.sources = sources
                self.captures = captures
                self.source_calls: dict[str, int] = {}
                self.capture_calls: dict[str, int] = {}

            def source_paths(self) -> tuple[str, ...]:
                return tuple(self.sources)

            def capture_paths(self) -> tuple[str, ...]:
                return tuple(self.captures)

            def resolve_source(self, path: str) -> bytes:
                self.source_calls[path] = self.source_calls.get(path, 0) + 1
                return self.sources[path] if self.source_calls[path] == 1 else b"changed"

            def resolve_capture(self, path: str) -> bytes:
                self.capture_calls[path] = self.capture_calls.get(path, 0) + 1
                return self.captures[path] if self.capture_calls[path] == 1 else b"changed"

        changing = ChangingResolver(self.sources, self.captures)
        result = self.verify(resolver=changing)  # type: ignore[arg-type]
        self.assertTrue(result.report_verified)
        self.assertTrue(all(count == 1 for count in changing.source_calls.values()))
        self.assertTrue(all(count == 1 for count in changing.capture_calls.values()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
