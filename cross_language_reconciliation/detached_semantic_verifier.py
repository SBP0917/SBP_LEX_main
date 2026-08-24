#!/usr/bin/env python3
"""Detached, byte-resolved verification of a copied C10 reconciliation report.

This verifier deliberately does not inspect ``HEAD`` or the current worktree.
The caller supplies the expected immutable subject identity and a resolver whose
logical source paths are obtained from that already authenticated subject.  A
copied package that omits any report-bound source or capture returns the typed
``OPEN_OBSERVATION_ONLY`` result; it can never satisfy evidence readiness.

The resolver is part of the trust boundary.  Production callers must construct
it from an independently authenticated Git/object or closed-package inventory,
not from path claims inside the reconciliation report itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import PurePosixPath
import re
from types import MappingProxyType
from typing import Iterable, Mapping, Protocol
import unicodedata

try:  # Package import and ``python -I`` focused-test import are both supported.
    from . import verify_report as semantic
except ImportError:  # pragma: no cover - exercised by the standalone test file.
    import verify_report as semantic  # type: ignore[no-redef]


REPORT_NAME = "reconciliation_report.json"
SIDECAR_NAME = REPORT_NAME + ".sha512"
REPORT_SCHEMA = "SBP-LEX-C10-SEMANTIC-RECONCILIATION-REPORT/1"
CATALOG_PATH = "cross_language_reconciliation/case_catalog.json"
OBSERVATION_SCHEMA_PATH = "cross_language_reconciliation/observation_schema.json"
CATALOG_SHA512 = "c2f6510f099adb2f187e6801a41993b865c977df5a1b40c4c95d046e1e2149301c24b11894fc5069b9c993eecd6ef96c8e29b30b7b7f3d6f92e661004eaa0874"
OBSERVATION_SCHEMA_SHA512 = (
    "f222b6c78c11bb8d973b998ad7bbf2ff2dd680e3b6a6eaae61f6d5335b0daeabc2b4bc9a412aa2a064ab5794394a87fad6b72f824b02f3bb9aa7bd1570fa7b07"
)
ORACLE_SHA512 = "4953fa1136348279509933ddb91102591015af3e7d45f1d6b1ca39ccb9e44190b5880c9f1a0ec054add824dd31d74feefc2922aa652833b16252cac159921f82"
CATALOG_SCHEMA = "SBP-LEX-C10-RECONCILIATION-CASE-CATALOG/1"
NORMALIZED_SCHEMA = "SBP-LEX-C10-NORMALIZED-LIFECYCLE-OBSERVATION/1"
OBSERVATION_SET_SCHEMA = "SBP-LEX-C10-NORMALIZED-OBSERVATION-SET/1"
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{128})\Z")
SIDECAR = re.compile(rf"([0-9a-f]{{128}})  {re.escape(REPORT_NAME)}\n\Z")
EXCLUDED_PARTS = frozenset({"target", "obj", "bin", "__pycache__", ".pytest_cache"})
WINDOWS_DEVICE_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)
REQUIRED_EXTERNAL_LANES = (
    "wire_v2_rust",
    "rust_trusted_core",
    "rust_authority_service",
    "independent_verifier",
    "spark_safety_monitor",
    "formal_model",
)
EXPECTED_COMPONENTS = frozenset(
    {
        "formal_model",
        "independent_verifier",
        "reconciler",
        "rust_authority_service",
        "rust_trusted_core",
        "spark_safety_monitor",
        "wire_v2_python",
        "wire_v2_rust",
        "wire_v2_vectors",
    }
)
REPORT_KEYS = {
    "authority_effect",
    "capture_inventory",
    "case_catalog",
    "case_results",
    "component_aggregate_sha512",
    "evidence_execution_ready",
    "lane_results",
    "limitations",
    "normalized_observation_schema",
    "oracle_sha512",
    "overall_status",
    "report_class",
    "schema",
    "source_inventory",
    "subject",
}
LIMITATIONS = [
    "No production, live, deployment, safety, owner-admission or external-IV&V claim.",
    "TEST-SHA512 and fixture keys are non-production test material.",
    "Opaque PASS output and equal test counts never establish semantic equivalence.",
    "SPARK/formal raw-output bundles remain OPEN because no native lifecycle-observation mapping exists.",
    "Independent verifier V1 text alone does not cover the wire-v2 3x4 matrix.",
]


class DetachedVerificationError(RuntimeError):
    """A malformed, altered, self-inconsistent, or authority-widening report."""


class SemanticContentResolver(Protocol):
    """Explicit resolver for logical immutable-source and copied-capture bytes."""

    def source_paths(self) -> Iterable[str]: ...

    def capture_paths(self) -> Iterable[str]: ...

    def resolve_source(self, logical_path: str) -> bytes | None: ...

    def resolve_capture(self, logical_path: str) -> bytes | None: ...


@dataclass(frozen=True)
class MappingContentResolver:
    """Convenience resolver for callers with independently closed blob maps."""

    sources: Mapping[str, bytes]
    captures: Mapping[str, bytes]

    def __post_init__(self) -> None:
        # Snapshot caller mappings. A frozen dataclass alone would still retain
        # references to mutable dictionaries and permit mid-verification drift.
        object.__setattr__(self, "sources", MappingProxyType(dict(self.sources)))
        object.__setattr__(self, "captures", MappingProxyType(dict(self.captures)))

    def source_paths(self) -> tuple[str, ...]:
        return tuple(self.sources)

    def capture_paths(self) -> tuple[str, ...]:
        return tuple(self.captures)

    def resolve_source(self, logical_path: str) -> bytes | None:
        return self.sources.get(logical_path)

    def resolve_capture(self, logical_path: str) -> bytes | None:
        return self.captures.get(logical_path)


@dataclass(frozen=True, order=True)
class MissingBytes:
    kind: str
    path: str
    expected_sha512: str
    expected_size: int


@dataclass(frozen=True)
class DetachedVerificationResult:
    status: str
    reason: str
    report_verified: bool
    readiness_satisfied: bool
    production_or_live_authority: bool
    report_sha512: str
    subject_commit: str
    subject_tree: str
    missing_bytes: tuple[MissingBytes, ...]

    def as_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["missing_bytes"] = [asdict(item) for item in self.missing_bytes]
        return value


def _fail(message: str) -> None:
    raise DetachedVerificationError(message)


def _mapping(value: object, label: str) -> dict[str, object]:
    try:
        return semantic.mapping(value, label)
    except semantic.VerificationError as error:
        raise DetachedVerificationError(str(error)) from error


def _exact(value: Mapping[str, object], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _fail(f"{label} key set mismatch")


def _safe_path(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail(f"{label} path invalid")
    if (
        unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or ":" in value
    ):
        _fail(f"{label} path is not canonical printable ASCII")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        _fail(f"{label} path unsafe/noncanonical")
    for part in path.parts:
        if part.endswith((".", " ")) or part.split(".", 1)[0].upper() in WINDOWS_DEVICE_NAMES:
            _fail(f"{label} path is ambiguous on Windows")
    return value


def _no_path_collisions(paths: Iterable[str], label: str) -> None:
    values = list(paths)
    folded = [value.casefold() for value in values]
    if len(values) != len(set(values)) or len(folded) != len(set(folded)):
        _fail(f"{label} paths collide exactly or by case-fold")


def _snapshot_resolver(resolver: SemanticContentResolver) -> MappingContentResolver:
    """Read resolver inventories and each blob exactly once."""

    try:
        source_paths = [_safe_path(path, "resolver source") for path in resolver.source_paths()]
        capture_paths = [_safe_path(path, "resolver capture") for path in resolver.capture_paths()]
    except DetachedVerificationError:
        raise
    except Exception as error:
        raise DetachedVerificationError("resolver path enumeration failed") from error
    _no_path_collisions(source_paths, "resolver source")
    _no_path_collisions(capture_paths, "resolver capture")
    if set(source_paths) & set(capture_paths):
        _fail("source and capture resolver namespaces overlap")
    sources: dict[str, bytes] = {}
    captures: dict[str, bytes] = {}
    try:
        for path in source_paths:
            value = resolver.resolve_source(path)
            if value is not None:
                if not isinstance(value, bytes):
                    _fail(f"resolver source is not immutable bytes: {path}")
                sources[path] = value
        for path in capture_paths:
            value = resolver.resolve_capture(path)
            if value is not None:
                if not isinstance(value, bytes):
                    _fail(f"resolver capture is not immutable bytes: {path}")
                captures[path] = value
    except DetachedVerificationError:
        raise
    except Exception as error:
        raise DetachedVerificationError("resolver byte snapshot failed") from error
    return MappingContentResolver(sources, captures)


def _sha(data: bytes) -> str:
    return hashlib.sha512(data).hexdigest()


def _parse(data: bytes, label: str) -> dict[str, object]:
    try:
        return _mapping(semantic.parse_json(data), label)
    except semantic.VerificationError as error:
        raise DetachedVerificationError(f"{label}: {error}") from error


def _validate_object_id(value: str, label: str) -> None:
    if not OBJECT_ID.fullmatch(value) or set(value) == {"0"}:
        _fail(f"{label} is not an exact nonzero object identity")


def _inventory_shape(report: Mapping[str, object]) -> list[dict[str, object]]:
    raw_inventory = report["source_inventory"]
    if not isinstance(raw_inventory, list) or not raw_inventory:
        _fail("source inventory must be nonempty")
    inventory: list[dict[str, object]] = []
    paths: list[str] = []
    components: set[str] = set()
    for raw in raw_inventory:
        entry = _mapping(raw, "source inventory entry")
        _exact(entry, {"component", "path", "sha512", "size"}, "source inventory entry")
        component = entry["component"]
        path = _safe_path(entry["path"], "source inventory")
        digest = entry["sha512"]
        size = entry["size"]
        if component not in EXPECTED_COMPONENTS:
            _fail(f"unknown source component: {component!r}")
        if not isinstance(digest, str) or not HEX128.fullmatch(digest):
            _fail(f"source SHA-512 invalid: {path}")
        if type(size) is not int or size < 0:
            _fail(f"source size invalid: {path}")
        paths.append(path)
        components.add(str(component))
        inventory.append(entry)
    _no_path_collisions(paths, "source inventory")
    if paths != sorted(paths):
        _fail("source inventory is duplicated or not canonical path order")
    if components != EXPECTED_COMPONENTS:
        _fail("source inventory does not cover every canonical component")
    for fixed in (CATALOG_PATH, OBSERVATION_SCHEMA_PATH):
        if fixed not in paths:
            _fail(f"source inventory omits fixed semantic input: {fixed}")
    return inventory


def _capture_shape(report: Mapping[str, object]) -> list[dict[str, object]]:
    raw_captures = report["capture_inventory"]
    if not isinstance(raw_captures, list) or not raw_captures:
        _fail("capture inventory must be nonempty")
    captures: list[dict[str, object]] = []
    lanes: list[str] = []
    paths: list[str] = []
    for raw in raw_captures:
        capture = _mapping(raw, "capture")
        _exact(capture, {"format", "lane", "path", "sha512", "size"}, "capture")
        lane = capture["lane"]
        path = _safe_path(capture["path"], "capture")
        digest = capture["sha512"]
        size = capture["size"]
        if not isinstance(lane, str) or lane not in REQUIRED_EXTERNAL_LANES:
            _fail(f"unknown capture lane: {lane!r}")
        if not isinstance(digest, str) or not HEX128.fullmatch(digest):
            _fail(f"capture SHA-512 invalid: {path}")
        if type(size) is not int or size <= 0:
            _fail(f"capture must contain nonempty bytes: {path}")
        lanes.append(lane)
        paths.append(path)
        captures.append(capture)
    _no_path_collisions(paths, "capture inventory")
    if tuple(lanes) != REQUIRED_EXTERNAL_LANES:
        _fail("capture inventory must contain each required external lane exactly once in order")
    return captures


def _initial_report_shape(
    report: Mapping[str, object], expected_commit: str, expected_tree: str
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    _exact(report, REPORT_KEYS, "report")
    if report["schema"] != REPORT_SCHEMA:
        _fail("report schema mismatch")
    if report["authority_effect"] != "NONE":
        _fail("reconciliation report widens authority")

    catalog = _mapping(report["case_catalog"], "case catalog binding")
    _exact(catalog, {"case_count", "matrix_case_ids", "path", "sha512"}, "case catalog binding")
    if catalog["path"] != CATALOG_PATH or catalog["sha512"] != CATALOG_SHA512:
        _fail("case catalog is not the fixed Candidate 10 catalog")
    schema = _mapping(report["normalized_observation_schema"], "schema binding")
    _exact(schema, {"path", "sha512"}, "schema binding")
    if schema != {"path": OBSERVATION_SCHEMA_PATH, "sha512": OBSERVATION_SCHEMA_SHA512}:
        _fail("normalized observation schema is not the fixed Candidate 10 schema")

    subject = _mapping(report["subject"], "subject")
    _exact(subject, {"clean", "commit", "fixed_subject_verified", "tree"}, "subject")
    if subject["commit"] != expected_commit or subject["tree"] != expected_tree:
        _fail("report subject differs from explicit expected commit/tree")
    if type(subject["clean"]) is not bool or type(subject["fixed_subject_verified"]) is not bool:
        _fail("subject boolean fields invalid")

    inventory = _inventory_shape(report)
    captures = _capture_shape(report)
    results = report["case_results"]
    if not isinstance(results, list) or not results:
        _fail("case results must be nonempty")
    if type(catalog["case_count"]) is not int or catalog["case_count"] <= 0:
        _fail("case catalog count invalid")
    if len(results) != catalog["case_count"]:
        _fail("case result count does not match fixed catalog binding")
    lanes = report["lane_results"]
    if not isinstance(lanes, list) or len(lanes) != 1 + len(REQUIRED_EXTERNAL_LANES):
        _fail("lane result set is incomplete")
    actual_lane_order = [_mapping(item, "lane result").get("lane") for item in lanes]
    if actual_lane_order != ["wire_v2_python", *REQUIRED_EXTERNAL_LANES]:
        _fail("lane result set/order mismatch")
    return inventory, captures


def _missing(
    inventory: list[dict[str, object]],
    captures: list[dict[str, object]],
    resolver: SemanticContentResolver,
) -> tuple[MissingBytes, ...]:
    missing: dict[tuple[str, str], MissingBytes] = {}
    for entry in inventory:
        path = str(entry["path"])
        if resolver.resolve_source(path) is None:
            missing[("source", path)] = MissingBytes(
                "source", path, str(entry["sha512"]), int(entry["size"])
            )
    fixed = {
        CATALOG_PATH: CATALOG_SHA512,
        OBSERVATION_SCHEMA_PATH: OBSERVATION_SCHEMA_SHA512,
    }
    by_path = {str(entry["path"]): entry for entry in inventory}
    for path, digest in fixed.items():
        if resolver.resolve_source(path) is None:
            entry = by_path.get(path)
            missing[("source", path)] = MissingBytes(
                "source", path, digest, int(entry["size"]) if entry is not None else -1
            )
    for capture in captures:
        path = str(capture["path"])
        if resolver.resolve_capture(path) is None:
            missing[("capture", path)] = MissingBytes(
                "capture", path, str(capture["sha512"]), int(capture["size"])
            )
    return tuple(sorted(missing.values()))


def _validate_catalog(data: bytes) -> dict[str, object]:
    if _sha(data) != CATALOG_SHA512:
        _fail("fixed case catalog bytes changed")
    catalog = _parse(data, "case catalog")
    _exact(
        catalog,
        {"cases", "component_roots", "matrix_case_ids", "oracle_sha512", "schema"},
        "case catalog",
    )
    if catalog["schema"] != CATALOG_SCHEMA or catalog["oracle_sha512"] != ORACLE_SHA512:
        _fail("case catalog schema/oracle mismatch")
    cases = catalog["cases"]
    matrix = catalog["matrix_case_ids"]
    roots = catalog["component_roots"]
    if not isinstance(cases, list) or not cases or not isinstance(matrix, list) or len(matrix) != 12:
        _fail("case catalog case/matrix shape mismatch")
    if not isinstance(roots, dict) or set(roots) != EXPECTED_COMPONENTS - {"wire_v2_vectors"}:
        _fail("case catalog component roots mismatch")
    ids: list[str] = []
    for raw in cases:
        case = _mapping(raw, "catalog case")
        kind = case.get("kind")
        if kind == "vector":
            _exact(case, {"expected", "id", "kind", "mode", "scenario", "source"}, "vector case")
            _safe_path(case["source"], "vector source")
            if not isinstance(case["expected"], dict) or not case["expected"]:
                _fail("vector expectation missing")
        elif kind == "synthetic_negative":
            _exact(case, {"base", "id", "kind", "mutation", "required_registry_case"}, "negative case")
            _safe_path(case["base"], "negative base")
        else:
            _fail("unknown case kind")
        if not isinstance(case["id"], str) or not case["id"]:
            _fail("case id invalid")
        ids.append(str(case["id"]))
    if len(ids) != len(set(ids)) or any(item not in ids for item in matrix):
        _fail("case catalog ids are duplicated or matrix membership is invalid")
    return catalog


def _validate_observation_schema(data: bytes) -> list[str]:
    if _sha(data) != OBSERVATION_SCHEMA_SHA512:
        _fail("fixed normalized observation schema bytes changed")
    schema = _parse(data, "normalized observation schema")
    _exact(
        schema,
        {"deadline_semantics", "field_types", "required_fields", "schema", "semantic_invariants"},
        "normalized observation schema",
    )
    fields = schema["required_fields"]
    if (
        schema["schema"] != NORMALIZED_SCHEMA
        or not isinstance(fields, list)
        or not fields
        or len(fields) != len(set(fields))
        or not all(isinstance(item, str) and item for item in fields)
        or not isinstance(schema["field_types"], dict)
        or set(schema["field_types"]) != set(fields)
        or not isinstance(schema["semantic_invariants"], list)
        or not schema["semantic_invariants"]
    ):
        _fail("normalized observation schema semantics invalid")
    return [str(item) for item in fields]


def _component_assignments(
    catalog: Mapping[str, object], source_paths: set[str]
) -> dict[str, str]:
    roots = _mapping(catalog["component_roots"], "component roots")
    assignments: dict[str, str] = {}
    for component, raw_roots in roots.items():
        if not isinstance(raw_roots, list) or not raw_roots:
            _fail(f"component root list invalid: {component}")
        for raw_root in raw_roots:
            root = _safe_path(raw_root, f"component {component}")
            for path in source_paths:
                if path != root and not path.startswith(root + "/"):
                    continue
                relative_parts = PurePosixPath(path).parts[len(PurePosixPath(root).parts) :]
                if any(part in EXCLUDED_PARTS for part in relative_parts):
                    continue
                prior = assignments.get(path)
                if prior is not None and prior != component:
                    _fail(f"source component roots overlap: {path}")
                assignments[path] = component
    cases = catalog["cases"]
    assert isinstance(cases, list)
    for raw in cases:
        case = _mapping(raw, "catalog case")
        path = _safe_path(case["source"] if case["kind"] == "vector" else case["base"], "case source")
        assignments.setdefault(path, "wire_v2_vectors")
    assignments.setdefault("wire_protocol/v2/vectors/adversarial_cases.txt", "wire_v2_vectors")
    return assignments


def _validate_inventory(
    report: Mapping[str, object],
    catalog: Mapping[str, object],
    inventory: list[dict[str, object]],
    resolver: SemanticContentResolver,
) -> dict[str, bytes]:
    available = {_safe_path(path, "resolver source") for path in resolver.source_paths()}
    assignments = _component_assignments(catalog, available)
    expected: list[dict[str, object]] = []
    resolved: dict[str, bytes] = {}
    for path, component in sorted(assignments.items()):
        data = resolver.resolve_source(path)
        if data is None:
            _fail(f"resolver listed but did not return source bytes: {path}")
        if not isinstance(data, bytes):
            _fail(f"resolver source is not bytes: {path}")
        resolved[path] = data
        expected.append(
            {"component": component, "path": path, "sha512": _sha(data), "size": len(data)}
        )
    if inventory != expected:
        _fail("source inventory differs from the explicit immutable-source resolver")
    aggregates = semantic.aggregate_inventory(expected)
    if report["component_aggregate_sha512"] != aggregates:
        _fail("component aggregate does not match exact resolved source inventory")
    if set(aggregates) != EXPECTED_COMPONENTS:
        _fail("resolved source inventory omits a canonical component")
    return resolved


def _case_semantics(
    report: Mapping[str, object],
    catalog: Mapping[str, object],
    required_fields: list[str],
    sources: Mapping[str, bytes],
) -> dict[str, dict[str, object]]:
    cases = catalog["cases"]
    results = report["case_results"]
    assert isinstance(cases, list) and isinstance(results, list)
    case_binding = _mapping(report["case_catalog"], "case catalog binding")
    matrix_ids = catalog["matrix_case_ids"]
    if (
        case_binding["case_count"] != len(cases)
        or case_binding["matrix_case_ids"] != matrix_ids
        or report["oracle_sha512"] != ORACLE_SHA512
    ):
        _fail("report case catalog/oracle membership mismatch")
    expected_ids = [_mapping(case, "case")["id"] for case in cases]
    actual_ids = [_mapping(result, "case result").get("case_id") for result in results]
    if actual_ids != expected_ids:
        _fail("case result set/order differs from fixed catalog")

    matrix: dict[str, dict[str, object]] = {}
    for raw_case, raw_result in zip(cases, results, strict=True):
        case = _mapping(raw_case, "case")
        result = _mapping(raw_result, f"case result {case['id']}")
        if case["kind"] == "vector":
            _exact(
                result,
                {"adapter", "case_id", "kind", "observation", "source_path", "source_sha512", "verdict"},
                f"vector result {case['id']}",
            )
            path = str(case["source"])
            data = sources.get(path)
            if data is None:
                _fail(f"vector source is outside resolved inventory: {path}")
            if (
                result["adapter"] != "WIRE_V2_PYTHON_EXECUTED"
                or result["kind"] != "VECTOR"
                or result["verdict"] != "ACCEPT"
                or result["source_path"] != path
                or result["source_sha512"] != _sha(data)
            ):
                _fail(f"vector result binding mismatch: {case['id']}")
            try:
                observation = semantic.derive_observation(semantic.load_vector_bytes(data))
            except semantic.VerificationError as error:
                raise DetachedVerificationError(f"vector {case['id']}: {error}") from error
            if set(observation) != set(required_fields) or result["observation"] != observation:
                _fail(f"normalized case semantics mismatch: {case['id']}")
            expected = _mapping(case["expected"], f"case expectation {case['id']}")
            if any(observation.get(key) != value for key, value in expected.items()):
                _fail(f"case catalog expectation mismatch: {case['id']}")
            if case["id"] in matrix_ids:
                matrix[str(case["id"])] = observation
        else:
            _exact(
                result,
                {"adapter", "base_path", "base_sha512", "case_id", "kind", "mutation", "registry_case", "rejection", "verdict"},
                f"negative result {case['id']}",
            )
            path = str(case["base"])
            data = sources.get(path)
            expected = {
                "adapter": "WIRE_V2_PYTHON_IN_MEMORY_SIGNED_NEGATIVE",
                "base_path": path,
                "base_sha512": _sha(data) if data is not None else "",
                "case_id": case["id"],
                "kind": "SYNTHETIC_NEGATIVE",
                "mutation": case["mutation"],
                "registry_case": case["required_registry_case"],
                "rejection": "WIRE_V2_REJECTED",
                "verdict": "REJECT",
            }
            if data is None or result != expected:
                _fail(f"negative result binding mismatch: {case['id']}")
    if list(matrix) != matrix_ids:
        _fail("matrix observation set/order mismatch")
    return matrix


def _capture_semantics(
    report: Mapping[str, object],
    captures: list[dict[str, object]],
    resolver: SemanticContentResolver,
    matrix: Mapping[str, dict[str, object]],
    matrix_ids: list[str],
    required_fields: list[str],
) -> list[dict[str, object]]:
    expected_paths = {str(item["path"]) for item in captures}
    actual_paths = {_safe_path(path, "resolver capture") for path in resolver.capture_paths()}
    if actual_paths != expected_paths:
        _fail("explicit capture resolver path set differs from report inventory")
    expected_lanes: list[dict[str, object]] = [
        {
            "case_count": len(report["case_results"]),  # type: ignore[arg-type]
            "lane": "wire_v2_python",
            "matrix_case_count": len(matrix_ids),
            "status": "CLOSED_LOCAL_FIXTURE_SEMANTICS",
        }
    ]
    actual_lanes = report["lane_results"]
    assert isinstance(actual_lanes, list)
    actual_by_lane = {
        str(_mapping(item, "lane result")["lane"]): _mapping(item, "lane result")
        for item in actual_lanes
    }
    if len(actual_by_lane) != len(actual_lanes):
        _fail("duplicate lane result")
    for lane, capture in zip(REQUIRED_EXTERNAL_LANES, captures, strict=True):
        path = str(capture["path"])
        data = resolver.resolve_capture(path)
        if not isinstance(data, bytes) or not data:
            _fail(f"capture is absent or empty: {path}")
        if _sha(data) != capture["sha512"] or len(data) != capture["size"]:
            _fail(f"capture bytes differ from report binding: {path}")
        actual_lane = actual_by_lane[lane]
        declared = actual_lane.get("declared_result")
        if declared not in {"PASS", "FAIL", "BLOCKED", "INCONCLUSIVE"}:
            _fail(f"capture lane declared result invalid: {lane}")
        capture_format = capture["format"]
        if capture_format == "canonical_observation_set":
            observed = _parse(data, f"capture observation set {lane}")
            _exact(
                observed,
                {"case_catalog_sha512", "implementation", "observations", "schema"},
                f"capture observation set {lane}",
            )
            if (
                observed["schema"] != OBSERVATION_SET_SCHEMA
                or observed["case_catalog_sha512"] != CATALOG_SHA512
                or not isinstance(observed["implementation"], str)
                or not observed["implementation"]
                or not isinstance(observed["observations"], list)
            ):
                _fail(f"capture observation contract mismatch: {lane}")
            by_id: dict[str, dict[str, object]] = {}
            for raw in observed["observations"]:
                item = _mapping(raw, f"captured observation {lane}")
                _exact(item, {"case_id", "observation"}, f"captured observation {lane}")
                case_id = str(item["case_id"])
                if case_id in by_id:
                    _fail(f"duplicate captured case: {lane}/{case_id}")
                observation = _mapping(item["observation"], f"captured observation {case_id}")
                if set(observation) != set(required_fields):
                    _fail(f"captured observation schema mismatch: {lane}/{case_id}")
                by_id[case_id] = observation
            if list(by_id) != matrix_ids:
                _fail(f"captured case set/order mismatch: {lane}")
            mismatches = [case_id for case_id in matrix_ids if by_id[case_id] != matrix[case_id]]
            expected_lanes.append(
                {
                    "declared_result": declared,
                    "lane": lane,
                    "semantic_mismatches": mismatches,
                    "status": (
                        "OPEN_MATCH_NOT_DERIVED_BY_NATIVE_OUTPUT_ADAPTER"
                        if not mismatches
                        else "FAIL_SEMANTIC_MISMATCH"
                    ),
                }
            )
        elif capture_format == "native_wire_v2_framed_transcripts" and lane in {
            "wire_v2_rust",
            "rust_authority_service",
        }:
            try:
                producer, native_cases = semantic.parse_native_wire_capture(
                    data, matrix_ids
                )
                native_observations = {
                    case_id: semantic.derive_observation(messages)
                    for case_id, messages in native_cases
                }
            except semantic.VerificationError as error:
                raise DetachedVerificationError(
                    f"native output adapter: {error}"
                ) from error
            mismatches = [
                case_id
                for case_id in matrix_ids
                if native_observations[case_id] != matrix[case_id]
            ]
            expected_lanes.append(
                {
                    "declared_result": declared,
                    "lane": lane,
                    "native_producer": producer,
                    "semantic_mismatches": mismatches,
                    "status": (
                        "OPEN_NATIVE_OUTPUT_ADAPTER_BINARY_IDENTITY_UNATTESTED"
                        if not mismatches
                        else "FAIL_SEMANTIC_MISMATCH"
                    ),
                }
            )
        elif capture_format == "independent_verifier_v1_trace" and lane == "independent_verifier":
            try:
                summary = semantic.parse_independent_trace(data)
            except semantic.VerificationError as error:
                raise DetachedVerificationError(f"independent trace: {error}") from error
            expected_lanes.append(
                {
                    "declared_result": declared,
                    "lane": lane,
                    "status": "OPEN_PROFILE_DOES_NOT_COVER_3X4_WIRE_V2_MATRIX",
                    "trace_summary": summary,
                }
            )
        elif capture_format == "native_tool_raw_output_bundle" and lane in {
            "spark_safety_monitor",
            "formal_model",
        }:
            subject = _mapping(report["subject"], "subject")
            component_aggregates = _mapping(
                report["component_aggregate_sha512"], "component aggregates"
            )
            try:
                native_output = semantic.parse_raw_native_tool_output_bundle(
                    data,
                    expected_lane=lane,
                    expected_candidate_commit=str(subject["commit"]),
                    expected_candidate_tree=str(subject["tree"]),
                    expected_source_aggregate_sha512=str(component_aggregates[lane]),
                )
            except semantic.VerificationError as error:
                raise DetachedVerificationError(
                    f"native raw tool adapter: {error}"
                ) from error
            expected_lanes.append(
                {
                    "declared_result": declared,
                    "lane": lane,
                    "native_output": native_output,
                    "status": semantic.RAW_TOOL_OPEN_STATUS,
                }
            )
        elif capture_format == "opaque_result":
            expected_lanes.append(
                {
                    "declared_result": declared,
                    "lane": lane,
                    "status": "OPEN_OPAQUE_RESULT_HAS_NO_CASE_SEMANTICS",
                }
            )
        else:
            _fail(f"unsupported capture format/lane: {lane}")
    if actual_lanes != expected_lanes:
        _fail("lane results do not exactly follow resolved capture semantics")
    return expected_lanes


def _final_semantics(
    report: Mapping[str, object], expected_lanes: list[dict[str, object]]
) -> bool:
    if report["limitations"] != LIMITATIONS:
        _fail("report limitations changed")
    subject = _mapping(report["subject"], "subject")
    report_class = report["report_class"]
    if report_class == "EVIDENTIARY_RECONCILIATION_CANDIDATE":
        if subject["clean"] is not True or subject["fixed_subject_verified"] is not True:
            _fail("evidentiary report subject is not clean and fixed")
        evidence = True
    elif report_class == "NON_EVIDENTIARY_SYNTHETIC_LOCAL_ASSURANCE":
        if subject["fixed_subject_verified"] is not False:
            _fail("synthetic report claims fixed-subject evidence")
        evidence = False
    else:
        _fail("unknown report class")
    external = expected_lanes[1:]
    all_closed = all(item.get("status") == "CLOSED_SEMANTIC_MATCH" for item in external)
    if evidence and not all_closed:
        _fail("evidentiary report class requires every external semantic lane closed")
    ready = bool(evidence and subject["fixed_subject_verified"] and all_closed)
    overall = (
        "CLOSED_ALL_DECLARED_IMPLEMENTATIONS_SEMANTICALLY_MATCH"
        if all_closed
        else "OPEN_CROSS_LANGUAGE_REFINEMENT_INCOMPLETE"
    )
    if report["evidence_execution_ready"] is not ready or report["overall_status"] != overall:
        _fail("report readiness/overall status is not the exact semantic derivation")
    return ready


def verify_detached_report(
    report_bytes: bytes,
    sidecar_bytes: bytes,
    *,
    expected_commit: str,
    expected_tree: str,
    resolver: SemanticContentResolver,
) -> DetachedVerificationResult:
    """Verify a copied report without consulting a mutable repository.

    Malformed or altered reports raise :class:`DetachedVerificationError`.
    Missing report-bound bytes return ``OPEN_OBSERVATION_ONLY`` with an exact
    inventory; this is intentionally not a verification PASS.
    """

    _validate_object_id(expected_commit, "expected commit")
    _validate_object_id(expected_tree, "expected tree")
    if not isinstance(report_bytes, bytes) or not isinstance(sidecar_bytes, bytes):
        _fail("report and sidecar must be bytes")
    report_sha512 = _sha(report_bytes)
    try:
        sidecar_text = sidecar_bytes.decode("ascii")
    except UnicodeDecodeError as error:
        raise DetachedVerificationError("report sidecar is not ASCII") from error
    matched = SIDECAR.fullmatch(sidecar_text)
    if matched is None or matched.group(1) != report_sha512:
        _fail("report sidecar mismatch")
    report = _parse(report_bytes, "reconciliation report")
    inventory, captures = _initial_report_shape(report, expected_commit, expected_tree)
    stable_resolver = _snapshot_resolver(resolver)
    missing = _missing(inventory, captures, stable_resolver)
    if missing:
        return DetachedVerificationResult(
            status="OPEN_OBSERVATION_ONLY",
            reason="COPIED_SEMANTIC_CLOSURE_MISSING_BYTES",
            report_verified=False,
            readiness_satisfied=False,
            production_or_live_authority=False,
            report_sha512=report_sha512,
            subject_commit=expected_commit,
            subject_tree=expected_tree,
            missing_bytes=missing,
        )

    catalog_data = stable_resolver.resolve_source(CATALOG_PATH)
    schema_data = stable_resolver.resolve_source(OBSERVATION_SCHEMA_PATH)
    assert isinstance(catalog_data, bytes) and isinstance(schema_data, bytes)
    catalog = _validate_catalog(catalog_data)
    required_fields = _validate_observation_schema(schema_data)
    sources = _validate_inventory(report, catalog, inventory, stable_resolver)
    matrix_ids = [str(item) for item in catalog["matrix_case_ids"]]  # type: ignore[index]
    matrix = _case_semantics(report, catalog, required_fields, sources)
    lanes = _capture_semantics(
        report, captures, stable_resolver, matrix, matrix_ids, required_fields
    )
    ready = _final_semantics(report, lanes)
    return DetachedVerificationResult(
        status="VERIFIED_SEMANTIC_CLOSURE" if ready else "OPEN_OBSERVATION_ONLY",
        reason=(
            "EXACT_SEMANTIC_CLOSURE_AND_READINESS_VERIFIED"
            if ready
            else "REPORT_VERIFIED_BUT_NATIVE_CROSS_LANGUAGE_REFINEMENT_REMAINS_OPEN"
        ),
        report_verified=True,
        readiness_satisfied=ready,
        production_or_live_authority=False,
        report_sha512=report_sha512,
        subject_commit=expected_commit,
        subject_tree=expected_tree,
        missing_bytes=(),
    )


__all__ = [
    "DetachedVerificationError",
    "DetachedVerificationResult",
    "MappingContentResolver",
    "MissingBytes",
    "SemanticContentResolver",
    "verify_detached_report",
]
