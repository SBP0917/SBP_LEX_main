from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

import sbp_ptde.preparation as preparation_module
from sbp_lex.local_trust.constants import (
    ACCEPTED_HISTORY_SCHEMA,
    DUAL_SIGNATURE_TRANSITION_POLICY,
    DUAL_SIGNATURE_VERIFICATION_RULE,
    GENESIS,
    HISTORY_SIGNING_PURPOSE,
    HYBRID_SIGNATURE_PROFILE,
    PRODUCTION,
)
from sbp_lex.local_trust.constants import (
    NO_AUTHORITY as LOCAL_NO_AUTHORITY,
)
from sbp_lex.local_trust.digests import digest
from sbp_lex.local_trust.signing import (
    PRODUCTION_DUAL_CUSTODY_CLASS,
    DualSignatureLaneCustody,
    HybridVerificationContext,
    _bound_message,
)
from sbp_lex.supply_chain.python_inventory import GOVERNED_PYTHON_ENVIRONMENT
from sbp_lex.supply_chain.python_lock_builder import (
    build_python_lock_document,
    write_python_lock_document_exclusive,
)
from sbp_lex.supply_chain.source_binding import bind_p_object
from sbp_ptde.canonical import canonical_json_document_bytes, canonical_sha512
from sbp_ptde.constants import INVENTORY_CLASSES, NO_AUTHORITY
from sbp_ptde.errors import PTDEVerificationError
from sbp_ptde.policy import policy_document_bytes
from sbp_ptde.preparation import (
    E_INPUT_PREPARATION_SCHEMA,
    P_PREPARATION_SCHEMA,
    prepare_d_descriptor,
    prepare_e_campaign_input_skeleton,
    prepare_p_selection_packet,
    prepare_t_profile,
    validate_e_campaign_input_skeleton,
    validate_p_selection_packet,
    write_canonical_document_exclusive,
)
from sbp_ptde.trust import (
    AcceptedAttemptHistory,
    accepted_attempt_history_from_document,
)
from tools.prepare_v2_ptde_inputs import main as prepare_v2_ptde_inputs_main


def _run(*arguments: str, cwd: Path | None = None) -> None:
    subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )


def _output(*arguments: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        list(arguments),
        cwd=cwd,
        check=True,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _wheel_bytes(root: Path, name: str, version: str) -> bytes:
    path = root / f"{name}-{version}-fixture.whl"
    dist_info = f"{name}-{version}.dist-info"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{dist_info}/METADATA",
            (
                "Metadata-Version: 2.4\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "Requires-Python: >=3.12,<3.13\n"
            ),
        )
        archive.writestr(
            f"{dist_info}/WHEEL",
            (
                "Wheel-Version: 1.0\n"
                "Generator: ptde-preparation-fixture\n"
                "Root-Is-Purelib: true\n"
                "Tag: py3-none-any\n"
            ),
        )
    content = path.read_bytes()
    path.unlink()
    return content


def _production_history(
    repository_identity_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    ml_private = MLDSA87PrivateKey.generate()
    ed_private = Ed448PrivateKey.generate()
    ml_custody = DualSignatureLaneCustody(
        algorithm="ML-DSA-87",
        provider_id="external-history-ml-dsa-87",
        key_version="1",
        key_epoch=1,
        rotation_epoch=1,
        custody_class="EXTERNAL_NON_EXPORTABLE_ML_DSA_87",
        custody_reference="hsm/history/ml-dsa-87",
        signer_class=PRODUCTION,
        external_custody_admitted=True,
        custody_admission_sha512="1" * 128,
        non_exportable=True,
    )
    ed_custody = DualSignatureLaneCustody(
        algorithm="Ed448",
        provider_id="external-history-ed448",
        key_version="1",
        key_epoch=1,
        rotation_epoch=1,
        custody_class="EXTERNAL_NON_EXPORTABLE_ED448",
        custody_reference="hsm/history/ed448",
        signer_class=PRODUCTION,
        external_custody_admitted=True,
        custody_admission_sha512="2" * 128,
        non_exportable=True,
    )
    context = HybridVerificationContext(
        context_id="external-history-context",
        provider_id="external-history-provider",
        key_id="external-history-key",
        custody_class=PRODUCTION_DUAL_CUSTODY_CLASS,
        signer_class=PRODUCTION,
        purpose=HISTORY_SIGNING_PURPOSE,
        mldsa87_public_key=ml_private.public_key(),
        ed448_public_key=ed_private.public_key(),
        key_epoch=1,
        key_version="1",
        dual_custody_admission_sha512="3" * 128,
        mldsa87_custody=ml_custody,
        ed448_custody=ed_custody,
    )
    unsigned = {
        "schema_id": ACCEPTED_HISTORY_SCHEMA,
        "repository_identity_digest": repository_identity_digest,
        "history_id": "external-local-trust-history",
        "sequence": 0,
        "prior_history_digest": GENESIS,
        "live_head_digest": GENESIS,
        "records": [],
        "status": "CURRENT_LIVE_HEAD",
        "no_authority": dict(LOCAL_NO_AUTHORITY),
    }
    message = _bound_message(
        unsigned, HISTORY_SIGNING_PURPOSE, context.context_digest
    )
    public = context.public_record()
    signatures = {
        "signature_profile": HYBRID_SIGNATURE_PROFILE,
        "verification_rule": DUAL_SIGNATURE_VERIFICATION_RULE,
        "transition_policy": DUAL_SIGNATURE_TRANSITION_POLICY,
        "lane_independence_required": True,
        "context_id": context.context_id,
        "context_digest": context.context_digest,
        "provider_id": context.provider_id,
        "key_id": context.key_id,
        "custody_class": context.custody_class,
        "signer_class": context.signer_class,
        "purpose": context.purpose,
        "key_epoch": context.key_epoch,
        "key_version": context.key_version,
        "mldsa87_custody_sha512": digest(public["mldsa87_custody"]),
        "ed448_custody_sha512": digest(public["ed448_custody"]),
        "dual_custody_admission_sha512": context.dual_custody_admission_sha512,
        "mldsa87": {
            "algorithm": "ML-DSA-87",
            "fingerprint": context.mldsa87_fingerprint,
            "signature_b64": base64.b64encode(ml_private.sign(message)).decode(
                "ascii"
            ),
        },
        "ed448": {
            "algorithm": "Ed448",
            "fingerprint": context.ed448_fingerprint,
            "signature_b64": base64.b64encode(ed_private.sign(message)).decode(
                "ascii"
            ),
        },
    }
    history = {**unsigned, "signatures": signatures}
    history["history_digest"] = digest(history)
    return history, public


class PreparationFixture:
    def __init__(self, root: Path) -> None:
        located = shutil.which("git")
        if located is None:
            pytest.skip("git executable unavailable")
        assert located is not None
        self.git = str(Path(located).resolve(strict=True))
        self.git_sha512 = hashlib.sha512(Path(self.git).read_bytes()).hexdigest()
        self.root = root
        self.work = root / "work"
        self.bare = root / "objects.git"
        self.production_wheels = root / "production-wheelhouse"
        self.assurance_wheels = root / "assurance-wheelhouse"
        self.work.mkdir()
        self.production_wheels.mkdir()
        self.assurance_wheels.mkdir()
        _run(self.git, "init", str(self.work))
        _run(self.git, "-C", str(self.work), "config", "user.name", "PTDE Prep Test")
        _run(
            self.git,
            "-C",
            str(self.work),
            "config",
            "user.email",
            "ptde-prep@example.invalid",
        )
        _run(self.git, "-C", str(self.work), "config", "core.autocrlf", "false")
        _run(self.git, "-C", str(self.work), "config", "core.eol", "lf")

        self.ptde_history = AcceptedAttemptHistory(
            "external-ptde-history", 0, "0" * 128, ()
        )
        self.ptde_digest = self.ptde_history.sha512()
        self.repository_identity_digest = hashlib.sha512(
            b"externally-pinned-local-trust-repository"
        ).hexdigest()
        self.local_history, self.local_context = _production_history(
            self.repository_identity_digest
        )
        self.local_digest = self.local_history["history_digest"]
        self.context_digest = self.local_context["context_digest"]

        self._write(".gitignore", b"ignored-secret.txt\n")
        self._write("contracts/ptde/PTDE_POLICY_V1.json", policy_document_bytes())
        self._write("main.py", b"def run_sbp_lex():\n    return 'ok'\n")
        self._write(
            "sbp_lex/pipeline/runner.py",
            (
                b"def run_v2():\n    return 'v2'\n\n"
                b"def run_v2_pipeline():\n    return 'pipeline'\n"
            ),
        )
        cryptography = _wheel_bytes(root, "cryptography", "50.0.0")
        pytest_wheel = _wheel_bytes(root, "pytest", "9.1.1")
        (self.production_wheels / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            cryptography
        )
        (self.assurance_wheels / "cryptography-50.0.0-py3-none-any.whl").write_bytes(
            cryptography
        )
        (self.assurance_wheels / "pytest-9.1.1-py3-none-any.whl").write_bytes(
            pytest_wheel
        )
        self._write("requirements.txt", b"cryptography==50.0.0\n")
        production_lock = (
            "--only-binary=:all:\n"
            "--require-hashes\n\n"
            f"cryptography==50.0.0 --hash=sha256:{hashlib.sha256(cryptography).hexdigest()}\n"
        ).encode()
        assurance_lock = production_lock + (
            f"pytest==9.1.1 --hash=sha256:{hashlib.sha256(pytest_wheel).hexdigest()}\n"
        ).encode()
        self._write("requirements-production.lock.txt", production_lock)
        self._write("requirements-test.lock.txt", assurance_lock)
        lock = build_python_lock_document(
            self.work,
            production_wheelhouse=self.production_wheels,
            assurance_wheelhouse=self.assurance_wheels,
            expected_environment=GOVERNED_PYTHON_ENVIRONMENT,
            ptde_accepted_attempt_history_sequence=0,
            ptde_accepted_attempt_history_sha512=self.ptde_digest,
            local_trust_accepted_package_history_sequence=0,
            local_trust_accepted_package_history_sha512=self.local_digest,
            prior_lock_document=None,
            expected_python_dependency_prior_lock_sha512="GENESIS",
        )
        write_python_lock_document_exclusive(
            lock, self.work / "python-dependencies.lock.json"
        )
        _run(self.git, "-C", str(self.work), "add", ".")
        _run(self.git, "-C", str(self.work), "commit", "-m", "P candidate")
        self.p_oid = _output(self.git, "-C", str(self.work), "rev-parse", "HEAD")
        _run(self.git, "clone", "--bare", str(self.work), str(self.bare))

    def _write(self, relative: str, content: bytes) -> None:
        path = self.work / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def packet_arguments(self) -> dict[str, Any]:
        return {
            "candidate_oid": self.p_oid,
            "git_executable": self.git,
            "expected_git_executable_sha512": self.git_sha512,
            "ptde_accepted_attempt_history_document": (
                canonical_json_document_bytes(self.ptde_history.as_dict())
            ),
            "expected_ptde_accepted_attempt_history_sha512": self.ptde_digest,
            "local_trust_accepted_package_history_document": (
                canonical_json_document_bytes(self.local_history)
            ),
            "local_trust_history_context_document": (
                canonical_json_document_bytes(self.local_context)
            ),
            "owner_pinned_local_trust_history_context_sha512": self.context_digest,
            "expected_local_trust_repository_identity_sha512": (
                self.repository_identity_digest
            ),
            "expected_local_trust_accepted_package_history_sequence": 0,
            "expected_local_trust_accepted_package_history_sha512": (
                self.local_digest
            ),
            "expected_python_dependency_prior_lock_sha512": "GENESIS",
        }

    def packet(self) -> dict[str, Any]:
        return prepare_p_selection_packet(
            self.work, self.bare, **self.packet_arguments()
        )

    def downstream_arguments(self) -> dict[str, Any]:
        arguments = self.packet_arguments()
        arguments.pop("candidate_oid")
        return {"expected_p_oid": self.p_oid, **arguments}

    def validate_packet(
        self, packet: dict[str, Any], *, expected_p_oid: str | None = None
    ) -> dict[str, Any]:
        arguments = self.downstream_arguments()
        if expected_p_oid is not None:
            arguments["expected_p_oid"] = expected_p_oid
        return validate_p_selection_packet(
            packet,
            expected_packet_sha512=packet["packet_sha512"],
            object_database=self.bare,
            **arguments,
        )

    def push(self) -> None:
        _run(
            self.git,
            "-C",
            str(self.work),
            "push",
            str(self.bare),
            "HEAD:refs/heads/preparation",
        )

    def assignments(self, packet: dict[str, Any]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {
            name: [] for name in INVENTORY_CLASSES
        }
        paths = [
            item["path"]
            for item in packet["candidate_binding"]["p_inventory"]
        ]
        for path in paths:
            if path == "contracts/ptde/PTDE_POLICY_V1.json":
                result["contract"].append(path)
            elif path in {"main.py", "sbp_lex/pipeline/runner.py"}:
                result["source"].append(path)
            else:
                result["dependency_build"].append(path)
        for values in result.values():
            values.sort()
        return result

    @staticmethod
    def lanes() -> list[dict[str, Any]]:
        environment = ["CI"]
        return [
            {
                "lane_id": "unit",
                "order": 1,
                "executable_id": "python",
                "argv": ["python", "-m", "pytest"],
                "cwd_rule": "P_ROOT",
                "environment_name_allowlist": environment,
                "environment_name_allowlist_sha512": canonical_sha512(environment),
                "timeout_seconds": 600,
                "expected_exit_codes": [0],
                "stdout_contract": {
                    "capture": "FULL_BYTES",
                    "relative_path": "unit/stdout.bin",
                    "maximum_byte_count": 1_048_576,
                },
                "stderr_contract": {
                    "capture": "FULL_BYTES",
                    "relative_path": "unit/stderr.bin",
                    "maximum_byte_count": 1_048_576,
                },
                "produced_artifact_contract": {
                    "required_relative_paths": ["unit/report.json"],
                    "optional_relative_paths": [],
                    "maximum_file_count": 1,
                    "maximum_total_byte_count": 1_048_576,
                },
            }
        ]

    @staticmethod
    def fingerprints() -> dict[str, str]:
        return {
            name: hashlib.sha512(name.encode("ascii")).hexdigest()
            for name in (
                "os_fingerprint_sha512",
                "build_fingerprint_sha512",
                "architecture_fingerprint_sha512",
                "runtime_fingerprint_sha512",
                "toolchain_fingerprint_sha512",
            )
        }


def _commit_document(
    fixture: PreparationFixture, relative: str, document: dict[str, Any], message: str
) -> str:
    path = fixture.work / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    write_canonical_document_exclusive(document, path)
    _run(fixture.git, "-C", str(fixture.work), "add", relative)
    _run(fixture.git, "-C", str(fixture.work), "commit", "-m", message)
    oid = _output(fixture.git, "-C", str(fixture.work), "rev-parse", "HEAD")
    fixture.push()
    return oid


def test_prepares_exact_non_authorizing_p_t_d_and_e_inputs(tmp_path: Path) -> None:
    fixture = PreparationFixture(tmp_path)
    packet = fixture.packet()
    assert packet["schema_id"] == P_PREPARATION_SCHEMA
    assert packet["p_selection_state"] == "NOT_SELECTED"
    assert packet["admission_state"] == "NOT_ADMITTED"
    assert packet["no_authority"] == NO_AUTHORITY
    assert packet["python_dependency_binding"]["python_lock_schema_id"].endswith(
        "/3"
    )

    profile = prepare_t_profile(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        test_profile_id="v2-preparation-profile",
        inventory_assignments=fixture.assignments(packet),
        lanes=fixture.lanes(),
        **fixture.downstream_arguments(),
    )
    t_oid = _commit_document(
        fixture, "ptde_subjects/T_TEST_BUILD_PROFILE.json", profile, "T profile"
    )
    descriptor = prepare_d_descriptor(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        t_oid=t_oid,
        campaign="campaign-preparation-1",
        external_fingerprints=fixture.fingerprints(),
        **fixture.downstream_arguments(),
    )
    assert descriptor["no_authority"] == NO_AUTHORITY
    assert descriptor["assurance_limits"]["production_admitted"] is False
    d_oid = _commit_document(
        fixture,
        "ptde_subjects/D_RUNTIME_DESCRIPTOR.json",
        descriptor,
        "D descriptor",
    )
    skeleton = prepare_e_campaign_input_skeleton(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        t_oid=t_oid,
        d_oid=d_oid,
        campaign="campaign-preparation-1",
        **fixture.downstream_arguments(),
    )
    assert skeleton["schema_id"] == E_INPUT_PREPARATION_SCHEMA
    assert skeleton["e_commit_state"] == "NOT_CREATED"
    assert skeleton["evidence_state"] == "NOT_SUPPLIED"
    assert skeleton["admission_state"] == "NOT_ADMITTED"
    assert "lane_results" not in skeleton
    assert "evidence_inventory" not in skeleton
    requirement = skeleton["lane_input_requirements"][0]
    assert requirement["committed_lane_contract"] == fixture.lanes()[0]
    assert requirement["lane_contract_sha512"] == canonical_sha512(
        fixture.lanes()[0]
    )
    assert requirement["required_transcript_schema_id"].endswith("/1")
    assert requirement["transcript_maximum_byte_count"] > 0
    assert {
        "authority_mutation_observed",
        "ledger_mutation_observed",
        "output_truncated",
        "source_mutation_observed",
        "stderr_byte_count",
        "stderr_path",
        "stdout_byte_count",
        "stdout_path",
        "transcript_sha512",
        "transcript_path",
    }.issubset(requirement["required_external_result_fields"])
    assert skeleton["fixed_manifest_bindings"]["d_commit_oid"] == d_oid

    approved = deepcopy(skeleton)
    approved["e_commit_state"] = "CREATED_AND_APPROVED"
    approved["evidence_state"] = "ACCEPTED"
    approved["admission_state"] = "ADMITTED"
    approved["assurance_limits"] = {"production_admitted": True}
    approved["skeleton_sha512"] = canonical_sha512(
        {key: value for key, value in approved.items() if key != "skeleton_sha512"}
    )
    with pytest.raises(PTDEVerificationError):
        validate_e_campaign_input_skeleton(
            approved, expected_skeleton_sha512=approved["skeleton_sha512"]
        )

    substituted = deepcopy(skeleton)
    substituted_lane = substituted["lane_input_requirements"][0][
        "committed_lane_contract"
    ]
    substituted_lane["timeout_seconds"] += 1
    substituted["lane_input_requirements"][0]["lane_contract_sha512"] = (
        canonical_sha512(substituted_lane)
    )
    substituted["skeleton_sha512"] = canonical_sha512(
        {
            key: value
            for key, value in substituted.items()
            if key != "skeleton_sha512"
        }
    )
    with pytest.raises(
        PTDEVerificationError, match="PTDE_E_INPUT_LANES_NOT_FIXED_D_BINDING"
    ):
        validate_e_campaign_input_skeleton(
            substituted,
            expected_skeleton_sha512=substituted["skeleton_sha512"],
        )


def test_p_preparation_rejects_dirty_wrong_oid_and_missing_external_inputs(
    tmp_path: Path,
) -> None:
    fixture = PreparationFixture(tmp_path)
    arguments = fixture.packet_arguments()
    scripted_git = fixture.root / "scripted-git-launcher"
    scripted_git.write_bytes(b"#!/usr/bin/env python3\nraise SystemExit(99)\n")
    scripted_arguments = dict(arguments)
    scripted_arguments["git_executable"] = str(scripted_git)
    scripted_arguments["expected_git_executable_sha512"] = hashlib.sha512(
        scripted_git.read_bytes()
    ).hexdigest()
    with pytest.raises(
        PTDEVerificationError, match="PTDE_PREPARATION_GIT_SCRIPT_REJECTED"
    ):
        prepare_p_selection_packet(
            fixture.work, fixture.bare, **scripted_arguments
        )

    (fixture.work / "untracked-critical.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(
        PTDEVerificationError, match="PTDE_PREPARATION_WORKTREE_EXTRA_FILE"
    ):
        prepare_p_selection_packet(fixture.work, fixture.bare, **arguments)
    (fixture.work / "untracked-critical.py").unlink()

    (fixture.work / "ignored-secret.txt").write_text("hidden\n", encoding="utf-8")
    with pytest.raises(
        PTDEVerificationError, match="PTDE_PREPARATION_WORKTREE_EXTRA_FILE"
    ):
        prepare_p_selection_packet(fixture.work, fixture.bare, **arguments)
    (fixture.work / "ignored-secret.txt").unlink()

    marker = fixture.root / "fsmonitor-executed.txt"
    helper = fixture.root / "hostile-fsmonitor.py"
    helper.write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    helper_command = (
        f'"{Path(sys.executable).as_posix()}" "{helper.as_posix()}"'
    )
    _run(
        fixture.git,
        "-C",
        str(fixture.work),
        "config",
        "core.fsmonitor",
        helper_command,
    )
    fixture.packet()
    assert not marker.exists()
    _run(
        fixture.git,
        "-C",
        str(fixture.work),
        "config",
        "--unset",
        "core.fsmonitor",
    )

    wrong_oid = dict(arguments)
    wrong_oid["candidate_oid"] = "0" * 40
    with pytest.raises(PTDEVerificationError):
        prepare_p_selection_packet(fixture.work, fixture.bare, **wrong_oid)

    missing_history = dict(arguments)
    missing_history["ptde_accepted_attempt_history_document"] = b""
    with pytest.raises(PTDEVerificationError):
        prepare_p_selection_packet(fixture.work, fixture.bare, **missing_history)

    missing_local_history = dict(arguments)
    missing_local_history["local_trust_accepted_package_history_document"] = b""
    with pytest.raises(PTDEVerificationError):
        prepare_p_selection_packet(
            fixture.work, fixture.bare, **missing_local_history
        )

    missing_pin = dict(arguments)
    missing_pin["owner_pinned_local_trust_history_context_sha512"] = ""
    with pytest.raises(PTDEVerificationError):
        prepare_p_selection_packet(fixture.work, fixture.bare, **missing_pin)


def test_p_preparation_requires_committed_governed_v3_lock(tmp_path: Path) -> None:
    fixture = PreparationFixture(tmp_path)
    _run(
        fixture.git,
        "-C",
        str(fixture.work),
        "rm",
        "python-dependencies.lock.json",
    )
    _run(fixture.git, "-C", str(fixture.work), "commit", "-m", "remove lock")
    fixture.p_oid = _output(
        fixture.git, "-C", str(fixture.work), "rev-parse", "HEAD"
    )
    fixture.push()
    with pytest.raises(PTDEVerificationError):
        fixture.packet()


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("python_dependency_binding", "python_inputs_sha512", "f" * 128),
        ("local_trust_history_binding", "history_id", "bad/history"),
        ("local_trust_history_binding", "history_context_digest", "e" * 128),
        ("local_trust_history_binding", "repository_identity_digest", "d" * 128),
        ("candidate_binding", "p_commit_oid", "0" * 40),
    ),
)
def test_rehashed_p_packet_cannot_substitute_recomputed_trust(
    tmp_path: Path,
    section: str,
    field: str,
    value: str,
) -> None:
    fixture = PreparationFixture(tmp_path)
    forged = fixture.packet()
    forged[section][field] = value
    forged["packet_sha512"] = canonical_sha512(
        {key: item for key, item in forged.items() if key != "packet_sha512"}
    )
    with pytest.raises(PTDEVerificationError):
        fixture.validate_packet(forged)


def test_external_malformed_history_id_and_invalid_committed_lock_fail_deep(
    tmp_path: Path,
) -> None:
    fixture = PreparationFixture(tmp_path)
    packet = fixture.packet()

    malformed_history = AcceptedAttemptHistory(
        history_id="bad/history",
        sequence=0,
        prior_history_sha512="0" * 128,
        records=(),
    )
    malformed_arguments = fixture.downstream_arguments()
    malformed_arguments["ptde_accepted_attempt_history_document"] = (
        canonical_json_document_bytes(malformed_history.as_dict())
    )
    malformed_arguments["expected_ptde_accepted_attempt_history_sha512"] = (
        malformed_history.sha512()
    )
    with pytest.raises(
        PTDEVerificationError, match="PTDE_PREPARATION_PTDE_HISTORY_ID_INVALID"
    ):
        validate_p_selection_packet(
            packet,
            expected_packet_sha512=packet["packet_sha512"],
            object_database=fixture.bare,
            **malformed_arguments,
        )

    lock_path = fixture.work / "python-dependencies.lock.json"
    invalid_lock = json.loads(lock_path.read_text(encoding="utf-8"))
    invalid_lock["schema_id"] = "sbp.lex.v2.python-dependency-lock/2"
    lock_path.write_bytes(canonical_json_document_bytes(invalid_lock))
    _run(fixture.git, "-C", str(fixture.work), "add", str(lock_path.name))
    _run(fixture.git, "-C", str(fixture.work), "commit", "-m", "invalid lock")
    invalid_p_oid = _output(
        fixture.git, "-C", str(fixture.work), "rev-parse", "HEAD"
    )
    fixture.push()
    arguments = fixture.packet_arguments()
    ptde_history = accepted_attempt_history_from_document(
        arguments["ptde_accepted_attempt_history_document"]
    )
    invalid_binding = bind_p_object(
        fixture.bare,
        p_oid=invalid_p_oid,
        expected_p_oid=invalid_p_oid,
        git_executable=fixture.git,
        expected_git_executable_sha512=fixture.git_sha512,
        ptde_accepted_attempt_history=ptde_history,
        expected_ptde_accepted_attempt_history_sha512=fixture.ptde_digest,
        expected_local_trust_accepted_package_history_sequence=0,
        expected_local_trust_accepted_package_history_sha512=(
            fixture.local_digest
        ),
        expected_python_dependency_prior_lock_sha512="GENESIS",
    )
    forged = deepcopy(packet)
    forged["candidate_binding"] = invalid_binding.document()
    forged["python_dependency_binding"] = {
        "schema_id": "sbp.lex.v2.supply-chain.python-inputs/2",
        "python_lock_schema_id": "sbp.lex.v2.python-dependency-lock/3",
        "python_lock_blob": invalid_binding.tree[
            "python-dependencies.lock.json"
        ].record(),
        "python_inputs_sha512": "f" * 128,
        "dependency_evidence_status": "COMPLETE",
    }
    forged["packet_sha512"] = canonical_sha512(
        {key: item for key, item in forged.items() if key != "packet_sha512"}
    )
    with pytest.raises(
        PTDEVerificationError,
        match="PTDE_PREPARATION_GOVERNED_PYTHON_LOCK_REQUIRED",
    ):
        fixture.validate_packet(forged, expected_p_oid=invalid_p_oid)


def test_reordered_mutated_and_self_approved_stages_fail_closed(
    tmp_path: Path,
) -> None:
    fixture = PreparationFixture(tmp_path)
    packet = fixture.packet()
    approved = deepcopy(packet)
    approved["p_selection_state"] = "SELECTED"
    approved["packet_sha512"] = canonical_sha512(
        {key: value for key, value in approved.items() if key != "packet_sha512"}
    )
    with pytest.raises(PTDEVerificationError):
        validate_p_selection_packet(
            approved,
            expected_packet_sha512=approved["packet_sha512"],
            object_database=fixture.bare,
            **fixture.downstream_arguments(),
        )

    profile = prepare_t_profile(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        test_profile_id="v2-preparation-profile",
        inventory_assignments=fixture.assignments(packet),
        lanes=fixture.lanes(),
        **fixture.downstream_arguments(),
    )
    path = fixture.work / "ptde_subjects/T_TEST_BUILD_PROFILE.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(canonical_json_document_bytes(profile))
    (fixture.work / "unexpected-stage-mutation.txt").write_text(
        "forbidden\n", encoding="utf-8"
    )
    _run(fixture.git, "-C", str(fixture.work), "add", ".")
    _run(fixture.git, "-C", str(fixture.work), "commit", "-m", "invalid T")
    invalid_t = _output(fixture.git, "-C", str(fixture.work), "rev-parse", "HEAD")
    fixture.push()
    with pytest.raises(PTDEVerificationError):
        prepare_d_descriptor(
            packet,
            fixture.bare,
            expected_p_packet_sha512=packet["packet_sha512"],
            t_oid=invalid_t,
            campaign="campaign-preparation-1",
            external_fingerprints=fixture.fingerprints(),
            **fixture.downstream_arguments(),
        )
    with pytest.raises(PTDEVerificationError):
        prepare_d_descriptor(
            packet,
            fixture.bare,
            expected_p_packet_sha512=packet["packet_sha512"],
            t_oid=fixture.p_oid,
            campaign="campaign-preparation-1",
            external_fingerprints=fixture.fingerprints(),
            **fixture.downstream_arguments(),
        )


def test_canonical_output_is_exclusive(
    tmp_path: Path,
) -> None:
    output = tmp_path / "packet.json"
    document = {"admission_state": "NOT_ADMITTED", "authority_granted": False}
    digest = write_canonical_document_exclusive(document, output)
    assert digest == hashlib.sha512(output.read_bytes()).hexdigest()
    assert output.read_bytes() == canonical_json_document_bytes(document)
    with pytest.raises(PTDEVerificationError):
        write_canonical_document_exclusive(document, output)


@pytest.mark.skipif(os.name != "nt", reason="Windows held-parent regression")
def test_windows_output_parent_swap_cannot_redirect_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "validated-parent"
    displaced = tmp_path / "validated-parent-original"
    parent.mkdir()
    output = parent / "packet.json"
    original = preparation_module._open_windows_relative_output

    def swap_then_create(parent_handle: int, leaf_name: str) -> int:
        parent.rename(displaced)
        parent.mkdir()
        return original(parent_handle, leaf_name)

    monkeypatch.setattr(
        preparation_module,
        "_open_windows_relative_output",
        swap_then_create,
    )
    with pytest.raises(PTDEVerificationError):
        write_canonical_document_exclusive(
            {"admission_state": "NOT_ADMITTED"}, output
        )
    assert not output.exists()
    assert (displaced / "packet.json").exists()


def test_e_preparation_rejects_d_descriptor_delta_mutation(tmp_path: Path) -> None:
    fixture = PreparationFixture(tmp_path)
    packet = fixture.packet()
    profile = prepare_t_profile(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        test_profile_id="v2-preparation-profile",
        inventory_assignments=fixture.assignments(packet),
        lanes=fixture.lanes(),
        **fixture.downstream_arguments(),
    )
    t_oid = _commit_document(
        fixture, "ptde_subjects/T_TEST_BUILD_PROFILE.json", profile, "T profile"
    )
    descriptor = prepare_d_descriptor(
        packet,
        fixture.bare,
        expected_p_packet_sha512=packet["packet_sha512"],
        t_oid=t_oid,
        campaign="campaign-preparation-1",
        external_fingerprints=fixture.fingerprints(),
        **fixture.downstream_arguments(),
    )
    descriptor_path = fixture.work / "ptde_subjects/D_RUNTIME_DESCRIPTOR.json"
    descriptor_path.write_bytes(canonical_json_document_bytes(descriptor))
    (fixture.work / "d-stage-source-mutation.txt").write_text(
        "forbidden\n", encoding="utf-8"
    )
    _run(fixture.git, "-C", str(fixture.work), "add", ".")
    _run(fixture.git, "-C", str(fixture.work), "commit", "-m", "invalid D")
    invalid_d = _output(fixture.git, "-C", str(fixture.work), "rev-parse", "HEAD")
    fixture.push()
    with pytest.raises(PTDEVerificationError):
        prepare_e_campaign_input_skeleton(
            packet,
            fixture.bare,
            expected_p_packet_sha512=packet["packet_sha512"],
            t_oid=t_oid,
            d_oid=invalid_d,
            campaign="campaign-preparation-1",
            **fixture.downstream_arguments(),
        )


def test_cli_reports_internal_and_persisted_digests_without_ambiguity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    fixture = PreparationFixture(tmp_path)
    ptde_history_path = tmp_path / "ptde-history.json"
    local_history_path = tmp_path / "local-history.json"
    local_context_path = tmp_path / "local-context.json"
    t_inputs_path = tmp_path / "t-inputs.json"
    fingerprints_path = tmp_path / "fingerprints.json"
    packet_for_assignments = fixture.packet()
    for path, document in (
        (ptde_history_path, fixture.ptde_history.as_dict()),
        (local_history_path, fixture.local_history),
        (local_context_path, fixture.local_context),
        (
            t_inputs_path,
            {
                "test_profile_id": "v2-cli-digest-profile",
                "inventory_assignments": fixture.assignments(
                    packet_for_assignments
                ),
                "lanes": fixture.lanes(),
            },
        ),
        (fingerprints_path, fixture.fingerprints()),
    ):
        write_canonical_document_exclusive(document, path)

    def external_arguments(*, include_expected_p_oid: bool) -> list[str]:
        result = [
            "--ptde-accepted-attempt-history",
            str(ptde_history_path),
            "--expected-ptde-accepted-attempt-history-sha512",
            fixture.ptde_digest,
            "--local-trust-accepted-package-history",
            str(local_history_path),
            "--local-trust-history-context",
            str(local_context_path),
            "--owner-pinned-local-trust-history-context-sha512",
            fixture.context_digest,
            "--expected-local-trust-repository-identity-sha512",
            fixture.repository_identity_digest,
            "--expected-local-trust-accepted-package-history-sequence",
            "0",
            "--expected-local-trust-accepted-package-history-sha512",
            fixture.local_digest,
            "--expected-python-dependency-prior-lock-sha512",
            "GENESIS",
        ]
        if include_expected_p_oid:
            result = ["--expected-p-oid", fixture.p_oid, *result]
        return result

    def common_arguments(output: Path) -> list[str]:
        return [
            "--object-database",
            str(fixture.bare),
            "--git-executable",
            fixture.git,
            "--expected-git-executable-sha512",
            fixture.git_sha512,
            "--output",
            str(output),
        ]

    def invoke(arguments: list[str]) -> tuple[int, dict[str, Any]]:
        result = prepare_v2_ptde_inputs_main(arguments)
        report = json.loads(capsys.readouterr().out)
        assert isinstance(report, dict)
        return result, report

    p_output = tmp_path / "p-packet.json"
    result, p_report = invoke(
        [
            "p-candidate",
            *common_arguments(p_output),
            "--repository",
            str(fixture.work),
            "--candidate-oid",
            fixture.p_oid,
            *external_arguments(include_expected_p_oid=False),
        ]
    )
    assert result == 0
    p_packet = json.loads(p_output.read_bytes())
    p_internal_digest = p_packet["packet_sha512"]
    p_persisted_digest = hashlib.sha512(p_output.read_bytes()).hexdigest()
    assert p_internal_digest != p_persisted_digest
    assert p_report == {
        "admission_state": "NOT_ADMITTED",
        "authority_granted": False,
        "no_authority": NO_AUTHORITY,
        "output": str(p_output),
        "p_packet_internal_sha512": p_internal_digest,
        "p_selection_state": "NOT_SELECTED",
        "persisted_output_document_sha512": p_persisted_digest,
    }

    t_output = tmp_path / "t-profile.json"
    t_arguments = [
        "t-profile",
        *common_arguments(t_output),
        *external_arguments(include_expected_p_oid=True),
        "--p-packet",
        str(p_output),
        "--expected-p-packet-sha512",
        p_internal_digest,
        "--t-inputs",
        str(t_inputs_path),
    ]
    result, t_report = invoke(t_arguments)
    assert result == 0
    assert t_report == {
        "admission_state": "NOT_ADMITTED",
        "authority_granted": False,
        "no_authority": NO_AUTHORITY,
        "output": str(t_output),
        "persisted_output_document_sha512": hashlib.sha512(
            t_output.read_bytes()
        ).hexdigest(),
        "validated_p_packet_internal_sha512": p_internal_digest,
    }

    rejected_t_output = tmp_path / "t-profile-persisted-digest.json"
    rejected_arguments = list(t_arguments)
    output_value_index = rejected_arguments.index(str(t_output))
    rejected_arguments[output_value_index] = str(rejected_t_output)
    pin_option_index = rejected_arguments.index("--expected-p-packet-sha512")
    rejected_arguments[pin_option_index + 1] = p_persisted_digest
    result, rejection = invoke(rejected_arguments)
    assert result == 2
    assert rejection == {
        "error_code": "PTDE_P_PREPARATION_PACKET_CONTRACT_INVALID"
    }
    assert not rejected_t_output.exists()

    t_profile = json.loads(t_output.read_bytes())
    t_oid = _commit_document(
        fixture,
        "ptde_subjects/T_TEST_BUILD_PROFILE.json",
        t_profile,
        "T profile from CLI",
    )
    d_output = tmp_path / "d-descriptor.json"
    result, d_report = invoke(
        [
            "d-descriptor",
            *common_arguments(d_output),
            *external_arguments(include_expected_p_oid=True),
            "--p-packet",
            str(p_output),
            "--expected-p-packet-sha512",
            p_internal_digest,
            "--t-oid",
            t_oid,
            "--campaign-id",
            "cli-digest-campaign",
            "--external-fingerprints",
            str(fingerprints_path),
        ]
    )
    assert result == 0
    assert d_report == {
        "admission_state": "NOT_ADMITTED",
        "authority_granted": False,
        "no_authority": NO_AUTHORITY,
        "output": str(d_output),
        "persisted_output_document_sha512": hashlib.sha512(
            d_output.read_bytes()
        ).hexdigest(),
        "validated_p_packet_internal_sha512": p_internal_digest,
    }

    d_descriptor = json.loads(d_output.read_bytes())
    d_oid = _commit_document(
        fixture,
        "ptde_subjects/D_RUNTIME_DESCRIPTOR.json",
        d_descriptor,
        "D descriptor from CLI",
    )
    e_output = tmp_path / "e-inputs.json"
    result, e_report = invoke(
        [
            "e-inputs",
            *common_arguments(e_output),
            *external_arguments(include_expected_p_oid=True),
            "--p-packet",
            str(p_output),
            "--expected-p-packet-sha512",
            p_internal_digest,
            "--t-oid",
            t_oid,
            "--d-oid",
            d_oid,
            "--campaign-id",
            "cli-digest-campaign",
        ]
    )
    assert result == 0
    e_inputs = json.loads(e_output.read_bytes())
    e_persisted_digest = hashlib.sha512(e_output.read_bytes()).hexdigest()
    assert e_inputs["skeleton_sha512"] != e_persisted_digest
    assert e_report == {
        "admission_state": "NOT_ADMITTED",
        "authority_granted": False,
        "e_input_skeleton_internal_sha512": e_inputs["skeleton_sha512"],
        "no_authority": NO_AUTHORITY,
        "output": str(e_output),
        "persisted_output_document_sha512": e_persisted_digest,
        "validated_p_packet_internal_sha512": p_internal_digest,
    }
