from __future__ import annotations

import base64
import importlib.metadata
import os
import platform
import sys
import sysconfig
import time
from copy import deepcopy
from dataclasses import replace
from hashlib import sha512
from pathlib import Path
from types import SimpleNamespace

import pytest

from sbp_lex.local_trust import command_evidence
from sbp_lex.local_trust.artifact import (
    LocalTrustArtifactError,
    build_signed_artifact,
    build_trusted_time_evidence,
    validate_artifact_chain,
)
from sbp_lex.local_trust.boundary_checker import check_runtime_detachment
from sbp_lex.local_trust.constants import (
    COMMAND_POLICY,
    EVIDENCE_GROUPS,
    GENESIS,
    NO_AUTHORITY,
    PRODUCTION,
    STAGE_ORDER,
)
from sbp_lex.local_trust.deployment import (
    DeploymentTrust,
    DeploymentTrustError,
    ExternalProviderAdmission,
)
from sbp_lex.local_trust.digests import digest
from sbp_lex.local_trust.history import (
    AcceptedHistoryError,
    advance_accepted_package_history,
    validate_accepted_package_history,
)
from sbp_lex.local_trust.paths import (
    LocalTrustPathError,
    canonical_relative_path,
    inventory_root,
    measure_file,
    strict_load_json,
    validated_root,
    write_json_exclusive,
)
from sbp_lex.local_trust.signing import (
    PRODUCTION_DUAL_CUSTODY_CLASS,
    DualSignatureLaneCustody,
    LocalTrustSignatureError,
    sign_hybrid,
    verify_hybrid,
)
from sbp_lex.local_trust.toolchain_guard import (
    _executable_pin_evidence,
    _isolated_assurance_complete,
    collect_isolated_assurance_evidence,
    collect_toolchain_inventory,
)


def test_external_executable_pins_are_absent_wrong_or_exact() -> None:
    measurements = [
        {
            "tool_id": tool_id,
            "sha512": f"{ordinal:x}" * 128,
            "resolved_path": f"C:/measured/{tool_id}.exe",
            "hardlink_count": 2 if tool_id in {"cargo", "git"} else 1,
        }
        for ordinal, tool_id in enumerate(
            ("python", "cargo", "java", "alr", "git"),
            1,
        )
    ]
    absent = _executable_pin_evidence(measurements, [], None)
    assert absent["external_executable_pins_present"] is False
    assert absent["executable_pin_failures"] == [
        "EXTERNAL_EXECUTABLE_PINS_ABSENT"
    ]
    wrong = _executable_pin_evidence(
        measurements,
        [],
        {item["tool_id"]: "f" * 128 for item in measurements},
    )
    assert wrong["external_executable_pins_present"] is False
    assert wrong["executable_pin_failures"] == [
        "EXTERNAL_EXECUTABLE_PIN_MISMATCH"
    ]
    exact = _executable_pin_evidence(
        measurements,
        [],
        {item["tool_id"]: item["sha512"] for item in measurements},
    )
    assert exact["external_executable_pins_present"] is True
    assert exact["executable_pin_failures"] == []


def test_detached_canonical_sha512_matches_exact_v2_contract() -> None:
    from sbp_lex.security.integrity import canonical_integrity_hash

    values = [
        {"z": 2, "a": [True, None, "e\u0301", 1.25, -0.0]},
        {"\U0001f600": "astral", "\uffff": "bmp", "exact": 10},
    ]
    for value in values:
        assert digest(value) == canonical_integrity_hash(value)
    source = Path("sbp_lex/local_trust/digests.py").read_text(encoding="utf-8")
    assert "sbp_lex.security" not in source
    assert "sbp_lex.assurance" not in source


def test_hybrid_requires_both_exact_lanes_and_owner_pin(signers: dict) -> None:
    signer = signers["artifact"]
    context = signer.verification_context(allow_test_only=True)
    unsigned = {"payload": "evidence", "no_authority": NO_AUTHORITY}
    signatures = sign_hybrid(unsigned, signer)
    assert verify_hybrid(
        unsigned,
        signatures,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
    )
    for mutation in (
        lambda value: value.pop("ed448"),
        lambda value: value["mldsa87"].update(algorithm="ML-DSA-65"),
        lambda value: value.update(purpose="TRUSTED_MONOTONIC_CLOCK"),
        lambda value: value.update(
            signature_profile="SBP_LEX_V2_HYBRID_ML_DSA_87_ED448_V2"
        ),
        lambda value: value.update(verification_rule="ANY_LANE_SUFFICIENT"),
        lambda value: value.update(lane_independence_required=False),
        lambda value: value.update(mldsa87_custody_sha512="0" * 128),
        lambda value: value.update(ed448_custody_sha512="0" * 128),
    ):
        hostile = deepcopy(signatures)
        mutation(hostile)
        assert not verify_hybrid(
            unsigned,
            hostile,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        )
    assert not verify_hybrid(
        unsigned,
        signatures,
        trust_context=context,
        owner_pinned_context_digest="0" * 128,
    )


def test_deployment_requires_distinct_roles_and_external_providers_for_production(
    deployment_material: dict,
) -> None:
    deployment = deployment_material["deployment"]
    same_raw_keys_clock = replace(
        deployment.clock_context,
        mldsa87_public_key=deployment.artifact_context.mldsa87_public_key,
        ed448_public_key=deployment.artifact_context.ed448_public_key,
    )
    with pytest.raises(DeploymentTrustError, match="raw_public_keys_not_distinct"):
        DeploymentTrust(
            composition_class="TEST_ONLY",
            repository_identity=deployment.repository_identity,
            artifact_context=deployment.artifact_context,
            clock_context=same_raw_keys_clock,
            history_context=deployment.history_context,
            owner_pinned_artifact_context_digest=deployment.artifact_context.context_digest,
            owner_pinned_clock_context_digest=same_raw_keys_clock.context_digest,
            owner_pinned_history_context_digest=deployment.history_context.context_digest,
            expected_accepted_history_digest=deployment.expected_accepted_history_digest,
            minimum_accepted_history_sequence=0,
        )
    production_contexts = []
    contexts = (
        deployment.artifact_context,
        deployment.clock_context,
        deployment.history_context,
    )
    admission_tokens = (("1", "2", "3"), ("4", "5", "6"), ("7", "8", "9"))
    for context, (aggregate_token, ml_token, ed_token) in zip(
        contexts, admission_tokens
    ):
        production_contexts.append(
            replace(
                context,
                signer_class=PRODUCTION,
                allow_test_only=False,
                custody_class=PRODUCTION_DUAL_CUSTODY_CLASS,
                dual_custody_admission_sha512=aggregate_token * 128,
                mldsa87_custody=DualSignatureLaneCustody(
                    algorithm="ML-DSA-87",
                    provider_id=f"PRODUCTION:{context.context_id}:ML-DSA-87",
                    key_version=f"{context.key_version}:ml-dsa-87",
                    key_epoch=context.key_epoch,
                    rotation_epoch=context.key_epoch,
                    custody_class="EXTERNAL_NON_EXPORTABLE_ML_DSA_87",
                    custody_reference=f"{context.context_id}/hsm/ml-dsa-87",
                    signer_class=PRODUCTION,
                    external_custody_admitted=True,
                    custody_admission_sha512=ml_token * 128,
                    non_exportable=True,
                ),
                ed448_custody=DualSignatureLaneCustody(
                    algorithm="Ed448",
                    provider_id=f"PRODUCTION:{context.context_id}:ED448",
                    key_version=f"{context.key_version}:ed448",
                    key_epoch=context.key_epoch,
                    rotation_epoch=context.key_epoch,
                    custody_class="EXTERNAL_NON_EXPORTABLE_ED448",
                    custody_reference=f"{context.context_id}/hsm/ed448",
                    signer_class=PRODUCTION,
                    external_custody_admitted=True,
                    custody_admission_sha512=ed_token * 128,
                    non_exportable=True,
                ),
            )
        )
    with pytest.raises(
        LocalTrustSignatureError, match="production_dual_custody_not_admitted"
    ):
        replace(production_contexts[0], custody_class="SINGLE_SHARED_CUSTODY")
    with pytest.raises(DeploymentTrustError, match="production_external_providers_required"):
        DeploymentTrust(
            composition_class=PRODUCTION,
            repository_identity=deployment.repository_identity,
            artifact_context=production_contexts[0],
            clock_context=production_contexts[1],
            history_context=production_contexts[2],
            owner_pinned_artifact_context_digest=production_contexts[0].context_digest,
            owner_pinned_clock_context_digest=production_contexts[1].context_digest,
            owner_pinned_history_context_digest=production_contexts[2].context_digest,
            expected_accepted_history_digest=deployment.expected_accepted_history_digest,
            minimum_accepted_history_sequence=0,
        )
    admission = ExternalProviderAdmission(
        trust_custody_attestation_sha512="a" * 128,
        trusted_clock_attestation_sha512="b" * 128,
        durable_history_attestation_sha512="c" * 128,
        admission_record_sha512="d" * 128,
    )
    with pytest.raises(DeploymentTrustError, match="production_provider_integration_not_implemented"):
        DeploymentTrust(
            composition_class=PRODUCTION,
            repository_identity=deployment.repository_identity,
            artifact_context=production_contexts[0],
            clock_context=production_contexts[1],
            history_context=production_contexts[2],
            owner_pinned_artifact_context_digest=production_contexts[0].context_digest,
            owner_pinned_clock_context_digest=production_contexts[1].context_digest,
            owner_pinned_history_context_digest=production_contexts[2].context_digest,
            expected_accepted_history_digest=deployment.expected_accepted_history_digest,
            minimum_accepted_history_sequence=0,
            external_provider_admission=admission,
        )


def test_independent_clock_chain_is_strictly_monotonic(signers: dict) -> None:
    artifact_signer = signers["artifact"]
    clock_signer = signers["clock"]
    artifact_context = artifact_signer.verification_context(allow_test_only=True)
    clock_context = clock_signer.verification_context(allow_test_only=True)
    first_time = build_trusted_time_evidence(
        signer=clock_signer, observed_at_ms=1000, time_sequence=1
    )
    first = build_signed_artifact(
        stage="manifest",
        payload={"status": "PASS"},
        signer=artifact_signer,
        prior_artifact_digest=GENESIS,
        time_evidence=first_time,
    )
    second_time = build_trusted_time_evidence(
        signer=clock_signer,
        observed_at_ms=1001,
        time_sequence=2,
        prior_time_digest=first_time["time_evidence_digest"],
    )
    second = build_signed_artifact(
        stage="execution_envelope",
        payload={"status": "PASS"},
        signer=artifact_signer,
        prior_artifact_digest=first["artifact_digest"],
        time_evidence=second_time,
    )
    result = validate_artifact_chain(
        [first, second],
        trust_context=artifact_context,
        owner_pinned_context_digest=artifact_context.context_digest,
        clock_trust_context=clock_context,
        owner_pinned_clock_context_digest=clock_context.context_digest,
        expected_stages=("manifest", "execution_envelope"),
    )
    assert result["status"] == "PASS"
    rollback = deepcopy(second)
    rollback["time_evidence"]["observed_at_ms"] = 1000
    assert validate_artifact_chain(
        [first, rollback],
        trust_context=artifact_context,
        owner_pinned_context_digest=artifact_context.context_digest,
        clock_trust_context=clock_context,
        owner_pinned_clock_context_digest=clock_context.context_digest,
        expected_stages=("manifest", "execution_envelope"),
    )["status"] == "FAIL"
    with pytest.raises(LocalTrustArtifactError, match="trusted_time_signer_purpose_invalid"):
        build_trusted_time_evidence(
            signer=artifact_signer, observed_at_ms=1, time_sequence=1
        )


def test_history_rejects_rollback_replay_and_predecessor_tamper(
    deployment_material: dict,
    signers: dict,
) -> None:
    history = deployment_material["history"]
    deployment = deployment_material["deployment"]
    context = deployment.history_context
    validated = validate_accepted_package_history(
        history,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        expected_history_digest=history["history_digest"],
        minimum_sequence=0,
    )
    assert validated["status"] == "PASS"
    advanced = advance_accepted_package_history(
        history,
        package_digest="1" * 128,
        chain_head_digest="2" * 128,
        time_head_digest="3" * 128,
        signer=signers["history"],
        prior_trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        expected_prior_history_digest=history["history_digest"],
    )
    assert validate_accepted_package_history(
        advanced,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        expected_history_digest=advanced["history_digest"],
        minimum_sequence=1,
    )["status"] == "PASS"
    assert validate_accepted_package_history(
        history,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        expected_history_digest=advanced["history_digest"],
        minimum_sequence=1,
    )["status"] == "FAIL"
    hostile = deepcopy(advanced)
    hostile["records"][0]["prior_package_digest"] = "4" * 128
    assert validate_accepted_package_history(
        hostile,
        repository_identity_digest=deployment.repository_identity.identity_digest,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        expected_history_digest=advanced["history_digest"],
        minimum_sequence=1,
    )["status"] == "FAIL"
    with pytest.raises(AcceptedHistoryError, match="prior_history_not_current_or_valid"):
        advance_accepted_package_history(
            hostile,
            package_digest="5" * 128,
            chain_head_digest="6" * 128,
            time_head_digest="7" * 128,
            signer=signers["history"],
            prior_trust_context=context,
            owner_pinned_context_digest=context.context_digest,
            expected_prior_history_digest=advanced["history_digest"],
        )


@pytest.mark.parametrize(
    "path",
    ["../escape", "a\\b", "file:stream", "CON", "name.", "name ", "/absolute"],
)
def test_hostile_paths_are_rejected(path: str) -> None:
    with pytest.raises(LocalTrustPathError):
        canonical_relative_path(path)


def test_hardlink_casefold_and_immutable_receipt_controls(tmp_path: Path) -> None:
    root = validated_root(tmp_path)
    source = tmp_path / "source.txt"
    source.write_bytes(b"evidence")
    hardlink = tmp_path / "hardlink.txt"
    os.link(source, hardlink)
    with pytest.raises(LocalTrustPathError, match="hard_link"):
        measure_file(root, "source.txt")
    receipt = write_json_exclusive({"status": "PASS"}, tmp_path / "receipt.json")
    assert strict_load_json(receipt) == {"status": "PASS"}
    with pytest.raises(LocalTrustPathError, match="already_exists"):
        write_json_exclusive({"status": "FAIL"}, receipt)
    noncanonical = tmp_path / "noncanonical.json"
    noncanonical.write_bytes(b'{"z": 1}\n')
    with pytest.raises(LocalTrustPathError, match="not_canonical"):
        strict_load_json(noncanonical)
    symlink = tmp_path / "symlink.txt"
    try:
        symlink.symlink_to(noncanonical)
    except OSError:
        pass
    else:
        with pytest.raises(LocalTrustPathError, match="symlink_or_reparse"):
            measure_file(root, "symlink.txt")
    mixed_case = tmp_path / "MixedCase.txt"
    mixed_case.write_bytes(b"case")
    with pytest.raises(LocalTrustPathError, match="case"):
        measure_file(root, "mixedcase.txt")
    if os.name != "nt":
        (tmp_path / "Case").mkdir()
        (tmp_path / "case").mkdir()
        with pytest.raises(LocalTrustPathError, match="casefold"):
            inventory_root(root, "Case")


def test_repository_root_alias_is_rejected_before_cli_validation(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    alias = tmp_path / "repository-alias"
    try:
        alias.symlink_to(repository, target_is_directory=True)
    except OSError:
        pass
    else:
        with pytest.raises(LocalTrustPathError, match="symlink_or_reparse"):
            validated_root(alias)

    cli_source = Path("sbp_lex/local_trust/cli.py").read_text(encoding="utf-8")
    assert "Path(args.repository_root).resolve()" not in cli_source


def test_command_capture_retains_full_bytes_and_fails_closed_on_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = ("{python}", "-c", "import sys;sys.stdout.buffer.write(b'abc')")
    monkeypatch.setattr(command_evidence, "COMMAND_POLICY", (("focused", arguments, True),))
    command = command_evidence.resolved_command_policy()[0]
    result = command_evidence.capture_command(tmp_path, command, timeout_seconds=10)
    assert result["status"] == "COMMAND_PASS"
    assert result["shell_used"] is False
    assert base64.b64decode(result["stdout_b64"]) == b"abc"
    assert command_evidence.validate_full_byte_transcript(result)
    monkeypatch.setattr(command_evidence, "MAX_COMMAND_OUTPUT_BYTES", 16)
    overflow_arguments = ("{python}", "-c", "import sys;sys.stdout.buffer.write(b'x'*4096)")
    monkeypatch.setattr(command_evidence, "COMMAND_POLICY", (("overflow", overflow_arguments, True),))
    overflow_command = command_evidence.resolved_command_policy()[0]
    overflow = command_evidence.capture_command(tmp_path, overflow_command, timeout_seconds=10)
    assert overflow["status"] == "COMMAND_OUTPUT_LIMIT"
    assert overflow["output_truncated"] is True
    assert not command_evidence.validate_full_byte_transcript(overflow)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_command_timeout_terminates_the_entire_windows_process_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = tmp_path / "surviving-child.txt"
    child = (
        "import pathlib,time;time.sleep(2);"
        f"pathlib.Path({str(marker)!r}).write_text('survived',encoding='utf-8')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        "time.sleep(10)"
    )
    arguments = ("{python}", "-c", parent)
    monkeypatch.setattr(command_evidence, "COMMAND_POLICY", (("tree_timeout", arguments, True),))
    result = command_evidence.capture_command(
        tmp_path,
        command_evidence.resolved_command_policy()[0],
        timeout_seconds=1,
    )
    assert result["status"] == "COMMAND_TIMEOUT"
    time.sleep(3)
    assert not marker.exists()
    repository_source = Path("sbp_lex/local_trust/repository.py").read_text(encoding="utf-8")
    assert "_WindowsCommandJob(process)" in repository_source
    assert "creationflags=_windows_creation_flags()" in repository_source
    assert "_terminate(process, windows_job)" in repository_source


def test_present_tested_but_inactive_requires_source_log_and_status() -> None:
    files = [
        {"path": "hybrid_signature_rust/src/lib.rs", "sha512": "1" * 128},
        {"path": "independent_verifier_rust/src/lib.rs", "sha512": "1" * 128},
        {"path": "polyglot/rust/v2_assurance_kernel/src/lib.rs", "sha512": "1" * 128},
        {"path": "rust_authority_service/src/lib.rs", "sha512": "1" * 128},
        {"path": "security_core/src/lib.rs", "sha512": "1" * 128},
        {"path": "trusted_core_rust/src/lib.rs", "sha512": "1" * 128},
        {"path": "wire_protocol/rust/src/lib.rs", "sha512": "1" * 128},
        {"path": "wire_protocol/v2/rust/src/lib.rs", "sha512": "1" * 128},
        {"path": "docs/security/RUST_TCB_AND_TLA_VALIDATION.md", "sha512": "2" * 128},
        {"path": "formal/tla/SBPLEXV2.tla", "sha512": "3" * 128},
        {"path": "formal/SBPLexAuthority.cfg", "sha512": "3" * 128},
        {"path": "formal/SBPLexAuthority.tla", "sha512": "3" * 128},
        {"path": "formal/check_model.py", "sha512": "3" * 128},
        {"path": "formal/README.md", "sha512": "4" * 128},
        {"path": "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md", "sha512": "4" * 128},
        {"path": "docs/validation/V2_CANONICAL_STATUS.md", "sha512": "4" * 128},
        {"path": "spark_safety_monitor/src/spark_safety_monitor.adb", "sha512": "5" * 128},
        {"path": "spark_safety_monitor/spark_safety_monitor.gpr", "sha512": "5" * 128},
        {"path": "spark_safety_monitor/tools/run_harness.py", "sha512": "5" * 128},
    ]
    empty_sha512 = sha512(b"").hexdigest()
    commands = [
        {
            "command_id": command_id,
            "status": "COMMAND_PASS",
            "exit_code": 0,
            "stdout_b64": "",
            "stdout_bytes": 0,
            "stdout_sha512": empty_sha512,
            "stdout_full_bytes": True,
            "stderr_b64": "",
            "stderr_bytes": 0,
            "stderr_sha512": empty_sha512,
            "stderr_full_bytes": True,
            "output_truncated": False,
            "shell_used": False,
            "timed_out": False,
        }
        for command_id in (
            command[0]
            for command in COMMAND_POLICY
            if command[0].startswith("rust_")
            or command[0].startswith("formal_")
            or command[0].startswith("spark_")
        )
    ]
    manifest = {"payload": {"evidence_inventory": {"files": files}}}
    envelope = {"payload": {"command_results": commands}}
    proofs = collect_isolated_assurance_evidence(manifest, envelope)
    validation_contracts = next(
        group for group in EVIDENCE_GROUPS
        if group.get("group_id") == "validation_contracts"
    )
    assert "evidence/v2/spark-proof-evidence.json" not in validation_contracts["paths"]
    assert [item["component"] for item in proofs] == [
        "RUST_ALL_CRATES",
        "TLA_ALL_FORMAL_MODELS",
        "PYTHON_FORMAL_EXPLORER",
        "SPARK_SAFETY_MONITOR",
    ]
    assert all(
        item["source_evidence"]
        and item["native_command_transcript_evidence"]
        and item["status_evidence"]
        and item["classification"] == "PRESENT_TESTED_BUT_INACTIVE"
        and item["runtime_attachment"] == "NONE"
        for item in proofs
    )
    assert _isolated_assurance_complete(proofs) is True
    spark_proof = next(
        item for item in proofs if item["component"] == "SPARK_SAFETY_MONITOR"
    )
    assert {
        item["path"] for item in spark_proof["status_evidence"]
    } == {
        "docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md",
        "docs/validation/V2_CANONICAL_STATUS.md",
    }
    failed_commands = deepcopy(commands)
    failed_commands[0]["status"] = "COMMAND_FAIL"
    failed_proofs = collect_isolated_assurance_evidence(
        manifest, {"payload": {"command_results": failed_commands}}
    )
    assert _isolated_assurance_complete(failed_proofs) is False
    truncated_commands = deepcopy(commands)
    truncated_commands[1]["stdout_full_bytes"] = False
    truncated_commands[1]["output_truncated"] = True
    truncated_proofs = collect_isolated_assurance_evidence(
        manifest, {"payload": {"command_results": truncated_commands}}
    )
    assert _isolated_assurance_complete(truncated_proofs) is False
    duplicate_commands = [*commands, deepcopy(commands[2])]
    duplicate_proofs = collect_isolated_assurance_evidence(
        manifest, {"payload": {"command_results": duplicate_commands}}
    )
    assert _isolated_assurance_complete(duplicate_proofs) is False
    missing_logs = collect_isolated_assurance_evidence(manifest, {"payload": {"command_results": []}})
    assert all(item["native_command_transcript_evidence"] == [] for item in missing_logs)


def test_python_dependency_lock_is_distinct_and_host_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_history_digest = "a" * 128
    monkeypatch.setattr(
        importlib.metadata,
        "distributions",
        lambda: [
            SimpleNamespace(metadata={"Name": "cryptography"}, version="50.0.0"),
            SimpleNamespace(metadata={"Name": "pip"}, version="25.2"),
            SimpleNamespace(metadata={"Name": "pytest"}, version="9.1.1"),
        ],
    )
    requirements = [{
        "identity": "cryptography",
        "version": "50.0.0",
        "source_requirement": "cryptography==50.0.0",
    }]
    (tmp_path / "requirements.txt").write_text(
        "cryptography==50.0.0\n", encoding="utf-8", newline=""
    )
    production_hash_lock = (
        "--only-binary=:all:\n--require-hashes\n"
        "cryptography==50.0.0 --hash=sha256:" + "1" * 64 + "\n"
    ).encode()
    assurance_hash_lock = (
        "--only-binary=:all:\n--require-hashes\n"
        "cryptography==50.0.0 --hash=sha256:" + "1" * 64 + "\n"
        "pytest==9.1.1 --hash=sha256:" + "2" * 64 + "\n"
    ).encode()
    (tmp_path / "requirements-production.lock.txt").write_bytes(
        production_hash_lock
    )
    (tmp_path / "requirements-test.lock.txt").write_bytes(
        assurance_hash_lock
    )
    lock_document = {
        "schema_id": "sbp.lex.v2.python-dependency-lock/2",
        "lock_sequence": 1,
        "prior_lock_sha512": "GENESIS",
        "requirements_sha512": digest(requirements),
        "production_hash_lock_sha512": sha512(production_hash_lock).hexdigest(),
        "assurance_hash_lock_sha512": sha512(assurance_hash_lock).hexdigest(),
        "target_environment": {
            "implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
            "abi_tag": sys.implementation.cache_tag,
            "platform_tag": sysconfig.get_platform(),
            "installed_scope": "assurance",
        },
        "rollback_guard": {
            "accepted_attempt_history_sequence": 0,
            "accepted_attempt_history_sha512": expected_history_digest,
        },
        "packages": [{
            "name": "cryptography",
            "version": "50.0.0",
            "hashes": ["sha256:" + "1" * 64],
            "scopes": ["assurance", "production"],
            "direct_scopes": ["assurance", "production"],
            "dependencies": [],
        }, {
            "name": "pytest",
            "version": "9.1.1",
            "hashes": ["sha256:" + "2" * 64],
            "scopes": ["assurance"],
            "direct_scopes": ["assurance"],
            "dependencies": [],
        }],
    }
    write_json_exclusive(lock_document, tmp_path / "python-dependencies.lock.json")
    unbound = collect_toolchain_inventory(tmp_path.resolve())
    assert unbound["python_dependency_evidence"]["dependency_evidence_status"] == "INCOMPLETE"
    assert "PYTHON_LOCK_ROLLBACK_GUARD_INVALID" in unbound["python_dependency_evidence"]["lock_failures"]
    inventory = collect_toolchain_inventory(
        tmp_path.resolve(),
        expected_accepted_history_sequence=0,
        expected_accepted_history_digest=expected_history_digest,
    )
    python_evidence = inventory["python_dependency_evidence"]
    assert python_evidence["dependency_evidence_status"] == "COMPLETE"
    assert python_evidence["authority_granted"] is False
    assert python_evidence["runtime_attachment"] == "NONE"
    assert inventory["bootstrap_python_tooling"] == [
        {"name": "pip", "version": "25.2"}
    ]
    assert (
        inventory["bootstrap_python_tooling_classification"]
        == "NON_RUNTIME_INSTALL_TOOLING"
    )
    assert "requirements.txt" not in [item["path"] for item in inventory["dependency_locks"]]
    assert "python-dependencies.lock.json" in [
        item["path"] for item in inventory["dependency_locks"]
    ]
    monkeypatch.setattr(
        importlib.metadata,
        "distributions",
        lambda: [
            SimpleNamespace(metadata={"Name": "cryptography"}, version="50.0.0"),
            SimpleNamespace(metadata={"Name": "pip"}, version="25.2"),
            SimpleNamespace(metadata={"Name": "pytest"}, version="9.1.1"),
            SimpleNamespace(metadata={"Name": "unexpected"}, version="1.0.0"),
        ],
    )
    mismatch = collect_toolchain_inventory(
        tmp_path.resolve(),
        expected_accepted_history_sequence=0,
        expected_accepted_history_digest=expected_history_digest,
    )["python_dependency_evidence"]
    assert mismatch["dependency_evidence_status"] == "INCOMPLETE"
    assert "PYTHON_INSTALLED_PACKAGES_LOCK_MISMATCH_OR_EXTRA" in mismatch["lock_failures"]
    wrong_history = collect_toolchain_inventory(
        tmp_path.resolve(),
        expected_accepted_history_sequence=0,
        expected_accepted_history_digest="b" * 128,
    )["python_dependency_evidence"]
    assert wrong_history["dependency_evidence_status"] == "INCOMPLETE"
    assert "PYTHON_LOCK_ROLLBACK_GUARD_INVALID" in wrong_history["lock_failures"]
    cross_contaminated = deepcopy(lock_document)
    cross_contaminated["packages"][1]["scopes"] = ["assurance", "production"]
    (tmp_path / "python-dependencies.lock.json").unlink()
    write_json_exclusive(
        cross_contaminated,
        tmp_path / "python-dependencies.lock.json",
    )
    cross_contamination = collect_toolchain_inventory(
        tmp_path.resolve(),
        expected_accepted_history_sequence=0,
        expected_accepted_history_digest=expected_history_digest,
    )["python_dependency_evidence"]
    assert cross_contamination["dependency_evidence_status"] == "INCOMPLETE"
    assert "PYTHON_LOCK_SCOPE_CLOSURE_MISMATCH" in cross_contamination["lock_failures"]


def test_unpinned_requirements_and_missing_python_lock_fail_closed(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "fastapi\nuvicorn\n", encoding="utf-8", newline=""
    )
    hash_lock = (
        "--only-binary=:all:\n--require-hashes\n"
        "cryptography==50.0.0 --hash=sha256:" + "1" * 64 + "\n"
    )
    (tmp_path / "requirements-production.lock.txt").write_text(
        hash_lock, encoding="utf-8", newline=""
    )
    (tmp_path / "requirements-test.lock.txt").write_text(
        hash_lock, encoding="utf-8", newline=""
    )
    inventory = collect_toolchain_inventory(tmp_path.resolve())
    evidence = inventory["python_dependency_evidence"]
    assert evidence["requirements_status"] == "INVALID_OR_UNPINNED"
    assert evidence["lock_status"] == "COMMITTED_LOCK_MISSING"
    assert evidence["dependency_evidence_status"] == "INCOMPLETE"
    assert "python-dependencies.lock.json" in inventory["missing_dependency_locks"]


def test_stage_order_detachment_and_no_cli_admission() -> None:
    assert STAGE_ORDER == (
        "manifest", "execution_envelope", "evidence_chain", "regression_matrix",
        "constitutional_gates", "toolchain_guard", "capstone", "release_integrity",
        "adversarial_harness", "university_dossier",
    )
    assert check_runtime_detachment(Path.cwd())["status"] == "PASS"
    cli_source = Path("sbp_lex/local_trust/cli.py").read_text(encoding="utf-8")
    assert 'add_parser("build")' not in cli_source
    assert 'add_parser("admit")' not in cli_source
    package_source = Path("sbp_lex/local_trust/pipeline.py").read_text(encoding="utf-8")
    assert "public_trust_context" not in package_source
    assert "owner_pin_must_be_distributed_out_of_band" not in package_source
