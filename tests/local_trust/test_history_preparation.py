from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.local_trust.constants import (
    ACCEPTED_HISTORY_SCHEMA,
    GENESIS,
    HISTORY_SIGNING_PURPOSE,
    PRODUCTION,
    TEST_ONLY,
)
from sbp_lex.local_trust.constants import (
    NO_AUTHORITY as LOCAL_NO_AUTHORITY,
)
from sbp_lex.local_trust.digests import digest
from sbp_lex.local_trust.history_preparation import (
    EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED,
    LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA,
    NOT_A_VALID_HISTORY,
    NOT_ADMITTED,
    NOT_INDEPENDENTLY_PINNED,
    OWNER_ACTION_REQUIRED,
    PRODUCTION_CUSTODY_METADATA_SCHEMA,
    PTDE_HISTORY_PREPARATION_SCHEMA,
    UNSIGNED,
    prepare_local_trust_genesis_signing_request,
    prepare_local_trust_genesis_signing_request_from_files,
    prepare_ptde_genesis_history,
    validate_local_trust_genesis_signing_request,
    validate_ptde_genesis_preparation,
    write_history_preparation_document_exclusive,
)
from sbp_lex.local_trust.signing import (
    PRODUCTION_DUAL_CUSTODY_CLASS,
    DualSignatureLaneCustody,
    HybridSigningContext,
    HybridVerificationContext,
)
from sbp_ptde.canonical import canonical_json_document_bytes, canonical_sha512
from sbp_ptde.constants import MAX_JSON_DOCUMENT_BYTES
from sbp_ptde.constants import NO_AUTHORITY as PTDE_NO_AUTHORITY
from sbp_ptde.errors import PTDEVerificationError
from sbp_ptde.trust import (
    ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID,
    GENESIS_SHA512,
    accepted_attempt_history_from_document,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPOSITORY_ROOT / "tools" / "prepare_v2_history_inputs.py"
REPOSITORY_IDENTITY = "a" * 128


def _custody_metadata(context_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_id": PRODUCTION_CUSTODY_METADATA_SCHEMA,
        "verification_context_sha512": context_record["context_digest"],
        "custody_class": context_record["custody_class"],
        "dual_custody_admission_sha512": context_record[
            "dual_custody_admission_sha512"
        ],
        "mldsa87_custody": deepcopy(context_record["mldsa87_custody"]),
        "ed448_custody": deepcopy(context_record["ed448_custody"]),
        "no_authority": dict(LOCAL_NO_AUTHORITY),
    }


def _production_inputs(
    *, ml_custody_class: str = "EXTERNAL_NON_EXPORTABLE_ML_DSA_87"
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    ml_private = MLDSA87PrivateKey.generate()
    ed_private = Ed448PrivateKey.generate()
    ml_custody = DualSignatureLaneCustody(
        algorithm="ML-DSA-87",
        provider_id="external-history-ml-dsa-87",
        key_version="1",
        key_epoch=1,
        rotation_epoch=1,
        custody_class=ml_custody_class,
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
    context_record = context.public_record()
    metadata = _custody_metadata(context_record)
    return (
        context_record,
        metadata,
        context.context_digest,
        canonical_sha512(metadata),
    )


@pytest.fixture(scope="module")
def production_inputs() -> tuple[dict[str, Any], dict[str, Any], str, str]:
    return _production_inputs()


def _prepare_request(
    inputs: tuple[dict[str, Any], dict[str, Any], str, str]
) -> dict[str, Any]:
    context, custody, context_pin, custody_pin = inputs
    return prepare_local_trust_genesis_signing_request(
        repository_identity_digest=REPOSITORY_IDENTITY,
        history_id="external-local-trust-history",
        verification_context_record=context,
        owner_pinned_verification_context_sha512=context_pin,
        production_custody_metadata=custody,
        owner_pinned_production_custody_metadata_sha512=custody_pin,
    )


def _run_ptde_genesis_cli(
    envelope_output: Path,
    raw_history_output: Path,
    *,
    history_id: str = "owner-cli-ptde-history",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "ptde-genesis",
            "--history-id",
            history_id,
            "--output",
            str(envelope_output),
            "--raw-history-output",
            str(raw_history_output),
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_ptde_genesis_is_unsigned_unpinned_and_owner_action_only(
    tmp_path: Path,
) -> None:
    document = prepare_ptde_genesis_history("owner-supplied-ptde-history")

    assert set(document) == {
        "schema_id",
        "preparation_state",
        "pin_state",
        "signature_state",
        "admission_state",
        "accepted_attempt_history",
        "accepted_attempt_history_sha512",
        "no_authority",
    }
    assert document["schema_id"] == PTDE_HISTORY_PREPARATION_SCHEMA
    assert document["preparation_state"] == OWNER_ACTION_REQUIRED
    assert document["pin_state"] == NOT_INDEPENDENTLY_PINNED
    assert document["signature_state"] == UNSIGNED
    assert document["admission_state"] == NOT_ADMITTED
    assert document["no_authority"] == PTDE_NO_AUTHORITY
    snapshot = document["accepted_attempt_history"]
    assert snapshot == {
        "history_id": "owner-supplied-ptde-history",
        "no_authority": PTDE_NO_AUTHORITY,
        "prior_history_sha512": GENESIS_SHA512,
        "records": [],
        "schema_id": ACCEPTED_ATTEMPT_HISTORY_SCHEMA_ID,
        "sequence": 0,
    }
    parsed = accepted_attempt_history_from_document(
        canonical_json_document_bytes(snapshot)
    )
    assert parsed.sequence == 0
    assert parsed.records == ()
    assert parsed.sha512() == document["accepted_attempt_history_sha512"]
    assert validate_ptde_genesis_preparation(document) == document

    output = (tmp_path / "ptde-history-preparation.json").resolve()
    output_digest = write_history_preparation_document_exclusive(document, output)
    assert output_digest == hashlib.sha512(output.read_bytes()).hexdigest()
    assert output.read_bytes() == canonical_json_document_bytes(document)
    before = output.read_bytes()
    with pytest.raises(PTDEVerificationError):
        write_history_preparation_document_exclusive(document, output)
    assert output.read_bytes() == before


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("preparation_state", "COMPLETE"),
        ("pin_state", "INDEPENDENTLY_PINNED"),
        ("signature_state", "SIGNED"),
        ("admission_state", "ADMITTED"),
    ),
)
def test_ptde_preparation_rejects_self_approval(field: str, value: str) -> None:
    document = prepare_ptde_genesis_history("owner-ptde-history")
    document[field] = value
    with pytest.raises(PTDEVerificationError):
        validate_ptde_genesis_preparation(document)


@pytest.mark.parametrize("history_id", ("", "TEST_ONLY", "bad/history"))
def test_ptde_preparation_requires_valid_explicit_owner_history_id(
    history_id: str,
) -> None:
    with pytest.raises(PTDEVerificationError):
        prepare_ptde_genesis_history(history_id)


def test_local_request_is_exact_unsigned_and_not_a_history(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    tmp_path: Path,
) -> None:
    document = _prepare_request(production_inputs)

    assert document["schema_id"] == LOCAL_TRUST_HISTORY_SIGNING_REQUEST_SCHEMA
    assert document["request_state"] == EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED
    assert document["signature_state"] == UNSIGNED
    assert document["history_validation_state"] == NOT_A_VALID_HISTORY
    assert document["admission_state"] == NOT_ADMITTED
    assert document["no_authority"] == LOCAL_NO_AUTHORITY
    assert document["signing_purpose"] == HISTORY_SIGNING_PURPOSE
    unsigned = document["unsigned_history"]
    assert unsigned == {
        "schema_id": ACCEPTED_HISTORY_SCHEMA,
        "repository_identity_digest": REPOSITORY_IDENTITY,
        "history_id": "external-local-trust-history",
        "sequence": 0,
        "prior_history_digest": GENESIS,
        "live_head_digest": GENESIS,
        "records": [],
        "status": "CURRENT_LIVE_HEAD",
        "no_authority": LOCAL_NO_AUTHORITY,
    }
    assert "signatures" not in unsigned
    assert "history_digest" not in unsigned
    encoded_document = canonical_json_document_bytes(document).lower()
    assert b"private" not in encoded_document
    assert b"signature_b64" not in encoded_document
    assert document["unsigned_history_sha512"] == canonical_sha512(unsigned)
    assert validate_local_trust_genesis_signing_request(document) == document

    output = (tmp_path / "local-history-signing-request.json").resolve()
    digest_value = write_history_preparation_document_exclusive(document, output)
    assert digest_value == hashlib.sha512(output.read_bytes()).hexdigest()
    assert output.read_bytes() == canonical_json_document_bytes(document)


def test_local_request_rejects_missing_and_mismatched_inputs(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
) -> None:
    context, custody, context_pin, custody_pin = production_inputs
    common: dict[str, Any] = {
        "repository_identity_digest": REPOSITORY_IDENTITY,
        "history_id": "external-local-trust-history",
        "verification_context_record": context,
        "owner_pinned_verification_context_sha512": context_pin,
        "production_custody_metadata": custody,
        "owner_pinned_production_custody_metadata_sha512": custody_pin,
    }
    mutations: tuple[dict[str, Any], ...] = (
        {"repository_identity_digest": ""},
        {"history_id": ""},
        {"verification_context_record": {}},
        {"owner_pinned_verification_context_sha512": "4" * 128},
        {"production_custody_metadata": {}},
        {"owner_pinned_production_custody_metadata_sha512": "5" * 128},
        {
            "owner_pinned_production_custody_metadata_sha512": context_pin,
        },
    )
    for mutation in mutations:
        with pytest.raises(PTDEVerificationError):
            prepare_local_trust_genesis_signing_request(**{**common, **mutation})


def test_local_request_rejects_test_only_and_software_custody() -> None:
    test_signer = HybridSigningContext(
        context_id="test-history-context",
        provider_id="test-history-provider",
        key_id="test-history-key",
        custody_class="TEST_ONLY_SOFTWARE",
        signer_class=TEST_ONLY,
        purpose=HISTORY_SIGNING_PURPOSE,
        mldsa87_private_key=MLDSA87PrivateKey.generate(),
        ed448_private_key=Ed448PrivateKey.generate(),
    )
    test_context = test_signer.verification_context(
        allow_test_only=True
    ).public_record()
    test_custody = _custody_metadata(test_context)
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_record=test_context,
            owner_pinned_verification_context_sha512=test_context[
                "context_digest"
            ],
            production_custody_metadata=test_custody,
            owner_pinned_production_custody_metadata_sha512=canonical_sha512(
                test_custody
            ),
        )

    software_context, software_custody, context_pin, custody_pin = (
        _production_inputs(
            ml_custody_class="EXTERNAL_NON_EXPORTABLE_ML_DSA_87_SOFTWARE"
        )
    )
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_record=software_context,
            owner_pinned_verification_context_sha512=context_pin,
            production_custody_metadata=software_custody,
            owner_pinned_production_custody_metadata_sha512=custody_pin,
        )


def test_local_request_rejects_copied_lane_key_binding(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
) -> None:
    context, _custody, _context_pin, _custody_pin = production_inputs
    copied = deepcopy(context)
    copied["ed448_custody"]["key_id"] = copied["mldsa87_custody"]["key_id"]
    unsigned_context = dict(copied)
    unsigned_context.pop("context_digest")
    copied["context_digest"] = digest(unsigned_context)
    copied_custody = _custody_metadata(copied)
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_record=copied,
            owner_pinned_verification_context_sha512=copied["context_digest"],
            production_custody_metadata=copied_custody,
            owner_pinned_production_custody_metadata_sha512=canonical_sha512(
                copied_custody
            ),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("request_state", "SIGNATURE_COMPLETE"),
        ("signature_state", "SIGNED"),
        ("history_validation_state", "VALID"),
        ("admission_state", "ADMITTED"),
    ),
)
def test_local_request_rejects_self_approval(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    field: str,
    value: str,
) -> None:
    document = _prepare_request(production_inputs)
    document[field] = value
    with pytest.raises(PTDEVerificationError):
        validate_local_trust_genesis_signing_request(document)


def test_stable_inputs_reject_links_and_output_never_overwrites(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    tmp_path: Path,
) -> None:
    context, custody, context_pin, custody_pin = production_inputs
    context_path = (tmp_path / "context.json").resolve()
    custody_path = (tmp_path / "custody.json").resolve()
    context_path.write_bytes(canonical_json_document_bytes(context))
    custody_path.write_bytes(canonical_json_document_bytes(custody))
    request = prepare_local_trust_genesis_signing_request_from_files(
        repository_identity_digest=REPOSITORY_IDENTITY,
        history_id="external-local-trust-history",
        verification_context_path=context_path,
        owner_pinned_verification_context_sha512=context_pin,
        production_custody_metadata_path=custody_path,
        owner_pinned_production_custody_metadata_sha512=custody_pin,
    )
    assert request["signature_state"] == UNSIGNED

    hardlink = (tmp_path / "context-hardlink.json").resolve()
    os.link(context_path, hardlink)
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request_from_files(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_path=hardlink,
            owner_pinned_verification_context_sha512=context_pin,
            production_custody_metadata_path=custody_path,
            owner_pinned_production_custody_metadata_sha512=custody_pin,
        )

    sentinel = (tmp_path / "sentinel.json").resolve()
    sentinel.write_bytes(b"sentinel")
    linked_output = (tmp_path / "linked-output.json").resolve()
    os.link(sentinel, linked_output)
    with pytest.raises(PTDEVerificationError):
        write_history_preparation_document_exclusive(request, linked_output)
    assert sentinel.read_bytes() == b"sentinel"


def test_stable_input_read_is_bounded_and_missing_inputs_fail_closed(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    tmp_path: Path,
) -> None:
    _context, custody, context_pin, custody_pin = production_inputs
    custody_path = (tmp_path / "custody.json").resolve()
    custody_path.write_bytes(canonical_json_document_bytes(custody))
    oversized = (tmp_path / "oversized-context.json").resolve()
    oversized.write_bytes(b"{" + (b" " * MAX_JSON_DOCUMENT_BYTES) + b"}\n")
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request_from_files(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_path=oversized,
            owner_pinned_verification_context_sha512=context_pin,
            production_custody_metadata_path=custody_path,
            owner_pinned_production_custody_metadata_sha512=custody_pin,
        )
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request_from_files(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_path=(tmp_path / "missing-context.json").resolve(),
            owner_pinned_verification_context_sha512=context_pin,
            production_custody_metadata_path=custody_path,
            owner_pinned_production_custody_metadata_sha512=custody_pin,
        )


def test_symlinked_input_or_parent_is_rejected_when_supported(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    tmp_path: Path,
) -> None:
    context, custody, context_pin, custody_pin = production_inputs
    context_path = (tmp_path / "context.json").resolve()
    custody_path = (tmp_path / "custody.json").resolve()
    context_path.write_bytes(canonical_json_document_bytes(context))
    custody_path.write_bytes(canonical_json_document_bytes(custody))
    linked_context = tmp_path / "linked-context.json"
    try:
        linked_context.symlink_to(context_path)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(PTDEVerificationError):
        prepare_local_trust_genesis_signing_request_from_files(
            repository_identity_digest=REPOSITORY_IDENTITY,
            history_id="external-local-trust-history",
            verification_context_path=linked_context.absolute(),
            owner_pinned_verification_context_sha512=context_pin,
            production_custody_metadata_path=custody_path,
            owner_pinned_production_custody_metadata_sha512=custody_pin,
        )

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    request = _prepare_request(production_inputs)
    with pytest.raises(PTDEVerificationError):
        write_history_preparation_document_exclusive(
            request, (linked_parent / "request.json").absolute()
        )
    assert not (real_parent / "request.json").exists()


def test_cli_builds_both_preparation_documents_only(
    production_inputs: tuple[dict[str, Any], dict[str, Any], str, str],
    tmp_path: Path,
) -> None:
    context, custody, context_pin, custody_pin = production_inputs
    context_path = (tmp_path / "context.json").resolve()
    custody_path = (tmp_path / "custody.json").resolve()
    context_path.write_bytes(canonical_json_document_bytes(context))
    custody_path.write_bytes(canonical_json_document_bytes(custody))

    ptde_output = (tmp_path / "ptde-preparation.json").resolve()
    raw_ptde_output = (tmp_path / "ptde-accepted-attempt-history.json").resolve()
    ptde = _run_ptde_genesis_cli(
        ptde_output,
        raw_ptde_output,
    )
    assert ptde.returncode == 0, ptde.stderr
    ptde_status = json.loads(ptde.stdout)
    assert ptde_status["status"] == OWNER_ACTION_REQUIRED
    assert ptde_status["pin_state"] == NOT_INDEPENDENTLY_PINNED
    assert ptde_status["admitted"] is False
    assert ptde_status["authority_granted"] is False
    assert ptde_status["output"] == str(ptde_output)
    assert ptde_status["raw_history_output"] == str(raw_ptde_output)

    envelope_bytes = ptde_output.read_bytes()
    raw_history_bytes = raw_ptde_output.read_bytes()
    envelope = json.loads(envelope_bytes)
    raw_history = json.loads(raw_history_bytes)
    parsed_history = accepted_attempt_history_from_document(raw_history_bytes)
    assert raw_history_bytes == canonical_json_document_bytes(
        envelope["accepted_attempt_history"]
    )
    assert raw_history == envelope["accepted_attempt_history"]
    assert parsed_history.sequence == 0
    assert parsed_history.records == ()
    assert parsed_history.sha512() == ptde_status[
        "accepted_attempt_history_sha512"
    ]
    assert ptde_status["accepted_attempt_history_sha512"] == envelope[
        "accepted_attempt_history_sha512"
    ]
    assert ptde_status["raw_history_output_sha512"] == hashlib.sha512(
        raw_history_bytes
    ).hexdigest()
    assert ptde_status["envelope_output_sha512"] == hashlib.sha512(
        envelope_bytes
    ).hexdigest()
    assert ptde_status["accepted_attempt_history_sha512"] != ptde_status[
        "raw_history_output_sha512"
    ]
    assert ptde_status["raw_history_output_sha512"] != ptde_status[
        "envelope_output_sha512"
    ]
    assert ptde_status["digest_domains"] == {
        "accepted_attempt_history_sha512": (
            "CANONICAL_JSON_WITHOUT_TERMINAL_LF"
        ),
        "document_sha512": "CANONICAL_JSON_DOCUMENT_WITH_TERMINAL_LF",
    }

    mutated_history = deepcopy(raw_history)
    mutated_history["history_id"] = "mutated-owner-history"
    assert canonical_sha512(mutated_history) != ptde_status[
        "accepted_attempt_history_sha512"
    ]
    assert hashlib.sha512(
        canonical_json_document_bytes(mutated_history)
    ).hexdigest() != ptde_status["raw_history_output_sha512"]

    local_output = (tmp_path / "local-request.json").resolve()
    local = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "local-trust-genesis-request",
            "--repository-identity-sha512",
            REPOSITORY_IDENTITY,
            "--history-id",
            "external-local-trust-history",
            "--verification-context",
            str(context_path),
            "--owner-pinned-verification-context-sha512",
            context_pin,
            "--production-custody-metadata",
            str(custody_path),
            "--owner-pinned-production-custody-metadata-sha512",
            custody_pin,
            "--output",
            str(local_output),
        ],
        cwd=REPOSITORY_ROOT,
        check=False,
        shell=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert local.returncode == 0, local.stderr
    local_status = json.loads(local.stdout)
    assert local_status["status"] == EXTERNAL_PRODUCTION_SIGNATURE_REQUIRED
    assert local_status["signature_state"] == UNSIGNED
    local_document = json.loads(local_output.read_text(encoding="utf-8"))
    assert local_document["history_validation_state"] == NOT_A_VALID_HISTORY
    assert "signatures" not in local_document["unsigned_history"]


@pytest.mark.parametrize("existing", ("envelope", "raw"))
def test_ptde_cli_never_overwrites_either_output(
    tmp_path: Path, existing: str
) -> None:
    envelope = (tmp_path / f"{existing}-envelope.json").resolve()
    raw = (tmp_path / f"{existing}-raw.json").resolve()
    occupied = envelope if existing == "envelope" else raw
    occupied.write_bytes(b"sentinel")

    result = _run_ptde_genesis_cli(envelope, raw)

    assert result.returncode == 1
    assert json.loads(result.stdout) == {
        "admitted": False,
        "authority_granted": False,
        "failure": "HISTORY_PREPARATION_OUTPUT_ALREADY_EXISTS",
        "status": "FAIL",
    }
    assert occupied.read_bytes() == b"sentinel"
    other = raw if existing == "envelope" else envelope
    assert not other.exists()


def test_ptde_cli_rejects_same_output_before_creation(tmp_path: Path) -> None:
    shared = (tmp_path / "shared-output.json").resolve()

    result = _run_ptde_genesis_cli(shared, shared)

    assert result.returncode == 1
    assert json.loads(result.stdout)["failure"] == (
        "HISTORY_PREPARATION_OUTPUT_PATHS_NOT_DISTINCT"
    )
    assert not shared.exists()


def test_ptde_cli_rejects_parent_alias_before_creation(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-output-parent"
    real_parent.mkdir()
    alias_parent = tmp_path / "alias-output-parent"
    try:
        alias_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink creation is unavailable")
    real_output = (real_parent / "shared-output.json").absolute()
    alias_output = (alias_parent / "shared-output.json").absolute()

    result = _run_ptde_genesis_cli(real_output, alias_output)

    assert result.returncode == 1
    assert json.loads(result.stdout)["failure"] == (
        "HISTORY_PREPARATION_OUTPUT_PARENT_INVALID"
    )
    assert not real_output.exists()
