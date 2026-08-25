"""Repository-wide hostile checks for the V2 trust and effect boundaries.

These tests deliberately attack only repository-local mechanics.  They do not
stand in for independent validation, real HSM/TPM custody, or deployed stores.
"""

from __future__ import annotations

import base64
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from unittest import mock

import pytest

import sbp_lex.security.application_integrity as application_integrity
import tests.test_application_integrity as application_fixtures
import tests.test_controlled_local_adapter as effect_fixtures
from sbp_lex.execution.controlled_local_adapter import LocalEffectError
from sbp_lex.security.application_integrity import ApplicationIntegrityRejected
from sbp_lex.security.signature_provider import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_signed_object,
    verify_signed_object,
)


def _hybrid_fixture():
    provider = HybridMLDSA87Ed448SoftwareProvider.generate(
        provider_id="TEST_ONLY:V2_REPOSITORY_ADVERSARIAL_CAMPAIGN"
    )
    context = provider.hybrid_verification_context(allow_test_only=True)
    signed = build_signed_object(
        {"campaign": "v2-repository-adversarial", "sequence": 1},
        provider=provider,
    )
    assert verify_signed_object(
        signed,
        provider=provider,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
    )
    return provider, context, signed


@pytest.mark.parametrize("lane_index", (0, 1))
def test_every_signature_byte_single_bit_corruption_is_rejected(
    lane_index: int,
) -> None:
    provider, context, signed = _hybrid_fixture()
    encoded = signed["signature"]["signatures"][lane_index]["signature_b64"]
    original = base64.b64decode(encoded, validate=True)

    for byte_index in range(len(original)):
        corrupted = bytearray(original)
        corrupted[byte_index] ^= 1 << (byte_index % 8)
        candidate = deepcopy(signed)
        candidate["signature"]["signatures"][lane_index]["signature_b64"] = (
            base64.b64encode(corrupted).decode("ascii")
        )
        assert not verify_signed_object(
            candidate,
            provider=provider,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        ), (lane_index, byte_index)


@pytest.mark.parametrize("lane_index", (0, 1))
def test_every_signature_truncation_boundary_is_rejected(lane_index: int) -> None:
    provider, context, signed = _hybrid_fixture()
    encoded = signed["signature"]["signatures"][lane_index]["signature_b64"]
    original = base64.b64decode(encoded, validate=True)

    for length in range(len(original)):
        candidate = deepcopy(signed)
        candidate["signature"]["signatures"][lane_index]["signature_b64"] = (
            base64.b64encode(original[:length]).decode("ascii")
        )
        assert not verify_signed_object(
            candidate,
            provider=provider,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        ), (lane_index, length)


def _mutated_scalar(value):
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is str:
        return ("f" if not value.startswith("f") else "0") * max(1, len(value))
    if value is None:
        return "FORGED"
    raise AssertionError(f"unsupported scalar {type(value)!r}")


def test_every_hybrid_policy_and_lane_metadata_field_is_pinned() -> None:
    provider, context, signed = _hybrid_fixture()
    envelope = signed["signature"]
    attacks: list[tuple[tuple[object, ...], object]] = []
    for field, value in envelope.items():
        if field not in {"lanes", "signatures"}:
            attacks.append(((field,), _mutated_scalar(value)))
    for collection in ("lanes", "signatures"):
        for index, record in enumerate(envelope[collection]):
            for field, value in record.items():
                if field != "signature_b64":
                    attacks.append(
                        ((collection, index, field), _mutated_scalar(value))
                    )

    for path, replacement in attacks:
        candidate = deepcopy(signed)
        target = candidate["signature"]
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = replacement
        assert not verify_signed_object(
            candidate,
            provider=provider,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        ), path

    swapped = deepcopy(signed)
    swapped["signature"]["lanes"].reverse()
    assert not verify_signed_object(
        swapped,
        provider=provider,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
    )


@pytest.mark.parametrize("depth", (64, 128, 256, 512, 1024, 2048))
def test_deeply_nested_payload_never_crashes_open(depth: int) -> None:
    provider, context, signed = _hybrid_fixture()
    nested: object = "terminal"
    for _ in range(depth):
        nested = [nested]
    candidate = {
        "campaign": nested,
        "sequence": 1,
        "digest": signed["digest"],
        "signature": signed["signature"],
        "verified": False,
    }
    try:
        verified = verify_signed_object(
            candidate,
            provider=provider,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        )
    except Exception as exc:  # A hostile payload must be a denial, not a crash.
        pytest.fail(f"depth {depth} escaped verifier as {type(exc).__name__}: {exc}")
    assert verified is False


@pytest.mark.parametrize(
    "hostile_value",
    (
        float("nan"),
        float("inf"),
        float("-inf"),
        b"binary-not-json",
        {"oversized": "X" * (4 * 1024 * 1024)},
    ),
)
def test_noncanonical_and_oversized_payloads_fail_closed(hostile_value) -> None:
    provider, context, signed = _hybrid_fixture()
    candidate = {
        "campaign": hostile_value,
        "sequence": 1,
        "digest": signed["digest"],
        "signature": signed["signature"],
        "verified": False,
    }
    try:
        verified = verify_signed_object(
            candidate,
            provider=provider,
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
        )
    except Exception as exc:
        pytest.fail(f"hostile value escaped verifier as {type(exc).__name__}: {exc}")
    assert verified is False


def test_application_file_swap_inside_measurement_window_is_rejected() -> None:
    fixture = application_fixtures.ApplicationIntegrityTests(
        methodName=(
            "test_exact_release_passes_with_deterministic_trace_and_no_authority"
        )
    )
    fixture.setUp()
    target = fixture.root / "sbp_lex" / "runtime.py"
    replacement = fixture.root / "sbp_lex" / "runtime.replacement"
    original_open = os.open
    swapped = False

    def swap_then_open(path, flags, *args, **kwargs):
        nonlocal swapped
        if not swapped and Path(path) == target:
            original = target.read_bytes()
            replacement.write_bytes(bytes(byte ^ 0xA5 for byte in original))
            os.replace(replacement, target)
            swapped = True
        return original_open(path, flags, *args, **kwargs)

    try:
        with mock.patch.object(
            application_integrity.os,
            "open",
            side_effect=swap_then_open,
        ):
            with pytest.raises(
                ApplicationIntegrityRejected,
                match=(
                    "RELEASE_FILE_IDENTITY_CHANGED|"
                    "RELEASE_FILE_CHANGED_DURING_MEASUREMENT|"
                    "RELEASE_FILE_MEASUREMENT_MISMATCH"
                ),
            ):
                fixture._verify()
        assert swapped
    finally:
        fixture.doCleanups()


POINT_OF_USE_ATTACK_PATHS = (
    ("application_integrity_result_digest",),
    ("application_integrity_receipt_digest",),
    ("application_integrity_manifest_digest",),
    ("application_integrity_runtime_measurement_digest",),
    ("application_integrity_trust_context_digest",),
    ("digital_provenance_digest",),
    ("digital_provenance_verification_receipt", "durable_claim_result"),
    ("impersonation_protection_digest",),
    ("impersonation_protection_trace", -1, "reason"),
    ("australian_minor_access", "privacy_data_destroyed"),
    ("australian_minor_access", "replay", "receipt_digest"),
    ("foundational_baseline_digest",),
    ("foundational_baseline_record", "digital_provenance_digest"),
    ("tokens", "foundational", "digital_provenance_digest"),
    ("state_hash",),
)


def _mutate_path(target, path: tuple[object, ...]) -> None:
    current = target
    for component in path[:-1]:
        current = current[component]
    field = path[-1]
    current[field] = _mutated_scalar(current[field])


@pytest.mark.parametrize("path", POINT_OF_USE_ATTACK_PATHS)
def test_post_permit_extension_mutation_never_reaches_effect(path) -> None:
    fixture = effect_fixtures.ControlledLocalAdapterTests(
        methodName="test_replay_is_rejected_without_second_effect"
    )
    fixture.setUp()
    try:
        state = fixture.ready_state()
        permit = fixture.adapter.build_permit(
            state,
            authority_provider=fixture.authority,
            three_p_attestation_provider=fixture.authority,
            ttl_ms=500,
            **fixture.foundational_runtime_arguments(),
        )
        _mutate_path(state, path)
        with pytest.raises(LocalEffectError):
            fixture.adapter.dispatch(
                state,
                permit,
                authority_provider=fixture.authority,
                three_p_attestation_provider=fixture.authority,
                **fixture.foundational_runtime_arguments(),
            )
        assert fixture.handler.invocations == 0
    finally:
        fixture.tearDown()


def test_concurrent_same_permit_storm_has_at_most_one_effect() -> None:
    fixture = effect_fixtures.ControlledLocalAdapterTests(
        methodName="test_replay_is_rejected_without_second_effect"
    )
    fixture.setUp()
    workers = 32
    barrier = threading.Barrier(workers)
    try:
        state = fixture.ready_state()
        permit = fixture.adapter.build_permit(
            state,
            authority_provider=fixture.authority,
            three_p_attestation_provider=fixture.authority,
            ttl_ms=500,
            **fixture.foundational_runtime_arguments(),
        )

        def attack() -> str:
            barrier.wait()
            try:
                fixture.adapter.dispatch(
                    deepcopy(state),
                    deepcopy(permit),
                    authority_provider=fixture.authority,
                    three_p_attestation_provider=fixture.authority,
                    **fixture.foundational_runtime_arguments(),
                )
            except LocalEffectError:
                return "DENIED"
            return "EFFECT"

        with ThreadPoolExecutor(max_workers=workers) as executor:
            results = list(executor.map(lambda _: attack(), range(workers)))
        assert results.count("EFFECT") <= 1
        assert fixture.handler.invocations <= 1
        assert results.count("EFFECT") == fixture.handler.invocations
    finally:
        fixture.tearDown()
