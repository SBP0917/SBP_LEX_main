"""Regenerate deterministic shared v2 vectors from the independent Python codec."""

from __future__ import annotations

import pathlib

from .golden import (
    BASE_MS,
    build_mode1_release_denial_transcript,
    build_mode1_witness_time_transplant_counterexample,
    build_transcript,
    fixture_admission,
)
from .sbp_lex_wire_v2 import (
    admission_policy_digest,
    authority_artifact_digest,
    authority_artifact_id,
    effect_receipt_digest,
    encode_message,
    fixture_verify,
    validate_request_prefix,
)


def main() -> None:
    vectors = pathlib.Path(__file__).resolve().parents[1] / "vectors"
    registry = None
    for mode in ("MODE_1", "MODE_2", "MODE_3"):
        current_registry, messages = build_transcript(mode)
        registry = current_registry
        filename = "mode1_golden.jsonl" if mode == "MODE_1" else f"{mode.lower()}_golden.jsonl"
        (vectors / filename).write_bytes(
            b"\n".join(encode_message(message) for message in messages) + b"\n"
        )
    for label, kwargs in (
        ("mode1_failure_golden.jsonl", {"outcome": "FAILED"}),
        ("mode1_unknown_golden.jsonl", {"outcome": "UNKNOWN"}),
        ("mode1_timeout_golden.jsonl", {"timeout": True}),
    ):
        current_registry, messages = build_transcript("MODE_1", **kwargs)
        registry = current_registry
        (vectors / label).write_bytes(
            b"\n".join(encode_message(message) for message in messages) + b"\n"
        )
    for mode, stem in (("MODE_2", "mode2"), ("MODE_3", "mode3")):
        for suffix, kwargs in (
            ("failure", {"outcome": "FAILED"}),
            ("unknown", {"outcome": "UNKNOWN"}),
            ("timeout", {"timeout": True}),
        ):
            current_registry, messages = build_transcript(mode, **kwargs)
            registry = current_registry
            (vectors / f"{stem}_{suffix}_golden.jsonl").write_bytes(
                b"\n".join(encode_message(message) for message in messages) + b"\n"
            )
    current_registry, messages = build_mode1_release_denial_transcript()
    registry = current_registry
    (vectors / "mode1_release_denial_golden.jsonl").write_bytes(
        b"\n".join(encode_message(message) for message in messages) + b"\n"
    )
    current_registry, messages = build_mode1_witness_time_transplant_counterexample()
    registry = current_registry
    (vectors / "mode1_witness_time_transplant_negative.jsonl").write_bytes(
        b"\n".join(encode_message(message) for message in messages) + b"\n"
    )
    for label, offsets in (
        ("mode1_timeout_lease_bound_golden.jsonl", (1_200, 2_500, 1_200)),
        ("mode1_timeout_watchdog_bound_golden.jsonl", (2_000, 1_200, 1_200)),
    ):
        current_registry, messages = build_transcript(
            "MODE_1", timeout=True, deadline_offsets=offsets,
        )
        registry = current_registry
        (vectors / label).write_bytes(
            b"\n".join(encode_message(message) for message in messages) + b"\n"
        )
    for label, variant in (
        ("mode2_equal_golden.jsonl", "equal"),
        ("mode2_mixed_golden.jsonl", "candidate_equal"),
    ):
        current_registry, messages = build_transcript("MODE_2", mode2_variant=variant)
        registry = current_registry
        (vectors / label).write_bytes(
            b"\n".join(encode_message(message) for message in messages) + b"\n"
        )
    assert registry is not None
    destination = vectors / "mode1_golden.jsonl"
    registry_path = destination.with_name("test_trust_registry.txt")
    registry_path.write_text(
        "".join(
            f"{role}|{item.key_class}|{item.public_key_hex}\n"
            for role, item in sorted(registry.entries.items())
        ),
        encoding="ascii",
        newline="\n",
    )
    stage_digests: dict[str, str] = {}
    for mode in ("MODE_1", "MODE_2", "MODE_3"):
        current_registry, messages = build_transcript(mode)
        admission = fixture_admission(current_registry, mode)
        index = next(i for i, item in enumerate(messages) if item["kind"] == "convergence_request")
        context = validate_request_prefix(
            messages[: index + 1], expected_request_kind="convergence_request",
            registry=current_registry, admission=admission, verifier=fixture_verify,
            trusted_now_ms=BASE_MS + 5_000,
        )
        stage_digests[f"{mode}.admission_policy_digest"] = admission_policy_digest(admission)
        stage_digests[f"{mode}.authenticated_convergence_binding_digest"] = context.authenticated_convergence_binding_digest
        stage_digests[f"{mode}.convergence_stage_context_digest"] = context.context_digest
    (vectors / "staged_context_digests.txt").write_text(
        "".join(f"{key}|{stage_digests[key]}\n" for key in sorted(stage_digests)),
        encoding="ascii", newline="\n",
    )
    current_registry, messages = build_transcript("MODE_1")
    admission = fixture_admission(current_registry, "MODE_1")
    lifecycle: dict[str, str] = {}
    result_fields = {
        "prepare_request": ("prepare_proof_digest", "prepare_id"),
        "commit_request": ("capability_digest", "capability_id"),
        "lease_redeem_request": ("lease_digest", "lease_id"),
        "watchdog_arm_request": ("watchdog_digest", None),
        "effect_permit_request": ("permit_digest", "permit_id"),
    }
    for stage, (artifact_field, identity_field) in result_fields.items():
        index = next(i for i, item in enumerate(messages) if item["kind"] == stage)
        context = validate_request_prefix(
            messages[: index + 1], expected_request_kind=stage,
            registry=current_registry, admission=admission, verifier=fixture_verify,
            trusted_now_ms=BASE_MS + 5_000,
        )
        artifact = authority_artifact_digest(stage, context, messages[index], messages[index + 1])
        lifecycle[f"{stage}.artifact_digest"] = artifact
        if identity_field is not None:
            lifecycle[f"{stage}.artifact_id"] = authority_artifact_id(stage, artifact)
        assert messages[index + 1][artifact_field] == artifact
        if identity_field is not None:
            assert messages[index + 1][identity_field] == lifecycle[f"{stage}.artifact_id"]
    receipt = next(item for item in messages if item["kind"] == "effect_receipt")
    lifecycle["effect_receipt.receipt_digest"] = effect_receipt_digest(receipt)
    lifecycle["effect_receipt.permit_digest"] = str(receipt["permit_digest"])
    lifecycle["effect_receipt.permit_id"] = str(receipt["permit_id"])
    assert receipt["receipt_digest"] == lifecycle["effect_receipt.receipt_digest"]
    (vectors / "lifecycle_derivations.txt").write_text(
        "".join(f"{key}|{lifecycle[key]}\n" for key in sorted(lifecycle)),
        encoding="ascii", newline="\n",
    )


if __name__ == "__main__":
    main()
