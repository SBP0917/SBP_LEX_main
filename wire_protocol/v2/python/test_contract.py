"""Independent Python conformance and adversarial tests for wire v2."""

from __future__ import annotations

import copy
import pathlib
import unittest
from dataclasses import replace

from .golden import (
    BASE_MS,
    build_mode1_release_denial_transcript,
    build_mode1_witness_time_transplant_counterexample,
    build_transcript,
    digest,
    fixture_admission,
)
from .sbp_lex_wire_v2 import (
    MAX_FRAME_BYTES,
    ZERO,
    authority_artifact_digest,
    authority_artifact_id,
    admission_policy_digest,
    KeyRecord,
    WireError,
    decode_frame,
    encode_frame,
    encode_message,
    effect_receipt_digest,
    fixture_verify,
    parse_message,
    projection_digest,
    point_of_use_digest,
    convergence_digest,
    rendezvous_ack_digest,
    rendezvous_checkpoint_digest,
    rendezvous_release_digest,
    seal_fixture_message,
    validate_and_append_result,
    validate_effect_permit_for_atomic_consumption,
    validate_request_prefix,
    validate_transcript,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]


def validate(registry, messages) -> None:
    validate_transcript(
        messages,
        registry=registry,
        admission=fixture_admission(registry, messages[0]["mode"]),
        verifier=fixture_verify,
        trusted_now_ms=BASE_MS + 5_000,
    )


def rechain(messages, registry) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for sequence, source in enumerate(messages):
        item = dict(source)
        item["sequence"] = sequence
        item["prior_transcript_digest"] = result[-1]["transcript_digest"] if result else "0" * 128
        result.append(seal_fixture_message(item, registry.entries[item["signer_role"]]))
    return result


class ContractTests(unittest.TestCase):
    def test_zero_extension_digests_are_never_admitted(self) -> None:
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry, "MODE_1")
        for field in (
            "extension_configuration_digest",
            "extension_admission_binding_digest",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    WireError,
                    "zero extension admission digest",
                ):
                    admission_policy_digest(replace(admission, **{field: ZERO}))
                changed = copy.deepcopy(messages)
                for item in changed:
                    item[field] = ZERO
                with self.assertRaises(WireError):
                    rechain(changed, registry)

    def test_mode1_release_request_time_equality_accepted_and_retrocausal_release_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry, "MODE_1")
        self.assertEqual(
            messages[0]["message_time_ms"], messages[1]["rendezvous_released_at_ms"],
        )
        validate(registry, messages)

        context = validate_request_prefix(
            messages[:1], expected_request_kind="mode1_release_request",
            registry=registry, admission=admission, verifier=fixture_verify,
            trusted_now_ms=BASE_MS + 5_000,
        )
        appended = validate_and_append_result(
            messages[:1], messages[1], context=context, registry=registry,
            admission=admission, verifier=fixture_verify,
            trusted_now_ms=BASE_MS + 5_000,
        )
        self.assertEqual(appended[-1], messages[1])

        retrocausal = dict(messages[1])
        released_at = int(messages[0]["message_time_ms"]) - 1
        retrocausal["rendezvous_released_at_ms"] = released_at
        retrocausal["rendezvous_release_digest"] = rendezvous_release_digest(
            str(messages[0]["a_checkpoint_digest"]),
            str(messages[0]["b_checkpoint_digest"]),
            int(messages[0]["rendezvous_opened_at_ms"]),
            released_at,
        )
        retrocausal = seal_fixture_message(retrocausal, registry.entries["AUTHORITY"])
        with self.assertRaisesRegex(WireError, "Mode 1 release result evidence"):
            validate_and_append_result(
                messages[:1], retrocausal, context=context, registry=registry,
                admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )

        changed = copy.deepcopy(messages)
        changed[1] = retrocausal
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "Mode 1 admitted causal release evidence"):
            validate(registry, changed)

    def test_staged_request_validation_all_modes_and_lifecycle(self) -> None:
        for mode in ("MODE_1", "MODE_2", "MODE_3"):
            registry, messages = build_transcript(mode)
            admission = fixture_admission(registry, mode)
            if mode == "MODE_1":
                release = validate_request_prefix(
                    messages[:1], expected_request_kind="mode1_release_request",
                    registry=registry, admission=admission, verifier=fixture_verify,
                    trusted_now_ms=BASE_MS + 5_000,
                )
                self.assertEqual(release.expected_result_kind, "mode1_release_result")
                self.assertEqual(release.authenticated_convergence_binding_digest, "0" * 128)
            for kind in (
                "convergence_request", "prepare_request", "commit_request",
                "lease_redeem_request", "watchdog_arm_request",
                "effect_permit_request", "effect_receipt", "watchdog_terminal",
            ):
                index = next(i for i, item in enumerate(messages) if item["kind"] == kind)
                context = validate_request_prefix(
                    messages[: index + 1], expected_request_kind=kind,
                    registry=registry, admission=admission, verifier=fixture_verify,
                    trusted_now_ms=BASE_MS + 5_000,
                )
                self.assertEqual(context.stage_kind, kind)
                self.assertNotEqual(context.context_digest, "0" * 128)
                self.assertNotEqual(context.authenticated_convergence_binding_digest, "0" * 128)

    def test_invalid_staged_request_cannot_produce_verified_context(self) -> None:
        registry, messages = build_transcript("MODE_1")
        index = next(i for i, item in enumerate(messages) if item["kind"] == "convergence_request")
        changed = copy.deepcopy(messages[: index + 1])
        changed[-1]["projection_digest"] = digest("INVENTED-EQUAL")
        changed = rechain(changed, registry)
        with self.assertRaises(WireError):
            validate_request_prefix(
                changed, expected_request_kind="convergence_request", registry=registry,
                admission=fixture_admission(registry), verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
        import wire_protocol.v2.python.sbp_lex_wire_v2 as codec
        self.assertFalse(hasattr(codec, "validate_construct_and_append_result"))
        self.assertFalse(hasattr(codec, "dispatch_validated_request"))

    def test_partial_terminal_denials_are_auditable_after_valid_request(self) -> None:
        registry, messages = build_transcript("MODE_1")
        for result_kind in ("mode1_release_result", "convergence_result", "prepare_result", "commit_result", "lease_redeem_result", "watchdog_arm_result", "effect_permit_result"):
            index = next(i for i, item in enumerate(messages) if item["kind"] == result_kind)
            denied = copy.deepcopy(messages[: index + 1])
            denied[-1]["decision"] = "DENY"
            denied[-1]["error_code"] = "STAGE_DENIED"
            if result_kind == "mode1_release_result":
                denied[-1]["rendezvous_release_digest"] = ZERO
                denied[-1]["rendezvous_released_at_ms"] = 0
            artifact = {
                "prepare_result": "prepare_proof_digest",
                "commit_result": "capability_digest",
                "lease_redeem_result": "lease_digest",
                "watchdog_arm_result": "watchdog_digest",
                "effect_permit_result": "permit_digest",
            }.get(result_kind)
            if artifact is not None:
                denied[-1][artifact] = "0" * 128
            identity = {
                "prepare_result": "prepare_id",
                "commit_result": "capability_id",
                "lease_redeem_result": "lease_id",
                "effect_permit_result": "permit_id",
            }.get(result_kind)
            if identity is not None:
                denied[-1][identity] = "0" * 32
            denied = rechain(denied, registry)
            with self.subTest(result=result_kind):
                validate(registry, denied)

    def test_staged_result_append_rejects_derived_forgery_and_deadline(self) -> None:
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry)
        for request_kind, result_kind in (
            ("convergence_request", "convergence_result"),
            ("lease_redeem_request", "lease_redeem_result"),
            ("effect_receipt", "receipt_ack"),
            ("watchdog_terminal", "watchdog_result"),
        ):
            request_index = next(i for i, item in enumerate(messages) if item["kind"] == request_kind)
            result_index = next(i for i, item in enumerate(messages) if i > request_index and item["kind"] == result_kind)
            prefix = messages[: request_index + 1]
            context = validate_request_prefix(
                prefix, expected_request_kind=request_kind, registry=registry,
                admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
            appended = validate_and_append_result(
                prefix, messages[result_index], context=context, registry=registry,
                admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
            self.assertEqual(appended[-1], messages[result_index])
        request_index = next(i for i, item in enumerate(messages) if item["kind"] == "convergence_request")
        prefix = messages[: request_index + 1]
        context = validate_request_prefix(
            prefix, expected_request_kind="convergence_request", registry=registry,
            admission=admission, verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
        )
        forged = dict(messages[request_index + 1])
        forged["projection_digest"] = digest("FORGED-DERIVED-RESULT")
        forged = seal_fixture_message(forged, registry.entries["AUTHORITY"])
        with self.assertRaises(WireError):
            validate_and_append_result(
                prefix, forged, context=context, registry=registry, admission=admission,
                verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
            )
        terminal_index = next(i for i, item in enumerate(messages) if item["kind"] == "watchdog_terminal")
        prefix = messages[: terminal_index + 1]
        context = validate_request_prefix(
            prefix, expected_request_kind="watchdog_terminal", registry=registry,
            admission=admission, verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
        )
        late = dict(messages[terminal_index + 1])
        late["message_time_ms"] = context.derived("completion_deadline_ms")
        late = seal_fixture_message(late, registry.entries["AUTHORITY"])
        with self.assertRaisesRegex(WireError, "deadline"):
            validate_and_append_result(
                prefix, late, context=context, registry=registry, admission=admission,
                verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
            )

    def test_staged_and_full_half_open_lease_and_watchdog_result_deadlines(self) -> None:
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry)
        cases = (
            ("lease_redeem_request", "lease_redeem_result", "lease_deadline_ms", "lease_digest", "lease_id"),
            ("watchdog_arm_request", "watchdog_arm_result", "watchdog_deadline_ms", "watchdog_digest", None),
        )
        for request_kind, result_kind, deadline_field, artifact_field, identity_field in cases:
            request_index = next(i for i, item in enumerate(messages) if item["kind"] == request_kind)
            result_index = next(i for i, item in enumerate(messages) if item["kind"] == result_kind)
            prefix = messages[: request_index + 1]
            context = validate_request_prefix(
                prefix, expected_request_kind=request_kind, registry=registry,
                admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
            for delta in (0, 1):
                changed_result = dict(messages[result_index])
                changed_result["message_time_ms"] = changed_result[deadline_field] + delta
                changed_result[artifact_field] = authority_artifact_digest(
                    request_kind, context, prefix[-1], changed_result,
                )
                if identity_field is not None:
                    changed_result[identity_field] = authority_artifact_id(
                        request_kind, changed_result[artifact_field],
                    )
                changed_result = seal_fixture_message(
                    changed_result, registry.entries[changed_result["signer_role"]],
                )
                with self.subTest(stage=request_kind, delta=delta), self.assertRaisesRegex(WireError, "deadline"):
                    validate_and_append_result(
                        prefix, changed_result, context=context, registry=registry,
                        admission=admission, verifier=fixture_verify,
                        trusted_now_ms=BASE_MS + 5_000,
                    )
                completed_prefix = rechain(messages[:result_index] + [changed_result], registry)
                with self.assertRaisesRegex(WireError, "deadline"):
                    validate(registry, completed_prefix)

    def test_untrusted_prefix_replays_all_completed_result_semantics(self) -> None:
        registry, messages = build_transcript("MODE_1", timeout=True)
        artifact_cases = (
            (8, "prepare_proof_digest"), (10, "capability_digest"),
            (12, "lease_digest"), (14, "watchdog_digest"), (16, "permit_digest"),
        )
        for result_index, field in artifact_cases:
            changed = copy.deepcopy(messages)
            changed[result_index][field] = "0" * 128
            # Keep any later handoff internally linked, then end in a DENY so
            # no operational authority is exercised by this negative vector.
            for item in changed[result_index + 1 :]:
                if field in item:
                    item[field] = "0" * 128
            changed = rechain(changed, registry)
            with self.subTest(field=field), self.assertRaisesRegex(WireError, "authority artifact|authority lifecycle handoff|point-of-use"):
                validate(registry, changed)

    def test_nonzero_artifact_transplants_fail_before_later_denial(self) -> None:
        registry, messages = build_transcript("MODE_1", timeout=True)
        cases = (
            (8, "prepare_proof_digest", 9, 10, "capability_digest"),
            (10, "capability_digest", 11, 12, "lease_digest"),
            (12, "lease_digest", 13, 14, "watchdog_digest"),
            (14, "watchdog_digest", 15, 16, "permit_digest"),
            (16, "permit_digest", 17, 18, None),
        )
        for result_index, field, handoff_index, denial_index, denial_artifact in cases:
            changed = copy.deepcopy(messages[: denial_index + 1])
            replacement = digest("NONZERO-ARTIFACT-TRANSPLANT|" + field)
            changed[result_index][field] = replacement
            changed[handoff_index][field] = replacement
            if field == "watchdog_digest":
                changed[handoff_index]["point_of_use_digest"] = point_of_use_digest(changed[handoff_index])
            if denial_artifact is not None:
                changed[denial_index]["decision"] = "DENY"
                changed[denial_index]["error_code"] = "LATER_STAGE_DENIED"
                changed[denial_index][denial_artifact] = "0" * 128
            changed = rechain(changed, registry)
            with self.subTest(field=field), self.assertRaisesRegex(WireError, "authority artifact derivation"):
                validate(registry, changed)

    def test_artifact_ids_are_derived_zero_on_denial_and_handoff_bound(self) -> None:
        registry, messages = build_transcript("MODE_1", timeout=True)
        cases = (
            (8, "prepare_id", 9), (10, "capability_id", 11),
            (12, "lease_id", 13), (16, "permit_id", 17),
        )
        for result_index, field, handoff_index in cases:
            changed = copy.deepcopy(messages)
            changed[result_index][field] = "f" * 32
            changed = rechain(changed, registry)
            with self.subTest(kind="derived", field=field), self.assertRaisesRegex(WireError, "artifact ID derivation|lifecycle handoff"):
                validate(registry, changed)
            changed = copy.deepcopy(messages[: result_index + 1])
            changed[-1]["decision"] = "DENY"
            changed[-1]["error_code"] = "STAGE_DENIED"
            changed[-1][field] = "f" * 32
            artifact = {"prepare_id": "prepare_proof_digest", "capability_id": "capability_digest", "lease_id": "lease_digest", "permit_id": "permit_digest"}[field]
            changed[-1][artifact] = ZERO
            changed = rechain(changed, registry)
            with self.subTest(kind="denial", field=field), self.assertRaisesRegex(WireError, "artifact ID must be zero"):
                validate(registry, changed)
            changed = copy.deepcopy(messages)
            changed[result_index][field] = "f" * 32
            for item in changed[handoff_index:]:
                if field in item:
                    item[field] = "f" * 32
            changed = rechain(changed, registry)
            with self.subTest(kind="handoff", field=field), self.assertRaisesRegex(WireError, "artifact ID derivation|point-of-use derivation"):
                validate(registry, changed)

    def test_receipt_digest_and_full_permit_identity_tail_are_bound(self) -> None:
        for outcome in ("SUCCEEDED", "FAILED", "UNKNOWN"):
            registry, messages = build_transcript("MODE_1", outcome=outcome)
            for replacement in (ZERO, digest("OPAQUE-RECEIPT-TRANSPLANT")):
                changed = copy.deepcopy(messages)
                for item in changed[-4:]:
                    if "receipt_digest" in item:
                        item["receipt_digest"] = replacement
                changed = rechain(changed, registry)
                with self.subTest(outcome=outcome, receipt=replacement[:8]), self.assertRaisesRegex(WireError, "effect receipt derivation"):
                    validate(registry, changed)
            changed = copy.deepcopy(messages)
            for item in changed[-4:]:
                if "permit_id" in item:
                    item["permit_id"] = "f" * 32
            changed = rechain(changed, registry)
            with self.subTest(outcome=outcome, field="permit_id"), self.assertRaisesRegex(WireError, "receipt tail binding|receipt permit/watchdog binding"):
                validate(registry, changed)
            for field, replacement in (("permit_id", "f" * 32), ("permit_digest", digest("ACK-PERMIT-TRANSPLANT"))):
                changed = copy.deepcopy(messages)
                changed[-3][field] = replacement
                changed = rechain(changed, registry)
                with self.subTest(outcome=outcome, ack_field=field), self.assertRaisesRegex(WireError, "receipt tail binding|receipt/watchdog staged semantics"):
                    validate(registry, changed)
            changed = copy.deepcopy(messages)
            for item in changed[-3:]:
                item["permit_id"] = "f" * 32
                item["permit_digest"] = digest("TAIL-SUFFIX-PERMIT-TRANSPLANT")
            changed = rechain(changed, registry)
            with self.subTest(outcome=outcome, field="tail_permit_pair"), self.assertRaisesRegex(WireError, "receipt tail binding|receipt/watchdog staged semantics"):
                validate(registry, changed)
        registry, messages = build_transcript("MODE_1", timeout=True)
        changed = copy.deepcopy(messages)
        for item in changed[-2:]:
            item["permit_id"] = "f" * 32
            item["permit_digest"] = digest("TIMEOUT-PERMIT-TRANSPLANT")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "no-receipt"):
            validate(registry, changed)

    def test_atomic_permit_context_revalidates_full_private_prefix(self) -> None:
        registry, messages = build_transcript("MODE_1")
        permit = next(i for i, item in enumerate(messages) if item["kind"] == "effect_permit_result")
        context = validate_effect_permit_for_atomic_consumption(
            messages[: permit + 1], registry=registry, admission=fixture_admission(registry),
            verifier=fixture_verify, trusted_now_ms=BASE_MS + 1_000,
        )
        self.assertEqual(context.derived("permit_digest"), messages[permit]["permit_digest"])
        self.assertEqual(context.derived("point_of_use_digest"), messages[permit - 1]["point_of_use_digest"])
        self.assertNotEqual(context.authenticated_convergence_binding_digest, "0" * 128)
        with self.assertRaisesRegex(WireError, "expired at point of use"):
            validate_effect_permit_for_atomic_consumption(
                messages[: permit + 1], registry=registry, admission=fixture_admission(registry),
                verifier=fixture_verify, trusted_now_ms=messages[permit]["permit_deadline_ms"],
            )

    def test_shared_staged_context_digest_vectors(self) -> None:
        expected = dict(
            line.split("|", 1)
            for line in (ROOT / "vectors" / "staged_context_digests.txt").read_text(encoding="ascii").splitlines()
        )
        actual: dict[str, str] = {}
        from .sbp_lex_wire_v2 import admission_policy_digest

        for mode in ("MODE_1", "MODE_2", "MODE_3"):
            registry, messages = build_transcript(mode)
            admission = fixture_admission(registry, mode)
            index = next(i for i, item in enumerate(messages) if item["kind"] == "convergence_request")
            context = validate_request_prefix(
                messages[: index + 1], expected_request_kind="convergence_request",
                registry=registry, admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
            actual[f"{mode}.admission_policy_digest"] = admission_policy_digest(admission)
            actual[f"{mode}.authenticated_convergence_binding_digest"] = context.authenticated_convergence_binding_digest
            actual[f"{mode}.convergence_stage_context_digest"] = context.context_digest
        self.assertEqual(actual, expected)

    def test_shared_lifecycle_derivation_vectors(self) -> None:
        expected = dict(
            line.split("|", 1)
            for line in (ROOT / "vectors" / "lifecycle_derivations.txt").read_text(encoding="ascii").splitlines()
        )
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry)
        actual: dict[str, str] = {}
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
                registry=registry, admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
            artifact = authority_artifact_digest(stage, context, messages[index], messages[index + 1])
            actual[f"{stage}.artifact_digest"] = artifact
            self.assertEqual(messages[index + 1][artifact_field], artifact)
            if identity_field is not None:
                identity = authority_artifact_id(stage, artifact)
                actual[f"{stage}.artifact_id"] = identity
                self.assertEqual(messages[index + 1][identity_field], identity)
        receipt = next(item for item in messages if item["kind"] == "effect_receipt")
        actual["effect_receipt.receipt_digest"] = effect_receipt_digest(receipt)
        actual["effect_receipt.permit_digest"] = str(receipt["permit_digest"])
        actual["effect_receipt.permit_id"] = str(receipt["permit_id"])
        self.assertEqual(actual, expected)

    def test_epoch_domain_and_subject_are_owner_admitted_immutable_bindings(self) -> None:
        registry, messages = build_transcript("MODE_1")
        admission = fixture_admission(registry)
        for field, value in (
            ("authority_epoch", 8),
            ("domain_digest", digest("MUTATED-DOMAIN")),
            ("subject_digest", digest("MUTATED-SUBJECT")),
        ):
            changed = copy.deepcopy(messages)
            for item in changed:
                item[field] = value
            changed = rechain(changed, registry)
            with self.subTest(field=field), self.assertRaises(WireError):
                validate_transcript(
                    changed, registry=registry, admission=admission,
                    verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
                )
        changed = copy.deepcopy(messages)
        for item in changed:
            item["authority_epoch"] = 0
        with self.assertRaisesRegex(WireError, "authority epoch"):
            rechain(changed, registry)

    def test_shared_mode1_golden_round_trip_and_validation(self) -> None:
        registry, expected = build_transcript("MODE_1")
        lines = (ROOT / "vectors" / "mode1_golden.jsonl").read_bytes().splitlines()
        actual = [parse_message(line) for line in lines]
        self.assertEqual([encode_message(item) for item in expected], lines)
        self.assertEqual(actual, expected)
        self.assertEqual(actual[4]["rendezvous_opened_at_ms"], actual[0]["rendezvous_opened_at_ms"])
        self.assertEqual(actual[4]["rendezvous_released_at_ms"], actual[1]["rendezvous_released_at_ms"])
        self.assertEqual(
            actual[1]["rendezvous_released_at_ms"],
            min(actual[2]["substantive_start_ms"], actual[3]["substantive_start_ms"]),
        )
        validate(registry, actual)
        for item in actual:
            self.assertEqual(decode_frame(encode_frame(item)), item)

    def test_shared_mode1_release_denial_is_zero_release_and_auditable(self) -> None:
        registry, expected = build_mode1_release_denial_transcript()
        lines = (ROOT / "vectors" / "mode1_release_denial_golden.jsonl").read_bytes().splitlines()
        actual = [parse_message(line) for line in lines]
        self.assertEqual([encode_message(item) for item in expected], lines)
        self.assertEqual(actual, expected)
        self.assertEqual(actual[-1]["rendezvous_release_digest"], ZERO)
        self.assertEqual(actual[-1]["rendezvous_released_at_ms"], 0)
        validate(registry, actual)
        forged = copy.deepcopy(actual)
        forged[-1]["rendezvous_release_digest"] = "f" * 128
        forged = rechain(forged, registry)
        with self.assertRaisesRegex(WireError, "denied release evidence"):
            validate(registry, forged)

    def test_shared_mode1_witness_time_transplant_is_rejected_staged_and_full(self) -> None:
        registry, expected = build_mode1_witness_time_transplant_counterexample()
        lines = (
            ROOT / "vectors" / "mode1_witness_time_transplant_negative.jsonl"
        ).read_bytes().splitlines()
        actual = [parse_message(line) for line in lines]
        self.assertEqual([encode_message(item) for item in expected], lines)
        self.assertEqual(actual, expected)
        request, result, branch_a, branch_b, witness, convergence_request, convergence_result = actual

        release = rendezvous_release_digest(
            request["a_checkpoint_digest"], request["b_checkpoint_digest"],
            request["rendezvous_opened_at_ms"], result["rendezvous_released_at_ms"],
        )
        self.assertEqual(result["release_request_digest"], request["transcript_digest"])
        self.assertEqual(result["rendezvous_release_digest"], release)
        self.assertEqual(witness["rendezvous_release_digest"], release)
        self.assertEqual(witness["release_result_digest"], result["transcript_digest"])
        self.assertEqual(witness["statement_a_digest"], branch_a["transcript_digest"])
        self.assertEqual(witness["statement_b_digest"], branch_b["transcript_digest"])
        self.assertEqual(
            witness["a_ack_digest"],
            rendezvous_ack_digest("A", release, branch_a["transcript_digest"]),
        )
        self.assertEqual(
            witness["b_ack_digest"],
            rendezvous_ack_digest("B", release, branch_b["transcript_digest"]),
        )
        convergence = convergence_digest(
            branch_a["transcript_digest"], branch_b["transcript_digest"],
            witness["transcript_digest"], branch_a["projection_digest"],
        )
        self.assertEqual(convergence_request["convergence_digest"], convergence)
        self.assertEqual(convergence_result["convergence_digest"], convergence)

        self.assertNotEqual(witness["rendezvous_opened_at_ms"], request["rendezvous_opened_at_ms"])
        self.assertNotEqual(witness["rendezvous_released_at_ms"], result["rendezvous_released_at_ms"])
        self.assertGreater(
            result["rendezvous_released_at_ms"],
            min(branch_a["substantive_start_ms"], branch_b["substantive_start_ms"]),
        )
        admission = fixture_admission(registry, "MODE_1")
        with self.assertRaisesRegex(WireError, "Mode 1 causal rendezvous"):
            validate_request_prefix(
                actual[:6], expected_request_kind="convergence_request",
                registry=registry, admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )
        with self.assertRaisesRegex(WireError, "Mode 1 causal rendezvous"):
            validate(registry, actual)

    def test_all_modes_and_terminal_branches(self) -> None:
        cases = [build_transcript(mode) for mode in ("MODE_1", "MODE_2", "MODE_3")]
        cases.extend(
            build_transcript(mode, **kwargs)
            for mode in ("MODE_1", "MODE_2", "MODE_3")
            for kwargs in ({"outcome": "FAILED"}, {"outcome": "UNKNOWN"}, {"timeout": True})
        )
        for registry, messages in cases:
            with self.subTest(mode=messages[0]["mode"], tail=messages[-2]["kind"]):
                validate(registry, messages)

    def test_no_receipt_trip_and_block_result_timing_is_bounded(self) -> None:
        timeout_cases = (
            build_transcript("MODE_1", timeout=True),
            build_transcript(
                "MODE_1", timeout=True,
                deadline_offsets=(1_200, 2_500, 1_200),
            ),
            build_transcript(
                "MODE_1", timeout=True,
                deadline_offsets=(2_000, 1_200, 1_200),
            ),
        )
        for registry, messages in timeout_cases:
            effective_deadline = min(
                messages[12]["lease_deadline_ms"],
                messages[14]["watchdog_deadline_ms"],
                messages[16]["permit_deadline_ms"],
            )
            with self.subTest(deadline=effective_deadline):
                self.assertEqual(messages[-2]["message_time_ms"], effective_deadline)
                validate(registry, messages)

        registry, messages = build_transcript("MODE_1", timeout=True)
        admission = fixture_admission(registry)
        # A signed STOP may trip immediately after the permit; it cannot be late.
        early_stop = copy.deepcopy(messages)
        early_stop[-2]["watchdog_status"] = "STOP"
        early_stop[-2]["message_time_ms"] = early_stop[16]["message_time_ms"]
        early_stop[-1]["message_time_ms"] = early_stop[-2]["message_time_ms"] + 1
        early_stop[-1]["error_code"] = "WATCHDOG_STOP"
        early_stop = rechain(early_stop, registry)
        validate(registry, early_stop)

        late_terminal = copy.deepcopy(messages)
        late_terminal[-2]["message_time_ms"] += 1
        late_terminal[-1]["message_time_ms"] += 1
        late_terminal = rechain(late_terminal, registry)
        with self.assertRaisesRegex(WireError, "no-receipt"):
            validate(registry, late_terminal)
        with self.assertRaisesRegex(WireError, "no-receipt"):
            validate_request_prefix(
                late_terminal[:-1], expected_request_kind="watchdog_terminal",
                registry=registry, admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )

        max_result = copy.deepcopy(messages)
        max_result[-1]["message_time_ms"] = max_result[-2]["message_time_ms"] + 1_000
        max_result = rechain(max_result, registry)
        validate(registry, max_result)

        late_result = copy.deepcopy(messages)
        late_result[-1]["message_time_ms"] = late_result[-2]["message_time_ms"] + 1_001
        late_result = rechain(late_result, registry)
        with self.assertRaisesRegex(WireError, "deadline"):
            validate(registry, late_result)
        context = validate_request_prefix(
            late_result[:-1], expected_request_kind="watchdog_terminal",
            registry=registry, admission=admission, verifier=fixture_verify,
            trusted_now_ms=BASE_MS + 5_000,
        )
        with self.assertRaisesRegex(WireError, "deadline"):
            validate_and_append_result(
                late_result[:-1], late_result[-1], context=context,
                registry=registry, admission=admission, verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )

    def test_invented_equal_digests_unadmitted_signer_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        forged = copy.deepcopy(messages)
        invented = digest("ATTACKER-INVENTED-EQUAL-PROJECTION")
        attacker = KeyRecord(role="BRANCH_A", key_class="TEST_FIXTURE", public_key_hex=digest("ATTACKER-KEY"))
        branch_index = 2
        for key in tuple(forged[branch_index]):
            if key.startswith("projection_") and key.endswith("_digest"):
                forged[branch_index][key] = invented
        forged[branch_index]["projection_request_digest"] = forged[branch_index]["request_digest"]
        forged[branch_index]["projection_state_digest"] = forged[branch_index]["state_digest"]
        forged[branch_index]["projection_effect_digest"] = forged[branch_index]["effect_digest"]
        forged[branch_index]["projection_adapter_digest"] = forged[branch_index]["adapter_digest"]
        forged[branch_index]["projection_digest"] = projection_digest(forged[branch_index])
        forged[branch_index] = seal_fixture_message(forged[branch_index], attacker)
        with self.assertRaisesRegex(WireError, "signer registry mismatch"):
            validate(registry, forged)

    def test_unsigned_or_prefixless_convergence_cannot_authorize(self) -> None:
        registry, messages = build_transcript("MODE_1")
        with self.assertRaises(WireError):
            validate(registry, messages[5:])

    def test_signature_mutation_and_cross_role_key_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[2]["signature_hex"] = "00" * 32
        with self.assertRaisesRegex(WireError, "signature verification failed"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        cross_role = KeyRecord(
            role="BRANCH_A",
            key_class="TEST_FIXTURE",
            public_key_hex=registry.entries["BRANCH_B"].public_key_hex,
        )
        changed[2] = seal_fixture_message(changed[2], cross_role)
        with self.assertRaises(WireError):
            validate(registry, changed)

    def test_wrong_trust_root_registry_and_test_as_production_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        with self.assertRaisesRegex(WireError, "trust root mismatch"):
            validate_transcript(
                messages,
                registry=registry,
                admission=replace(fixture_admission(registry), trust_root_digest=digest("WRONG-ROOT")),
                verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 500,
            )
        changed = copy.deepcopy(messages)
        for item in changed:
            item["authority_class"] = "PRODUCTION_HSM"
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "registry authority class mismatch|authority/key/algorithm matrix"):
            validate_transcript(
                changed,
                registry=registry,
                admission=replace(fixture_admission(registry), authority_class="PRODUCTION_HSM"),
                verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )

    def test_dormant_registry_role_class_mismatch_rejected(self) -> None:
        registry, messages = build_transcript("MODE_3")
        entries = dict(registry.entries)
        dormant = entries["BRANCH_A"]
        entries["BRANCH_A"] = KeyRecord(
            role="BRANCH_A", key_class="PRODUCTION_HSM",
            public_key_hex=dormant.public_key_hex,
        )
        malformed_registry = type(registry)(root_digest=registry.root_digest, entries=entries)
        changed = copy.deepcopy(messages)
        for item in changed:
            item["trust_registry_digest"] = malformed_registry.digest()
        changed = rechain(changed, malformed_registry)
        with self.assertRaisesRegex(WireError, "registry authority class mismatch"):
            validate_transcript(
                changed, registry=malformed_registry,
                admission=fixture_admission(malformed_registry, "MODE_3"),
                verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
            )

    def test_nonoverlap_witness_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[4]["b_start_ms"] = changed[4]["a_end_ms"]
        changed[4]["b_end_ms"] = changed[4]["a_end_ms"] + 1
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "witness mismatch|did not overlap"):
            validate(registry, changed)

    def test_mode1_release_worker_and_process_transplants_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        for key, value in (
            ("worker_a_id", "OTHER_A"),
            ("a_process_digest", digest("OTHER-PROCESS-A")),
        ):
            changed = copy.deepcopy(messages[:6])
            changed[0][key] = value
            checkpoint = rendezvous_checkpoint_digest(
                "A", changed[0]["traversal_id"], changed[0]["challenge"],
                changed[0]["worker_a_id"], changed[0]["a_process_digest"],
            )
            release = rendezvous_release_digest(
                checkpoint, changed[0]["b_checkpoint_digest"],
                changed[0]["rendezvous_opened_at_ms"], changed[1]["rendezvous_released_at_ms"],
            )
            changed[0]["a_checkpoint_digest"] = checkpoint
            changed[1]["a_checkpoint_digest"] = checkpoint
            changed[1]["rendezvous_release_digest"] = release
            changed = rechain(changed, registry)
            changed[1]["release_request_digest"] = changed[0]["transcript_digest"]
            changed = rechain(changed, registry)
            changed[4].update({
                "a_checkpoint_digest": checkpoint,
                "rendezvous_release_digest": release,
                "release_result_digest": changed[1]["transcript_digest"],
                "statement_a_digest": changed[2]["transcript_digest"],
                "statement_b_digest": changed[3]["transcript_digest"],
                "a_ack_digest": rendezvous_ack_digest("A", release, changed[2]["transcript_digest"]),
                "b_ack_digest": rendezvous_ack_digest("B", release, changed[3]["transcript_digest"]),
            })
            changed = rechain(changed, registry)
            changed[5].update({
                "evidence_a_digest": changed[2]["transcript_digest"],
                "evidence_b_digest": changed[3]["transcript_digest"],
                "mode_evidence_digest": changed[4]["transcript_digest"],
            })
            changed[5]["convergence_digest"] = convergence_digest(
                changed[5]["evidence_a_digest"], changed[5]["evidence_b_digest"],
                changed[5]["mode_evidence_digest"], changed[5]["projection_digest"],
            )
            changed = rechain(changed, registry)
            with self.subTest(field=key), self.assertRaisesRegex(WireError, "Mode 1 release identity transplant"):
                validate_request_prefix(
                    changed, expected_request_kind="convergence_request", registry=registry,
                    admission=fixture_admission(registry), verifier=fixture_verify,
                    trusted_now_ms=BASE_MS + 5_000,
                )

    def test_mode2_non_reduction_and_bad_rejection_coverage_rejected(self) -> None:
        registry, messages = build_transcript("MODE_2")
        for variant in ("equal", "candidate_equal"):
            equal_registry, equal_messages = build_transcript("MODE_2", mode2_variant=variant)
            validate(equal_registry, equal_messages)
        changed = copy.deepcopy(messages)
        widened = digest("WIDENED-CANDIDATE")
        changed[1]["candidate_output_set"] = changed[1]["candidate_output_set"] + "," + widened
        changed = rechain(changed, registry)
        with self.assertRaises(WireError):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[1]["candidate_rejections"] = "NONE"
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "rejection coverage"):
            validate(registry, changed)

    def test_binding_mutation_kind_replay_and_order_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[5]["audit_anchor_digest"] = digest("MUTATED-AUDIT-ANCHOR")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "execution binding mutation"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[5]["extension_admission_binding_digest"] = digest("MUTATED-EXTENSION-BINDING")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "execution binding mutation"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[2]["extension_admission_binding_digest"] = digest("MUTATED-PROJECTION-EXTENSION")
        changed[2]["projection_digest"] = projection_digest(changed[2])
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "execution binding mutation"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[1]["nonce"] = changed[0]["nonce"]
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "nonce replay"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[0], changed[1] = changed[1], changed[0]
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "order mismatch"):
            validate(registry, changed)

    def test_receipt_watchdog_and_deadline_fail_closed(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[-4]["effect_outcome"] = "FAILED"
        changed = rechain(changed, registry)
        with self.assertRaises(WireError):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[-5]["permit_deadline_ms"] = changed[-5]["message_time_ms"] - 1
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "deadline"):
            validate(registry, changed)
        # Every deadline is half-open: equality is already expired.
        deadline_cases = ((11, "lease_deadline_ms"), (13, "watchdog_deadline_ms"), (16, "permit_deadline_ms"))
        for index, key in deadline_cases:
            changed = copy.deepcopy(messages)
            changed[index][key] = changed[index]["message_time_ms"]
            changed = rechain(changed, registry)
            with self.subTest(kind=changed[index]["kind"]), self.assertRaises(WireError):
                validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[-4]["adapter_consumed_at_ms"] = changed[-5]["permit_deadline_ms"]
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "consumption freshness"):
            validate(registry, changed)

    def test_canonical_json_and_frame_adversaries(self) -> None:
        registry, messages = build_transcript("MODE_1")
        payload = encode_message(messages[2])
        cases = (
            b" " + payload,
            payload[:-1] + b',"zz_extra":"x"}',
            payload.replace(b'"sequence":2', b'"sequence":02'),
            payload.replace(b'"worker_id":"WORKER_A_001"', b'"worker_id":"\\ud800"'),
            payload.replace(b'"kind":"branch_a_statement"', b'"kind":"branch_a_statement","kind":"branch_a_statement"'),
        )
        for bad in cases:
            with self.subTest(bad=bad[:30]), self.assertRaises(WireError):
                parse_message(bad)
        with self.assertRaises(WireError):
            decode_frame((MAX_FRAME_BYTES + 1).to_bytes(4, "big") + b"x" * (MAX_FRAME_BYTES + 1))
        with self.assertRaises(WireError):
            decode_frame(encode_frame(messages[0]) + b"x")

    def test_adversarial_inventory_is_complete(self) -> None:
        actual = set((ROOT / "vectors" / "adversarial_cases.txt").read_text(encoding="ascii").splitlines())
        expected = {
            "authority_key_algorithm_downgrade", "binding_mutation", "causal_rendezvous_mutation",
            "cross_role_signature", "duplicate_field", "extra_field", "failed_effect_success_ack",
            "future_message", "invented_equal_digests", "invalid_mode2_reduction",
            "missing_field", "mode2_rejection_gap", "mode3_provenance_substitution",
            "noncanonical_integer", "nonoverlap_witness", "order_mismatch", "oversize",
            "prefixless_convergence", "registry_mismatch", "registry_substitution_same_root",
            "replay_nonce", "same_core_alias", "semantic_provenance_substitution",
            "signature_mutation", "stable_effect_metadata_replay_bypass", "surrogate_escape",
            "timeout_success", "unadmitted_role_key", "wrong_projection_digest",
            "forged_staged_result", "late_staged_watchdog_result",
            "masked_zero_authority_artifact", "staged_callback_before_validation",
            "authority_epoch_mutation", "authority_epoch_zero",
            "domain_identity_mutation", "subject_identity_mutation",
            "authority_artifact_nonzero_transplant", "authority_artifact_id_derivation",
            "authority_artifact_id_handoff_transplant", "denial_nonzero_artifact_id",
            "mode1_release_worker_transplant", "mode1_release_process_transplant",
            "unused_role_registry_class", "point_of_use_mutation",
            "present_receipt_zero_sentinel", "receipt_digest_transplant",
            "success_tail_permit_id_transplant", "timeout_tail_permit_id_transplant",
            "failure_ack_permit_pair_transplant",
            "retrocausal_mode1_release",
            "mode1_witness_time_transplant",
            "release_denial_nonzero_evidence",
            "staged_lease_result_expired", "staged_watchdog_result_expired",
            "late_no_receipt_terminal", "late_no_receipt_block_result",
            "extension_admission_binding_mutation",
            "extension_projection_policy_mismatch",
            "extension_configuration_zero",
            "extension_admission_binding_zero",
        }
        self.assertEqual(actual, expected)

    def test_expired_and_future_messages_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        with self.assertRaisesRegex(WireError, "trusted-time freshness"):
            validate_transcript(
                messages,
                registry=registry,
                admission=fixture_admission(registry),
                verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 20_000,
            )

    def test_registry_digest_is_independently_pinned(self) -> None:
        from .sbp_lex_wire_v2 import TrustRegistry

        registry, messages = build_transcript("MODE_1")
        entries = dict(registry.entries)
        entries["WITNESS"] = KeyRecord(role="WITNESS", key_class="TEST_FIXTURE", public_key_hex=digest("UNPINNED-WITNESS"))
        substituted = TrustRegistry(root_digest=registry.root_digest, entries=entries)
        with self.assertRaisesRegex(WireError, "registry mismatch"):
            validate_transcript(
                messages,
                registry=substituted,
                admission=fixture_admission(registry),
                verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 5_000,
            )

    def test_future_message_semantic_provenance_and_same_core_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        with self.assertRaisesRegex(WireError, "trusted-time freshness"):
            validate_transcript(
                messages,
                registry=registry,
                admission=fixture_admission(registry),
                verifier=fixture_verify,
                trusted_now_ms=BASE_MS + 50,
            )
        changed = copy.deepcopy(messages)
        changed[2]["code_provenance_digest"] = digest("UNADMITTED-CODE-A")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "semantic provenance"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[3]["callable_digest"] = changed[2]["callable_digest"]
        changed = rechain(changed, registry)
        policy = replace(fixture_admission(registry), branch_b_callable_digest=changed[2]["callable_digest"])
        with self.assertRaisesRegex(WireError, "not distinct"):
            validate_transcript(changed, registry=registry, admission=policy, verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000)

    def test_causal_rendezvous_and_stable_effect_binding_rejected_on_mutation(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[4]["rendezvous_release_digest"] = digest("INVENTED-RELEASE")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "causal rendezvous"):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        for item in changed:
            item["stable_request_digest"] = digest("FRESH-METADATA-BYPASS")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "stable request derivation|expected execution context mismatch"):
            validate(registry, changed)
        admission = replace(fixture_admission(registry), replay_namespace=digest("FRESH-REPLAY-NAMESPACE"))
        with self.assertRaisesRegex(WireError, "expected execution context mismatch"):
            validate_transcript(messages, registry=registry, admission=admission, verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000)

    def test_mode3_implementation_provenance_is_pinned(self) -> None:
        registry, messages = build_transcript("MODE_3")
        changed = copy.deepcopy(messages)
        changed[0]["single_state_provenance_digest"] = digest("UNADMITTED-SINGLE-STATE")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "Mode 3 semantic provenance"):
            validate(registry, changed)

    def test_later_denial_does_not_sanitize_prior_invalid_authority(self) -> None:
        registry, messages = build_transcript("MODE_1")
        # Prefix through lease result; make lease result a terminal denial while
        # corrupting the already successful PREPARE -> COMMIT proof handoff.
        truncated = copy.deepcopy(messages[:13])
        truncated[9]["prepare_proof_digest"] = digest("WRONG-PREPARE-PROOF")
        truncated[-1]["decision"] = "DENY"
        truncated[-1]["error_code"] = "LEASE_DENIED"
        truncated = rechain(truncated, registry)
        with self.assertRaisesRegex(WireError, "authority lifecycle handoff|denied authority artifact"):
            validate(registry, truncated)
        truncated = copy.deepcopy(messages[:13])
        truncated[12]["lease_deadline_ms"] += 1
        truncated[12]["decision"] = "DENY"
        truncated[12]["error_code"] = "LEASE_DENIED"
        truncated = rechain(truncated, registry)
        with self.assertRaisesRegex(WireError, "authority lifecycle handoff|denied authority artifact"):
            validate(registry, truncated)

    def test_receipt_after_watchdog_and_arbitrary_consumption_digest_rejected(self) -> None:
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[-4]["message_time_ms"] = changed[13]["watchdog_deadline_ms"]
        changed[-4]["adapter_consumed_at_ms"] = changed[13]["watchdog_deadline_ms"] - 1
        changed = rechain(changed, registry)
        with self.assertRaises(WireError):
            validate(registry, changed)
        changed = copy.deepcopy(messages)
        changed[-4]["adapter_consumption_digest"] = digest("ARBITRARY-CONSUMPTION")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "consumption derivation"):
            validate(registry, changed)
        for index in (-3, -2, -1):
            changed = copy.deepcopy(messages)
            changed[index]["message_time_ms"] = changed[-5]["permit_deadline_ms"]
            changed = rechain(changed, registry)
            with self.subTest(kind=changed[index]["kind"]), self.assertRaises(WireError):
                validate(registry, changed)

    def test_mode3_opaque_proof_and_mode1_unadmitted_release_rejected(self) -> None:
        registry, messages = build_transcript("MODE_3")
        changed = copy.deepcopy(messages)
        changed[0]["single_state_proof_digest"] = digest("OPAQUE-PROOF")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "proof derivation"):
            validate(registry, changed)
        registry, messages = build_transcript("MODE_1")
        changed = copy.deepcopy(messages)
        changed[1]["rendezvous_release_digest"] = digest("WITNESS-ONLY-RELEASE")
        changed = rechain(changed, registry)
        with self.assertRaisesRegex(WireError, "admitted causal release"):
            validate(registry, changed)


if __name__ == "__main__":
    unittest.main()
