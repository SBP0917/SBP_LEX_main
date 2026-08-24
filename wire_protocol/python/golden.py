"""Deterministic, non-production SBP-LEX-WIRE/1 golden transcript builder."""

from __future__ import annotations

import hashlib

from .sbp_lex_wire import ORACLE_SHA256, PROTOCOL, ZERO_DIGEST, encode_message, seal_message


def _digest(label: str) -> str:
    return hashlib.sha256(("SBP-LEX-GOLDEN-V1:" + label).encode("ascii")).hexdigest()


def _key(role: str) -> tuple[str, str]:
    public_key = _digest(f"{role.lower()}-test-public-key")
    return public_key, hashlib.sha256(bytes.fromhex(public_key)).hexdigest()


def build_golden_transcript() -> list[dict[str, object]]:
    kinds_and_extras: list[tuple[str, dict[str, object]]] = [
        (
            "convergence_request",
            {
                "branch_a_provenance_digest": _digest("branch-a-provenance"),
                "branch_b_provenance_digest": _digest("branch-b-provenance"),
                "candidate_input_set": "NONE",
                "candidate_output_set": "NONE",
                "mode_evidence_digest": _digest("mode-1-evidence"),
                "mode_evidence_type": "DUAL_EXECUTION_PROOF",
                "no_widening_proof_digest": ZERO_DIGEST,
                "pathway_input_set": "NONE",
                "pathway_output_set": "NONE",
                "policy_projection_digest": _digest("execution-projection"),
                "projection_a_digest": _digest("execution-projection"),
                "projection_b_digest": _digest("execution-projection"),
                "snapshot_a_digest": _digest("snapshot-a"),
                "snapshot_b_digest": _digest("snapshot-b"),
                "validator_certificate_digest": ZERO_DIGEST,
            },
        ),
        (
            "convergence_result",
            {"convergence_digest": _digest("convergence"), "decision": "ALLOW"},
        ),
        ("prepare_request", {"convergence_digest": _digest("convergence")}),
        (
            "prepare_result",
            {"decision": "ALLOW", "prepare_proof_digest": _digest("prepare-proof")},
        ),
        ("commit_request", {"prepare_proof_digest": _digest("prepare-proof")}),
        (
            "commit_result",
            {"capability_digest": _digest("capability"), "decision": "ALLOW"},
        ),
        (
            "lease_redeem_request",
            {
                "capability_digest": _digest("capability"),
                "lease_deadline_ms": 1_900_000_000_400,
                "lease_digest": _digest("lease"),
            },
        ),
        (
            "lease_redeem_result",
            {
                "decision": "ALLOW",
                "lease_deadline_ms": 1_900_000_000_400,
                "lease_digest": _digest("lease"),
            },
        ),
        (
            "watchdog_arm_request",
            {
                "lease_digest": _digest("lease"),
                "watchdog_deadline_ms": 1_900_000_000_600,
            },
        ),
        (
            "watchdog_arm_result",
            {
                "decision": "ALLOW",
                "watchdog_deadline_ms": 1_900_000_000_600,
                "watchdog_digest": _digest("watchdog"),
            },
        ),
        (
            "effect_permit_request",
            {
                "lease_deadline_ms": 1_900_000_000_400,
                "lease_digest": _digest("lease"),
                "point_of_use_digest": _digest("point-of-use"),
                "watchdog_deadline_ms": 1_900_000_000_600,
                "watchdog_digest": _digest("watchdog"),
            },
        ),
        (
            "effect_permit_result",
            {
                "decision": "ALLOW",
                "permit_deadline_ms": 1_900_000_000_300,
                "permit_digest": _digest("permit"),
                "watchdog_digest": _digest("watchdog"),
            },
        ),
        (
            "effect_receipt",
            {
                "adapter_consumption_digest": _digest("adapter-consumption"),
                "adapter_consumed_at_ms": 1_900_000_000_115,
                "effect_outcome": "SUCCEEDED",
                "permit_digest": _digest("permit"),
                "receipt_digest": _digest("receipt"),
                "watchdog_digest": _digest("watchdog"),
            },
        ),
        (
            "receipt_ack",
            {
                "decision": "ACK",
                "receipt_digest": _digest("receipt"),
                "receipt_status": "SUCCESS_RECORDED",
                "watchdog_digest": _digest("watchdog"),
            },
        ),
        (
            "watchdog_terminal",
            {
                "permit_digest": _digest("permit"),
                "receipt_digest": _digest("receipt"),
                "watchdog_digest": _digest("watchdog"),
                "watchdog_status": "HEALTHY",
            },
        ),
        (
            "watchdog_result",
            {"decision": "ACK", "watchdog_digest": _digest("watchdog")},
        ),
    ]
    signer_roles = {
        1: "AUTHORITY",
        3: "AUTHORITY",
        5: "AUTHORITY",
        7: "AUTHORITY",
        9: "AUTHORITY",
        11: "AUTHORITY",
        12: "ADAPTER",
        13: "AUTHORITY",
        14: "WATCHDOG",
        15: "AUTHORITY",
    }
    keys = {role: _key(role) for role in ("AUTHORITY", "ADAPTER", "WATCHDOG")}
    prior = ZERO_DIGEST
    result: list[dict[str, object]] = []
    for sequence, (kind, extras) in enumerate(kinds_and_extras):
        signer_role = signer_roles.get(sequence, "NONE")
        checked = signer_role != "NONE"
        public_key, signer_key_id = keys.get(signer_role, ("NONE", ZERO_DIGEST))
        message: dict[str, object] = {
            "adapter_digest": _digest("adapter"),
            "adapter_boundary_digest": _digest("adapter-boundary"),
            "adapter_key_class": "TEST_FIXTURE",
            "adapter_key_id": keys["ADAPTER"][1],
            "audit_anchor_digest": _digest("audit-anchor"),
            "authority_build_id": _digest("authority-build"),
            "authority_class": "TEST_ONLY",
            "authority_key_class": "TEST_FIXTURE",
            "authority_key_id": keys["AUTHORITY"][1],
            "authority_profile": "FIXED_LOCAL_TEST_ONLY",
            "challenge": _digest("challenge"),
            "crypto_evidence_digest": _digest(f"crypto-evidence-{sequence}") if checked else ZERO_DIGEST,
            "crypto_key_class": "TEST_FIXTURE" if checked else "NONE",
            "crypto_result": "SIGNATURE_PRESENT" if checked else "NOT_CHECKED",
            "durable_consumption_digest": _digest("durable-consumption"),
            "effect_digest": _digest("effect"),
            "effect_intent_digest": _digest("effect-intent"),
            "error_code": "NONE",
            "expires_at_ms": 1_900_000_001_000,
            "inhibit_binding_digest": _digest("inhibit-binding"),
            "interlock_digest": _digest("interlock"),
            "issued_at_ms": 1_900_000_000_000,
            "kind": kind,
            "message_time_ms": 1_900_000_000_000 + sequence * 10,
            "mode": "MODE_1",
            "not_before_ms": 1_899_999_999_000,
            "nonce": _digest(f"nonce-{sequence}"),
            "operation_id": "4" * 32,
            "oracle_sha256": ORACLE_SHA256,
            "prior_transcript_digest": prior,
            "protocol": PROTOCOL,
            "request_digest": _digest("request"),
            "replay_namespace": _digest("replay-namespace"),
            "runtime_subject": "1" * 40,
            "runtime_tree": "2" * 40,
            "sequence": sequence,
            "signature_algorithm": "ML-DSA-65" if checked else "NONE",
            "signature_hex": _digest(f"synthetic-signature-{sequence}") if checked else "NONE",
            "signer_key_id": signer_key_id,
            "signer_role": signer_role,
            "signing_public_key_hex": public_key,
            "state_digest": _digest("state"),
            "traversal_id": "3" * 32,
            "watchdog_key_class": "TEST_FIXTURE",
            "watchdog_key_id": keys["WATCHDOG"][1],
            **extras,
        }
        sealed = seal_message(message)
        result.append(sealed)
        prior = sealed["transcript_digest"]  # type: ignore[assignment]
    return result


if __name__ == "__main__":
    for item in build_golden_transcript():
        print(encode_message(item).decode("ascii"))
