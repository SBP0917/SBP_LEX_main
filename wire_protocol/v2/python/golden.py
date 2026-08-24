"""Deterministic TEST_ONLY vectors for SBP-LEX-AUTH-WIRE/2."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .sbp_lex_wire_v2 import (
    ORACLE_SHA512,
    PROTOCOL,
    ZERO,
    ZERO_ID,
    KeyRecord,
    TrustRegistry,
    convergence_digest,
    durable_consumption_digest,
    point_of_use_digest,
    projection_digest,
    rendezvous_ack_digest,
    rendezvous_checkpoint_digest,
    rendezvous_release_digest,
    seal_fixture_message,
    set_digest,
    stable_effect_intent_digest,
    stable_request_digest,
    AdmissionPolicy,
    adapter_consumption_digest,
    effect_receipt_digest,
    authority_artifact_digest,
    authority_artifact_id,
    fixture_verify,
    mode3_single_state_proof_digest,
    mode3_state_seal_digest,
    validate_request_prefix,
)

BASE_MS = 2_000_000_000_000
TRUST_ROOT = hashlib.sha512(b"SBP-LEX-WIRE-V2-OWNER-ROOT").hexdigest()
EXTENSION_ADMISSION_MODE = "EXTENSIONS_DISABLED"
EXTENSION_SCHEMA = "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED"

ROLES = (
    "ADAPTER",
    "AUTHORITY",
    "BRANCH_A",
    "BRANCH_B",
    "COORDINATOR",
    "SINGLE_STATE",
    "VALIDATOR",
    "WATCHDOG",
    "WITNESS",
)


def digest(label: str) -> str:
    return hashlib.sha512(("SBP-LEX-WIRE-V2|" + label).encode("ascii")).hexdigest()


EXTENSION_CONFIGURATION_DIGEST = digest("EXTENSION-CONFIGURATION")
EXTENSION_ADMISSION_BINDING_DIGEST = digest("EXTENSION-ADMISSION-BINDING")


def fixture_registry() -> TrustRegistry:
    return TrustRegistry(
        root_digest=TRUST_ROOT,
        entries={
            role: KeyRecord(role=role, key_class="TEST_FIXTURE", public_key_hex=digest("PUBLIC-KEY|" + role))
            for role in ROLES
        },
    )


def fixture_admission(registry: TrustRegistry | None = None, mode: str = "MODE_1") -> AdmissionPolicy:
    admitted = registry or fixture_registry()
    return AdmissionPolicy(
        trust_root_digest=admitted.root_digest,
        registry_digest=admitted.digest(),
        runtime_subject=digest("RUNTIME-SUBJECT"),
        runtime_tree=digest("RUNTIME-TREE"),
        authority_class="TEST_ONLY",
        authority_epoch=7,
        authority_profile="DISPOSABLE_TEST_EVIDENCE_ONLY",
        authority_build_id="CANDIDATE10-WIRE-V2-TEST",
        mode=mode,
        traversal_id=digest("TRAVERSAL")[:32],
        operation_id=digest("OPERATION")[:32],
        challenge=digest("CHALLENGE"),
        replay_namespace=digest("REPLAY-NAMESPACE"),
        stable_request_digest=stable_request_digest(digest("REQUEST")),
        request_digest=digest("REQUEST"),
        state_digest=digest("STATE"),
        effect_digest=digest("EFFECT"),
        effect_intent_digest=digest("EFFECT-INTENT"),
        adapter_digest=digest("ADAPTER"),
        adapter_boundary_digest=digest("ADAPTER-BOUNDARY"),
        inhibit_binding_digest=digest("INHIBIT"),
        interlock_digest=digest("INTERLOCK"),
        audit_anchor_digest=digest("AUDIT-ANCHOR"),
        domain_digest=digest("DOMAIN-IDENTITY"),
        subject_digest=digest("SUBJECT-IDENTITY"),
        extension_admission_mode=EXTENSION_ADMISSION_MODE,
        extension_schema=EXTENSION_SCHEMA,
        extension_configuration_digest=EXTENSION_CONFIGURATION_DIGEST,
        extension_admission_binding_digest=EXTENSION_ADMISSION_BINDING_DIGEST,
        branch_a_callable_digest=digest("CALLABLE-A"),
        branch_a_code_provenance_digest=digest("CODE-A"),
        branch_b_callable_digest=digest("CALLABLE-B"),
        branch_b_code_provenance_digest=digest("CODE-B"),
        validator_code_digest=digest("VALIDATOR-CODE"),
        validator_provenance_digest=digest("VALIDATOR-PROVENANCE"),
        single_state_callable_digest=digest("SINGLE-STATE-CALLABLE"),
        single_state_provenance_digest=digest("SINGLE-STATE-PROVENANCE"),
    )


def projection(*, candidate: str | None = None, pathway: str | None = None) -> dict[str, object]:
    values: dict[str, object] = {
        "projection_schema": "SBP-LEX-EXEC-PROJECTION/2",
        "extension_admission_mode": EXTENSION_ADMISSION_MODE,
        "extension_schema": EXTENSION_SCHEMA,
        "extension_configuration_digest": EXTENSION_CONFIGURATION_DIGEST,
        "extension_admission_binding_digest": EXTENSION_ADMISSION_BINDING_DIGEST,
        "projection_request_digest": digest("REQUEST"),
        "projection_state_digest": digest("STATE"),
        "projection_effect_digest": digest("EFFECT"),
        "projection_adapter_digest": digest("ADAPTER"),
        "projection_audit_context_digest": digest("AUDIT-CONTEXT"),
        "projection_aurion_digest": digest("AURION"),
        "projection_candidate_digest": candidate or digest("CANDIDATE"),
        "projection_constraints_digest": digest("CONSTRAINTS"),
        "projection_domain_digest": digest("DOMAIN"),
        "projection_mode_freeze_digest": digest("MODE-FREEZE"),
        "projection_outcome_digest": digest("OUTCOME"),
        "projection_pathway_digest": pathway or digest("PATHWAY"),
        "projection_policy_digest": digest("POLICY"),
        "projection_provider_linkage_digest": digest("PROVIDER-LINKAGE"),
        "projection_token_stack_digest": digest("TOKEN-STACK"),
        "projection_digest": ZERO,
    }
    values["projection_digest"] = projection_digest(values)
    return values


@dataclass
class Builder:
    mode: str
    registry: TrustRegistry = field(default_factory=fixture_registry)
    messages: list[dict[str, object]] = field(default_factory=list)

    def append(
        self,
        kind: str,
        role: str,
        extras: dict[str, object],
        *,
        error_code: str = "NONE",
        at_ms: int | None = None,
    ) -> dict[str, object]:
        sequence = len(self.messages)
        stable_request = stable_request_digest(digest("REQUEST"))
        stable_intent = stable_effect_intent_digest(
            stable_request, digest("EFFECT-INTENT"), digest("EFFECT"),
            digest("ADAPTER"), digest("ADAPTER-BOUNDARY"),
        )
        fields: dict[str, object] = {
            "adapter_boundary_digest": digest("ADAPTER-BOUNDARY"),
            "adapter_digest": digest("ADAPTER"),
            "audit_anchor_digest": digest("AUDIT-ANCHOR"),
            "authority_build_id": "CANDIDATE10-WIRE-V2-TEST",
            "authority_class": "TEST_ONLY",
            "authority_epoch": 7,
            "authority_profile": "DISPOSABLE_TEST_EVIDENCE_ONLY",
            "challenge": digest("CHALLENGE"),
            "domain_digest": digest("DOMAIN-IDENTITY"),
            "durable_consumption_digest": durable_consumption_digest(digest("REPLAY-NAMESPACE"), stable_intent),
            "effect_digest": digest("EFFECT"),
            "effect_intent_digest": digest("EFFECT-INTENT"),
            "extension_admission_binding_digest": EXTENSION_ADMISSION_BINDING_DIGEST,
            "extension_admission_mode": EXTENSION_ADMISSION_MODE,
            "extension_configuration_digest": EXTENSION_CONFIGURATION_DIGEST,
            "extension_schema": EXTENSION_SCHEMA,
            "error_code": error_code,
            "expires_at_ms": BASE_MS + 10_000,
            "inhibit_binding_digest": digest("INHIBIT"),
            "interlock_digest": digest("INTERLOCK"),
            "issued_at_ms": BASE_MS,
            "kind": kind,
            "message_time_ms": at_ms if at_ms is not None else BASE_MS + 100 + sequence * 10,
            "mode": self.mode,
            "nonce": digest(f"NONCE|{self.mode}|{sequence}"),
            "not_before_ms": BASE_MS - 1_000,
            "operation_id": digest("OPERATION")[:32],
            "oracle_sha512": ORACLE_SHA512,
            "prior_transcript_digest": self.messages[-1]["transcript_digest"] if self.messages else ZERO,
            "protocol": PROTOCOL,
            "replay_namespace": digest("REPLAY-NAMESPACE"),
            "request_digest": digest("REQUEST"),
            "runtime_subject": digest("RUNTIME-SUBJECT"),
            "runtime_tree": digest("RUNTIME-TREE"),
            "sequence": sequence,
            "state_digest": digest("STATE"),
            "stable_effect_intent_digest": stable_intent,
            "stable_request_digest": stable_request,
            "subject_digest": digest("SUBJECT-IDENTITY"),
            "traversal_id": digest("TRAVERSAL")[:32],
            "trust_registry_digest": self.registry.digest(),
            "trust_root_digest": self.registry.root_digest,
        }
        fields.update(extras)
        result_stage = {
            "prepare_result": ("prepare_request", "prepare_proof_digest", "prepare_id"),
            "commit_result": ("commit_request", "capability_digest", "capability_id"),
            "lease_redeem_result": ("lease_redeem_request", "lease_digest", "lease_id"),
            "watchdog_arm_result": ("watchdog_arm_request", "watchdog_digest", None),
            "effect_permit_result": ("effect_permit_request", "permit_digest", "permit_id"),
        }.get(kind)
        if result_stage is not None:
            stage, artifact, identity = result_stage
            if fields.get("decision") == "ALLOW":
                context = validate_request_prefix(
                    self.messages, expected_request_kind=stage,
                    registry=self.registry, admission=fixture_admission(self.registry, self.mode),
                    verifier=fixture_verify, trusted_now_ms=BASE_MS + 5_000,
                )
                fields["signer_key_id"] = self.registry.entries[role].key_id
                fields[artifact] = authority_artifact_digest(
                    stage, context, self.messages[-1], fields,
                )
                if identity is not None:
                    fields[identity] = authority_artifact_id(stage, fields[artifact])
                fields.pop("signer_key_id")
            else:
                fields[artifact] = ZERO
                if identity is not None:
                    fields[identity] = ZERO_ID
        result = seal_fixture_message(fields, self.registry.entries[role])
        self.messages.append(result)
        return result


def _append_mode1(builder: Builder) -> None:
    projected = projection()
    worker_a, worker_b = "WORKER_A_001", "WORKER_B_001"
    process_a, process_b = digest("PROCESS-A"), digest("PROCESS-B")
    traversal, challenge = digest("TRAVERSAL")[:32], digest("CHALLENGE")
    checkpoint_a = rendezvous_checkpoint_digest("A", traversal, challenge, worker_a, process_a)
    checkpoint_b = rendezvous_checkpoint_digest("B", traversal, challenge, worker_b, process_b)
    opened_at = BASE_MS + 1
    release_request = builder.append(
        "mode1_release_request",
        "COORDINATOR",
        {
            "a_checkpoint_digest": checkpoint_a,
            "a_process_digest": process_a,
            "b_checkpoint_digest": checkpoint_b,
            "b_process_digest": process_b,
            "rendezvous_opened_at_ms": opened_at,
            "worker_a_id": worker_a,
            "worker_b_id": worker_b,
        },
    )
    # The equality boundary is deliberately exercised: an authority may release
    # at the signed request time, never before it.
    released_at = int(release_request["message_time_ms"])
    release = rendezvous_release_digest(checkpoint_a, checkpoint_b, opened_at, released_at)
    release_result = builder.append(
        "mode1_release_result",
        "AUTHORITY",
        {
            "a_checkpoint_digest": checkpoint_a,
            "b_checkpoint_digest": checkpoint_b,
            "decision": "ALLOW",
            "release_request_digest": release_request["transcript_digest"],
            "rendezvous_opened_at_ms": opened_at,
            "rendezvous_release_digest": release,
            "rendezvous_released_at_ms": released_at,
        },
    )
    a = builder.append(
        "branch_a_statement",
        "BRANCH_A",
        projected
        | {
            "callable_digest": digest("CALLABLE-A"),
            "code_provenance_digest": digest("CODE-A"),
            "process_digest": process_a,
            "release_checkpoint_digest": checkpoint_a,
            "snapshot_digest": digest("SNAPSHOT-A"),
            "substantive_end_ms": BASE_MS + 118,
            # Exercise the admitted half-open causal boundary: substantive work
            # may start exactly when the signed authority release occurs.
            "substantive_start_ms": released_at,
            "worker_id": worker_a,
        },
    )
    b = builder.append(
        "branch_b_statement",
        "BRANCH_B",
        projected
        | {
            "callable_digest": digest("CALLABLE-B"),
            "code_provenance_digest": digest("CODE-B"),
            "process_digest": process_b,
            "release_checkpoint_digest": checkpoint_b,
            "snapshot_digest": digest("SNAPSHOT-B"),
            "substantive_end_ms": BASE_MS + 119,
            "substantive_start_ms": BASE_MS + 108,
            "worker_id": worker_b,
        },
    )
    witness = builder.append(
        "mode1_overlap_witness",
        "WITNESS",
        {
            "a_ack_digest": rendezvous_ack_digest("A", release, a["transcript_digest"]),
            "a_checkpoint_digest": checkpoint_a,
            "a_process_digest": process_a,
            "a_end_ms": a["substantive_end_ms"],
            "a_start_ms": a["substantive_start_ms"],
            "b_end_ms": b["substantive_end_ms"],
            "b_ack_digest": rendezvous_ack_digest("B", release, b["transcript_digest"]),
            "b_checkpoint_digest": checkpoint_b,
            "b_process_digest": process_b,
            "b_start_ms": b["substantive_start_ms"],
            "projection_digest": a["projection_digest"],
            "statement_a_digest": a["transcript_digest"],
            "statement_b_digest": b["transcript_digest"],
            "rendezvous_opened_at_ms": opened_at,
            "rendezvous_release_digest": release,
            "rendezvous_released_at_ms": released_at,
            "release_result_digest": release_result["transcript_digest"],
            "worker_a_id": a["worker_id"],
            "worker_b_id": b["worker_id"],
        },
    )
    _append_convergence(builder, a["transcript_digest"], b["transcript_digest"], witness["transcript_digest"], a["projection_digest"])


def _append_mode2(builder: Builder, variant: str = "strict") -> None:
    candidates = sorted(digest(name) for name in ("CANDIDATE-1", "CANDIDATE-2", "CANDIDATE-3"))
    pathways = sorted(digest(name) for name in ("PATHWAY-1", "PATHWAY-2", "PATHWAY-3"))
    admitted_candidates = candidates if variant in {"equal", "candidate_equal"} else candidates[:2]
    admitted_pathways = pathways if variant == "equal" else pathways[:2]
    input_candidate_set, output_candidate_set = ",".join(candidates), ",".join(admitted_candidates)
    input_pathway_set, output_pathway_set = ",".join(pathways), ",".join(admitted_pathways)
    primary = builder.append(
        "branch_a_statement",
        "BRANCH_A",
        projection(candidate=set_digest(input_candidate_set), pathway=set_digest(input_pathway_set))
        | {
            "callable_digest": digest("CALLABLE-A"),
            "code_provenance_digest": digest("CODE-A"),
            "process_digest": digest("MODE2-PROCESS-A"),
            "release_checkpoint_digest": ZERO,
            "snapshot_digest": digest("SNAPSHOT-A"),
            "substantive_end_ms": BASE_MS + 40,
            "substantive_start_ms": BASE_MS + 10,
            "worker_id": "WORKER_A_001",
        },
    )
    cert = builder.append(
        "mode2_validator_certificate",
        "VALIDATOR",
        projection(candidate=set_digest(output_candidate_set), pathway=set_digest(output_pathway_set))
        | {
            "candidate_input_set": input_candidate_set,
            "candidate_output_set": output_candidate_set,
            "candidate_rejections": "NONE" if admitted_candidates == candidates else candidates[2] + "=POLICY_REJECTED",
            "pathway_input_set": input_pathway_set,
            "pathway_output_set": output_pathway_set,
            "pathway_rejections": "NONE" if admitted_pathways == pathways else pathways[2] + "=CONSTRAINT_REJECTED",
            "primary_statement_digest": primary["transcript_digest"],
            "validator_code_digest": digest("VALIDATOR-CODE"),
            "validator_provenance_digest": digest("VALIDATOR-PROVENANCE"),
        },
    )
    _append_convergence(builder, primary["transcript_digest"], cert["transcript_digest"], cert["transcript_digest"], cert["projection_digest"])


def _append_mode3(builder: Builder) -> None:
    projected = projection()
    callable_digest = digest("SINGLE-STATE-CALLABLE")
    provenance_digest = digest("SINGLE-STATE-PROVENANCE")
    seal = mode3_state_seal_digest(digest("STATE"), projected["projection_mode_freeze_digest"], projected["projection_digest"], digest("TRAVERSAL")[:32], digest("CHALLENGE"))
    proof = builder.append(
        "mode3_single_state_proof",
        "SINGLE_STATE",
        projected
        | {
            "single_state_callable_digest": callable_digest,
            "single_state_proof_digest": mode3_single_state_proof_digest(seal, callable_digest, provenance_digest),
            "single_state_provenance_digest": provenance_digest,
            "state_seal_digest": seal,
        },
    )
    _append_convergence(builder, proof["transcript_digest"], ZERO, proof["transcript_digest"], proof["projection_digest"])


def _append_convergence(builder: Builder, a: object, b: object, evidence: object, projected: object) -> None:
    convergence = convergence_digest(str(a), str(b), str(evidence), str(projected))
    extras = {
        "convergence_digest": convergence,
        "evidence_a_digest": a,
        "evidence_b_digest": b,
        "mode_evidence_digest": evidence,
        "projection_digest": projected,
    }
    builder.append("convergence_request", "COORDINATOR", extras)
    builder.append("convergence_result", "AUTHORITY", extras | {"decision": "ALLOW"})


def _append_authority_lifecycle(
    builder: Builder, *, outcome: str = "SUCCEEDED", timeout: bool = False,
    deadline_offsets: tuple[int, int, int] = (2_000, 2_500, 1_500),
) -> None:
    convergence = builder.messages[-1]["convergence_digest"]
    builder.append("prepare_request", "COORDINATOR", {"convergence_digest": convergence})
    prepare = builder.append("prepare_result", "AUTHORITY", {"decision": "ALLOW", "prepare_id": ZERO_ID, "prepare_proof_digest": ZERO})
    builder.append("commit_request", "COORDINATOR", {"prepare_id": prepare["prepare_id"], "prepare_proof_digest": prepare["prepare_proof_digest"]})
    commit = builder.append("commit_result", "AUTHORITY", {"capability_digest": ZERO, "capability_id": ZERO_ID, "decision": "ALLOW"})
    lease_offset, watchdog_offset, permit_offset = deadline_offsets
    lease_deadline = BASE_MS + lease_offset
    builder.append("lease_redeem_request", "ADAPTER", {"capability_digest": commit["capability_digest"], "capability_id": commit["capability_id"], "lease_deadline_ms": lease_deadline})
    lease = builder.append("lease_redeem_result", "AUTHORITY", {"decision": "ALLOW", "lease_deadline_ms": lease_deadline, "lease_digest": ZERO, "lease_id": ZERO_ID})
    watchdog_deadline = BASE_MS + watchdog_offset
    builder.append("watchdog_arm_request", "COORDINATOR", {"lease_digest": lease["lease_digest"], "lease_id": lease["lease_id"], "watchdog_deadline_ms": watchdog_deadline})
    armed = builder.append("watchdog_arm_result", "WATCHDOG", {"decision": "ALLOW", "watchdog_deadline_ms": watchdog_deadline, "watchdog_digest": digest("WATCHDOG")})
    permit_deadline = BASE_MS + permit_offset
    permit_request_fields = {
        "authority_build_id": "CANDIDATE10-WIRE-V2-TEST",
        "authority_class": "TEST_ONLY",
        "authority_epoch": 7,
        "authority_profile": "DISPOSABLE_TEST_EVIDENCE_ONLY",
        "adapter_boundary_digest": digest("ADAPTER-BOUNDARY"),
        "adapter_digest": digest("ADAPTER"),
        "audit_anchor_digest": digest("AUDIT-ANCHOR"),
        "domain_digest": digest("DOMAIN-IDENTITY"),
        "durable_consumption_digest": builder.messages[0]["durable_consumption_digest"],
        "effect_digest": digest("EFFECT"),
        "effect_intent_digest": digest("EFFECT-INTENT"),
        "inhibit_binding_digest": digest("INHIBIT"),
        "interlock_digest": digest("INTERLOCK"),
        "lease_deadline_ms": lease_deadline,
        "lease_digest": lease["lease_digest"],
        "lease_id": lease["lease_id"],
        "operation_id": digest("OPERATION")[:32],
        "replay_namespace": digest("REPLAY-NAMESPACE"),
        "request_digest": digest("REQUEST"),
        "stable_effect_intent_digest": builder.messages[0]["stable_effect_intent_digest"],
        "stable_request_digest": builder.messages[0]["stable_request_digest"],
        "state_digest": digest("STATE"),
        "subject_digest": digest("SUBJECT-IDENTITY"),
        "traversal_id": digest("TRAVERSAL")[:32],
        "watchdog_deadline_ms": watchdog_deadline,
        "watchdog_digest": armed["watchdog_digest"],
    }
    builder.append(
        "effect_permit_request",
        "ADAPTER",
        {
            "lease_deadline_ms": lease_deadline,
            "lease_digest": lease["lease_digest"],
            "lease_id": lease["lease_id"],
            "point_of_use_digest": point_of_use_digest(permit_request_fields),
            "watchdog_deadline_ms": watchdog_deadline,
            "watchdog_digest": armed["watchdog_digest"],
        },
    )
    permit = builder.append(
        "effect_permit_result",
        "AUTHORITY",
        {
            "decision": "ALLOW",
            "permit_deadline_ms": permit_deadline,
            "permit_digest": ZERO,
            "permit_id": ZERO_ID,
            "watchdog_digest": armed["watchdog_digest"],
        },
    )
    if timeout:
        fail_close_deadline = min(lease_deadline, permit_deadline, watchdog_deadline)
        terminal = builder.append(
            "watchdog_terminal",
            "WATCHDOG",
            {
                "permit_digest": permit["permit_digest"],
                "permit_id": permit["permit_id"],
                "receipt_digest": ZERO,
                "watchdog_digest": armed["watchdog_digest"],
                "watchdog_status": "TIMEOUT",
            },
            at_ms=fail_close_deadline,
        )
        builder.append(
            "watchdog_result",
            "AUTHORITY",
            {
                "decision": "BLOCK",
                "permit_digest": permit["permit_digest"],
                "permit_id": permit["permit_id"],
                "receipt_digest": ZERO,
                "watchdog_digest": terminal["watchdog_digest"],
            },
            error_code="WATCHDOG_TIMEOUT",
            at_ms=fail_close_deadline + 1,
        )
        return

    consumed_at = permit["message_time_ms"] + 5
    receipt = builder.append(
        "effect_receipt",
        "ADAPTER",
        {
            "adapter_consumed_at_ms": consumed_at,
            "adapter_consumption_digest": adapter_consumption_digest(
                permit["durable_consumption_digest"], permit["permit_digest"],
                permit["effect_digest"], permit["adapter_digest"], consumed_at, outcome,
            ),
            "effect_outcome": outcome,
            "permit_digest": permit["permit_digest"],
            "permit_id": permit["permit_id"],
            "receipt_digest": ZERO,
            "watchdog_digest": armed["watchdog_digest"],
        },
    )
    receipt["receipt_digest"] = effect_receipt_digest(receipt)
    receipt = seal_fixture_message(receipt, builder.registry.entries["ADAPTER"])
    builder.messages[-1] = receipt
    success = outcome == "SUCCEEDED"
    ack = builder.append(
        "receipt_ack",
        "AUTHORITY",
        {
            "decision": "ACK" if success else "FAILURE_ACK",
            "permit_digest": permit["permit_digest"],
            "permit_id": permit["permit_id"],
            "receipt_digest": receipt["receipt_digest"],
            "receipt_status": "SUCCESS_RECORDED" if success else ("FAILURE_RECORDED" if outcome == "FAILED" else "UNKNOWN_BLOCKED"),
            "watchdog_digest": armed["watchdog_digest"],
        },
        error_code="NONE" if success else "EFFECT_NOT_SUCCESSFUL",
    )
    terminal = builder.append(
        "watchdog_terminal",
        "WATCHDOG",
        {
            "permit_digest": permit["permit_digest"],
            "permit_id": permit["permit_id"],
            "receipt_digest": receipt["receipt_digest"],
            "watchdog_digest": armed["watchdog_digest"],
            "watchdog_status": "HEALTHY" if success else "STOP",
        },
    )
    builder.append(
        "watchdog_result",
        "AUTHORITY",
        {
            "decision": "ACK" if success else "BLOCK",
            "permit_digest": permit["permit_digest"],
            "permit_id": permit["permit_id"],
            "receipt_digest": receipt["receipt_digest"],
            "watchdog_digest": terminal["watchdog_digest"],
        },
        error_code="NONE" if success else "EFFECT_STOPPED",
    )


def build_transcript(
    mode: str = "MODE_1", *, outcome: str = "SUCCEEDED", timeout: bool = False,
    mode2_variant: str = "strict",
    deadline_offsets: tuple[int, int, int] = (2_000, 2_500, 1_500),
) -> tuple[TrustRegistry, list[dict[str, object]]]:
    builder = Builder(mode=mode)
    if mode == "MODE_1":
        _append_mode1(builder)
    elif mode == "MODE_2":
        _append_mode2(builder, mode2_variant)
    elif mode == "MODE_3":
        _append_mode3(builder)
    else:
        raise ValueError("unknown mode")
    _append_authority_lifecycle(
        builder, outcome=outcome, timeout=timeout,
        deadline_offsets=deadline_offsets,
    )
    return builder.registry, builder.messages


def build_mode1_release_denial_transcript() -> tuple[TrustRegistry, list[dict[str, object]]]:
    """Build a valid signed early fail-closed release refusal for parity tests."""
    registry, messages = build_transcript("MODE_1")
    denial = dict(messages[1])
    denial["decision"] = "DENY"
    denial["error_code"] = "MODE1_RELEASE_DENIED"
    denial["rendezvous_release_digest"] = ZERO
    denial["rendezvous_released_at_ms"] = 0
    denial = seal_fixture_message(denial, registry.entries["AUTHORITY"])
    return registry, [messages[0], denial]


def _rechain_fixture(
    messages: list[dict[str, object]], registry: TrustRegistry,
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for sequence, source in enumerate(messages):
        item = dict(source)
        item["sequence"] = sequence
        item["prior_transcript_digest"] = result[-1]["transcript_digest"] if result else ZERO
        result.append(seal_fixture_message(item, registry.entries[str(item["signer_role"])]))
    return result


def build_mode1_witness_time_transplant_counterexample(
) -> tuple[TrustRegistry, list[dict[str, object]]]:
    """Build the signed rendezvous-time transplant that wire v2 must reject."""
    registry, original = build_transcript("MODE_1")
    messages = [dict(item) for item in original[:7]]
    request = messages[0]
    result = messages[1]

    # The authority actually releases after branch A's claimed substantive
    # start, while the witness substitutes an earlier, apparently safe time.
    actual_release = int(messages[2]["substantive_start_ms"]) + 1
    release = rendezvous_release_digest(
        str(request["a_checkpoint_digest"]),
        str(request["b_checkpoint_digest"]),
        int(request["rendezvous_opened_at_ms"]),
        actual_release,
    )
    result["release_request_digest"] = request["transcript_digest"]
    result["rendezvous_release_digest"] = release
    result["rendezvous_released_at_ms"] = actual_release
    messages = _rechain_fixture(messages, registry)

    witness = messages[4]
    witness["rendezvous_opened_at_ms"] = int(messages[0]["rendezvous_opened_at_ms"]) + 1
    witness["rendezvous_release_digest"] = release
    witness["rendezvous_released_at_ms"] = int(messages[2]["substantive_start_ms"])
    witness["release_result_digest"] = messages[1]["transcript_digest"]
    witness["statement_a_digest"] = messages[2]["transcript_digest"]
    witness["statement_b_digest"] = messages[3]["transcript_digest"]
    witness["a_ack_digest"] = rendezvous_ack_digest(
        "A", release, str(messages[2]["transcript_digest"]),
    )
    witness["b_ack_digest"] = rendezvous_ack_digest(
        "B", release, str(messages[3]["transcript_digest"]),
    )
    messages = _rechain_fixture(messages, registry)

    convergence = convergence_digest(
        str(messages[2]["transcript_digest"]),
        str(messages[3]["transcript_digest"]),
        str(messages[4]["transcript_digest"]),
        str(messages[2]["projection_digest"]),
    )
    for index in (5, 6):
        messages[index]["convergence_digest"] = convergence
        messages[index]["evidence_a_digest"] = messages[2]["transcript_digest"]
        messages[index]["evidence_b_digest"] = messages[3]["transcript_digest"]
        messages[index]["mode_evidence_digest"] = messages[4]["transcript_digest"]
        messages[index]["projection_digest"] = messages[2]["projection_digest"]
    messages[6]["decision"] = "DENY"
    messages[6]["error_code"] = "MODE1_WITNESS_TIME_TRANSPLANT"
    messages = _rechain_fixture(messages, registry)
    return registry, messages
