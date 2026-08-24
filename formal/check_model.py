#!/usr/bin/env python3
"""Bounded stdlib-only explorer for the SBP-LEX authority protocol model.

The explorer is intentionally implemented independently of a TLA+ runtime so
the bounded design can be checked on a machine without TLC.  It mirrors the
state transitions and safety invariants in ``SBPLexAuthority.tla`` and writes
one deterministic JSON document to stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, deque
from dataclasses import dataclass, replace
from itertools import product
from typing import Iterable, Iterator, Optional


REJECT_KINDS = frozenset(
    {
        "DIVERGENT_CONVERGENCE",
        "PREPARE_WITHOUT_EXACT_PROOF",
        "PREPARE_REPLAY",
        "PROOF_EXPIRED",
        "PREPARE_EXPIRED",
        "MUTATED_BINDING",
        "COMMIT_WITHOUT_MATCHING_PREPARE",
        "COMMIT_REPLAY",
        "LEASE_BEFORE_COMMIT",
        "LEASE_EXPIRED",
        "ADAPTER_MISMATCH",
        "EFFECT_MISMATCH",
        "REDEMPTION_REPLAY",
        "SAFETY_ENVELOPE_BLOCK",
        "EFFECT_WITHOUT_LEASE_INTERLOCK",
        "RECEIPT_BINDING_MISMATCH",
        "RECEIPT_SIGNATURE_INVALID",
        "RECEIPT_DUPLICATE",
        "WATCHDOG_TIMEOUT",
        "FIXTURE_CUSTODY",
        "NONPRODUCTION_CUSTODY",
        "HSM_UNAVAILABLE",
        "HSM_STALE",
        "INHIBIT_BLOCK",
        "INHIBIT_STOP",
        "INHIBIT_UNAVAILABLE",
        "INHIBIT_STALE",
        "INHIBIT_BINDING_MISMATCH",
        "INHIBIT_NOT_INDEPENDENT",
        "REQUIRED_PRODUCTION_CONTROLS_MISSING",
    }
)

PRODUCTION_CONTROL_REJECTIONS = frozenset(
    {
        "FIXTURE_CUSTODY",
        "NONPRODUCTION_CUSTODY",
        "HSM_UNAVAILABLE",
        "HSM_STALE",
        "INHIBIT_BLOCK",
        "INHIBIT_STOP",
        "INHIBIT_UNAVAILABLE",
        "INHIBIT_STALE",
        "INHIBIT_BINDING_MISMATCH",
        "INHIBIT_NOT_INDEPENDENT",
        "REQUIRED_PRODUCTION_CONTROLS_MISSING",
    }
)


@dataclass(frozen=True, order=True)
class Binding:
    request: str
    state: str
    effect: str
    adapter: str
    extension_admission_mode: str
    extension_schema: str
    extension_configuration_digest: str
    extension_admission_binding: str


@dataclass(frozen=True)
class Control:
    snapshot_a: Optional[Binding] = None
    snapshot_b: Optional[Binding] = None
    proof_binding: Optional[Binding] = None
    proof_at: int = 0
    proof_consumed: bool = False
    prepare_binding: Optional[Binding] = None
    prepare_at: int = 0
    prepare_consumed: bool = False
    custody_status: str = "UNASSESSED"
    hsm_available: bool = False
    hsm_attested_at: int = 0
    inhibit_decision: str = "NONE"
    inhibit_available: bool = False
    inhibit_independent: bool = False
    inhibit_binding: Optional[Binding] = None
    inhibit_observed_at: int = 0
    commit_binding: Optional[Binding] = None
    commit_at: int = 0
    commit_count: int = 0
    commit_from_unconsumed_prepare: bool = False
    commit_control_binding: Optional[Binding] = None
    commit_hsm_evidence_at: int = 0
    commit_inhibit_evidence_at: int = 0
    commit_production_custody_ok: bool = False
    commit_independent_inhibit_ok: bool = False
    authority_active: bool = False
    authority_origin: str = "NONE"
    lease_binding: Optional[Binding] = None
    lease_issued_at: int = 0
    lease_revoked: bool = False
    redemption_binding: Optional[Binding] = None
    redemption_at: int = 0
    redemption_count: int = 0
    redemption_from_fresh_lease: bool = False
    redemption_control_binding: Optional[Binding] = None
    redemption_hsm_evidence_at: int = 0
    redemption_inhibit_evidence_at: int = 0
    redemption_production_custody_ok: bool = False
    redemption_independent_inhibit_ok: bool = False
    interlock_binding: Optional[Binding] = None
    effect_permit_binding: Optional[Binding] = None
    effect_permit_at: int = 0
    effect_permit_hsm_evidence_at: int = 0
    effect_permit_inhibit_evidence_at: int = 0
    effect_permit_production_custody_ok: bool = False
    effect_permit_independent_inhibit_ok: bool = False
    effect_binding: Optional[Binding] = None
    effect_at: int = 0
    effect_count: int = 0
    receipt_binding: Optional[Binding] = None
    receipt_at: int = 0
    continuation_allowed: bool = False
    watchdog_failed: bool = False
    blocked: bool = False
    rejections: frozenset[str] = frozenset()


@dataclass(frozen=True)
class ModelState:
    clock: int
    controls: tuple[Control, ...]


@dataclass(frozen=True)
class Bounds:
    traversals: int = 1
    max_time: int = 6
    max_depth: int = 20
    proof_ttl: int = 2
    prepare_ttl: int = 2
    lease_ttl: int = 2
    watchdog_ttl: int = 2
    hsm_ttl: int = 2
    inhibit_ttl: int = 2


class InvariantViolation(AssertionError):
    def __init__(self, name: str, detail: str) -> None:
        super().__init__(f"{name}: {detail}")
        self.name = name
        self.detail = detail


REQUESTS = ("request-A",)
STATES = ("state-A",)
EFFECTS = ("effect-approved", "effect-other")
ADAPTERS = ("adapter-A", "adapter-other")
EXTENSION_BINDINGS = ("extension-disabled-A", "extension-disabled-other")
EXTENSION_SCHEMA = "SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED"
EXTENSION_CONFIGURATION_DIGEST = (
    "77a276b56e7c28578539bd89bfe3b2fe6da541c1588bab2f9a8d9bf1543395fa"
)
SAFE_EFFECTS = frozenset({"effect-approved"})
HIGHEST_CONSEQUENCE_EFFECTS = frozenset({"effect-approved"})
BINDINGS = tuple(
    Binding(
        request,
        state,
        effect,
        adapter,
        "EXTENSIONS_DISABLED",
        EXTENSION_SCHEMA,
        EXTENSION_CONFIGURATION_DIGEST,
        extension_binding,
    )
    for request, state, effect, adapter, extension_binding in product(
        REQUESTS, STATES, EFFECTS, ADAPTERS, EXTENSION_BINDINGS
    )
)


def action_name(label: str) -> str:
    return label.split("[", 1)[0]


def update_control(
    state: ModelState, traversal: int, **changes: object
) -> ModelState:
    controls = list(state.controls)
    controls[traversal] = replace(controls[traversal], **changes)
    return ModelState(clock=state.clock, controls=tuple(controls))


def fail_closed(
    state: ModelState, traversal: int, kind: str, watchdog: bool = False
) -> Optional[ModelState]:
    control = state.controls[traversal]
    if kind in control.rejections:
        return None
    return update_control(
        state,
        traversal,
        authority_active=False,
        lease_revoked=True,
        continuation_allowed=False,
        watchdog_failed=control.watchdog_failed or watchdog,
        blocked=True,
        rejections=control.rejections | {kind},
    )


def lease_fresh(state: ModelState, control: Control, bounds: Bounds) -> bool:
    return (
        control.lease_binding is not None
        and not control.lease_revoked
        and state.clock < control.lease_issued_at + bounds.lease_ttl
    )


def needs_production_controls(binding: Optional[Binding]) -> bool:
    return binding is not None and binding.effect in HIGHEST_CONSEQUENCE_EFFECTS


def production_custody_ready(
    state: ModelState, control: Control, bounds: Bounds
) -> bool:
    return (
        control.custody_status == "PRODUCTION"
        and control.hsm_available
        and state.clock < control.hsm_attested_at + bounds.hsm_ttl
    )


def safety_inhibit_ready(
    state: ModelState,
    control: Control,
    binding: Optional[Binding],
    bounds: Bounds,
) -> bool:
    return (
        binding is not None
        and control.inhibit_decision == "CLEAR"
        and control.inhibit_available
        and control.inhibit_independent
        and control.inhibit_binding == binding
        and state.clock < control.inhibit_observed_at + bounds.inhibit_ttl
    )


def current_control_target(control: Control) -> Optional[Binding]:
    return control.commit_binding or control.prepare_binding


def commit_ready(state: ModelState, control: Control, bounds: Bounds) -> bool:
    return (
        control.commit_count == 0
        and control.prepare_binding is not None
        and not control.prepare_consumed
        and not control.proof_consumed
        and control.snapshot_a == control.snapshot_b
        and control.snapshot_a == control.proof_binding
        and control.proof_binding == control.prepare_binding
        and state.clock < control.proof_at + bounds.proof_ttl
        and state.clock < control.prepare_at + bounds.prepare_ttl
    )


def labelled_failure(
    state: ModelState,
    traversal: int,
    kind: str,
    watchdog: bool = False,
) -> tuple[str, ModelState]:
    successor = fail_closed(state, traversal, kind, watchdog)
    if successor is None:
        raise RuntimeError("duplicate fail-closed transition generated")
    return f"reject_{kind.lower()}[t{traversal + 1}]", successor


def successors(state: ModelState, bounds: Bounds) -> Iterator[tuple[str, ModelState]]:
    if state.clock < bounds.max_time:
        yield "tick", ModelState(state.clock + 1, state.controls)

    for traversal, control in enumerate(state.controls):
        tag = f"t{traversal + 1}"
        if control.blocked:
            continue

        if control.snapshot_a is None:
            for binding_index, binding in enumerate(BINDINGS):
                yield (
                    f"observe_a[{tag},b{binding_index}]",
                    update_control(state, traversal, snapshot_a=binding),
                )

        if control.snapshot_b is None:
            for binding_index, binding in enumerate(BINDINGS):
                yield (
                    f"observe_b[{tag},b{binding_index}]",
                    update_control(state, traversal, snapshot_b=binding),
                )

        if (
            control.proof_binding is None
            and control.snapshot_a is not None
            and control.snapshot_a == control.snapshot_b
        ):
            yield (
                f"certify_exact_convergence[{tag}]",
                update_control(
                    state,
                    traversal,
                    proof_binding=control.snapshot_a,
                    proof_at=state.clock,
                ),
            )

        if (
            control.prepare_binding is None
            and control.proof_binding is not None
            and not control.proof_consumed
            and control.snapshot_a == control.snapshot_b
            and control.snapshot_a == control.proof_binding
            and state.clock < control.proof_at + bounds.proof_ttl
        ):
            yield (
                f"prepare_non_authorizing[{tag}]",
                update_control(
                    state,
                    traversal,
                    prepare_binding=control.proof_binding,
                    prepare_at=state.clock,
                ),
            )

        if (
            control.prepare_binding is not None
            and needs_production_controls(control.prepare_binding)
            and control.custody_status == "UNASSESSED"
        ):
            yield (
                f"attest_production_custody[{tag}]",
                update_control(
                    state,
                    traversal,
                    custody_status="PRODUCTION",
                    hsm_available=True,
                    hsm_attested_at=state.clock,
                ),
            )

        if (
            control.prepare_binding is not None
            and needs_production_controls(control.prepare_binding)
            and control.inhibit_decision == "NONE"
        ):
            yield (
                f"observe_independent_safety_inhibit_clear[{tag}]",
                update_control(
                    state,
                    traversal,
                    inhibit_decision="CLEAR",
                    inhibit_available=True,
                    inhibit_independent=True,
                    inhibit_binding=control.prepare_binding,
                    inhibit_observed_at=state.clock,
                ),
            )

        commit_controls_ready = (
            not needs_production_controls(control.prepare_binding)
            or (
                production_custody_ready(state, control, bounds)
                and safety_inhibit_ready(
                    state, control, control.prepare_binding, bounds
                )
            )
        )
        if commit_ready(state, control, bounds) and commit_controls_ready:
            requires_controls = needs_production_controls(control.prepare_binding)
            yield (
                f"commit_sole_authority[{tag}]",
                update_control(
                    state,
                    traversal,
                    prepare_consumed=True,
                    proof_consumed=True,
                    commit_binding=control.prepare_binding,
                    commit_at=state.clock,
                    commit_count=1,
                    commit_from_unconsumed_prepare=True,
                    commit_control_binding=(
                        control.prepare_binding if requires_controls else None
                    ),
                    commit_hsm_evidence_at=control.hsm_attested_at,
                    commit_inhibit_evidence_at=control.inhibit_observed_at,
                    commit_production_custody_ok=requires_controls,
                    commit_independent_inhibit_ok=requires_controls,
                    authority_active=True,
                    authority_origin="SOLE_COMMIT",
                ),
            )

        if (
            control.authority_active
            and control.commit_count == 1
            and control.lease_binding is None
        ):
            yield (
                f"issue_effect_bound_lease[{tag}]",
                update_control(
                    state,
                    traversal,
                    lease_binding=control.commit_binding,
                    lease_issued_at=state.clock,
                    lease_revoked=False,
                ),
            )

        if (
            control.authority_active
            and control.redemption_count == 0
            and lease_fresh(state, control, bounds)
            and control.lease_binding == control.commit_binding
            and (
                not needs_production_controls(control.lease_binding)
                or (
                    production_custody_ready(state, control, bounds)
                    and safety_inhibit_ready(
                        state, control, control.lease_binding, bounds
                    )
                )
            )
        ):
            requires_controls = needs_production_controls(control.lease_binding)
            yield (
                f"redeem_at_point_of_use[{tag}]",
                update_control(
                    state,
                    traversal,
                    redemption_binding=control.lease_binding,
                    redemption_at=state.clock,
                    redemption_count=1,
                    redemption_from_fresh_lease=True,
                    redemption_control_binding=(
                        control.lease_binding if requires_controls else None
                    ),
                    redemption_hsm_evidence_at=control.hsm_attested_at,
                    redemption_inhibit_evidence_at=control.inhibit_observed_at,
                    redemption_production_custody_ok=requires_controls,
                    redemption_independent_inhibit_ok=requires_controls,
                ),
            )

        if (
            control.redemption_count == 1
            and control.interlock_binding is None
            and lease_fresh(state, control, bounds)
            and control.redemption_binding == control.lease_binding
            and control.lease_binding == control.commit_binding
            and control.lease_binding is not None
            and control.lease_binding.effect in SAFE_EFFECTS
            and state.clock == control.redemption_at
        ):
            yield (
                f"pass_safety_envelope_interlock[{tag}]",
                update_control(
                    state,
                    traversal,
                    interlock_binding=control.redemption_binding,
                ),
            )

        if (
            control.effect_count == 0
            and control.effect_permit_binding is None
            and control.interlock_binding is not None
            and needs_production_controls(control.interlock_binding)
            and control.interlock_binding == control.redemption_binding
            and control.redemption_binding == control.lease_binding
            and control.lease_binding == control.commit_binding
            and production_custody_ready(state, control, bounds)
            and safety_inhibit_ready(
                state, control, control.interlock_binding, bounds
            )
        ):
            yield (
                f"issue_final_effect_permit[{tag}]",
                update_control(
                    state,
                    traversal,
                    effect_permit_binding=control.interlock_binding,
                    effect_permit_at=state.clock,
                    effect_permit_hsm_evidence_at=control.hsm_attested_at,
                    effect_permit_inhibit_evidence_at=control.inhibit_observed_at,
                    effect_permit_production_custody_ok=True,
                    effect_permit_independent_inhibit_ok=True,
                ),
            )

        if (
            control.effect_count == 0
            and control.interlock_binding is not None
            and lease_fresh(state, control, bounds)
            and control.commit_binding == control.lease_binding
            and control.lease_binding == control.redemption_binding
            and control.redemption_binding == control.interlock_binding
            and control.interlock_binding.effect in SAFE_EFFECTS
            and (
                not needs_production_controls(control.interlock_binding)
                or (
                    control.effect_permit_binding
                    == control.interlock_binding
                    and control.effect_permit_production_custody_ok
                    and control.effect_permit_independent_inhibit_ok
                    and state.clock == control.effect_permit_at
                )
            )
            and state.clock == control.redemption_at
        ):
            yield (
                f"perform_effect[{tag}]",
                update_control(
                    state,
                    traversal,
                    effect_binding=control.interlock_binding,
                    effect_at=state.clock,
                    effect_count=1,
                ),
            )

        if (
            control.effect_count == 1
            and control.receipt_binding is None
            and not control.watchdog_failed
            and state.clock
            < control.lease_issued_at + bounds.lease_ttl
            and state.clock < control.effect_at + bounds.watchdog_ttl
        ):
            # This transition abstracts successful independent signature and
            # exact binding verification of the post-effect receipt.
            yield (
                f"accept_signed_effect_receipt[{tag}]",
                update_control(
                    state,
                    traversal,
                    receipt_binding=control.effect_binding,
                    receipt_at=state.clock,
                    continuation_allowed=True,
                ),
            )

        control_target = current_control_target(control)
        highest_consequence_target = needs_production_controls(control_target)

        if highest_consequence_target:
            yield labelled_failure(state, traversal, "FIXTURE_CUSTODY")
            yield labelled_failure(state, traversal, "NONPRODUCTION_CUSTODY")
            yield labelled_failure(state, traversal, "HSM_UNAVAILABLE")
            yield labelled_failure(state, traversal, "INHIBIT_BLOCK")
            yield labelled_failure(state, traversal, "INHIBIT_STOP")
            yield labelled_failure(state, traversal, "INHIBIT_UNAVAILABLE")
            yield labelled_failure(state, traversal, "INHIBIT_NOT_INDEPENDENT")

            if any(binding != control_target for binding in BINDINGS):
                yield labelled_failure(
                    state, traversal, "INHIBIT_BINDING_MISMATCH"
                )

        if (
            highest_consequence_target
            and control.custody_status == "PRODUCTION"
            and control.hsm_available
            and state.clock >= control.hsm_attested_at + bounds.hsm_ttl
        ):
            yield labelled_failure(state, traversal, "HSM_STALE")

        if (
            highest_consequence_target
            and control.inhibit_decision == "CLEAR"
            and control.inhibit_available
            and control.inhibit_independent
            and state.clock >= control.inhibit_observed_at + bounds.inhibit_ttl
        ):
            yield labelled_failure(state, traversal, "INHIBIT_STALE")

        if (
            control.commit_count == 0
            and commit_ready(state, control, bounds)
            and needs_production_controls(control.prepare_binding)
            and not (
                production_custody_ready(state, control, bounds)
                and safety_inhibit_ready(
                    state, control, control.prepare_binding, bounds
                )
            )
        ):
            successor = fail_closed(
                state,
                traversal,
                "REQUIRED_PRODUCTION_CONTROLS_MISSING",
            )
            if successor is not None:
                yield (
                    f"reject_required_production_controls_missing_at_commit[{tag}]",
                    successor,
                )

        if (
            control.redemption_count == 0
            and lease_fresh(state, control, bounds)
            and needs_production_controls(control.lease_binding)
            and not (
                production_custody_ready(state, control, bounds)
                and safety_inhibit_ready(
                    state, control, control.lease_binding, bounds
                )
            )
        ):
            successor = fail_closed(
                state,
                traversal,
                "REQUIRED_PRODUCTION_CONTROLS_MISSING",
            )
            if successor is not None:
                yield (
                    f"reject_required_production_controls_missing_at_redemption[{tag}]",
                    successor,
                )

        if (
            control.effect_count == 0
            and control.effect_permit_binding is None
            and control.interlock_binding is not None
            and needs_production_controls(control.interlock_binding)
            and not (
                production_custody_ready(state, control, bounds)
                and safety_inhibit_ready(
                    state, control, control.interlock_binding, bounds
                )
            )
        ):
            successor = fail_closed(
                state,
                traversal,
                "REQUIRED_PRODUCTION_CONTROLS_MISSING",
            )
            if successor is not None:
                yield (
                    f"reject_required_production_controls_missing_at_final_permit[{tag}]",
                    successor,
                )

        if (
            control.snapshot_a is not None
            and control.snapshot_b is not None
            and control.snapshot_a != control.snapshot_b
        ):
            yield labelled_failure(
                state, traversal, "DIVERGENT_CONVERGENCE"
            )

        if control.prepare_binding is None and (
            control.proof_binding is None
            or control.snapshot_a != control.snapshot_b
            or control.snapshot_a != control.proof_binding
        ):
            yield labelled_failure(
                state, traversal, "PREPARE_WITHOUT_EXACT_PROOF"
            )

        if control.prepare_binding is not None:
            yield labelled_failure(state, traversal, "PREPARE_REPLAY")

        if (
            control.proof_binding is not None
            and not control.proof_consumed
            and state.clock >= control.proof_at + bounds.proof_ttl
        ):
            yield labelled_failure(state, traversal, "PROOF_EXPIRED")

        if (
            control.prepare_binding is not None
            and not control.prepare_consumed
            and state.clock >= control.prepare_at + bounds.prepare_ttl
        ):
            yield labelled_failure(state, traversal, "PREPARE_EXPIRED")

        if control.proof_binding is not None and any(
            binding != control.proof_binding for binding in BINDINGS
        ):
            yield labelled_failure(state, traversal, "MUTATED_BINDING")

        if control.commit_count == 0 and not commit_ready(state, control, bounds):
            yield labelled_failure(
                state, traversal, "COMMIT_WITHOUT_MATCHING_PREPARE"
            )

        if control.commit_count == 1:
            yield labelled_failure(state, traversal, "COMMIT_REPLAY")

        if control.commit_count == 0:
            yield labelled_failure(state, traversal, "LEASE_BEFORE_COMMIT")

        if (
            control.lease_binding is not None
            and control.receipt_binding is None
            and state.clock >= control.lease_issued_at + bounds.lease_ttl
        ):
            yield labelled_failure(state, traversal, "LEASE_EXPIRED")

        if (
            control.lease_binding is not None
            and control.redemption_count == 0
            and any(
                adapter != control.lease_binding.adapter for adapter in ADAPTERS
            )
        ):
            yield labelled_failure(state, traversal, "ADAPTER_MISMATCH")

        if (
            control.lease_binding is not None
            and control.redemption_count == 0
            and any(effect != control.lease_binding.effect for effect in EFFECTS)
        ):
            yield labelled_failure(state, traversal, "EFFECT_MISMATCH")

        if control.redemption_count == 1:
            yield labelled_failure(state, traversal, "REDEMPTION_REPLAY")

        if (
            control.redemption_count == 1
            and control.interlock_binding is None
            and control.redemption_binding is not None
            and control.redemption_binding.effect not in SAFE_EFFECTS
        ):
            yield labelled_failure(state, traversal, "SAFETY_ENVELOPE_BLOCK")

        effect_preconditions_missing = (
            control.lease_binding is None
            or control.redemption_count == 0
            or control.interlock_binding is None
            or control.lease_binding != control.redemption_binding
            or control.redemption_binding != control.interlock_binding
            or control.lease_revoked
            or (
                needs_production_controls(control.interlock_binding)
                and control.effect_permit_binding != control.interlock_binding
            )
        )
        if control.effect_count == 0 and effect_preconditions_missing:
            yield labelled_failure(
                state, traversal, "EFFECT_WITHOUT_LEASE_INTERLOCK"
            )

        if (
            control.effect_count == 1
            and control.receipt_binding is None
            and any(binding != control.effect_binding for binding in BINDINGS)
        ):
            yield labelled_failure(
                state, traversal, "RECEIPT_BINDING_MISMATCH", watchdog=True
            )

        if control.effect_count == 1 and control.receipt_binding is None:
            yield labelled_failure(
                state, traversal, "RECEIPT_SIGNATURE_INVALID", watchdog=True
            )

        if control.receipt_binding is not None:
            yield labelled_failure(
                state, traversal, "RECEIPT_DUPLICATE", watchdog=True
            )

        if (
            control.effect_count == 1
            and control.receipt_binding is None
            and state.clock >= control.effect_at + bounds.watchdog_ttl
        ):
            yield labelled_failure(
                state, traversal, "WATCHDOG_TIMEOUT", watchdog=True
            )


def require(condition: bool, name: str, detail: str) -> None:
    if not condition:
        raise InvariantViolation(name, detail)


def assert_invariants(state: ModelState, bounds: Bounds) -> None:
    require(
        0 <= state.clock <= bounds.max_time,
        "TypeOK",
        f"clock={state.clock}",
    )
    require(
        len(state.controls) == bounds.traversals,
        "TypeOK",
        "unexpected traversal cardinality",
    )

    for traversal, control in enumerate(state.controls, start=1):
        detail = f"traversal={traversal}"
        require(control.rejections <= REJECT_KINDS, "TypeOK", detail)
        binding_fields = (
            control.snapshot_a,
            control.snapshot_b,
            control.proof_binding,
            control.prepare_binding,
            control.inhibit_binding,
            control.commit_binding,
            control.commit_control_binding,
            control.lease_binding,
            control.redemption_binding,
            control.redemption_control_binding,
            control.interlock_binding,
            control.effect_permit_binding,
            control.effect_binding,
            control.receipt_binding,
        )
        require(
            all(binding is None or binding in BINDINGS for binding in binding_fields),
            "TypeOK",
            f"{detail}, binding outside finite domain",
        )
        require(
            all(
                binding is None
                or (
                    binding.extension_admission_mode == "EXTENSIONS_DISABLED"
                    and binding.extension_schema == EXTENSION_SCHEMA
                    and binding.extension_configuration_digest
                    == EXTENSION_CONFIGURATION_DIGEST
                )
                for binding in binding_fields
            )
            and (
                control.commit_binding is None
                or control.snapshot_a is not None
                and control.commit_binding.extension_admission_binding
                == control.snapshot_a.extension_admission_binding
            )
            and (
                control.effect_binding is None
                or control.commit_binding is not None
                and control.effect_binding.extension_admission_binding
                == control.commit_binding.extension_admission_binding
            ),
            "ExtensionAdmissionDisabledAndCarried",
            detail,
        )
        require(
            all(
                0 <= timestamp <= bounds.max_time
                for timestamp in (
                    control.proof_at,
                    control.prepare_at,
                    control.hsm_attested_at,
                    control.inhibit_observed_at,
                    control.commit_at,
                    control.commit_hsm_evidence_at,
                    control.commit_inhibit_evidence_at,
                    control.lease_issued_at,
                    control.redemption_at,
                    control.redemption_hsm_evidence_at,
                    control.redemption_inhibit_evidence_at,
                    control.effect_permit_at,
                    control.effect_permit_hsm_evidence_at,
                    control.effect_permit_inhibit_evidence_at,
                    control.effect_at,
                    control.receipt_at,
                )
            ),
            "TypeOK",
            f"{detail}, timestamp outside finite domain",
        )
        require(
            control.custody_status in {"UNASSESSED", "PRODUCTION"}
            and control.inhibit_decision in {"NONE", "CLEAR"}
            and control.authority_origin in {"NONE", "SOLE_COMMIT"},
            "TypeOK",
            f"{detail}, invalid control status",
        )
        require(
            control.commit_count in (0, 1)
            and control.redemption_count in (0, 1)
            and control.effect_count in (0, 1),
            "AtMostOneCommitAndRedemptionPerTraversal",
            detail,
        )

        if control.proof_binding is not None:
            require(
                control.snapshot_a == control.snapshot_b
                and control.snapshot_a == control.proof_binding,
                "ProofCertifiesExactConvergence",
                detail,
            )

        if control.prepare_binding is not None:
            require(
                control.snapshot_a == control.snapshot_b
                and control.snapshot_a == control.proof_binding
                and control.proof_binding == control.prepare_binding,
                "ExactConvergenceBeforePrepare",
                detail,
            )

        if control.prepare_binding is not None and control.commit_count == 0:
            require(
                not control.authority_active,
                "PrepareIsNonAuthorizing",
                detail,
            )

        require(
            not control.authority_active or control.commit_count == 1,
            "NoAuthorityBeforeCommit",
            detail,
        )

        if control.commit_count == 1:
            require(
                control.commit_from_unconsumed_prepare
                and control.prepare_consumed
                and control.proof_consumed
                and control.commit_binding is not None
                and control.commit_binding == control.prepare_binding
                and control.prepare_binding == control.proof_binding
                and control.proof_binding == control.snapshot_a
                and control.snapshot_a == control.snapshot_b,
                "CommitRequiresMatchingUnconsumedPrepare",
                detail,
            )

        if control.commit_count == 1 and needs_production_controls(
            control.commit_binding
        ):
            require(
                control.custody_status == "PRODUCTION"
                and control.commit_production_custody_ok
                and control.commit_independent_inhibit_ok
                and control.commit_control_binding == control.commit_binding
                and control.commit_at
                < control.commit_hsm_evidence_at + bounds.hsm_ttl
                and control.commit_at
                < control.commit_inhibit_evidence_at + bounds.inhibit_ttl,
                "HighestConsequenceCommitRequiresProductionControls",
                detail,
            )

        if control.redemption_count == 1 and needs_production_controls(
            control.redemption_binding
        ):
            require(
                control.custody_status == "PRODUCTION"
                and control.redemption_production_custody_ok
                and control.redemption_independent_inhibit_ok
                and control.redemption_control_binding
                == control.redemption_binding
                and control.redemption_at
                < control.redemption_hsm_evidence_at + bounds.hsm_ttl
                and control.redemption_at
                < control.redemption_inhibit_evidence_at + bounds.inhibit_ttl,
                "HighestConsequenceRedemptionRequiresProductionControls",
                detail,
            )

        if control.effect_count == 1:
            require(
                control.commit_count == 1
                and control.redemption_count == 1
                and control.redemption_from_fresh_lease
                and control.effect_binding is not None
                and control.effect_binding == control.commit_binding
                and control.commit_binding == control.lease_binding
                and control.lease_binding == control.redemption_binding
                and control.redemption_binding == control.interlock_binding
                and control.interlock_binding is not None
                and control.interlock_binding.effect in SAFE_EFFECTS
                and control.redemption_at
                < control.lease_issued_at + bounds.lease_ttl
                and control.effect_at < control.lease_issued_at + bounds.lease_ttl
                and control.effect_at == control.redemption_at,
                "NoEffectWithoutMatchingLeaseAndInterlock",
                detail,
            )

        if control.effect_count == 1 and needs_production_controls(
            control.effect_binding
        ):
            require(
                control.effect_permit_binding == control.effect_binding
                and control.effect_permit_binding == control.interlock_binding
                and control.effect_permit_production_custody_ok
                and control.effect_permit_independent_inhibit_ok
                and control.effect_permit_at
                < control.effect_permit_hsm_evidence_at + bounds.hsm_ttl
                and control.effect_permit_at
                < control.effect_permit_inhibit_evidence_at
                + bounds.inhibit_ttl
                and control.effect_at == control.effect_permit_at,
                "HighestConsequenceEffectRequiresFinalPermit",
                detail,
            )

        require(
            (
                control.commit_count == 0
                or (
                    control.commit_at < control.proof_at + bounds.proof_ttl
                    and control.commit_at
                    < control.prepare_at + bounds.prepare_ttl
                )
            )
            and (
                control.redemption_count == 0
                or control.redemption_at
                < control.lease_issued_at + bounds.lease_ttl
            )
            and (
                control.effect_count == 0
                or control.effect_at
                < control.lease_issued_at + bounds.lease_ttl
            )
            and (
                control.receipt_binding is None
                or (
                    control.receipt_at
                    < control.lease_issued_at + bounds.lease_ttl
                    and control.receipt_at
                    < control.effect_at + bounds.watchdog_ttl
                )
            ),
            "HalfOpenExpiryNeverAuthorizes",
            detail,
        )

        require(
            (control.authority_origin == "SOLE_COMMIT")
            == (control.commit_count == 1)
            and (
                not control.authority_active
                or control.authority_origin == "SOLE_COMMIT"
            )
            and (
                control.inhibit_binding is None
                or control.inhibit_binding == control.prepare_binding
            )
            and (
                control.commit_control_binding is None
                or control.commit_control_binding == control.commit_binding
            )
            and (
                control.redemption_control_binding is None
                or control.redemption_control_binding == control.commit_binding
            )
            and (
                control.effect_permit_binding is None
                or (
                    control.effect_permit_binding == control.commit_binding
                    and control.effect_permit_binding
                    == control.interlock_binding
                )
            ),
            "IndependentControlsCannotGrantOrWidenAuthority",
            detail,
        )

        if control.rejections & PRODUCTION_CONTROL_REJECTIONS:
            require(
                control.blocked
                and not control.authority_active
                and control.lease_revoked
                and not control.continuation_allowed,
                "ProductionControlFailureIsFailClosed",
                detail,
            )

        if control.watchdog_failed:
            require(
                control.blocked
                and not control.authority_active
                and control.lease_revoked
                and not control.continuation_allowed,
                "WatchdogFailureBlocksContinuation",
                detail,
            )

        if control.continuation_allowed:
            require(
                not control.blocked
                and not control.watchdog_failed
                and control.effect_count == 1
                and control.receipt_binding is not None
                and control.receipt_binding == control.effect_binding
                and control.receipt_at
                < control.lease_issued_at + bounds.lease_ttl
                and control.receipt_at
                < control.effect_at + bounds.watchdog_ttl,
                "ContinuationRequiresMatchingSignedReceipt",
                detail,
            )

        if control.blocked:
            require(
                not control.authority_active
                and control.lease_revoked
                and not control.continuation_allowed,
                "FailClosedStateDisablesAuthority",
                detail,
            )


def binding_json(binding: Optional[Binding]) -> object:
    if binding is None:
        return None
    return {
        "request": binding.request,
        "state": binding.state,
        "effect": binding.effect,
        "adapter": binding.adapter,
        "extension_admission_mode": binding.extension_admission_mode,
        "extension_schema": binding.extension_schema,
        "extension_configuration_digest": binding.extension_configuration_digest,
        "extension_admission_binding": binding.extension_admission_binding,
    }


def state_json(state: ModelState) -> dict[str, object]:
    controls: list[dict[str, object]] = []
    for index, control in enumerate(state.controls, start=1):
        controls.append(
            {
                "traversal": index,
                "snapshot_a": binding_json(control.snapshot_a),
                "snapshot_b": binding_json(control.snapshot_b),
                "proof_binding": binding_json(control.proof_binding),
                "prepare_binding": binding_json(control.prepare_binding),
                "custody_status": control.custody_status,
                "hsm_available": control.hsm_available,
                "hsm_attested_at": control.hsm_attested_at,
                "inhibit_decision": control.inhibit_decision,
                "inhibit_available": control.inhibit_available,
                "inhibit_independent": control.inhibit_independent,
                "inhibit_binding": binding_json(control.inhibit_binding),
                "inhibit_observed_at": control.inhibit_observed_at,
                "commit_binding": binding_json(control.commit_binding),
                "commit_count": control.commit_count,
                "authority_active": control.authority_active,
                "authority_origin": control.authority_origin,
                "lease_binding": binding_json(control.lease_binding),
                "redemption_binding": binding_json(control.redemption_binding),
                "redemption_count": control.redemption_count,
                "interlock_binding": binding_json(control.interlock_binding),
                "effect_permit_binding": binding_json(
                    control.effect_permit_binding
                ),
                "effect_binding": binding_json(control.effect_binding),
                "effect_count": control.effect_count,
                "receipt_binding": binding_json(control.receipt_binding),
                "receipt_at": control.receipt_at,
                "continuation_allowed": control.continuation_allowed,
                "watchdog_failed": control.watchdog_failed,
                "blocked": control.blocked,
                "rejections": sorted(control.rejections),
            }
        )
    return {"clock": state.clock, "controls": controls}


def trace_to(
    target: ModelState,
    parents: dict[ModelState, tuple[Optional[ModelState], Optional[str]]],
) -> list[str]:
    actions: list[str] = []
    cursor = target
    while True:
        parent, action = parents[cursor]
        if parent is None or action is None:
            break
        actions.append(action)
        cursor = parent
    actions.reverse()
    return actions


def explore(bounds: Bounds) -> tuple[dict[str, object], int]:
    initial = ModelState(0, tuple(Control() for _ in range(bounds.traversals)))
    queue: deque[tuple[ModelState, int]] = deque([(initial, 0)])
    visited: dict[ModelState, int] = {initial: 0}
    parents: dict[ModelState, tuple[Optional[ModelState], Optional[str]]] = {
        initial: (None, None)
    }
    action_counts: Counter[str] = Counter()
    transition_count = 0
    rejection_coverage: set[str] = set()
    rejection_witness_states: dict[str, ModelState] = {}
    production_control_checkpoints = {
        "commit": False,
        "redemption": False,
        "final_effect_permit": False,
    }
    half_open_boundary_names = frozenset(
        {
            "proof_expiry_blocks_commit",
            "prepare_expiry_blocks_commit",
            "lease_expiry_blocks_redemption_or_effect",
            "lease_expiry_blocks_receipt",
            "watchdog_expiry_blocks_receipt",
            "hsm_expiry_blocks_production_authority",
            "inhibit_expiry_blocks_production_authority",
        }
    )
    half_open_boundary_witnesses: dict[str, list[str]] = {}
    happy_state: Optional[ModelState] = None
    watchdog_state: Optional[ModelState] = None
    frontier_truncated = False
    max_depth_reached = 0

    try:
        assert_invariants(initial, bounds)
        while queue:
            state, depth = queue.popleft()
            max_depth_reached = max(max_depth_reached, depth)
            outgoing = list(successors(state, bounds))
            if depth >= bounds.max_depth:
                if outgoing:
                    frontier_truncated = True
                continue

            for action, successor in outgoing:
                transition_count += 1
                base_action = action_name(action)
                action_counts[base_action] += 1
                for index, control in enumerate(state.controls, start=1):
                    if f"[t{index}]" not in action:
                        continue
                    boundary_name: Optional[str] = None
                    if (
                        base_action == "reject_proof_expired"
                        and state.clock
                        == control.proof_at + bounds.proof_ttl
                    ):
                        boundary_name = "proof_expiry_blocks_commit"
                    elif (
                        base_action == "reject_prepare_expired"
                        and state.clock
                        == control.prepare_at + bounds.prepare_ttl
                    ):
                        boundary_name = "prepare_expiry_blocks_commit"
                    elif (
                        base_action == "reject_lease_expired"
                        and state.clock
                        == control.lease_issued_at + bounds.lease_ttl
                    ):
                        boundary_name = (
                            "lease_expiry_blocks_receipt"
                            if control.effect_count == 1
                            else "lease_expiry_blocks_redemption_or_effect"
                        )
                    elif (
                        base_action == "reject_watchdog_timeout"
                        and state.clock
                        == control.effect_at + bounds.watchdog_ttl
                    ):
                        boundary_name = "watchdog_expiry_blocks_receipt"
                    elif (
                        base_action == "reject_hsm_stale"
                        and state.clock
                        == control.hsm_attested_at + bounds.hsm_ttl
                    ):
                        boundary_name = (
                            "hsm_expiry_blocks_production_authority"
                        )
                    elif (
                        base_action == "reject_inhibit_stale"
                        and state.clock
                        == control.inhibit_observed_at + bounds.inhibit_ttl
                    ):
                        boundary_name = (
                            "inhibit_expiry_blocks_production_authority"
                        )
                    if boundary_name is not None:
                        half_open_boundary_witnesses.setdefault(
                            boundary_name,
                            trace_to(state, parents) + [action],
                        )
                assert_invariants(successor, bounds)
                for control in successor.controls:
                    rejection_coverage.update(control.rejections)

                    if (
                        control.commit_count == 1
                        and needs_production_controls(control.commit_binding)
                        and control.commit_production_custody_ok
                        and control.commit_independent_inhibit_ok
                    ):
                        production_control_checkpoints["commit"] = True
                    if (
                        control.redemption_count == 1
                        and needs_production_controls(
                            control.redemption_binding
                        )
                        and control.redemption_production_custody_ok
                        and control.redemption_independent_inhibit_ok
                    ):
                        production_control_checkpoints["redemption"] = True
                    if (
                        control.effect_permit_binding is not None
                        and needs_production_controls(
                            control.effect_permit_binding
                        )
                        and control.effect_permit_production_custody_ok
                        and control.effect_permit_independent_inhibit_ok
                    ):
                        production_control_checkpoints[
                            "final_effect_permit"
                        ] = True

                if successor not in visited:
                    visited[successor] = depth + 1
                    parents[successor] = (state, action)
                    queue.append((successor, depth + 1))

                    if happy_state is None and any(
                        control.continuation_allowed
                        for control in successor.controls
                    ):
                        happy_state = successor
                    if watchdog_state is None and any(
                        "WATCHDOG_TIMEOUT" in control.rejections
                        for control in successor.controls
                    ):
                        watchdog_state = successor
                    for control in successor.controls:
                        for rejection in (
                            control.rejections & PRODUCTION_CONTROL_REJECTIONS
                        ):
                            rejection_witness_states.setdefault(
                                rejection, successor
                            )

        coverage_checks = {
            "bounded_graph_fully_closed": not frontier_truncated,
            "successful_signed_receipt_path_reached": happy_state is not None,
            "watchdog_timeout_fail_closed_path_reached": watchdog_state is not None,
            "all_rejected_attack_kinds_reached": rejection_coverage
            == REJECT_KINDS,
            "production_controls_checked_at_commit":
                production_control_checkpoints["commit"],
            "production_controls_checked_at_redemption":
                production_control_checkpoints["redemption"],
            "production_controls_checked_at_final_effect_permit":
                production_control_checkpoints["final_effect_permit"],
            "all_required_production_control_failures_reached":
                PRODUCTION_CONTROL_REJECTIONS <= rejection_coverage,
            "all_half_open_expiry_boundaries_fail_closed":
                set(half_open_boundary_witnesses) == half_open_boundary_names,
        }
        missing_rejections = sorted(REJECT_KINDS - rejection_coverage)
        if not all(coverage_checks.values()):
            failed = [name for name, passed in coverage_checks.items() if not passed]
            raise InvariantViolation(
                "ExplorerCoverage",
                f"failed={failed}, missing_rejections={missing_rejections}",
            )

        invariant_names = [
            "TypeOK",
            "ProofCertifiesExactConvergence",
            "ExactConvergenceBeforePrepare",
            "PrepareIsNonAuthorizing",
            "NoAuthorityBeforeCommit",
            "CommitRequiresMatchingUnconsumedPrepare",
            "AtMostOneCommitAndRedemptionPerTraversal",
            "NoEffectWithoutMatchingLeaseAndInterlock",
            "ExtensionAdmissionDisabledAndCarried",
            "HighestConsequenceCommitRequiresProductionControls",
            "HighestConsequenceRedemptionRequiresProductionControls",
            "HighestConsequenceEffectRequiresFinalPermit",
            "HalfOpenExpiryNeverAuthorizes",
            "IndependentControlsCannotGrantOrWidenAuthority",
            "ProductionControlFailureIsFailClosed",
            "WatchdogFailureBlocksContinuation",
            "ContinuationRequiresMatchingSignedReceipt",
            "FailClosedStateDisablesAuthority",
        ]
        result: dict[str, object] = {
            "checker": "formal/check_model.py",
            "model": "SBP-LEX minimal authority protocol (bounded abstraction)",
            "status": "PASS",
            "production_claim": False,
            "bounds": {
                "traversals": bounds.traversals,
                "bindings": len(BINDINGS),
                "max_time": bounds.max_time,
                "max_depth": bounds.max_depth,
                "proof_ttl": bounds.proof_ttl,
                "prepare_ttl": bounds.prepare_ttl,
                "lease_ttl": bounds.lease_ttl,
                "watchdog_ttl": bounds.watchdog_ttl,
                "hsm_ttl": bounds.hsm_ttl,
                "inhibit_ttl": bounds.inhibit_ttl,
                "highest_consequence_effects": sorted(
                    HIGHEST_CONSEQUENCE_EFFECTS
                ),
            },
            "exploration": {
                "states": len(visited),
                "transitions": transition_count,
                "max_depth_reached": max_depth_reached,
                "frontier_truncated": frontier_truncated,
                "action_counts": dict(sorted(action_counts.items())),
            },
            "invariants": {name: "PASS" for name in invariant_names},
            "coverage": {
                **coverage_checks,
                "rejected_attack_kinds_reached": sorted(rejection_coverage),
                "missing_rejected_attack_kinds": missing_rejections,
            },
            "witness_traces": {
                "successful_signed_receipt": trace_to(happy_state, parents)
                if happy_state is not None
                else None,
                "watchdog_timeout_fail_closed": trace_to(
                    watchdog_state, parents
                )
                if watchdog_state is not None
                else None,
                "production_control_fail_closed": {
                    rejection: trace_to(
                        rejection_witness_states[rejection], parents
                    )
                    for rejection in sorted(PRODUCTION_CONTROL_REJECTIONS)
                    if rejection in rejection_witness_states
                },
                "half_open_expiry_fail_closed": {
                    name: half_open_boundary_witnesses[name]
                    for name in sorted(half_open_boundary_witnesses)
                },
            },
        }
        return result, 0
    except InvariantViolation as exc:
        failure_state = locals().get("successor", locals().get("state", initial))
        result = {
            "checker": "formal/check_model.py",
            "model": "SBP-LEX minimal authority protocol (bounded abstraction)",
            "status": "FAIL",
            "production_claim": False,
            "failed_assertion": exc.name,
            "detail": exc.detail,
            "counterexample_state": state_json(failure_state),
            "exploration": {
                "states_before_failure": len(visited),
                "transitions_before_failure": transition_count,
            },
        }
        return result, 1


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Enumerate the bounded SBP-LEX authority protocol model."
    )
    parser.add_argument("--traversals", type=positive_int, default=1)
    parser.add_argument("--max-time", type=nonnegative_int, default=6)
    parser.add_argument("--max-depth", type=nonnegative_int, default=20)
    parser.add_argument("--proof-ttl", type=nonnegative_int, default=2)
    parser.add_argument("--prepare-ttl", type=nonnegative_int, default=2)
    parser.add_argument("--lease-ttl", type=nonnegative_int, default=2)
    parser.add_argument("--watchdog-ttl", type=nonnegative_int, default=2)
    parser.add_argument("--hsm-ttl", type=nonnegative_int, default=2)
    parser.add_argument("--inhibit-ttl", type=nonnegative_int, default=2)
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] = ()) -> int:
    args = parse_args(argv)
    bounds = Bounds(
        traversals=args.traversals,
        max_time=args.max_time,
        max_depth=args.max_depth,
        proof_ttl=args.proof_ttl,
        prepare_ttl=args.prepare_ttl,
        lease_ttl=args.lease_ttl,
        watchdog_ttl=args.watchdog_ttl,
        hsm_ttl=args.hsm_ttl,
        inhibit_ttl=args.inhibit_ttl,
    )
    result, exit_code = explore(bounds)
    json.dump(result, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
