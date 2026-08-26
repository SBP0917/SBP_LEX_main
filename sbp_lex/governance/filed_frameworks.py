from __future__ import annotations

from copy import deepcopy
import hmac
from types import MappingProxyType
from typing import Any, Final, Protocol

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.hybrid_signature import (
    HybridSignatureProvider,
    HybridVerificationContext,
    is_hybrid_provider,
    verify_hybrid_signed_object,
)
from sbp_lex.licensing.filed_licensing import invalidate_filed_licence


AJ_SAAF = "AJ-SAAF"
PTODF = "PTODF"
GALA = "GALA"
ABEGF = "ABEGF"
FILED_FRAMEWORK_ATTESTATION_PURPOSE: Final = (
    "SBP_LEX_V2_FILED_FRAMEWORK_ATTESTATION"
)

EVIDENTIARY_FRAMEWORK_ORDER = (PTODF,)
GOVERNANCE_FRAMEWORK_ORDER = (AJ_SAAF, GALA, ABEGF)
FILED_FRAMEWORK_ORDER = (
    *EVIDENTIARY_FRAMEWORK_ORDER,
    *GOVERNANCE_FRAMEWORK_ORDER,
)
FILED_FRAMEWORK_STAGES = MappingProxyType({
    AJ_SAAF: "filed_framework:aj_saaf",
    PTODF: "filed_framework:ptodf",
    GALA: "filed_framework:gala",
    ABEGF: "filed_framework:abegf",
})
FILED_FRAMEWORK_AUTHORITY_ROLE = "FILED_GOVERNANCE_FRAMEWORK_EVALUATOR"

FRAMEWORK_PASS = "PASS"
FRAMEWORK_DENY = "DENY"
FRAMEWORK_ESCALATE = "ESCALATE"

AJ_SAAF_CONTROL_ACTIONS = frozenset(
    {
        "PERMIT",
        "CONDITION",
        "CONSTRAIN",
        "SUSPEND",
        "DENY",
        "REVOKE",
        "ESCALATE",
    }
)
AJ_SAAF_PASS_ACTIONS = frozenset({"PERMIT", "CONDITION", "CONSTRAIN"})
AJ_SAAF_RECALCULATION_TRIGGERS = (
    "JURISDICTION_CHANGE",
    "CROSS_BORDER_DATA_MOVEMENT",
    "REGULATORY_RECLASSIFICATION",
    "TREATY_ACTIVATION",
    "EMERGENCY_DECLARATION",
    "SOVEREIGN_OVERRIDE",
    "INSTITUTIONAL_DIRECTIVE",
)
ABEGF_SUSPENSION_CONTROLS = (
    "IMMEDIATE_SUSPENSION",
    "PARTIAL_CAPABILITY_ISOLATION",
    "PROGRESSIVE_DE_ESCALATION",
    "PERMANENT_DISABLEMENT",
)

_COMMON_SOURCE_FIELDS = frozenset({
    "evaluator_id",
    "evaluator_version",
    "authority_credential",
    "framework",
    "stage",
    "evaluation_sequence",
    "request_fingerprint",
    "pre_evaluation_state_hash",
    "evaluation_time",
    "prior_framework_digest",
    "snapshot_digest",
    "determination",
    "digest",
    "signature",
    "verified",
})


class FiledFrameworkEvaluator(Protocol):
    evaluator_id: str
    evaluator_version: str
    authority_role: str
    authority_credential_id: str

    def evaluate_aj_saaf(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_ptodf(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_gala(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...

    def evaluate_abegf(
        self, *, stage: str, snapshot: dict[str, Any]
    ) -> dict[str, Any]: ...


def _safe_hash(value: Any) -> str | None:
    try:
        return canonical_integrity_hash(value)
    except (IntegrityContractError, TypeError, ValueError):
        return None


def _text(value: Any) -> bool:
    return type(value) is str and bool(value)


def _trust_context_owner_pinned(
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> bool:
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not is_sha512(owner_pinned_context_digest)
    ):
        return False
    return hmac.compare_digest(
        trust_context.context_digest,
        owner_pinned_context_digest,
    )


def _text_list(value: Any, *, allow_empty: bool = False) -> bool:
    return (
        type(value) is list
        and (allow_empty or bool(value))
        and all(_text(item) for item in value)
        and len(set(value)) == len(value)
    )


def _evidence_references_exact(value: Any) -> bool:
    if type(value) is not list or not value:
        return False
    identifiers: set[str] = set()
    for reference in value:
        if type(reference) is not dict or set(reference) != {
            "evidence_id",
            "source",
            "digest",
        }:
            return False
        identifier = reference.get("evidence_id")
        if type(identifier) is not str or not _text(identifier) or identifier in identifiers:
            return False
        identifiers.add(identifier)
        if not _text(reference.get("source")):
            return False
        if not is_sha512(reference.get("digest")):
            return False
    return True


def _token_digests(state: dict[str, Any]) -> dict[str, Any]:
    tokens = state.get("tokens")
    if type(tokens) is not dict:
        return {}
    return {
        name: token.get("digest") if type(token) is dict else None
        for name, token in sorted(tokens.items())
    }


def _required_ptodf_steps(state: dict[str, Any]) -> dict[str, bool]:
    return {
        "three_p_core": state.get("three_p_core_result") == "PASS",
        "authority_first": state.get("authority_first_result") == "ALLOW",
        "procedural_truth": state.get("procedural_truth_result") == "PASS",
    }


def _gala_audit_packet(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "request_fingerprint": state.get("request_fingerprint"),
        "pre_attestation_state_hash": state.get("state_hash") or GENESIS_HASH,
        "three_p_core_digest": state.get("three_p_core_digest"),
        "authority_first_result": state.get("authority_first_result"),
        "procedural_truth_result": state.get("procedural_truth_result"),
        "classification_result": state.get("classification_result"),
        "licensing_result": state.get("licensing_result"),
        "governance_result": state.get("governance_result"),
        "filed_framework_results": deepcopy(
            state.get("filed_framework_results", {})
        ),
        "token_digests": _token_digests(state),
    }


def _evaluation_snapshot(
    state: dict[str, Any],
    *,
    framework: str,
    sequence: int,
) -> dict[str, Any]:
    snapshot = {
        "framework": framework,
        "stage": FILED_FRAMEWORK_STAGES[framework],
        "evaluation_sequence": sequence,
        "request_fingerprint": state.get("request_fingerprint"),
        "state_hash": state.get("state_hash") or GENESIS_HASH,
        "evaluation_time": state.get("evaluation_time"),
        "action": deepcopy(state.get("action")),
        "payload": deepcopy(state.get("payload")),
        "context": deepcopy(state.get("context")),
        "resolved_authority": deepcopy(state.get("resolved_authority")),
        "jurisdiction": deepcopy(state.get("jurisdiction")),
        "ap_acf_class": deepcopy(state.get("ap_acf_class")),
        "requested_autonomy_level": deepcopy(
            state.get("requested_autonomy_level")
        ),
        "autonomy_ceiling": deepcopy(state.get("autonomy_ceiling")),
        "operational_scope": deepcopy(state.get("operational_scope")),
        "deployment_scope": deepcopy(state.get("deployment_scope")),
        "license_profile": deepcopy(state.get("license_profile")),
        "current_candidate": deepcopy(state.get("current_candidate")),
        "active_results": {
            name: deepcopy(state.get(name))
            for name in (
                "three_p_core_result",
                "authority_first_result",
                "procedural_truth_result",
                "classification_result",
                "licensing_result",
                "governance_result",
                "domain_result",
                "aurion15_result",
            )
        },
        "filed_framework_results": deepcopy(
            state.get("filed_framework_results", {})
        ),
        "prior_framework_digest": state.get("filed_framework_digest"),
        "token_digests": _token_digests(state),
    }
    if framework == AJ_SAAF:
        snapshot["operational_context"] = deepcopy(
            state.get("aj_saaf_operational_context")
        )
    elif framework == PTODF:
        snapshot["required_procedural_steps"] = _required_ptodf_steps(state)
    elif framework == GALA:
        packet = _gala_audit_packet(state)
        snapshot["audit_packet"] = packet
        snapshot["audit_packet_digest"] = _safe_hash(packet)
    elif framework == ABEGF:
        snapshot["autonomy_request"] = deepcopy(state.get("abegf_request"))
    return snapshot


def _common_error(
    source: Any,
    *,
    framework: str,
    sequence: int,
    snapshot: dict[str, Any],
    evaluator: FiledFrameworkEvaluator,
    provider: HybridSignatureProvider | None,
    trust_context: HybridVerificationContext | None,
    owner_pinned_context_digest: str | None,
) -> str | None:
    if (
        not is_hybrid_provider(provider)
        or getattr(provider, "framework_attestation_admitted", None) is not True
    ):
        return "FRAMEWORK_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
    if type(source) is not dict or set(source) != _COMMON_SOURCE_FIELDS:
        return f"{framework}_EVALUATOR_RESULT_SHAPE_INVALID"
    if (
        not isinstance(trust_context, HybridVerificationContext)
        or type(owner_pinned_context_digest) is not str
        or not _trust_context_owner_pinned(
            trust_context,
            owner_pinned_context_digest,
        )
    ):
        return "FILED_FRAMEWORK_OWNER_TRUST_PIN_INVALID"
    if not verify_hybrid_signed_object(
        source,
        trust_context=trust_context,
        owner_pinned_context_digest=owner_pinned_context_digest,
        expected_purpose=FILED_FRAMEWORK_ATTESTATION_PURPOSE,
        require_effect_authority=False,
    ):
        return f"{framework}_EVALUATION_ATTESTATION_INVALID"
    if source.get("evaluator_id") != getattr(evaluator, "evaluator_id", None):
        return f"{framework}_EVALUATOR_ID_MISMATCH"
    if source.get("evaluator_version") != getattr(
        evaluator, "evaluator_version", None
    ):
        return f"{framework}_EVALUATOR_VERSION_MISMATCH"
    if source.get("authority_credential") != {
        "credential_id": getattr(
            evaluator, "authority_credential_id", None
        ),
        "authority_role": FILED_FRAMEWORK_AUTHORITY_ROLE,
    }:
        return f"{framework}_AUTHORITY_CREDENTIAL_INVALID"
    bindings = {
        "framework": framework,
        "stage": FILED_FRAMEWORK_STAGES[framework],
        "evaluation_sequence": sequence,
        "request_fingerprint": snapshot.get("request_fingerprint"),
        "pre_evaluation_state_hash": snapshot.get("state_hash"),
        "evaluation_time": snapshot.get("evaluation_time"),
        "prior_framework_digest": snapshot.get("prior_framework_digest"),
        "snapshot_digest": _safe_hash(snapshot),
    }
    for field, expected in bindings.items():
        if source.get(field) != expected:
            return f"{framework}_EVALUATION_BINDING_MISMATCH:{field}"
    return None


def _aj_saaf_context_exact(snapshot: dict[str, Any]) -> bool:
    context = snapshot.get("operational_context")
    if type(context) is not dict or set(context) != {
        "geographic_location",
        "deployment_context",
        "data_origin",
        "subject_status",
        "regulatory_classification",
        "cross_border_data_movement",
    }:
        return False
    if not all(
        _text(context.get(field))
        for field in (
            "geographic_location",
            "deployment_context",
            "data_origin",
            "subject_status",
            "regulatory_classification",
        )
    ):
        return False
    return (
        type(context.get("cross_border_data_movement")) is bool
        and context["geographic_location"] == snapshot.get("jurisdiction")
        and context["regulatory_classification"] == snapshot.get("ap_acf_class")
    )


def _aj_saaf_error(
    determination: Any, snapshot: dict[str, Any]
) -> str | None:
    fields = {
        "result",
        "control_action",
        "applicable_authorities",
        "winning_authority",
        "conflicts",
        "precedence_resolved",
        "escalation_route",
        "lawful_override_limits",
        "runtime_recalculation_triggers",
        "evidence_references",
    }
    if type(determination) is not dict or set(determination) != fields:
        return "AJ-SAAF_DETERMINATION_SHAPE_INVALID"
    if not _aj_saaf_context_exact(snapshot):
        return "AJ-SAAF_OPERATIONAL_CONTEXT_INVALID"
    action = determination.get("control_action")
    result = determination.get("result")
    if action not in AJ_SAAF_CONTROL_ACTIONS:
        return "AJ-SAAF_CONTROL_ACTION_INVALID"
    expected_result = (
        FRAMEWORK_PASS
        if action in AJ_SAAF_PASS_ACTIONS
        else FRAMEWORK_ESCALATE
        if action == "ESCALATE"
        else FRAMEWORK_DENY
    )
    if result != expected_result:
        return "AJ-SAAF_RESULT_CONTROL_MISMATCH"
    if not _text_list(determination.get("applicable_authorities")):
        return "AJ-SAAF_APPLICABLE_AUTHORITIES_INVALID"
    if type(determination.get("conflicts")) is not list:
        return "AJ-SAAF_CONFLICTS_INVALID"
    if type(determination.get("precedence_resolved")) is not bool:
        return "AJ-SAAF_PRECEDENCE_STATUS_INVALID"
    if not _text_list(determination.get("lawful_override_limits")):
        return "AJ-SAAF_OVERRIDE_LIMITS_INVALID"
    triggers = determination.get("runtime_recalculation_triggers")
    if type(triggers) is not list or tuple(triggers) != AJ_SAAF_RECALCULATION_TRIGGERS:
        return "AJ-SAAF_RECALCULATION_TRIGGERS_INVALID"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return "AJ-SAAF_EVIDENCE_CONTRACT_INVALID"
    if result == FRAMEWORK_PASS:
        if determination.get("precedence_resolved") is not True:
            return "AJ-SAAF_PRECEDENCE_UNRESOLVED"
        winner = determination.get("winning_authority")
        if not _text(winner) or winner != snapshot.get("resolved_authority"):
            return "AJ-SAAF_WINNING_AUTHORITY_MISMATCH"
        if winner not in determination["applicable_authorities"]:
            return "AJ-SAAF_WINNING_AUTHORITY_NOT_APPLICABLE"
        if determination.get("escalation_route") is not None:
            return "AJ-SAAF_PASS_WITH_ESCALATION_ROUTE"
    elif result == FRAMEWORK_ESCALATE:
        route = determination.get("escalation_route")
        if type(route) is not dict or set(route) != {"entity_type", "entity_id"}:
            return "AJ-SAAF_ESCALATION_ROUTE_INVALID"
        if not all(_text(value) for value in route.values()):
            return "AJ-SAAF_ESCALATION_ROUTE_INVALID"
    return None


def _ptodf_error(
    determination: Any, snapshot: dict[str, Any]
) -> str | None:
    fields = {
        "result",
        "required_procedural_steps",
        "evidentiary_sufficiency",
        "licence_state_action",
        "evidence_references",
    }
    if type(determination) is not dict or set(determination) != fields:
        return "PTODF_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {
        FRAMEWORK_PASS,
        FRAMEWORK_DENY,
        FRAMEWORK_ESCALATE,
    }:
        return "PTODF_RESULT_INVALID"
    expected_steps = snapshot.get("required_procedural_steps")
    if determination.get("required_procedural_steps") != expected_steps:
        return "PTODF_PROCEDURAL_STEPS_MISMATCH"
    if type(determination.get("evidentiary_sufficiency")) is not bool:
        return "PTODF_EVIDENTIARY_STATUS_INVALID"
    if determination.get("licence_state_action") not in {"MAINTAIN", "INVALIDATE"}:
        return "PTODF_LICENCE_ACTION_INVALID"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return "PTODF_EVIDENCE_CONTRACT_INVALID"
    all_steps_passed = type(expected_steps) is dict and all(expected_steps.values())
    should_pass = (
        all_steps_passed
        and determination["evidentiary_sufficiency"] is True
    )
    if determination["result"] == FRAMEWORK_PASS:
        if not should_pass or determination["licence_state_action"] != "MAINTAIN":
            return "PTODF_PASS_CONTRACT_INVALID"
    elif determination["licence_state_action"] != "INVALIDATE":
        return "PTODF_FAILURE_MUST_INVALIDATE_LICENCE"
    return None


def _gala_error(
    determination: Any, snapshot: dict[str, Any]
) -> str | None:
    fields = {
        "result",
        "release_authorized",
        "certification_id",
        "attestation_status",
        "revocation_status",
        "audit_packet_digest",
        "evidence_references",
    }
    if type(determination) is not dict or set(determination) != fields:
        return "GALA_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {
        FRAMEWORK_PASS,
        FRAMEWORK_DENY,
        FRAMEWORK_ESCALATE,
    }:
        return "GALA_RESULT_INVALID"
    if type(determination.get("release_authorized")) is not bool:
        return "GALA_RELEASE_STATUS_INVALID"
    if determination.get("attestation_status") not in {
        "ATTESTED",
        "DENIED",
        "SUSPENDED",
        "REVOKED",
    }:
        return "GALA_ATTESTATION_STATUS_INVALID"
    if determination.get("revocation_status") not in {
        "ACTIVE",
        "SUSPENDED",
        "REVOKED",
    }:
        return "GALA_REVOCATION_STATUS_INVALID"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return "GALA_EVIDENCE_CONTRACT_INVALID"
    if determination.get("audit_packet_digest") != snapshot.get(
        "audit_packet_digest"
    ):
        return "GALA_AUDIT_PACKET_BINDING_MISMATCH"
    if determination["result"] == FRAMEWORK_PASS:
        if (
            determination["release_authorized"] is not True
            or not _text(determination.get("certification_id"))
            or determination["attestation_status"] != "ATTESTED"
            or determination["revocation_status"] != "ACTIVE"
            or snapshot.get("filed_framework_results", {}).get(AJ_SAAF)
            != FRAMEWORK_PASS
            or snapshot.get("filed_framework_results", {}).get(PTODF)
            != FRAMEWORK_PASS
            or snapshot.get("active_results", {}).get("governance_result")
            != "ALLOW"
        ):
            return "GALA_PASS_CONTRACT_INVALID"
    elif determination["release_authorized"] is not False:
        return "GALA_NON_PASS_RELEASE_INVALID"
    return None


def _abegf_request_exact(request: Any) -> bool:
    fields = {
        "decision_domain",
        "self_directed_scope",
        "self_modification_requested",
        "goal_expansion_requested",
        "delegation_targets",
        "cross_platform_interactions",
        "cross_vendor_interactions",
        "cross_jurisdiction_interactions",
    }
    if type(request) is not dict or set(request) != fields:
        return False
    if not _text(request.get("decision_domain")) or not _text(
        request.get("self_directed_scope")
    ):
        return False
    if type(request.get("self_modification_requested")) is not bool:
        return False
    if type(request.get("goal_expansion_requested")) is not bool:
        return False
    return all(
        _text_list(request.get(field), allow_empty=True)
        for field in (
            "delegation_targets",
            "cross_platform_interactions",
            "cross_vendor_interactions",
            "cross_jurisdiction_interactions",
        )
    )


def _abegf_error(
    determination: Any, snapshot: dict[str, Any]
) -> str | None:
    fields = {
        "result",
        "autonomy_ceiling",
        "permitted_decision_domains",
        "prohibited_actions",
        "maximum_self_directed_scope",
        "self_modification_allowed",
        "goal_expansion_allowed",
        "escalation_triggers",
        "suspension_controls",
        "cross_system_containment",
        "emergency_rollback_available",
        "evidence_references",
    }
    if type(determination) is not dict or set(determination) != fields:
        return "ABEGF_DETERMINATION_SHAPE_INVALID"
    if determination.get("result") not in {
        FRAMEWORK_PASS,
        FRAMEWORK_DENY,
        FRAMEWORK_ESCALATE,
    }:
        return "ABEGF_RESULT_INVALID"
    request = snapshot.get("autonomy_request")
    if type(request) is not dict or not _abegf_request_exact(request):
        return "ABEGF_AUTONOMY_REQUEST_INVALID"
    ceiling = determination.get("autonomy_ceiling")
    requested = snapshot.get("requested_autonomy_level")
    if not isinstance(ceiling, (int, float)) or isinstance(ceiling, bool) or ceiling < 0:
        return "ABEGF_AUTONOMY_CEILING_INVALID"
    if not isinstance(requested, (int, float)) or isinstance(requested, bool) or requested < 0:
        return "ABEGF_REQUESTED_AUTONOMY_INVALID"
    if not _text_list(determination.get("permitted_decision_domains")):
        return "ABEGF_PERMITTED_DOMAINS_INVALID"
    if not _text_list(determination.get("prohibited_actions"), allow_empty=True):
        return "ABEGF_PROHIBITED_ACTIONS_INVALID"
    if not _text(determination.get("maximum_self_directed_scope")):
        return "ABEGF_MAXIMUM_SCOPE_INVALID"
    if type(determination.get("self_modification_allowed")) is not bool:
        return "ABEGF_SELF_MODIFICATION_LIMIT_INVALID"
    if type(determination.get("goal_expansion_allowed")) is not bool:
        return "ABEGF_GOAL_EXPANSION_LIMIT_INVALID"
    if not _text_list(determination.get("escalation_triggers")):
        return "ABEGF_ESCALATION_TRIGGERS_INVALID"
    if tuple(determination.get("suspension_controls", [])) != ABEGF_SUSPENSION_CONTROLS:
        return "ABEGF_SUSPENSION_CONTROLS_INVALID"
    containment = determination.get("cross_system_containment")
    if type(containment) is not dict or set(containment) != {
        "system_chaining_limited",
        "cross_model_delegation_limited",
        "cross_platform_interaction_limited",
        "cross_vendor_interaction_limited",
        "cross_jurisdiction_interaction_limited",
    }:
        return "ABEGF_CROSS_SYSTEM_CONTAINMENT_INVALID"
    if not all(type(value) is bool for value in containment.values()):
        return "ABEGF_CROSS_SYSTEM_CONTAINMENT_INVALID"
    if type(determination.get("emergency_rollback_available")) is not bool:
        return "ABEGF_EMERGENCY_ROLLBACK_STATUS_INVALID"
    if not _evidence_references_exact(determination.get("evidence_references")):
        return "ABEGF_EVIDENCE_CONTRACT_INVALID"
    if determination["result"] == FRAMEWORK_PASS:
        licensed_ceiling = snapshot.get("license_profile", {}).get(
            "max_autonomy_level"
        )
        declared_ceiling = snapshot.get("autonomy_ceiling")
        numeric_ceilings: list[int | float] = [ceiling]
        for value in (licensed_ceiling, declared_ceiling):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return "ABEGF_UPSTREAM_AUTONOMY_CEILING_INVALID"
            numeric_ceilings.append(value)
        if requested > min(numeric_ceilings):
            return "ABEGF_AUTONOMY_CEILING_EXCEEDED"
        if request["decision_domain"] not in determination[
            "permitted_decision_domains"
        ]:
            return "ABEGF_DECISION_DOMAIN_NOT_PERMITTED"
        if snapshot.get("action") in determination["prohibited_actions"]:
            return "ABEGF_ACTION_PROHIBITED"
        if request["decision_domain"] != snapshot.get("action"):
            return "ABEGF_DECISION_DOMAIN_BINDING_INVALID"
        if request["self_directed_scope"] != determination[
            "maximum_self_directed_scope"
        ]:
            return "ABEGF_SELF_DIRECTED_SCOPE_EXCEEDED"
        if (
            request["self_modification_requested"]
            and not determination["self_modification_allowed"]
        ):
            return "ABEGF_SELF_MODIFICATION_NOT_PERMITTED"
        if (
            request["goal_expansion_requested"]
            and not determination["goal_expansion_allowed"]
        ):
            return "ABEGF_GOAL_EXPANSION_NOT_PERMITTED"
        if not all(containment.values()):
            return "ABEGF_CROSS_SYSTEM_CONTAINMENT_NOT_ENFORCED"
        if determination["emergency_rollback_available"] is not True:
            return "ABEGF_EMERGENCY_ROLLBACK_UNAVAILABLE"
        if snapshot.get("filed_framework_results", {}).get(GALA) != FRAMEWORK_PASS:
            return "ABEGF_GALA_PREREQUISITE_MISSING"
    return None


_DETERMINATION_VALIDATORS = MappingProxyType({
    AJ_SAAF: _aj_saaf_error,
    PTODF: _ptodf_error,
    GALA: _gala_error,
    ABEGF: _abegf_error,
})
_EVALUATOR_METHODS = MappingProxyType({
    AJ_SAAF: "evaluate_aj_saaf",
    PTODF: "evaluate_ptodf",
    GALA: "evaluate_gala",
    ABEGF: "evaluate_abegf",
})


def _record(
    *,
    framework: str,
    sequence: int,
    snapshot: dict[str, Any],
    source: dict[str, Any] | None,
    result: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "framework": framework,
        "stage": FILED_FRAMEWORK_STAGES[framework],
        "evaluation_sequence": sequence,
        "result": result,
        "reason": reason,
        "evaluation_snapshot": deepcopy(snapshot),
        "evaluation_snapshot_digest": _safe_hash(snapshot),
        "evaluation_source": deepcopy(source),
        "evaluation_source_digest": _safe_hash(source) if source else None,
        "evidence_references": deepcopy(
            source.get("determination", {}).get("evidence_references", [])
            if source
            else []
        ),
        "authority_granted": False,
        "execution_authority_granted": False,
    }


def evaluate_filed_framework(
    state: dict[str, Any],
    framework: str,
    *,
    evaluator: FiledFrameworkEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
) -> dict[str, Any]:
    if framework not in FILED_FRAMEWORK_ORDER:
        raise ValueError("FILED_FRAMEWORK_NOT_ADMITTED")
    trace = state.setdefault("filed_framework_trace", [])
    results = state.setdefault("filed_framework_results", {})
    if type(trace) is not list or type(results) is not dict:
        raise ValueError("FILED_FRAMEWORK_STATE_INVALID")
    sequence = len(trace) + 1
    expected_framework = (
        FILED_FRAMEWORK_ORDER[sequence - 1]
        if sequence <= len(FILED_FRAMEWORK_ORDER)
        else None
    )
    snapshot = _evaluation_snapshot(
        state,
        framework=framework,
        sequence=sequence,
    )
    source: dict[str, Any] | None = None
    error: str | None = None
    if framework != expected_framework:
        error = "FILED_FRAMEWORK_EXECUTION_ORDER_INVALID"
    elif evaluator is None:
        error = "FILED_FRAMEWORK_EVALUATOR_NOT_INJECTED"
    else:
        metadata = (
            getattr(evaluator, "evaluator_id", None),
            getattr(evaluator, "evaluator_version", None),
            getattr(evaluator, "authority_role", None),
            getattr(evaluator, "authority_credential_id", None),
        )
        method = getattr(evaluator, _EVALUATOR_METHODS[framework], None)
        if (
            not all(_text(value) for value in metadata)
            or metadata[2] != FILED_FRAMEWORK_AUTHORITY_ROLE
            or not callable(method)
        ):
            error = "FILED_FRAMEWORK_EVALUATOR_CONTRACT_INVALID"
        elif (
            not is_hybrid_provider(attestation_provider)
            or getattr(
                attestation_provider,
                "framework_attestation_admitted",
                None,
            )
            is not True
        ):
            error = "FRAMEWORK_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED"
        else:
            try:
                source = method(
                    stage=FILED_FRAMEWORK_STAGES[framework],
                    snapshot=deepcopy(snapshot),
                )
            except Exception as exc:
                error = (
                    f"{framework}_EVALUATOR_ERROR:"
                    f"{type(exc).__name__}:{exc}"
                )
            if error is None:
                error = _common_error(
                    source,
                    framework=framework,
                    sequence=sequence,
                    snapshot=snapshot,
                    evaluator=evaluator,
                    provider=attestation_provider,
                    trust_context=attestation_trust_context,
                    owner_pinned_context_digest=owner_pinned_context_digest,
                )
            if error is None:
                if type(source) is not dict:
                    error = f"{framework}_EVALUATION_SOURCE_INVALID"
                else:
                    error = _DETERMINATION_VALIDATORS[framework](
                        source.get("determination"),
                        snapshot,
                    )
    result = (
        source["determination"]["result"]
        if error is None and source is not None
        else FRAMEWORK_DENY
    )
    reason = error or f"{framework}_EVALUATION_COMPLETED"
    record = _record(
        framework=framework,
        sequence=sequence,
        snapshot=snapshot,
        source=source,
        result=result,
        reason=reason,
    )
    trace.append(record)
    results[framework] = result
    state["filed_framework_digest"] = canonical_integrity_hash(trace)
    state["filed_framework_result"] = result
    state["filed_framework_reason"] = reason
    if framework == GALA:
        state["gala_attestation"] = deepcopy(source) if source else {}
    if result != FRAMEWORK_PASS:
        invalidation_reason = (
            f"{framework.lower().replace('-', '_')}_failure_"
            "invalidated_licence_state"
        )
        state = invalidate_filed_licence(
            state,
            stage=FILED_FRAMEWORK_STAGES[framework],
            reason=invalidation_reason,
        )
        state.setdefault("licensing_trace", []).append(
            {
                "layer": framework,
                "result": "INVALIDATED",
                "reason": reason,
            }
        )
    return state


def filed_framework_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    trace = state.get("filed_framework_trace", [])
    record = trace[-1] if type(trace) is list and trace else {}
    return {
        "framework": record.get("framework"),
        "stage": record.get("stage"),
        "evaluation_sequence": record.get("evaluation_sequence"),
        "result": record.get("result"),
        "reason": record.get("reason"),
        "record_digest": _safe_hash(record),
        "trace_digest": _safe_hash(trace),
        "authority_granted": False,
        "execution_authority_granted": False,
    }


def verify_filed_frameworks(
    state: dict[str, Any],
    *,
    evaluator: FiledFrameworkEvaluator | None,
    attestation_provider: HybridSignatureProvider | None,
    attestation_trust_context: HybridVerificationContext,
    owner_pinned_context_digest: str,
    require_hash_binding: bool = True,
) -> bool:
    trace = state.get("filed_framework_trace")
    results = state.get("filed_framework_results")
    if (
        evaluator is None
        or type(trace) is not list
        or len(trace) != len(FILED_FRAMEWORK_ORDER)
        or type(results) is not dict
        or set(results) != set(FILED_FRAMEWORK_ORDER)
        or state.get("filed_framework_digest") != _safe_hash(trace)
    ):
        return False
    for index, (framework, record) in enumerate(
        zip(FILED_FRAMEWORK_ORDER, trace),
        start=1,
    ):
        if type(record) is not dict or set(record) != {
            "framework",
            "stage",
            "evaluation_sequence",
            "result",
            "reason",
            "evaluation_snapshot",
            "evaluation_snapshot_digest",
            "evaluation_source",
            "evaluation_source_digest",
            "evidence_references",
            "authority_granted",
            "execution_authority_granted",
        }:
            return False
        snapshot = record.get("evaluation_snapshot")
        source = record.get("evaluation_source")
        if type(snapshot) is not dict or type(source) is not dict:
            return False
        if (
            record.get("framework") != framework
            or record.get("stage") != FILED_FRAMEWORK_STAGES[framework]
            or record.get("evaluation_sequence") != index
            or record.get("result") != FRAMEWORK_PASS
            or results.get(framework) != FRAMEWORK_PASS
            or record.get("authority_granted") is not False
            or record.get("execution_authority_granted") is not False
            or record.get("evaluation_snapshot_digest") != _safe_hash(snapshot)
            or record.get("evaluation_source_digest") != _safe_hash(source)
        ):
            return False
        if _common_error(
            source,
            framework=framework,
            sequence=index,
            snapshot=snapshot,
            evaluator=evaluator,
            provider=attestation_provider,
            trust_context=attestation_trust_context,
            owner_pinned_context_digest=owner_pinned_context_digest,
        ) is not None:
            return False
        if _DETERMINATION_VALIDATORS[framework](
            source.get("determination"), snapshot
        ) is not None:
            return False
        if record.get("evidence_references") != source[
            "determination"
        ]["evidence_references"]:
            return False
    records_by_framework = {
        record["framework"]: record
        for record in trace
    }
    if state.get("gala_attestation") != records_by_framework[GALA].get(
        "evaluation_source"
    ):
        return False
    if state.get("licensing_result") != "ALLOW":
        return False
    final_snapshot = trace[-1]["evaluation_snapshot"]
    if type(final_snapshot) is not dict:
        return False
    live_bindings = {
        "request_fingerprint": state.get("request_fingerprint"),
        "action": state.get("action"),
        "payload": state.get("payload"),
        "context": state.get("context"),
        "resolved_authority": state.get("resolved_authority"),
        "jurisdiction": state.get("jurisdiction"),
        "ap_acf_class": state.get("ap_acf_class"),
        "requested_autonomy_level": state.get("requested_autonomy_level"),
        "autonomy_ceiling": state.get("autonomy_ceiling"),
        "operational_scope": state.get("operational_scope"),
        "deployment_scope": state.get("deployment_scope"),
        "license_profile": state.get("license_profile"),
        "autonomy_request": state.get("abegf_request"),
    }
    if any(
        final_snapshot.get(field) != value
        for field, value in live_bindings.items()
    ):
        return False
    aj_snapshot = records_by_framework[AJ_SAAF]["evaluation_snapshot"]
    if type(aj_snapshot) is not dict:
        return False
    if aj_snapshot.get("operational_context") != state.get(
        "aj_saaf_operational_context"
    ):
        return False
    if not require_hash_binding:
        return True
    chain = state.get("hash_chain")
    if type(chain) is not list or not verify_hash_chain_entries(
        chain, state.get("state_hash")
    ):
        return False
    previous_index = -1
    for index, (framework, record) in enumerate(
        zip(FILED_FRAMEWORK_ORDER, trace),
        start=1,
    ):
        prefix = trace[:index]
        payload = {
            "framework": framework,
            "stage": FILED_FRAMEWORK_STAGES[framework],
            "evaluation_sequence": index,
            "result": FRAMEWORK_PASS,
            "reason": record.get("reason"),
            "record_digest": _safe_hash(record),
            "trace_digest": _safe_hash(prefix),
            "authority_granted": False,
            "execution_authority_granted": False,
        }
        matches = [
            chain_index
            for chain_index, entry in enumerate(chain)
            if entry.get("stage") == FILED_FRAMEWORK_STAGES[framework]
            and entry.get("payload_hash") == _safe_hash(payload)
        ]
        if len(matches) != 1 or matches[0] <= previous_index:
            return False
        framework_index = matches[0]
        pre_stage = f"three_p_core:{FILED_FRAMEWORK_STAGES[framework]}"
        post_stage = f"{pre_stage}:post"
        if (
            framework_index == 0
            or framework_index + 1 >= len(chain)
            or chain[framework_index - 1].get("stage") != pre_stage
            or chain[framework_index + 1].get("stage") != post_stage
        ):
            return False
        previous_index = framework_index
    return True
