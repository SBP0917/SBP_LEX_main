"""IMPLEMENTATION_DEFINED_V2 mechanics for externally governed 3P evaluation.

This module is an interpreter, not a source of P1/P2/P3 policy.  A caller must
supply the substantive rules, thresholds, evidence authorities, decision
logic, lifecycle state, revocation data, and conformance fixtures.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Final, Mapping

from sbp_lex.governance.three_p_doctrine import (
    THREE_P_ATTESTATION_PURPOSE,
    THREE_P_AUTHORITY_ROLE,
    THREE_P_PRIMITIVES,
)
from sbp_lex.security.integrity import canonical_integrity_hash, is_sha512
from sbp_lex.security.signature_provider import SignatureProvider, build_signed_object


THREE_P_POLICY_SCHEMA_ID: Final = "IMPLEMENTATION_DEFINED_V2.THREE_P_POLICY.1"
THREE_P_POLICY_CLASSIFICATION: Final = "IMPLEMENTATION_DEFINED_V2"
THREE_P_MECHANICS_STATUS: Final = "AI_PROPOSED_AWAITING_APPROVAL"
_COMPARATORS: Final = frozenset({"EQ", "GTE", "LTE", "IN"})
_LIFECYCLE_STATES: Final = frozenset({"ACTIVE", "SUSPENDED", "REVOKED", "SUPERSEDED"})

EvidenceResolver = Callable[[str, str, dict[str, Any]], Mapping[str, Any] | None]


def _utc(value: Any) -> datetime | None:
    if type(value) is not str or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        return None


def validate_three_p_policy(policy: Any) -> tuple[str, ...]:
    """Validate mechanics only; successful validation is not policy approval."""

    errors: list[str] = []
    if type(policy) is not dict:
        return ("POLICY_NOT_SUPPLIED",)
    try:
        canonical_integrity_hash(policy)
    except (TypeError, ValueError):
        errors.append("POLICY_NOT_CANONICAL")
    required = {
        "schema_id", "classification", "policy_id", "policy_version",
        "effective_from", "expires_at", "authority", "lifecycle", "primitives",
        "fixtures",
    }
    if set(policy) != required:
        errors.append("POLICY_SHAPE_INVALID")
    if policy.get("schema_id") != THREE_P_POLICY_SCHEMA_ID:
        errors.append("POLICY_SCHEMA_INVALID")
    if policy.get("classification") != THREE_P_POLICY_CLASSIFICATION:
        errors.append("POLICY_CLASSIFICATION_INVALID")
    for field in ("policy_id", "policy_version"):
        if type(policy.get(field)) is not str or not policy.get(field):
            errors.append(f"{field.upper()}_INVALID")
    effective_from = _utc(policy.get("effective_from"))
    expires_at = _utc(policy.get("expires_at"))
    if (
        effective_from is None
        or expires_at is None
        or effective_from >= expires_at
    ):
        errors.append("POLICY_EFFECTIVITY_INVALID")
    authority = policy.get("authority")
    if type(authority) is not dict or set(authority) != {"credential_id", "evidence_authorities"}:
        errors.append("POLICY_AUTHORITY_INVALID")
    elif (
        type(authority.get("credential_id")) is not str
        or not authority.get("credential_id")
        or type(authority.get("evidence_authorities")) is not list
        or not authority.get("evidence_authorities")
        or any(
            type(item) is not str or not item or item != item.strip()
            for item in authority["evidence_authorities"]
        )
        or len(authority["evidence_authorities"])
        != len(set(authority["evidence_authorities"]))
    ):
        errors.append("POLICY_AUTHORITY_INVALID")
    lifecycle = policy.get("lifecycle")
    if type(lifecycle) is not dict or set(lifecycle) != {
        "state", "revision", "supersedes", "revoked_at", "revocation_reason"
    }:
        errors.append("POLICY_LIFECYCLE_INVALID")
    elif (
        lifecycle.get("state") not in _LIFECYCLE_STATES
        or type(lifecycle.get("revision")) is not int
        or lifecycle.get("revision", 0) < 1
    ):
        errors.append("POLICY_LIFECYCLE_INVALID")
    primitives = policy.get("primitives")
    if type(primitives) is not dict or set(primitives) != set(THREE_P_PRIMITIVES):
        errors.append("POLICY_PRIMITIVES_INVALID")
    else:
        for primitive in THREE_P_PRIMITIVES:
            spec = primitives[primitive]
            if type(spec) is not dict or set(spec) != {"rules", "thresholds", "decision_logic"}:
                errors.append(f"{primitive}_SPEC_INVALID")
                continue
            rules = spec.get("rules")
            thresholds = spec.get("thresholds")
            logic = spec.get("decision_logic")
            if type(thresholds) is not dict or not thresholds:
                errors.append(f"{primitive}_THRESHOLDS_MISSING")
            if type(rules) is not list or not rules:
                errors.append(f"{primitive}_RULES_MISSING")
                continue
            rule_ids: set[str] = set()
            admitted_authorities = set(
                authority.get("evidence_authorities", [])
                if type(authority) is dict
                else []
            )
            for rule in rules:
                if type(rule) is not dict or set(rule) != {
                    "rule_id", "evidence_type", "authority_id", "field", "comparator", "threshold_id"
                }:
                    errors.append(f"{primitive}_RULE_INVALID")
                    continue
                rule_id = rule.get("rule_id")
                if (
                    type(rule_id) is not str
                    or not rule_id
                    or rule_id in rule_ids
                    or type(rule.get("evidence_type")) is not str
                    or not rule.get("evidence_type")
                    or type(rule.get("authority_id")) is not str
                    or not rule.get("authority_id")
                    or rule.get("authority_id") not in admitted_authorities
                    or type(rule.get("field")) is not str
                    or not rule.get("field")
                    or rule.get("comparator") not in _COMPARATORS
                    or rule.get("threshold_id") not in thresholds
                ):
                    errors.append(f"{primitive}_RULE_INVALID")
                    continue
                rule_ids.add(rule_id)
            required_rule_ids = (
                logic.get("required_rule_ids")
                if type(logic) is dict
                else None
            )
            if (
                type(logic) is not dict
                or set(logic) != {"operator", "required_rule_ids"}
                or logic.get("operator") not in {"ALL", "ANY"}
                or type(required_rule_ids) is not list
                or not required_rule_ids
                or any(type(item) is not str for item in required_rule_ids)
                or len(required_rule_ids) != len(set(required_rule_ids))
                or set(required_rule_ids) != rule_ids
            ):
                errors.append(f"{primitive}_DECISION_LOGIC_INVALID")
    fixtures = policy.get("fixtures")
    if type(fixtures) is not list or not fixtures:
        errors.append("POLICY_FIXTURES_MISSING")
    else:
        fixture_ids: set[str] = set()
        for item in fixtures:
            fixture_id = item.get("fixture_id") if type(item) is dict else None
            if (
                type(item) is not dict
                or set(item) != {"fixture_id", "input_digest", "expected"}
                or type(fixture_id) is not str
                or not fixture_id
                or fixture_id in fixture_ids
                or not is_sha512(item.get("input_digest"))
                or type(item.get("expected")) is not dict
                or set(item.get("expected", {})) != set(THREE_P_PRIMITIVES)
                or any(
                    value not in {"SATISFIED", "NOT_SATISFIED"}
                    for value in item.get("expected", {}).values()
                )
            ):
                errors.append("POLICY_FIXTURES_INVALID")
                continue
            fixture_ids.add(fixture_id)
    return tuple(dict.fromkeys(errors))


def _compare(value: Any, comparator: str, threshold: Any) -> bool | None:
    try:
        if comparator == "EQ":
            return value == threshold
        if comparator == "GTE":
            return value >= threshold
        if comparator == "LTE":
            return value <= threshold
        if comparator == "IN":
            return value in threshold if type(threshold) in (list, tuple) else None
    except (TypeError, ValueError):
        return None
    return None


class ImplementationDefinedV2ThreePEvaluator:
    """Adapter for the existing ``ThreePCoreEvaluator`` trust boundary."""

    authority_role = THREE_P_AUTHORITY_ROLE

    def __init__(
        self,
        *,
        policy: dict[str, Any] | None,
        evidence_resolver: EvidenceResolver | None,
        attestation_provider: SignatureProvider,
        evaluator_id: str,
        evaluator_version: str,
    ) -> None:
        self.policy = deepcopy(policy)
        self.evidence_resolver = evidence_resolver
        self.provider = attestation_provider
        self.evaluator_id = evaluator_id
        self.evaluator_version = evaluator_version
        authority = policy.get("authority") if type(policy) is dict else None
        self.authority_credential_id = (
            authority.get("credential_id") if type(authority) is dict else "UNAVAILABLE"
        )

    def _policy_error(self, snapshot: dict[str, Any]) -> str | None:
        errors = validate_three_p_policy(self.policy)
        if errors:
            return errors[0]
        lifecycle = self.policy["lifecycle"]
        if lifecycle["state"] != "ACTIVE":
            return f"POLICY_{lifecycle['state']}"
        evaluation_time = _utc(snapshot.get("evaluation_time"))
        if evaluation_time is None:
            return "EVALUATION_TIME_INVALID"
        if evaluation_time < _utc(self.policy["effective_from"]):
            return "POLICY_NOT_YET_EFFECTIVE"
        if evaluation_time >= _utc(self.policy["expires_at"]):
            return "POLICY_EXPIRED"
        if self.evidence_resolver is None:
            return "EVIDENCE_RESOLVER_NOT_SUPPLIED"
        return None

    def evaluate(self, *, stage: str, snapshot: dict[str, Any]) -> dict[str, Any]:
        policy_error = self._policy_error(snapshot)
        determinations: dict[str, Any] = {}
        for primitive in THREE_P_PRIMITIVES:
            references: list[dict[str, str]] = []
            results: list[bool | None] = []
            spec = self.policy["primitives"][primitive] if policy_error is None else None
            if spec is not None:
                for rule in spec["rules"]:
                    try:
                        evidence = self.evidence_resolver(
                            rule["evidence_type"],
                            rule["authority_id"],
                            deepcopy(snapshot),
                        )
                    except Exception:
                        evidence = None
                    valid = (
                        type(evidence) is dict
                        and evidence.get("authority_id") == rule["authority_id"]
                        and rule["authority_id"] in self.policy["authority"]["evidence_authorities"]
                        and type(evidence.get("evidence_id")) is str
                        and type(evidence.get("source")) is str
                        and is_sha512(evidence.get("digest"))
                        and type(evidence.get("values")) is dict
                    )
                    if not valid:
                        results.append(None)
                        continue
                    references.append({key: evidence[key] for key in ("evidence_id", "source", "digest")})
                    results.append(_compare(evidence["values"].get(rule["field"]), rule["comparator"], spec["thresholds"][rule["threshold_id"]]))
            operator = spec["decision_logic"]["operator"] if spec is not None else "ALL"
            satisfied = bool(results) and None not in results and (all(results) if operator == "ALL" else any(results))
            if not references:
                diagnostic = {"policy_error": policy_error or "EVIDENCE_ABSENT_OR_INDETERMINATE", "primitive": primitive}
                references = [{
                    "evidence_id": f"fail-closed:{primitive}",
                    "source": "IMPLEMENTATION_DEFINED_V2_DIAGNOSTIC",
                    "digest": canonical_integrity_hash(diagnostic),
                }]
            determinations[primitive] = {
                "result": "SATISFIED" if satisfied else "NOT_SATISFIED",
                "evidence_references": references,
            }
        payload = {
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "authority_credential": {"credential_id": self.authority_credential_id, "authority_role": self.authority_role},
            "stage": stage,
            "evaluation_sequence": snapshot.get("evaluation_sequence"),
            "request_fingerprint": snapshot.get("request_fingerprint"),
            "pre_evaluation_state_hash": snapshot.get("state_hash"),
            "evaluation_time": snapshot.get("evaluation_time"),
            "prior_three_p_digest": snapshot.get("prior_three_p_digest"),
            "snapshot_digest": canonical_integrity_hash(snapshot),
            "determinations": determinations,
        }
        return build_signed_object(
            payload,
            provider=self.provider,
            purpose=THREE_P_ATTESTATION_PURPOSE,
        )


__all__ = [
    "EvidenceResolver",
    "ImplementationDefinedV2ThreePEvaluator",
    "THREE_P_POLICY_CLASSIFICATION",
    "THREE_P_MECHANICS_STATUS",
    "THREE_P_POLICY_SCHEMA_ID",
    "validate_three_p_policy",
]
