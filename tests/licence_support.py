from __future__ import annotations

from copy import deepcopy
from typing import Any

from sbp_lex.licensing.filed_licensing import (
    FILED_LICENCE_AUTHORITY_ROLE,
    LICENCE_ALLOW,
    LICENCE_DENY,
    evaluate_filed_licence,
    filed_licence_hash_payload,
)
from sbp_lex.security.integrity import (
    GENESIS_HASH,
    build_hash_chain_entry,
    canonical_integrity_hash,
)
from sbp_lex.security.signature_provider import build_signed_object


class PassingFiledLicenceEvaluator:
    licence_evaluator_id = "filed-licence-authority"
    licence_evaluator_version = "1"
    licence_authority_role = FILED_LICENCE_AUTHORITY_ROLE
    licence_authority_credential_id = "filed-licence-authority-credential"

    def __init__(self, provider: Any) -> None:
        self.provider = provider
        self.licence_id = "filed-licence-au-0001"
        self.invalidation_status = "VALID"
        self.revocation_status = "ACTIVE"
        self.revocation_sequence = 1
        self.tier_override: str | None = None
        self.binding_overrides: dict[str, Any] = {}

    def evaluate_licence(
        self,
        *,
        stage: str,
        snapshot: dict[str, Any],
    ) -> dict[str, Any]:
        result = (
            LICENCE_ALLOW
            if self.invalidation_status == "VALID"
            and self.revocation_status == "ACTIVE"
            else LICENCE_DENY
        )
        bindings = deepcopy(snapshot["bindings"])
        bindings.update(deepcopy(self.binding_overrides))
        determination = {
            "result": result,
            "licence_id": self.licence_id,
            "tier": (
                self.tier_override
                if self.tier_override is not None
                else deepcopy(snapshot["tier"])
            ),
            "bindings": bindings,
            "invalidation_status": self.invalidation_status,
            "revocation_status": self.revocation_status,
            "revocation_sequence": self.revocation_sequence,
            "evidence_references": [
                {
                    "evidence_id": (
                        f"{self.licence_id}:{self.revocation_sequence}"
                    ),
                    "source": "filed-licence-authority-record",
                    "digest": canonical_integrity_hash(
                        {
                            "licence_id": self.licence_id,
                            "stage": stage,
                            "revocation_status": self.revocation_status,
                            "revocation_sequence": self.revocation_sequence,
                        }
                    ),
                }
            ],
        }
        return build_signed_object(
            {
                "evaluator_id": self.licence_evaluator_id,
                "evaluator_version": self.licence_evaluator_version,
                "authority_credential": {
                    "credential_id": self.licence_authority_credential_id,
                    "authority_role": self.licence_authority_role,
                },
                "stage": stage,
                "evaluation_sequence": snapshot["evaluation_sequence"],
                "request_fingerprint": snapshot["request_fingerprint"],
                "pre_evaluation_state_hash": snapshot["state_hash"],
                "evaluation_time": snapshot["evaluation_time"],
                "prior_licence_digest": snapshot["prior_licence_digest"],
                "snapshot_digest": canonical_integrity_hash(snapshot),
                "determination": determination,
            },
            provider=self.provider,
        )


def append_filed_licence_evaluation(
    state: dict[str, Any],
    *,
    stage: str,
    evaluator: PassingFiledLicenceEvaluator,
    provider: Any,
) -> None:
    context_method = getattr(provider, "hybrid_verification_context", None)
    context = (
        context_method(allow_test_only=True)
        if callable(context_method)
        else None
    )
    evaluate_filed_licence(
        state,
        stage=stage,
        evaluator=evaluator,
        attestation_provider=provider,
        trust_context=context,
        owner_pinned_context_digest=(
            context.context_digest if context is not None else None
        ),
    )
    previous_hash = (
        state["hash_chain"][-1]["hash"]
        if state.get("hash_chain")
        else GENESIS_HASH
    )
    entry = build_hash_chain_entry(
        previous_hash=previous_hash,
        stage=stage,
        payload=filed_licence_hash_payload(state),
    )
    state.setdefault("hash_chain", []).append(entry)
    state["state_hash"] = entry["hash"]


def filed_licence_request_fields() -> dict[str, Any]:
    return {
        "identity": {"subject_id": "owner"},
        "license_tier": "TIER_2_COMMERCIAL",
        "execution_rights": {"allowed_actions": ["review"]},
    }
