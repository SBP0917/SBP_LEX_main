from __future__ import annotations

"""Compatibility entry point routed through the complete V2 traversal."""

from typing import Any, Dict

from sbp_lex.execution.controlled_local_adapter import EffectAdapter
from sbp_lex.governance.filed_frameworks import FiledFrameworkEvaluator
from sbp_lex.governance.filed_lifecycle import FiledLifecycleEvaluator
from sbp_lex.governance.skg_authority import SKGAuthorityEvaluator
from sbp_lex.governance.three_p_doctrine import ThreePCoreEvaluator
from sbp_lex.licensing.filed_licensing import FiledLicenceEvaluator
from sbp_lex.pipeline.runner import run_v2
from sbp_lex.security.signature_provider import SignatureProvider


def run_pipeline(
    input_data: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    *,
    signature_provider: SignatureProvider | None = None,
    three_p_evaluator: ThreePCoreEvaluator | None = None,
    three_p_attestation_provider: SignatureProvider | None = None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    effect_adapter: EffectAdapter | None = None,
    effect_permit_ttl_ms: int | None = None,
) -> Dict[str, Any]:
    """Run the complete single pipeline; no compatibility shortcut exists."""

    return run_v2(
        input_data,
        pre_context_signals,
        signature_provider=signature_provider,
        three_p_evaluator=three_p_evaluator,
        three_p_attestation_provider=three_p_attestation_provider,
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_attestation_provider,
        filed_framework_evaluator=filed_framework_evaluator,
        filed_framework_attestation_provider=(
            filed_framework_attestation_provider
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        effect_adapter=effect_adapter,
        effect_permit_ttl_ms=effect_permit_ttl_ms,
    )
