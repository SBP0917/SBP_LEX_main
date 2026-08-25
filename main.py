from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, Sequence, TextIO

from sbp_lex.pipeline.runner import (
    PipelineHybridTrustContexts,
    run_v2 as _pipeline_run_v2,
)
from sbp_lex.security.signature_provider import SignatureProvider
from sbp_lex.governance.three_p_doctrine import ThreePCoreEvaluator
from sbp_lex.governance.filed_frameworks import FiledFrameworkEvaluator
from sbp_lex.governance.skg_authority import SKGAuthorityEvaluator
from sbp_lex.governance.filed_lifecycle import FiledLifecycleEvaluator
from sbp_lex.governance.filed_governance_integrity import (
    FiledGovernanceIntegrityEvaluator,
)
from sbp_lex.licensing.filed_licensing import FiledLicenceEvaluator
from sbp_lex.execution.controlled_local_adapter import EffectAdapter
from sbp_lex.execution.rust_authority_client import RustAuthorityRoute
from sbp_lex.baseline.application_startup import (
    ApplicationIntegrityRuntimeBundle,
)
from sbp_lex.baseline.request_controls import (
    FoundationalRequestDependencies,
)


# ─────────────────────────────────────────────
# SBP-LEX V2 SINGLE-PIPELINE ENTRY POINT
# ─────────────────────────────────────────────

def run_v2(
    request: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    *,
    signature_provider: SignatureProvider | None = None,
    three_p_evaluator: ThreePCoreEvaluator | None = None,
    three_p_attestation_provider: SignatureProvider | None = None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        SignatureProvider | None
    ) = None,
    filed_governance_integrity_revocation_binding: (
        dict[str, Any] | None
    ) = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
    foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    possession_proof: dict[str, Any] | None = None,
    effect_adapter: EffectAdapter | None = None,
    effect_permit_ttl_ms: int | None = None,
    rust_authority_route: RustAuthorityRoute | None = None,
    hybrid_trust_contexts: PipelineHybridTrustContexts | None = None,
) -> Dict[str, Any]:
    """
    Canonical library entry point for the SBP-LEX V2 single pipeline.

    Accepts:
    - request (action, payload, context)
    - optional pre_context_signals (DTN/SKG output)
    - a build/composition-root signature_provider (never request data)
    - a separately admitted 3P evaluation attestation provider

    Delegates execution to the deterministic pipeline.
    """
    return _pipeline_run_v2(
        request,
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
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        filed_governance_integrity_evaluator=(
            filed_governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        filed_governance_integrity_revocation_binding=(
            filed_governance_integrity_revocation_binding
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        application_integrity_bundle=application_integrity_bundle,
        foundational_request_dependencies=foundational_request_dependencies,
        possession_proof=possession_proof,
        effect_adapter=effect_adapter,
        effect_permit_ttl_ms=effect_permit_ttl_ms,
        rust_authority_route=rust_authority_route,
        hybrid_trust_contexts=hybrid_trust_contexts,
    )


def run_sbp_lex(
    request: Dict[str, Any],
    pre_context_signals: Dict[str, Any] | None = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Compatibility wrapper for callers using the former public name."""

    return run_v2(request, pre_context_signals, **kwargs)


def _json_object(value: str, *, label: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label}_JSON_INVALID:{error.msg}") from error
    if type(parsed) is not dict:
        raise ValueError(f"{label}_JSON_OBJECT_REQUIRED")
    return parsed


def _read_json_object(path: str, *, label: str) -> Dict[str, Any]:
    try:
        content = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError(f"{label}_FILE_UNREADABLE:{type(error).__name__}") from error
    return _json_object(content, label=label)


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sbp-lex-v2",
        description=(
            "Run one fail-closed SBP-LEX V2 evaluation. The CLI does not "
            "inject or admit production authorities."
        ),
    )
    request = parser.add_mutually_exclusive_group(required=True)
    request.add_argument("--request-json")
    request.add_argument("--request-file")
    signals = parser.add_mutually_exclusive_group()
    signals.add_argument("--signals-json")
    signals.add_argument("--signals-file")
    return parser


def cli(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
) -> int:
    """Canonical one-shot CLI launcher."""

    parser = _build_cli_parser()
    arguments = parser.parse_args(argv)
    try:
        request = (
            _json_object(arguments.request_json, label="REQUEST")
            if arguments.request_json is not None
            else _read_json_object(arguments.request_file, label="REQUEST")
        )
        signals = None
        if arguments.signals_json is not None:
            signals = _json_object(arguments.signals_json, label="SIGNALS")
        elif arguments.signals_file is not None:
            signals = _read_json_object(arguments.signals_file, label="SIGNALS")
    except ValueError as error:
        parser.error(str(error))
    result = run_v2(request, signals)
    output = stdout if stdout is not None else sys.stdout
    json.dump(result, output, sort_keys=True, separators=(",", ":"), allow_nan=False)
    output.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
