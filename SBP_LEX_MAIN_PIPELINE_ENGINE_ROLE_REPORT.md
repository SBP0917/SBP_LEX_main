# SBP_LEX_MAIN Pipeline Engine and File Role Report

## Purpose

This report explains the observed role of every repository file and engine in `SBP0917/SBP_LEX_MAIN` after the minimum run-restoration pass.

This is descriptive only. It does not redesign the architecture, merge from `SBP_LEX_V6`, add convergence nodes, add quorum/cloud/distributed authority, or claim that inactive files are production-ready. It records what exists, what is directly used by the current launcher path, and what appears to be present but not wired into `run_v6`.

## Repository and Runtime Context

- Repository cloned locally as: `SBP_LEX_MAIN`
- Remote: `https://github.com/SBP0917/SBP_LEX_main.git`
- Current branch: `main`
- Primary local launcher: `main.py`
- Primary pipeline function: `sbp_lex.pipeline.runner.run_v6`
- Secondary smoke script: `test_run.py`
- Declared deployment entry: `Procfile` -> `uvicorn main:app`
- Observed deployment mismatch: `main.py` does not currently expose a FastAPI `app`
- Validation runtime used: bundled Codex Python `3.12.13`
- Declared runtime: `python-3.11.9`

## Current Pipeline Flow

The current launcher path is:

```text
main.py
run_sbp_lex(...)
sbp_lex.pipeline.runner.run_v6(...)
build_state(...)
enforce_non_repeat_rule(...)
attach_collective_signals(...)
_run_root_of_trust(...)
evaluate_procedural_truth(...)
classification_engine.execute(...)
licensing_engine.execute(...)
governance_engine.execute(...)
apply_grc(...)
run_domain_wrap(...)
run_aurion15(...)
run_execution_gate(...)
_finalize_audit(...)
```

Current observed behavior:

- `python main.py` completes without crashing.
- The default sample request fails closed at the authority-first anchor check.
- Final observed decision is `DENY`.
- `execution_result` exists but remains blank on the early authority-denial path.
- `audit_trace` and `audit_hash` fields exist.
- `audit_hash` remains blank on the early authority-denial path.
- No persistent `audit_log_path` output was observed.

## Pipeline Role Legend

- `ACTIVE`: directly imported or called by the current `run_v6` path.
- `ACTIVE_SUPPORT`: used by active modules or required for their imports.
- `SMOKE_OR_DEPLOY`: entry, deployment, or manual smoke-run surface.
- `PRESENT_NOT_WIRED`: source exists but was not observed as part of the active `run_v6` path.
- `BROKEN_OR_AMBIGUOUS`: present, but extension/name/entry shape prevents confident active use.
- `REPORT`: local report artifact added by this pass.

## Top-Level Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `README.md` | Short repository description and rebuild note. Describes the system as deterministic governance and execution control. | `SMOKE_OR_DEPLOY` |
| `requirements.txt` | Declares `fastapi` and `uvicorn`. These are not required for `python main.py`, but are required for the declared web deployment path. | `SMOKE_OR_DEPLOY` |
| `runtime.txt` | Declares `python-3.11.9` for hosted/runtime environments. | `SMOKE_OR_DEPLOY` |
| `Procfile` | Declares Railway-style web startup: `uvicorn main:app --host 0.0.0.0 --port $PORT`. Current mismatch: `main.py` has no `app`. | `SMOKE_OR_DEPLOY` |
| `start.sh` | Starts `python test_run.py`. | `SMOKE_OR_DEPLOY` |
| `main.py` | Local launcher. Exposes `run_sbp_lex(...)` and runs a default sample request when executed directly. | `ACTIVE` |
| `test_run.py` | Manual smoke payload. Calls `run_v6_pipeline(...)`. It is not a pytest test function. | `SMOKE_OR_DEPLOY` |
| `__init__.py` | Top-level package marker. | `ACTIVE_SUPPORT` |
| `SBP_LEX_MAIN_REPOSITORY_INSPECTION_REPORT.md` | Inspection/debug report covering errors, fixes, validation, and comparison to `SBP_LEX_V6`. | `REPORT` |
| `SBP_LEX_MAIN_PIPELINE_ENGINE_ROLE_REPORT.md` | This file. Maps every observed file/engine role. | `REPORT` |

## Core Pipeline Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/pipeline/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/pipeline/runner.py` | Main deterministic pipeline coordinator. Builds request fingerprint, attaches collective signals, runs authority-first checks, procedural truth, classification, licensing, governance, domain wrap, Aurion runtime, execution gate, and audit finalization. | `ACTIVE` |
| `sbp_lex/shared/state_builder.py` | Builds the initial runtime state and default output fields. | `ACTIVE` |
| `sbp_lex/shared/state_schema.py` | Defines expected state keys/schema-style constants for state shape. | `ACTIVE_SUPPORT` |
| `sbp_lex/shared/types.py` | Defines `EngineResult` used by many engine modules. | `ACTIVE_SUPPORT` |
| `sbp_lex/types.py` | Also defines `EngineResult`; several modules import this path. | `ACTIVE_SUPPORT` |
| `sbp_lex/shared/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |

## Configuration Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/config/pipeline_config.py` | Central constants for governance, procedural truth, classification, licensing, Aurion, execution result names, pipeline order, and configuration builders. | `ACTIVE` |
| `sbp_lex/config/security_config.py` | Security policy constants and builders for PQC placeholder settings, token requirements, collective signal security, execution-gate security, audit security, and fail-closed behavior. | `ACTIVE` |
| `sbp_lex/config/thresholds.py` | Computes safety tier, financial factor, consequentiality tier, corroboration requirement, and threshold snapshots. | `ACTIVE` |

## Authority-First Root-of-Trust Files

The root-of-trust chain is actively invoked from `sbp_lex.pipeline.runner._run_root_of_trust`.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/authority_first/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/authority_first/registry.py` | Lightweight local decorator registry required by existing `@register(...)` imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/authority_first/anchor_validation_engine.py` | Validates required governance anchors: procedural truth, SKG, DTN, and planetary population constraints. Current default `main.py` request fails here because anchors are missing. | `ACTIVE` |
| `sbp_lex/authority_first/attestation_engine.py` | Validates the presence and verified/attested shape of an attestation payload. | `ACTIVE` |
| `sbp_lex/authority_first/attestation_consensus_engine.py` | Validates indexed attestations and consensus threshold. Current `test_run.py` payload fails here because it lacks `indexed_attestations`. | `ACTIVE` |
| `sbp_lex/authority_first/truth_anchor_engine.py` | Builds a truth anchor from indexed attestations and output material. | `ACTIVE` |
| `sbp_lex/authority_first/truth_continuity_engine.py` | Validates continuity between previous and current truth anchors. | `ACTIVE` |
| `sbp_lex/authority_first/truth_expiry_engine.py` | Validates truth anchor timestamp/expiry window. | `ACTIVE` |
| `sbp_lex/authority_first/truth_revocation_engine.py` | Checks truth anchor revocation index. | `ACTIVE` |

## Collective Signal Files

Only `context_interface.py` is directly active in `run_v6`. The other collective engines exist as concept/validation engines but are not currently called by the active pipeline runner.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/collective/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/collective/registry.py` | Lightweight local decorator registry required by existing collective engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/collective/context_interface.py` | Attaches normalized collective signal fields to state and binds request fingerprint into collective signals. | `ACTIVE` |
| `sbp_lex/collective/conflict_detection_engine.py` | Concept engine for detecting policy/jurisdiction/precedence conflict. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/digital_twin_network_engine.py` | Concept engine for DTN jurisdiction/twin availability and verification. Restored from malformed syntax. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/jurisdiction_drift_engine.py` | Concept engine for jurisdiction drift checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/planetary_population_constraints_engine.py` | Concept engine for population/planetary constraint checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/policy_drift_detection_engine.py` | Concept engine comparing current and baseline policy digests. Restored from malformed syntax. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/policy_validation_engine.py` | Concept engine for policy validity checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/sovereign_knowledge_graph_engine.py` | Concept engine for SKG lookup/authority evidence. | `PRESENT_NOT_WIRED` |
| `sbp_lex/collective/sovereign_precedence_matrix_engine.py` | Concept engine for sovereign precedence evaluation. | `PRESENT_NOT_WIRED` |

## Procedural Truth and Governance Files

The active governance path uses `procedural_truth_engine.py`, `engine.py`, and `grc.py`. Many other governance engines exist but are not called by `run_v6`.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/governance/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/governance/base_engine.py` | Lightweight base class required by existing governance engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/governance/registry.py` | Lightweight local decorator registry required by existing governance engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/governance/procedural_truth_engine.py` | Evaluates procedural truth, corroboration, evidence sufficiency, source ratio, and constitutional truth status. Added `evaluate_procedural_truth(...)` wrapper to match the pipeline import. | `ACTIVE` |
| `sbp_lex/governance/engine.py` | Current high-level governance engine. It currently sets `governance_result=ALLOW` with reason `placeholder`. | `ACTIVE` |
| `sbp_lex/governance/grc.py` | Governance response control helpers for allow/deny/escalate feedback, repeat-denial handling, and feedback shaping. | `ACTIVE` |
| `sbp_lex/governance/Authority_engine.py` | Standalone authority engine concept file. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/Procedural_validation_engine.py` | Aurion-style procedural validation class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_attestation_engine.py` | Concept engine for authority attestation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_chain_engine.py` | Concept engine name appears audit-like and computes authority/audit hash material. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_confidence_engine.py` | Concept engine for authority confidence. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_first_execution_engine.py` | Aurion-style authority-first execution class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_resolution_engine.py` | Aurion-style authority resolution class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_revocation_engine.py` | Concept engine for revoked authority checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/authority_scope_engine.py` | Concept engine for authority scope checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/autonomy_boundary_engine.py` | Aurion-style autonomy boundary class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_compliance_engine.py` | Aurion-style governance compliance class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_confidence_engine.py` | Concept engine for governance confidence. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_immutability_engine.py` | Concept engine for governance immutability/hash binding. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_integrity_engine.py` | Concept engine for governance integrity. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_routing_engine.py` | Aurion-style governance routing class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/governance_state_engine.py` | Concept engine for governance state. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/indexed_attestation_engine.py` | Concept engine for validating indexed attestations. Restored from malformed syntax. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/jurisdiction_engine.py` | Concept engine for jurisdiction validation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/jurisdiction_verification_engine.p` | Jurisdiction verification source-like file with `.p` extension, not imported as a normal Python module. | `BROKEN_OR_AMBIGUOUS` |
| `sbp_lex/governance/legitimacy_engine.py` | Aurion-style legitimacy validation class concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/non_bypass_verification_engine.py` | Concept engine for non-bypass verification. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/permanent_sovereign_governance_cycle_engine.py` | Concept engine for permanent sovereign governance cycle checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/precedence_engine.py` | Concept engine for precedence evaluation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/governance/supervisory_override_engine.py` | Concept engine for supervisory override handling. | `PRESENT_NOT_WIRED` |

## Classification Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/classification/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/classification/engine.py` | Thin `ClassificationEngine` wrapper used by the pipeline. | `ACTIVE` |
| `sbp_lex/classification/router.py` | Performs AP-ACF classification checks, validates class/autonomy/environment, and produces ALLOW/DENY/ESCALATE classification result. | `ACTIVE` |

## Licensing Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/licensing/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/licensing/engine.py` | Thin `LicensingEngine` wrapper used by the pipeline. | `ACTIVE` |
| `sbp_lex/licensing/router.py` | Validates license profile, allowed classes, and autonomy ceiling. | `ACTIVE` |

## Domain Files

Only `runner.py` is currently called by `run_v6`. Other domain classes/engines exist as broader domain concepts.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/domains/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/domains/runner.py` | Active domain wrap. Checks legal, sovereign, operational, and risk domain admissibility using current state and collective signals. | `ACTIVE` |
| `sbp_lex/domains/base_domain.py` | Base domain class for domain modules. | `ACTIVE_SUPPORT` |
| `sbp_lex/domains/legal_domain.py` | Domain class concept for legal checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/sovereign_domain.py` | Domain class concept for sovereign checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/operational_domain.py` | Domain class concept for operational checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/risk_domain.py` | Domain class concept for risk checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/demographic_monitoring_engine.py` | Aurion-style domain concept for demographic monitoring. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/economic_signal_engine.py` | Aurion-style domain concept for economic signal checks. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/ethical_constraint_engine.py` | Aurion-style domain concept for ethical constraints. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/infrastructure_state_engine.py` | Aurion-style domain concept for infrastructure state. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/institutional_integrity_engine.py` | Aurion-style domain concept for institutional integrity. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/operational_stability_engine.py` | Aurion-style domain concept for operational stability. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/predictive_risk_engine.py` | Aurion-style domain concept for predictive risk. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/resource_allocation_engine.py` | Aurion-style domain concept for resource allocation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/risk_detection_engine.py` | Aurion-style domain concept for risk detection. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/security_state_engine.py` | Aurion-style domain concept for security state. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/societal_stability_engine.py` | Aurion-style domain concept for societal stability. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/strategic_conflict_detection_engine.py` | Aurion-style domain concept for strategic conflict detection. | `PRESENT_NOT_WIRED` |
| `sbp_lex/domains/technology_impact_engine.py` | Aurion-style domain concept for technology impact. | `PRESENT_NOT_WIRED` |

## Aurion-15 Runtime Files

The active runner is `sbp_lex/aurion15/runtime/runner.py`. Other runtime engine files exist as broader concept modules and are not directly called by the active runner.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/aurion15/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/core/__init__.py` | Core package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/core/base_engine.py` | Base class for Aurion-style engines. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/core/registry.py` | Core registry metadata and/or registration support. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/runtime/__init__.py` | Runtime package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/runtime/base_engine.py` | Lightweight base class required by runtime engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/runtime/registry.py` | Lightweight local decorator registry required by runtime engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/runtime/runner.py` | Active deterministic Aurion candidate runtime. Generates direct/restricted/minimal candidates and maps candidate evaluation to pass/fail/escalate/require_next_candidate. | `ACTIVE` |
| `sbp_lex/aurion15/runtime/cascading_failure_detection_engine.py` | Aurion-style concept engine for cascading failure detection. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/constraint_alignment_engine.py` | Aurion-style concept engine for constraint alignment. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/decision_expiry_engine.py` | Concept engine for decision token expiry. Restored from malformed syntax. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/decision_integrity_engine.py` | Aurion-style concept engine for decision integrity. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/decision_token_engine.py` | Concept engine/class for decision token verification. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/escalation_engine.py` | Concept engine for escalation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/evidence_corroboration_engine.py` | Aurion-style concept engine for evidence corroboration. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/evidence_sufficiency_engine.py` | Aurion-style concept engine for evidence sufficiency. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/execution_attestation_engine.py` | Concept engine for execution attestation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/execution_boundary_engine.py` | Concept engine for execution boundary. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/information_integrity_engine.py` | Aurion-style concept engine for information integrity. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/output_discipline_engine.py` | Concept engine for output discipline. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/runtime_revalidation_engine.py` | Concept engine/class for runtime revalidation. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/runtime/system_interdependency_engine.py` | Aurion-style concept engine for system interdependency. | `PRESENT_NOT_WIRED` |

## Aurion-15 Candidate Files

The current active Aurion runner implements its own candidate generation/evaluation internally. The candidate package appears to be a broader candidate subsystem, but it is not directly invoked by `run_v6` through the active runner.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/aurion15/candidate/__init__.py` | Candidate package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/aurion15/candidate/candidate_generator.py` | Candidate generation helper concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/candidate/candidate_loop_controller.py` | Candidate loop controller concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/candidate/candidate_ranker.py` | Candidate ranking helper concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/candidate/candidate_search_controller.py` | Candidate search decision helper concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/candidate/candidate_selector.py` | Candidate selection helper concept. | `PRESENT_NOT_WIRED` |
| `sbp_lex/aurion15/candidate/runtime_constraint_controller.py` | Runtime constraint helper concept. | `PRESENT_NOT_WIRED` |

## Execution Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/execution/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/execution/base_engine.py` | Lightweight base class required by execution engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/execution/registry.py` | Lightweight local decorator registry required by execution engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/execution/execution_gate.py` | Active execution gate. Verifies hash chain, governance allow, procedural truth pass, corroboration/tier, domain pass, Aurion pass, token stack, boundary/attestation, and collective signal consistency. | `ACTIVE` |
| `sbp_lex/execution/execution_gate_engine.py` | Standalone execution gate engine/class concept. Restored from corrupt syntax, but not called by `run_v6`. | `PRESENT_NOT_WIRED` |
| `sbp_lex/execution/execution_trace_engine.p` | Execution trace source-like file with `.p` extension, not imported as a normal Python module. | `BROKEN_OR_AMBIGUOUS` |

## Audit Files

The active audit path only executes if the pipeline reaches successful execution. The default observed runs terminate earlier, so persistent audit output was not produced.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/audit/__init__.py` | Package marker. | `ACTIVE_SUPPORT` |
| `sbp_lex/audit/registry.py` | Lightweight local decorator registry required by existing audit engine imports. | `ACTIVE_SUPPORT` |
| `sbp_lex/audit/engine.py` | Active `AuditEngine` class used by `_finalize_audit`; builds deterministic in-memory audit trace record and audit digest. | `ACTIVE` |
| `sbp_lex/audit/audit_ledger.py` | Active audit ledger helper used by `_finalize_audit`; appends audit hash to in-memory ledger when audit record/hash already exist. | `ACTIVE` |
| `sbp_lex/audit/audit_engine.py` | Standalone registered audit engine concept that builds an audit record/hash from action/authority/jurisdiction data. Not called by `run_v6`. | `PRESENT_NOT_WIRED` |

## Security Files

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/security/pqc.py` | Placeholder digest/sign/verify helpers for PQC-style signed objects. Used by token stack. | `ACTIVE_SUPPORT` |
| `sbp_lex/security/token_stack.py` | Issues and verifies governance/execution tokens, token digests, signatures, request fingerprint binding, state hash binding, and threshold-token requirements. | `ACTIVE` |

## Response Controller Files

These files appear to define a simpler response-control pipeline surface separate from the active `main.py -> run_v6` path.

| File | Role | Pipeline status |
| --- | --- | --- |
| `sbp_lex/response_controller/__init__.py` | Package marker. | `PRESENT_NOT_WIRED` |
| `sbp_lex/response_controller/controller.py` | Contains `stop(...)` helper for stopping/halting state. | `PRESENT_NOT_WIRED` |
| `sbp_lex/response_controller/runner.py` | Alternate response-controller runner. Not used by `main.py`. | `PRESENT_NOT_WIRED` |

## Files Changed by the Minimum Debug Pass

| File | Why changed |
| --- | --- |
| `sbp_lex/aurion15/runtime/decision_expiry_engine.py` | Repaired malformed/truncated syntax so repository compiles. |
| `sbp_lex/collective/digital_twin_network_engine.py` | Repaired malformed syntax so repository compiles. |
| `sbp_lex/collective/policy_drift_detection_engine.py` | Repaired malformed syntax so repository compiles. |
| `sbp_lex/execution/execution_gate_engine.py` | Repaired corrupt duplicate tail and invalid syntax while preserving fail-closed intent. |
| `sbp_lex/governance/indexed_attestation_engine.py` | Removed invalid `@indexed = None` syntax and restored registered engine shape. |
| `sbp_lex/governance/procedural_truth_engine.py` | Fixed invalid import and added `evaluate_procedural_truth(...)` wrapper expected by pipeline. |
| `sbp_lex/pipeline/runner.py` | Repaired truncated final return, added fail-closed runtime exception response, and added `run_v6_pipeline(...)` alias expected by `test_run.py`. |
| `sbp_lex/audit/registry.py` | Added minimal registry required by existing audit imports. |
| `sbp_lex/authority_first/registry.py` | Added minimal registry required by existing authority-first imports. |
| `sbp_lex/aurion15/runtime/base_engine.py` | Added minimal base engine required by existing runtime imports. |
| `sbp_lex/aurion15/runtime/registry.py` | Added minimal registry required by existing runtime imports. |
| `sbp_lex/collective/context_interface.py` | Added missing `attach_collective_signals(...)` required by active pipeline import. |
| `sbp_lex/collective/registry.py` | Added minimal registry required by existing collective imports. |
| `sbp_lex/execution/base_engine.py` | Added minimal base engine required by existing execution imports. |
| `sbp_lex/execution/registry.py` | Added minimal registry required by existing execution imports. |
| `sbp_lex/governance/base_engine.py` | Added minimal base engine required by existing governance imports. |
| `sbp_lex/governance/registry.py` | Added minimal registry required by existing governance imports. |
| `SBP_LEX_MAIN_REPOSITORY_INSPECTION_REPORT.md` | Added full inspection/debugging report. |
| `SBP_LEX_MAIN_PIPELINE_ENGINE_ROLE_REPORT.md` | Added this file/engine role map. |

## Current Runtime Result

Final validation state observed after the minimum debug pass:

```text
compileall: PASS
main.py: PASS, structured fail-closed DENY
test_run.py: PASS, structured fail-closed DENY
pytest: no tests collected
git diff --check: PASS with line-ending warnings only
```

## Current Trust and Audit Caveats

- This repository now runs, but it is not hardened.
- There is no real pytest suite.
- The active default run fails before execution gate and audit finalization.
- `execution_trace` is only produced by `run_execution_gate`; early denial paths currently do not reach it.
- `audit_hash` exists in state but remains blank on early denial paths.
- `audit_log_path` is not emitted.
- No persistent JSONL audit log was observed.
- FastAPI/uvicorn deployment remains mismatched until `main:app` exists and dependencies are installed.

## Boundary Confirmation

This report and the accompanying minimum debug pass did not:

- redesign the architecture
- merge code from `SBP_LEX_V6`
- merge code from `SBP_LEX_DUAL_V6`
- add convergence nodes
- add active nodes
- add quorum
- add cloud authority
- add distributed authority
- add speculative engines beyond the missing shims already required by existing imports

