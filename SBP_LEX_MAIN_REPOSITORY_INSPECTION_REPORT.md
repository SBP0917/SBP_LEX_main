# SBP_LEX_MAIN Repository Inspection Report

> **HISTORICAL / SUPERSEDED SNAPSHOT — 25 JUNE 2026.** This report records the
> repository, commit, runtime and observations identified below at that date. It
> is not current V2 traversal, test, dependency, launcher, deployment or handover
> evidence. Later work deliberately deleted `sbp_lex/security/pqc.py`, which was
> a fake placeholder rather than a post-quantum implementation. Nothing in this
> historical report supports a current PQC implementation or security claim.

## 1. Repository Inspected

- Repository requested: `SBP0917/SBP_LEX_MAIN`
- GitHub repository cloned: `SBP0917/SBP_LEX_main`
- Local inspection path: `C:\Users\LeighMC\Documents\Codex\2026-06-25\s\work\SBP_LEX_MAIN`
- Branch: `main`
- Starting HEAD observed: `c98e05c Update runner.py`
- Scope followed: inspection, minimum debugging, run validation, and report only.
- Commit/push status: no commit and no push performed.

## 2. Current Repository Structure

Top-level files:

- `main.py`
- `test_run.py`
- `README.md`
- `requirements.txt`
- `runtime.txt`
- `Procfile`
- `start.sh`
- `__init__.py`

Main package structure:

- `sbp_lex/audit/`
- `sbp_lex/aurion15/`
- `sbp_lex/authority_first/`
- `sbp_lex/classification/`
- `sbp_lex/collective/`
- `sbp_lex/config/`
- `sbp_lex/domains/`
- `sbp_lex/execution/`
- `sbp_lex/governance/`
- `sbp_lex/licensing/`
- `sbp_lex/pipeline/`
- `sbp_lex/response_controller/`
- `sbp_lex/security/`
- `sbp_lex/shared/`

Notable repository issues:

- Several modules were syntactically incomplete.
- Several package-local imports referenced missing `registry.py` and `base_engine.py` modules.
- `Procfile` expects `uvicorn main:app`, but `main.py` does not currently expose a FastAPI `app`.
- `requirements.txt` declares `fastapi` and `uvicorn`, but they were not installed in the bundled runtime used for validation.
- No real pytest test suite exists.

## 3. Detected Runtime / Framework

- Language: Python.
- Runtime declared by repository: `runtime.txt` -> `python-3.11.9`.
- Runtime used for inspection: `Python 3.12.13` from bundled Codex runtime:
  `C:\Users\LeighMC\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`
- Declared web framework dependencies:
  - `fastapi`
  - `uvicorn`
- Installed in validation runtime:
  - `pytest 9.1.1`
  - `fastapi`: not installed
  - `uvicorn`: not installed

## 4. Intended Entry Point

Local entry point:

- `main.py`
- Function: `run_sbp_lex(request, pre_context_signals=None)`
- Delegates to: `sbp_lex.pipeline.runner.run_v6`

Existing local smoke entry:

- `test_run.py`
- Imports `run_v6_pipeline` from `sbp_lex.pipeline.runner`

Declared deployment entry:

- `Procfile`: `web: uvicorn main:app --host 0.0.0.0 --port $PORT`

Deployment mismatch:

- `main.py` does not currently define `app`.
- FastAPI and uvicorn were not available in the validation runtime.
- This was reported as a deployment mismatch, not redesigned during this pass.

## 5. Dependency State

Declared dependencies:

```text
fastapi
uvicorn
```

Observed local validation dependency state:

```text
Python 3.12.13
pytest 9.1.1 installed
fastapi not installed
uvicorn not installed
```

No dependency installation was performed because `main.py` can run without FastAPI/uvicorn and the task asked for minimum debugging only.

## 6. Commands Run

Commands run with the bundled Codex Python runtime:

```bat
git clone https://github.com/SBP0917/SBP_LEX_main.git C:\Users\LeighMC\Documents\Codex\2026-06-25\s\work\SBP_LEX_MAIN
git status --short --branch
git log -5 --oneline
python -m compileall .
python main.py
python test_run.py
python -m pytest
python --version
python -m pip show fastapi uvicorn pytest
git diff --check
git diff --stat
git status --short
```

Validation command results:

- `python -m compileall .`: pass after fixes.
- `python main.py`: pass after fixes.
- `python test_run.py`: pass after fixes.
- `python -m pytest`: no tests collected; pytest returned a no-test-suite result.
- `git diff --check`: pass, with line-ending warnings only.

## 7. Errors Found

Syntax errors:

- `sbp_lex/aurion15/runtime/decision_expiry_engine.py`: unterminated string literal.
- `sbp_lex/collective/digital_twin_network_engine.py`: unclosed parenthesis.
- `sbp_lex/collective/policy_drift_detection_engine.py`: unclosed dictionary literal.
- `sbp_lex/execution/execution_gate_engine.py`: corrupt duplicated tail and invalid syntax.
- `sbp_lex/governance/indexed_attestation_engine.py`: invalid `@indexed = None`.
- `sbp_lex/pipeline/runner.py`: incomplete final `return {`.

Import and naming errors:

- Missing `sbp_lex.collective.context_interface.attach_collective_signals`.
- Missing package-local `registry.py` modules used by existing imports.
- Missing package-local `base_engine.py` modules used by existing imports.
- Invalid relative import beyond top-level package in governance/execution engine code.
- `test_run.py` expected `run_v6_pipeline`, but only `run_v6` existed.
- `runner.py` expected `evaluate_procedural_truth`, but `procedural_truth_engine.py` only exposed lower-level engine functions/classes.

Runtime/deployment mismatches:

- `Procfile` expects `main:app`, but no ASGI app is defined.
- `requirements.txt` dependencies were not installed in the validation runtime.

Functional limitations observed after launch:

- `main.py` completes without crashing and returns a fail-closed `DENY`.
- `execution_result` key exists but remains blank on the early authority-denial path.
- `governance_feedback`, `audit_trace`, and `audit_hash` keys exist.
- `audit_hash` remains blank on the early authority-denial path.
- `execution_trace` is not currently emitted.
- `audit_log_path` is not currently emitted.
- No persistent JSONL audit log was observed.

## 8. Fixes Applied

Minimum fixes applied:

- Repaired malformed Python syntax in the six broken modules reported by `compileall`.
- Completed incomplete engine return structures where files were truncated.
- Replaced the corrupt `execution_gate_engine.py` tail with a syntactically valid fail-closed gate implementation consistent with existing field names.
- Added missing lightweight `registry.py` decorators in packages that already imported `.registry`.
- Added missing lightweight `base_engine.py` classes in packages that already imported `.base_engine`.
- Added `sbp_lex/collective/context_interface.py` with `attach_collective_signals` because `runner.py` already imported and called it.
- Corrected invalid relative imports to `sbp_lex.types`.
- Added `evaluate_procedural_truth(state)` wrapper around the existing procedural truth engine output.
- Added `run_v6_pipeline(...)` alias in `sbp_lex/pipeline/runner.py` because `test_run.py` already imports that name.
- Added a fail-closed exception response in `run_v6` for direct runtime exceptions.

No architecture redesign was performed.
No SBP_LEX_V6 or SBP_LEX_DUAL_V6 code was merged into this repository.
No convergence nodes, quorum, cloud authority, distributed authority, or speculative components were added.

## 9. Final Run Status

Final local launcher command:

```bat
python main.py
```

Final launcher status:

- Completed without crashing.
- Returned a structured dictionary.
- Final decision: `DENY`.
- Final execution mode: fail-closed early denial.
- Denial reason: authority-first failure because the default `main.py` sample request has no anchors.

Key output fields observed:

```text
decision=DENY
execution_result=<blank>
governance_feedback=present
audit_trace=present
audit_hash=present but blank
execution_trace=missing
audit_log_path=missing
```

`test_run.py` also completed without crashing and returned a fail-closed `DENY`, this time because attestation consensus lacked the expected detailed attestations despite the sample payload containing several governance fields.

## 10. Test Status

No real pytest test suite is present.

Command:

```bat
python -m pytest
```

Observed result:

```text
collected 0 items
no tests ran
```

This means test coverage is effectively absent. The repository can be compiled and smoke-run, but it is not yet test-verified.

## 11. Security Hardening Stage Assessment

`SBP_LEX_MAIN` appears to contain a broad security/governance concept set, but it is not yet hardened to the level of the already worked `SBP_LEX_V6` repository.

Current security stage assessment:

- Early runtime restoration stage.
- Fail-closed defaults are visible.
- Governance, authority-first, procedural truth, token, audit, and execution-gate concepts are present.
- Several concept modules are present but not necessarily integrated into the main pipeline.
- No mature local trust manifest, release verification, 25-year certainty package, baseline verifier, or stable test suite was observed in this repository.

## 12. Trust / Audit / Governance Features Currently Present

Present components:

- Authority-first root-of-trust chain:
  - anchor validation
  - attestation
  - attestation consensus
  - truth anchor
  - truth continuity
  - truth expiry
  - truth revocation
- Procedural truth engine.
- Classification engine.
- Licensing engine.
- Governance engine.
- GRC feedback and non-repeat handling.
- Domain routing/wrap layer.
- Aurion-15 runtime and candidate modules.
- Execution gate.
- Audit engine and in-memory audit ledger concepts.
- Token stack and a then-present digest/sign/verify placeholder that was later
  deliberately deleted because it was not a PQC implementation.
- Hash-chain/state-hash fields.
- Collective concept modules including SKG/DTN-related files.

Important limitation:

- These features are not yet fully proven by tests.
- Persistent audit JSONL logging was not observed.
- Deployment entry is incomplete.

## 13. Missing Security / Trust Hardening Areas

Missing or incomplete areas:

- Real pytest suite.
- Persistent JSONL audit log path and append validation.
- `audit_log_path` output.
- Full execution trace output.
- Stable deterministic replay verifier.
- Baseline/source hash manifests.
- Toolchain manifest and lock/pinning discipline.
- Release/provenance verification.
- Local root-of-trust manifest.
- Clean deployment app entry matching `Procfile`.
- CI or repeatable clean-clone verification.
- Dependency pinning.
- Runtime/test separation.
- Generated artifact hygiene.
- Canonical schema enforcement tests.
- Fail-closed denial tests.
- Audit corruption detection tests.
- Hash-chain continuity tests.

## 14. Likely Capability When Running

When stabilized, `SBP_LEX_MAIN` appears intended to operate as a backend control-plane pipeline for deterministic governance and execution control.

Likely intended capabilities:

- Accept a request/action payload.
- Build canonical-ish runtime state.
- Attach collective/context signals.
- Run authority-first governance checks.
- Evaluate procedural truth.
- Apply classification/licensing/governance routing.
- Apply domain and Aurion-15 pathway handling.
- Gate execution.
- Produce audit and hash-chain evidence.
- Return a final governance/execution decision.

Current demonstrated capability:

- It can now compile and execute from `main.py`.
- It currently demonstrates fail-closed denial rather than a fully successful execution path.

## 15. Still Needed To Make It Stable

Recommended stabilization tasks:

- Decide whether `main.py` should expose a FastAPI `app` or whether the deployment entry should be changed.
- Install or pin declared dependencies in a reproducible environment.
- Add a real smoke test suite.
- Add a valid authority/evidence fixture for a controlled non-production pass path if current governance rules support it.
- Normalize output so all denial paths produce a clear `execution_result=HALT`.
- Add persistent audit JSONL output if audit logging is a required repository behavior.
- Ensure `audit_hash` and `audit_log_path` are populated when audit is expected.
- Rename or handle `.p` files if they are intended Python modules:
  - `sbp_lex/execution/execution_trace_engine.p`
  - `sbp_lex/governance/jurisdiction_verification_engine.p`
- Add `.gitignore` coverage for cache/runtime artifacts if missing.
- Add clean-clone validation instructions.

## 16. Still Needed To Harden It

Hardening work should be a later explicit pass, not part of this minimum run-restoration task.

Recommended hardening areas:

- Canonical schema definition and validation.
- Deterministic replay validation.
- Audit hash-chain persistence and corruption detection.
- Execution gate denial and token verification tests.
- Source/provenance manifests.
- Dependency and toolchain reproducibility manifests.
- Release/archive verification.
- Authority/evidence payload validation.
- Clear boundary documentation for SKG/DTN as external/non-authoritative unless explicitly changed.
- Lifecycle change-control documentation.

## 17. High-Level Comparison Against `SBP_LEX_V6`

Compared against local reference checkout:

`C:\Users\LeighMC\Documents\Codex\2026-06-25\s\work\SBP_LEX_V6`

Observed differences:

- `SBP_LEX_MAIN` appears broader and rougher in concept surface.
- `SBP_LEX_MAIN` contains many more standalone engine files across governance, domains, collective, Aurion runtime, and response controller areas.
- `SBP_LEX_MAIN` appears to have a Railway/FastAPI deployment intention, but the app entry is incomplete.
- `SBP_LEX_MAIN` had broken syntax/imports and no test suite before this pass.
- `SBP_LEX_V6` is more compact and currently much more verified.
- `SBP_LEX_V6` contains tests, baseline manifests, repository governance artifacts, 25-year certainty artifacts, source/toolchain manifests, and verification scripts.
- `SBP_LEX_V6` has a clearer local trust hardening baseline.

Useful material in `SBP_LEX_MAIN` that may not exist in the same breadth in `SBP_LEX_V6`:

- Broader conceptual governance engine library.
- More domain-specific engine files.
- More Aurion-15 runtime/candidate files.
- Response controller package.
- Railway/FastAPI deployment intent.

Assessment:

- `SBP_LEX_MAIN` appears earlier, broader, and less stable than `SBP_LEX_V6`.
- It should remain separate unless the owner explicitly asks for a carefully governed comparison or migration.
- Dual/V6 hardened features should remain out of scope for this repository unless separately instructed.

## 18. Recommended Next Steps

Recommended immediate next steps:

1. Decide whether this repository should be a web service (`main:app`) or a local CLI/runtime pipeline.
2. Add dependency installation verification for `fastapi` and `uvicorn`, or remove the deployment assumption if not wanted.
3. Add a minimal pytest suite around `main.py`, fail-closed denial, and `test_run.py`.
4. Add persistent audit logging only after confirming that audit JSONL is required for this repository.
5. Normalize denial outputs to include `execution_result=HALT`.
6. Add clean `.gitignore` rules for generated caches and runtime artifacts.
7. Keep this repo separate from `SBP_LEX_V6` until an owner-approved migration/comparison plan exists.

Recommended later hardening:

- Local trust manifest.
- Baseline verifier.
- Replay verifier.
- Audit tamper detection.
- Source/provenance manifests.
- Dependency lock/pinning.
- Deployment smoke test.

## 19. Do Not Commit / Push Confirmation

- No commit was created.
- No push was performed.
- No repository rename was performed.
- No merge from `SBP_LEX_V6` was performed.
- No merge from `SBP_LEX_DUAL_V6` was performed.
- No convergence nodes were added.
- No active nodes were added.
- No quorum/cloud/distributed authority was added.
- No speculative architecture was introduced.

Current worktree contains only local inspection/debug changes plus generated Python cache artifacts from validation.
