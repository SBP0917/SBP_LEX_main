# V2 Parallel Readiness Preparation

## Purpose and status

This record prepares the six V2 workstreams that do not alter the concurrent
dual-signature implementation.  It is a preparation and evidence-design
record, not production admission, a custody assertion, a reproducibility
freeze, or an independent validation result.

All rows remain non-admitting until their stated evidence is supplied against
a named, clean, committed P object.

## 1. Local toolchain readiness

| Item | Observed status | Required completion evidence |
| --- | --- | --- |
| Windows architecture | x64: Intel Core i7-1265U, 64-bit address width | Retain the Windows build and architecture in the validation capture. |
| Visual Studio Community | Community 2022 17.14.37614.0 has `Microsoft.VisualStudio.Component.VC.Tools.x86.x64`; Windows SDK 10.0.26100.0 headers and `Hostx64\\x64\\link.exe` are present. Observed linker SHA-512: `6efc6068fec722ab0bbcc6149a3b618bf60ca4ff3c4032b2d23a0bbac4bc58a86742387c90c456d5d60999a54cd777e417f3c1ef1f6ed516a9133bbcb6895b6b`. | Re-measure and require exact compiler, linker and SDK pins in a declared validation lane. |
| Rust | `stable-x86_64-pc-windows-msvc` is active/default; GNU is also installed; MSVC linker is now observed. The current eight-crate MSVC test/check/format/strict-Clippy matrix passed. | Re-measure and require exact compiler, linker and SDK pins in a final P-bound lane. |
| Git | `C:\\Program Files\\Git\\cmd\\git.exe` is available; observed SHA-512 `6cb22ca658c00c82158b8ea4538808e5f7e28e31e67896f7c1616937ef080c71eb78043630e01aca5c67b54b7e025bba4ccdf87ee857845cdbf4e00cd7a3a46a` | Re-measure and require the exact pin in each P/T/D/E attempt. |
| PowerShell | The workspace runtime provides PowerShell 7 | Pin any executable used by a declared reproducibility lane. |
| Java/TLC | Eclipse Temurin JDK 21.0.12.101 is installed at `C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.12.101-hotspot\\bin\\java.exe`; `java -version` reports Temurin 21.0.12.1 LTS; executable SHA-512 `ffb212c4a727b04b6ce7fd08c111aca5d55100631b39419ca111d93b5ec05173e53a62f17a6de04894ced013fdfded4ba815e44083b0a83d604b64fee2d8b1d1` | Re-measure and require the exact pin before a local TLC run. |

No compiler, Java runtime, or host tool is itself an authority source.

## 2. Supply-chain reproducibility

### Present non-admitted input evidence

`requirements.lock` and
`evidence/v2/python311-resolution-evidence.json` contain a CPython 3.11.9,
win-amd64 resolution with 17 exact wheels, versions, sizes, SHA-256 wheel
hashes, active dependency edges, and SHA-512 hashes for `requirements.txt`.
Their stated status is correctly
`UNSEALED_ACCEPTED_HISTORY_AND_FREEZE_BINDING_UNAVAILABLE`.

The checkout currently has active modifications and untracked implementation
material.  Its observed HEAD is `015d9009bc58d0e22cb3e32f1bf4d5d9003a7cbf`.
It must not be represented as a final P freeze.

`evidence/v2/unsealed-candidate-release-manifest-20260824.json` records the
current candidate Python/Rust SBOM inputs, executable pins and deterministic
SHA-512 values.  It explicitly remains `UNSEALED_NOT_ADMITTED`: it is not a
P-object package, committed SBOM, signed release or reproducibility result.
The existing SHA-512 handover snapshot was preserved rather than overwritten,
so it is not a fresh snapshot of this candidate worktree.

### Required freeze procedure

1. Stop concurrent source changes and select one final P commit object ID.
2. Obtain out-of-band pins for that exact P ID, the Git executable SHA-512,
   and the accepted-attempt-history SHA-512.
3. Bind only the P commit from a bare object database through
   `sbp_lex.supply_chain.bind_p_object`; never bind a mutable checkout, branch,
   tag, or remote ref.
4. Build Python dependency inputs only from P's committed `requirements.txt`.
   Retain the 17-wheel resolution evidence only if the committed requirements
   SHA-512 and target environment remain identical; otherwise resolve again in
   a clean environment.
5. Build Rust dependency inputs only from every P-committed `Cargo.toml` and
   corresponding `Cargo.lock`.  A missing Rust lock remains
   `P_SOURCE_INCOMPLETE`, never a success.
6. Generate SBOM documents from those P-bound Python and Rust inputs.  Each
   document must contain the P commit/tree identifiers, source-blob identities,
   package name/version/source/checksum information, canonical payload
   SHA-512, and `NOT_ADMITTED` state until an external admission lane exists.
7. Retain full byte transcripts, executable pre/post SHA-512 pins, clean-source
   checks before and after every reproduction lane, and a 7,200-second
   fail-closed whole-lane limit.

### Clean-machine reproduction package

The second machine must receive only the P object database or immutable P
archive, out-of-band pins, declared tool executables, wheelhouse/SBOM inputs,
Cargo locks, and the accepted-attempt history.  It must record:

- operating-system version, CPU architecture, locale, code page and timezone;
- Python, pip, Rust, Cargo, Git, Java and TLC executable versions and
  SHA-512 values;
- exact command arguments, declared environment names and values, start/end
  times, exit status, full stdout and stderr bytes, and output file hashes;
- clean-source status before and after each lane; and
- a byte-for-byte comparison of canonical documents and SBOM payload hashes.

Any missing pin, dirty source, stale object, unavailable tool, incomplete
lockfile, transcript truncation or mismatch is non-success.

## 3. TPM and Windows-provider readiness

The local provider enumeration lists `Microsoft Platform Crypto Provider`.
It also lists `Microsoft Pluton Cryptographic Provider`, for which the current
enumeration returned `Not implemented`.  An administrator-authorized raw
`Get-Tpm` capture is retained in
`evidence/v2/host-readiness-tpm-raw-20260824.json`: the STM TPM reports
present, ready, enabled and activated, with version `1.258.0.0`.  This host
readiness observation establishes neither a provisioned key nor a custody
claim.  A direct read-only `NCryptOpenStorageProvider` call for `Microsoft
Platform Crypto Provider` returned `0x80090030` (`NTE_DEVICE_NOT_READY`) to
the non-elevated current-user probe.  An elevated read-only probe opened the
provider successfully (`0x00000000`). Both results are recorded in
`evidence/v2/host-readiness-platform-provider-20260824.json`.  Neither result
establishes a key, algorithm support, non-exportability, custody or signing.
No algorithm or key-format compatibility has been inferred.

No provider creation, key provisioning, signing operation, signature-provider
change, or production custody claim is included in this workstream.

Before any provider implementation begins, capture these facts on the target
deployment host:

| Required observation | Fail-closed interpretation if absent or changed |
| --- | --- |
| Windows edition/build, x64 architecture and firmware/TPM version | No host or provider custody claim. |
| `Get-Tpm` presence, readiness, enabled and activated state | No TPM-backed lane. |
| Provider name, provider type, key name and public-key SHA-512 | Wrong or unpinned provider/key is rejected. |
| Non-exportability and operation-policy evidence | Software or exportable fallback is rejected. |
| Supported ML-DSA-87 and Ed448 representation through the chosen provider | No production hybrid signing path exists. |
| Restart, unavailable-provider, wrong-key, rotation and revocation results | Each must deny without a software fallback. |

## 4. Deployment-boundary inventory

| Boundary | Repository status | Required deployment evidence |
| --- | --- | --- |
| `main.py:app` | Canonical FastAPI launcher; `/v2/evaluate` calls `run_sbp_lex` | The deployed launcher, reverse proxy and service account must be identified and pinned. |
| `main.py:run_sbp_lex` and `sbp_lex.pipeline.runner:run_v2` | Python pipeline entry points | Show that callers cannot bypass the reviewed route by direct import, alternate process, debug entry point or replacement configuration. |
| `sbp_lex.execution.rust_authority_client.RustAuthorityRoute` | Injectable route; its production admission is not established | Bind one reviewed Rust authority endpoint and reject its absence, replacement or transport failure. |
| `security_core` and `rust_authority_service` | Reviewed Rust components remain runtime-detached | Demonstrate that the deployed process reaches the Rust boundary before any dispatch. |
| `sbp_lex.execution.controlled_local_adapter.EffectAdapter` | Explicitly `ISOLATED_TEST_ONLY_NOT_LIVE`; uses local software/SQLite behaviour | Exclude it from a production artifact and prove it cannot become an alternate effect route. |
| Physical or external effect adapter | No production adapter/choke point is present in the repository | Inventory every real handler and prove each is reachable solely after the admitted Rust decision/permit path. |

Known bypass classes requiring deployment inspection are direct Python imports,
alternate launchers, optional dependency injection, direct local-adapter use,
separate Rust service invocation, replaced binaries/configuration, and any
physical handler outside the reviewed process boundary.  This inventory does
not claim they are closed.

## 5. Durable replay, revocation and audit state

The Rust boundary defines injected durable-store concepts, but there is no
deployed production replay, revocation or audit service.  The production design
must supply all of the following as one atomic effect-admission unit:

| Store | Required property | Required failure result |
| --- | --- | --- |
| Replay/permit claim | Atomic, durable, single successful claim keyed by canonical permit identity and bound request/effect fingerprint | Contention, restart, timeout, duplicate or unknown outcome denies dispatch. |
| Revocation | Authenticated append-only sequence with monotonic ordering, current-head binding, rollback detection and point-of-use lookup | Missing, stale, forked, lower-sequence, unverifiable or unavailable state denies. |
| Audit | Canonical append-only terminal record, durable canonical-head authority and request-decision-permit-claim-receipt lineage | Failed persistence or unknown physical outcome is recorded/denied; an unauthorised suffix never becomes canonical. |

The chosen deployment must document transaction boundaries, crash recovery,
concurrency, backup/restore, retention, clock source, access control, rotation,
key loss, network partition and administrator rollback behaviour.  A local
SQLite/WAL fixture or an in-memory Rust test store is not production evidence.

## 6. Independent-validation preparation

The following independent experiment matrix is ready to run after the
dual-signature work, final P binding and production provider decision are
complete:

| Experiment | Required observation | Pass criterion |
| --- | --- | --- |
| Second-machine reproduction | Independent P object, tool pins and full transcripts | Canonical artifacts and declared verdicts match without undeclared network input. |
| Canonical-input fuzzing | Unicode, ordering, duplicate field, size, non-finite and malformed-object corpus | Every malformed or ambiguous input fails before dispatch. |
| Dual-signature fault injection | Missing, substituted, wrong-purpose, altered-byte, invalid and lane-order variants | Both required lanes must verify the identical canonical bytes; any lane failure denies. |
| Provider/TPM faults | Provider unavailable, wrong key, changed public key, permission failure, restart and rotation | Denial without software fallback or partial authority. |
| Replay/revocation/audit faults | Duplicate permit, concurrent claim, rollback, stale head, crash and audit write failure | No handler reachability or ambiguous success. |
| Deployment bypass review | Every launcher, direct import path, binary/config replacement and real handler | No effect path exists outside the admitted Rust/permit boundary. |
| TLA+/code correspondence | Each formal transition/invariant mapped to current code and tests | Differences are classified; no model claim is promoted to code/deployment proof. |

Each experiment must retain raw commands, tool hashes, source/object pins,
full byte outputs, failure classifications and an independent reviewer result.
`PASS` is unavailable when a required external dependency remains
indeterminate.

### Model-to-code review worksheet

The independent reviewer shall use the following existing sources together:

| Review material | Review use |
| --- | --- |
| `docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md` | Property identifiers P01–P22, experiment definitions and explicit external-dependency boundaries. |
| `formal/tla/SBPLEXV2.tla` and `formal/tla/SBPLEXV2.cfg` | The exact bounded model, transition order and invariant definitions. |
| `docs/security/RUST_TCB_AND_TLA_VALIDATION.md` | Rust boundary, model limitations and current TCB/non-bypass limits. |
| `security_core/src/` | Rust implementation locations for each asserted boundary. |
| `main.py`, `sbp_lex/pipeline/`, and `sbp_lex/execution/` | Python launcher, traversal, adapter and bypass candidates. |
| Raw test/transcript artifacts | Reproducible evidence rather than a documentation-only assertion. |

For every reviewed property, retain one row containing: property/invariant ID;
P commit/tree ID; canonical source locations; exact test or TLC command and
full-byte transcript hash; outcome; unexplained model/code divergence; external
dependency; reviewer identity; and one of `PASS`, `FAIL`, or `INDETERMINATE`.
No row may use a TLC pass as proof of code, TPM, custody, deployment or
physical-effect behaviour.

## 7. Post-signature local validation, 24 August 2026

All results in this section are current-worktree local validation only. They
are not P/T/D/E evidence, a release freeze, a custody assertion, university
admission or production authority.

### Python and cross-language integration

| Command | Result | Machine-readable report |
| --- | --- | --- |
| `.venv\\Scripts\\python.exe -m pytest -q -p no:cacheprovider --tb=short --basetemp=runtime_artifacts\\readiness_pytest_tmp_20260824 --junitxml=runtime_artifacts\\readiness_deferred_final_pytest_workspace_temp_20260824.xml tests` | 660 passed; 0 failed; 0 errors; 0 skipped; 812.94 seconds | SHA-512 `1852b0e3f5950802d31f24c99bf3278feb39dba4528e283b386b12c6af2112738884119f3d8ee2839eb54779b0b3ea2da125cc667d38d8f3b57cf223e20401f9` |
| `.venv\\Scripts\\python.exe -m pytest -q -p no:cacheprovider --tb=short --basetemp=runtime_artifacts\\readiness_authority_route_tmp_20260824 --junitxml=runtime_artifacts\\readiness_authority_route_20260824.xml tests\\test_fastapi_entrypoint.py tests\\test_foundational_public_pipeline.py tests\\test_rust_authority_client.py tests\\test_controlled_local_adapter.py tests\\test_execution_skg_lifecycle_integration.py tests\\test_hybrid_signature_provider.py` | 127 passed; 0 failed; 0 errors; 0 skipped; 279.192 seconds | SHA-512 `f8dc404fb71abe1839e27ad4b42d7c0e07f69ada0d5823193cf102e797a626c4bf1705fc374410ca71114ef2cba10ab669ee8c9f2589941a06506b9cd4efe965` |
| `.venv\\Scripts\\python.exe -m pytest -q -p no:cacheprovider --tb=short --basetemp=runtime_artifacts\\readiness_cross_language_tmp_20260824 --junitxml=runtime_artifacts\\readiness_cross_language_20260824.xml wire_protocol\\v2\\python\\test_contract.py cross_language_reconciliation\\test_reconciliation.py cross_language_reconciliation\\test_detached_semantic_verifier.py` | 67 passed; 0 failed; 0 errors; 0 skipped; 266.091 seconds | SHA-512 `65f065561b22e41f71956a4457888d1e6ae1af3b22f5580d9db5f1eba16107f66c445371f59a01023b2ba3621a2a8d32b7b627e5f99b9a93e03f33b20f81a980` |

Two preliminary attempts are intentionally non-evidence: the Codex runtime
Python lacks FastAPI (five collection errors), and the default Windows pytest
temporary directory produced 64 permission-denied setup errors.  The final
workspace-local `--basetemp` command above is the valid local result; it did
not change source code or production configuration.

The focused route suite includes FastAPI entry tests, public-pipeline tests,
Rust-route tests, controlled-local-adapter tests, lifecycle integration and
strict hybrid-provider tests. It confirms the current mechanical boundary:
the public route terminates `BLOCKED`/`HALT` when no admitted Rust route is
present; terminal route evidence remains `NOT_ADMITTED`; and a supplied Python
effect adapter remains `ISOLATED_TEST_ONLY_NOT_LIVE`.

### MSVC Rust matrix

Using Cargo/Rustc 1.97.1 on `x86_64-pc-windows-msvc`, every command below
returned exit zero: `cargo test --locked`, `cargo check --all-targets
--locked`, `cargo fmt -- --check`, and `cargo clippy --all-targets --locked --
-D warnings`, with feature arguments where shown.

| Manifest | Test result | Feature argument where required |
| --- | --- | --- |
| `security_core/Cargo.toml` | 35 passed | none |
| `hybrid_signature_rust/Cargo.toml` | 7 passed | `--features software-signing` |
| `rust_authority_service/Cargo.toml` | 44 passed | `--all-targets --features evidence-only-fixtures` |
| `wire_protocol/v2/rust/Cargo.toml` | 35 passed | none |
| `polyglot/rust/v2_assurance_kernel/Cargo.toml` | 4 passed | none |
| `trusted_core_rust/Cargo.toml` | 40 passed | none |
| `independent_verifier_rust/Cargo.toml` | 23 passed | none |
| `wire_protocol/rust/Cargo.toml` | 5 passed | none |

The strict-hybrid results include both-lane verification of identical bound
bytes and rejection of a single corrupted lane. The authority-service results
include a production binary that fails closed when physical dependencies are
absent. A preliminary independent-verifier command that supplied a nonexistent
package feature, `--features software-signing`, was rejected by Cargo and was
then rerun correctly without that package feature; no source change was made.

## Completion gate

This preparation record becomes eligible for a final handover update only when
the dual-signature changes stop, the user names a final P commit, all required
pins and accepted history exist, tool installations are independently
confirmed, and the external TPM/deployment evidence is supplied.  Until then,
every item above remains preparation only and non-admitting.
