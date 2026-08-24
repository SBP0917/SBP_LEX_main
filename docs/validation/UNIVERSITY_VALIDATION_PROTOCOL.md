# SBP-LEX V2 Independent University Validation Protocol

## Protocol status and scope

This is an `AI_PROPOSED_AWAITING_APPROVAL` protocol for possible independent,
reproducible validation of the current SBP-LEX V2 Python evidence contracts, the
isolated Rust security boundary under `security_core/`, and the traversal model
under `formal/tla/`. No explicit owner decision adopts the complete protocol as
acceptance policy. It is not a certification, a completed validation report,
legal advice, or approval to integrate the isolated work into the active
pipeline.

Baseline date: 24 August 2026.

All numeric test and model-check totals in this protocol are dated recorded
runs from the stated baseline/migration work. They are not refreshed current
suite totals and are not admissible as reproduced evidence unless the exact
revision, dirty patch where applicable, command, environment and complete
captured log are pinned with the result.

Current evidence state:

The current repository-local execution record is
`docs/validation/V2_CURRENT_REPOSITORY_VALIDATION_STATUS.md`.

- The repository contains substantial Python mechanisms and automated test
  source. The complete suite currently passes under both CPython 3.11.9 and
  CPython 3.12.13: 660 tests and 269 subtests in each environment.
- The isolated `security_core/` contains all 19 requested responsibility areas.
  The current strict-dual hardening run recorded 35/35 passing Rust tests,
  formatting, and strict Clippy with warnings denied.
- `formal/tla/` contains the requested model/configuration. Two bounded runs
  under checksum-verified stable TLA+ tools v1.7.4 passed `TypeOK` and all 22
  invariants with no counterexamples. The
  primary TPM-disabled run explored 8,904 distinct states; the hypothetical
  TPM-enabled non-vacuity run explored 10,788 distinct states.
- Actual TPM enforcement has not been demonstrated on the inspected host. The
  Microsoft Platform Crypto Provider was enumerated, but the observation
  returned `NTE_DEVICE_NOT_READY`.
- TLC was run with repository-local Microsoft OpenJDK 21.0.12.1+1 and stable
  TLA+ tools v1.7.4; both publisher/release checksums and all formal-source
  SHA-512 bindings are recorded in `evidence/v2/tla-model-evidence.json`.
- No university has independently validated the system.
- The repository-local SPARK monitor build, executable assertions, Python
  harness and GNATprove run pass; GNATprove reports all 53 checks proved. The
  record is hash-bound but remains mutable, unsealed and non-independent.

The proposed protocol is intended to evaluate engineering evidence. It must not be used to describe
the system as uncrackable, wholly formally verified, production-safe,
TPM-enforced, or legally/patent conformant unless the corresponding evidence is
separately obtained.

## Evidence-status vocabulary

Every reported property must use these seven distinctions without collapsing
them:

| Evidence status | Meaning |
|---|---|
| Provisionally attributed requirement | A transcription or summary attributed by repository records to a submission; it is not authenticated filed wording or implementation evidence |
| V2 implementation-defined mechanism | A repository engineering choice; it must not be attributed to a filing without an admitted primary source |
| Implemented mechanism | Operative source is present at the identified revision; presence alone does not establish correctness |
| Tested property | Automated test source and captured execution result address the property; test presence without a captured run must be stated separately |
| Formally modelled property | The property is an invariant of the identified TLA+ model/configuration; it is not a code or deployment proof |
| Independently validated property | An independent university reproduced the evidence and issued an attributable result |
| External or unproven dependency | The property depends on evidence, infrastructure, semantics, deployment, or trust not established by this repository |

`PASS`, `FAIL`, and `INDETERMINATE` are experiment outcomes defined in section
12. They do not replace the seven evidence-status categories.

## Source controls

Any independent validator must preserve the two provisionally attributed
submission branches separately. The repository's current traceability documents
are:

- `docs/patent/SBP_LEX_PATENT_TO_BUILD_CONFORMANCE_MATRIX.md`;
- `docs/patent/FIRST_FILED_20_CLAIMS_IMPLEMENTATION_REGISTER.md`; and
- `docs/patent/V2_IMPLEMENTATION_DEFINED_SKG_LIFECYCLE_CONSTRUCTION.md`.

The first-submission register records no one of its 20 transcribed broad claims
as fully implemented. The conformance matrix records F2-S9's four-framework
mechanical V2 traversal as present but its provisional conformance as partial,
F2-S10 licensing as partial, F2-S11 substrate
non-bypass as missing, F2-S13 lifecycle as partial, and F2-S14 root/revocation
as partial. Those status boundaries must be preserved. The university must not
use Rust or TLA+ security work to fill unrelated substantive patent gaps.

The named primary first-claims PDF and primary final specification are absent;
a temporary second-claims review copy does not prove filing status. Filing
descriptions and dates in the traceability documents are repository-recorded
provenance only. This protocol does not independently verify exact wording,
legal filing, prosecution, publication, grant, scope or validity.

## Detached P/T/D/E handover evidence

V2 P/T/D/E is detached, non-authorising committed-Git-object proof/verification
tooling under `contracts/ptde/PTDE_POLICY_V1.json` and `sbp_ptde/`. It is outside
runtime authority, `ALLOW`, licence and effect semantics, but is part of the
handover evidence process. A university may evaluate a future committed
P/T/D/E campaign as detached evidence; this protocol does not claim that such a
campaign has been completed or admitted.

`sbp_lex/security/pqc.py` was deliberately deleted because it was a fake
digest/sign/verify placeholder, not a post-quantum cryptographic
implementation. No current PQC implementation or security claim is made.

## 1. Proposed system properties for validation

The following are validation hypotheses, not pre-declared successful outcomes.
An independent claim may be made only after the associated experiment satisfies
the criteria in section 12.

| ID | Proposed property to evaluate |
|---|---|
| P01 | An effect is never dispatched unless the complete required 3P evidence is currently valid and bound to the same lineage. |
| P02 | An effect is never dispatched unless the required SKG record is authenticated, complete, current, non-authorising, and bound to the same lineage. |
| P03 | An effect is never dispatched without a valid authority state bound to the request and later evidence. |
| P04 | An effect is never dispatched unless PTODF, AJ-SAAF, Governance determination, GALA, and ABEGF all occur in the repository-configured order and all mandatory outcomes permit continuation. |
| P05 | An effect is never dispatched unless all three separate repository-configured lifecycle contracts occur in their implementation-defined order and satisfy their non-authorising constraints. |
| P06 | An effect is never dispatched without an active, current licence whose exact identity, jurisdiction, authority state, execution rights, autonomy, status, and revocation bindings match the live request. |
| P07 | Revocation before validation, after token issuance, after permit minting, or immediately before effect prevents dispatch. |
| P08 | An effect is never dispatched without one complete, non-duplicated, correctly issued and ordered token chronology bound to the same request, state, evidence, and hash-chain lineage. |
| P09 | An effect is never dispatched without an authentic, current, unconsumed effect permit bound to the exact request, decision, effect, adapter, licence, and evidence lineage. |
| P10 | Immediate pre-effect revalidation repeats every specified point-of-use prerequisite and denies if any bound fact changed. |
| P11 | No individual governance framework, lifecycle stage, token, cryptographic provider, or Rust component independently creates Governance `ALLOW`. |
| P12 | No individual token independently grants execution or effect authority. |
| P13 | No lifecycle engine supersedes Governance, grants a licence, or grants execution/effect authority. |
| P14 | A missing, failed, indeterminate, duplicated, skipped, or reordered mandatory stage cannot be bypassed to reach dispatch. |
| P15 | A terminal deny, escalation, halt, revocation, or malformed/unknown state prevents every later execution transition. |
| P16 | Revocation state is monotonic: an older sequence or snapshot cannot reactivate authority, licence, permit, or execution. |
| P17 | A consumed permit cannot be replayed, including after concurrent claims or process restart when the admitted durable store is used. |
| P18 | Traversal stages and tokens cannot be skipped, duplicated, substituted, or reordered. |
| P19 | Audit finalization cannot precede the terminal decision/effect outcome it records. |
| P20 | A mutated audit record or appended/substituted, internally rehashed suffix cannot be accepted as the canonical terminal audit. |
| P21 | Unknown, malformed, missing, unverifiable, stale, or indeterminate evidence cannot transition to execution. |
| P22 | Every permitted effect has exactly one traceable request, decision, permit, claim, effect/receipt outcome, and terminal audit lineage. |

The protocol also evaluates cross-cutting implementation properties:
deterministic cross-language canonicalization and digest stability; every
signed-field mutation; wrong/missing signer; TPM provider unavailability;
closed decision vocabularies; handler non-reachability after failure; and the
absence of a production software-key fallback.

## 2. Provisional patent-support mapping for each property

The following mapping is `AI_PROPOSED_AWAITING_APPROVAL`. The primary artifacts
needed to authenticate exact filed support are incomplete, so these are
provisional traceability hypotheses, not patent conclusions:

- The provisional second-submission mapping associates claims 1 and 11 with authority-first external gating,
  procedural validation, authority precedence, and mechanical prevention of
  execution unless authority conditions are satisfied.
- The provisional mapping associates claims 3 and 11 with separation from the governed system's model internals.
- The provisional mapping associates claim 6 with pre-execution jurisdiction, licence-state, evidentiary, and
  statutory validation.
- The provisional mapping associates claims 7 and 13 with runtime authority instantiation, suspension,
  modification, and revocation without modifying the governed AI.
- The provisional mapping associates claims 8 and 14 with cryptographically attributable, tamper-detectable
  audit records identifying authority basis and validation state.
- The provisional final-specification mapping associates F2-S3.1 with the
  complete 3P constraint; F2-S6 with the seven-content-class SKG substrate and
  downstream non-override; F2-S9 with mandatory AJ-SAAF, PTODF, GALA, and ABEGF
  traversal; F2-S10 with the four licence tiers and five cryptographic bindings
  with invalidation/revocation cascades; F2-S11 with no execution path outside
  governance; F2-S13 with the three separate lifecycle engines and their 3P/SKG
  subordination; and F2-S14 with root binding and distributed revocation.
- The provisional first-submission mapping associates claims 16 and 19 with related cryptographic exchange and
  governed-action context but do not define the current token/permit/TLA+
  mechanics.

Where the matrix in section 15 says that no authenticated primary-source token, permit, replay,
chronology, or implementation-order schema was found, the mechanism is V2
implementation-defined and merely supports a provisional constraint. It must
not be presented as patent wording.

## 3. Python implementation evidence

The university must inspect, hash, and cite the exact revision of these files:

| Evidence area | Python source | Bounded observation |
|---|---|---|
| Canonical assurance envelope | `sbp_lex/assurance/envelope.py` | Restricted canonical JSON, NFC strings, UTF-16 key ordering, floats prohibited, SHA-512 envelope binding |
| Integrity/hash chain | `sbp_lex/security/integrity.py` | Exact float conversion for integrity use sites, SHA-512, entry recomputation and link verification |
| Signature objects | `sbp_lex/security/signature_provider.py`, `hybrid_signature.py` | Exact `SBP_LEX_V2_ML_DSA_87_ED448_AND_V1` envelope and binary preimage; strict AND verification over the same canonical bytes and purpose; missing, substituted or invalid lane rejects; two independent lane-custody/lifecycle records are bound; included software provider is `TEST_ONLY`, has no effect authority and is not external custody; Ed25519 is retained only for explicitly legacy non-effect objects |
| Detached PQC wrapper | `sbp_lex/local_trust/pqc_wrapper.py`, `pqc_channel.py`, `hybrid_signature_rust` | Genuine ML-DSA-87 AND Ed448 exact-byte strict-dual wrapper with separately pinned lane providers, custody references and custody attestations; common Python/Rust fixed preimage vector and Rust verification of both Python-produced lanes; separate non-deployed ML-KEM-1024 channel-capability evidence; no production admission, authority, transport or custody claim |
| Token chronology | `sbp_lex/security/token_stack.py` | Required token names, issuer/stage contracts, payload/chain/evidence/licence binding, required-stack verification |
| Traversal order | `sbp_lex/config/pipeline_config.py`, `sbp_lex/pipeline/runner.py` | Active implementation-defined order and repeated 3P boundaries |
| 3P | `sbp_lex/governance/three_p_doctrine.py` | Signed evidence/trace/hash contract; substantive evaluator remains external |
| SKG | `sbp_lex/governance/skg_authority.py` | Seven-class authenticated, non-authorising V2 record; substantive authority corpus/resolver external |
| Framework mechanics | `sbp_lex/governance/filed_frameworks.py` | Separate PTODF, AJ-SAAF, GALA, ABEGF mechanical contracts; filename does not authenticate filed provenance |
| Lifecycle | `sbp_lex/governance/filed_lifecycle.py` | Three separate, non-authorising, 3P/SKG-bound contracts in implementation-defined order; substantive models external |
| Licence | `sbp_lex/licensing/filed_licensing.py` | Four repository-configured tier labels; identity, jurisdiction, authority state, execution rights, autonomy, status and revocation checks |
| Execution gate | `sbp_lex/execution/execution_gate.py` | Rechecks hash chain, 3P, SKG, licence, frameworks, lifecycle, Governance, procedural truth, thresholds, Domain, Aurion, tokens, boundary, attestation and collective signals |
| Permit/effect | `sbp_lex/execution/controlled_local_adapter.py` | Controlled-local permit, claim, point-of-use checks, receipt and replay behavior |
| Audit | `sbp_lex/audit/engine.py`, `audit_engine.py`, `audit_ledger.py` | Decision/evidence/permit/receipt digests and terminal ledger mechanisms |

These observations establish source presence. The Python process is outside the
new Rust TCB, current Python execution remains callable without that isolated
boundary, and source inspection does not establish physical non-bypass.

## 4. Rust security-boundary evidence

`security_core/` now supplies the following repository evidence:

- `FORMAT_MAP.md` maps the current assurance/integrity canonicalization, digest,
  signed-object, request, hash-chain, 3P, SKG, filed-framework, lifecycle,
  licence, token, audit, permit, revocation, replay, and final-decision formats.
- `src/decision.rs` defines the closed `ClosedDecision` vocabulary:
  `PermitExistingAuthorization`, `Deny`, `Escalate`, `Revoke`, `Unsupported`,
  and `Indeterminate`; it contains no Governance `ALLOW` variant.
- The source modules represent all 19 requested responsibility areas through
  canonical/digest, signature/TPM, request, 3P, SKG, authority,
  filed-framework, filed-lifecycle, licence, token, hash-chain, audit, permit,
  pre-effect, revocation, replay, and dispatch verifiers plus closed
  decision/evidence support.
- `src/replay.rs` requires an injected `DurableReplayStore`; no production
  in-memory fallback is provided.
- `src/tpm.rs` performs the real Windows NCrypt Platform Provider availability
  probe. Production strict-dual key creation, signing and public verification
  retain the explicit `HybridHardwareCustodyAndPinningUnavailable` gap. No
  admitted non-exportable ML-DSA-87 AND Ed448 custody mapping is demonstrated,
  and there is no production software-key fallback.
- In the dated recorded run on installed stable `x86_64-pc-windows-gnu`,
  `cargo check --all-targets`, `cargo fmt`, and
  `cargo clippy --all-targets -- -D warnings` passed, and 35/35 tests passed.
  The MSVC target was not checked because `link.exe`/Visual C++ Build Tools were
  unavailable.

The university must still obtain and preserve this evidence package:

1. Exact source/module inventory mapping all 19 repository-recorded responsibility areas.
2. Closed decision enum and exhaustive parsing showing that unknown values
   cannot become true or permit.
3. Canonical-format compatibility map and cross-language golden vectors for
   every admitted Python object.
4. Maintained cryptographic-library inventory; no hand-written primitive.
5. Signed-field manifest and mutation test for every field in every envelope.
6. Windows provider/TPM implementation, exact API flags, error mapping,
   public-key digest binding, and proof that production features contain no
   software-key fallback.
7. Request, 3P, SKG, authority, framework, lifecycle, licence, token, hash,
   audit, permit, revocation, replay, and point-of-use verifier mapping.
8. Atomic permit consumption and durable rollback/replay-state design.
9. Effect-dispatch call graph and tests proving the handler is unreachable after
   every prerequisite failure.
10. `Cargo.toml`, `Cargo.lock`, compiler/toolchain versions, dependency licenses
    and advisories, feature flags, unsafe/FFI inventory, and release-build hash.

Implemented/tested status is therefore supported for the isolated reviewed
code and exercised cases, but production admission is not. External non-effect
signer trust roots, complete lifecycle/licence evaluator-source mapping,
durable replay/revocation/audit stores, actual TPM signing, and physical
dispatch non-bypass remain unresolved. Existing Rust directories are not
substitutes for evidence from the specifically reviewed `security_core/` path.

## 5. TLA+ invariant supporting each property

`formal/tla/SBPLEXV2.tla` models all 23 repository-recorded traversal concepts and defines
`TypeOK` plus one named invariant for each P01-P22.

The university must reject a formal-evidence claim if:

- the property has no named invariant;
- a required failure/revocation/mutation transition is absent;
- success is unreachable, making a safety property vacuous;
- the model permits no adversarial transition relevant to the claim;
- constants/bounds are not recorded;
- TLC output, state counts, or counterexamples are missing; or
- the result comes only from the separate existing
  `formal/SBPLexAuthority.tla`.

Two current repository-local breadth-first runs under checksum-verified stable
TLA+ tools v1.7.4 used two request identifiers, two permit identifiers, and one
revocation increment:

- Retained `HostTPMAvailable = FALSE`: 17,298 generated, 8,904 distinct, zero
  queued, depth 32; `TypeOK` and all 22 invariants passed; no counterexamples.
  The effect path is unreachable and effect-conditional invariants are vacuous
  in this configuration.
- Retained hypothetical `HostTPMAvailable = TRUE` non-vacuity configuration:
  20,968 generated, 10,788
  distinct, zero queued, depth 35; `TypeOK` and all 22 invariants passed; no
  counterexamples. The primary configuration remains `FALSE`. This run reached
  permit, claim, immediate revalidation, effect, receipt, and audit states, but
  its TPM constant is a model assumption, not host-TPM evidence.

Static authoring review corrected invalid TLA+ `EXCEPT` record-field references
before these completed runs. No completed counterexample was hidden or
reclassified. The model remains bounded and abstract: it does not prove
cryptography, canonical-byte equivalence, evaluator/legal truth, TPM custody,
implementation correspondence, time/TTL/clock rollback, crashes, durable
transactions, concurrent requests, distributed replicas, filesystems, or
network partitions.

## 6. Existing automated tests

Test source currently present includes:

- `tests/test_polyglot_assurance_contract.py`: canonical JSON, Unicode,
  forbidden floats, envelope binding, and verifier contradiction cases.
- `tests/test_integrity_chain.py`: digest determinism, exact float handling,
  non-finite rejection, entry recomputation, and broken relink rejection.
- `tests/test_signature_provider.py`: no fallback signer, Ed25519 mutation,
  non-effect-authority software provider, and pipeline provider failure.
- `tests/test_three_p_patent_alignment.py`: 3P evidence, failure, mutation,
  trace, stage, and hash binding.
- `tests/test_skg_authority.py`: SKG content/evidence/source and mutation/failure
  cases.
- `tests/test_filed_frameworks.py`: four-framework identity, ordering,
  non-authorisation, evidence, mutation, and boundary cases.
- `tests/test_filed_lifecycle.py`: exact separate stages, order, non-authorising
  behavior, 3P/SKG binding, replay/mutation, and deterministic inputs.
- `tests/test_skg_lifecycle_token_config.py`: exact configured order, token
  issuer/stage/payload bindings, and tamper rejection.
- `tests/test_four_tier_licensing.py`: exact tiers/bindings, rights mismatch,
  provider/signature failure, rollback, revocation, and invalidation.
- `tests/test_execution_skg_lifecycle_integration.py`: execution integration of
  SKG/lifecycle prerequisites.
- `tests/test_controlled_local_adapter.py`: real controlled-local effect path,
  missing adapter, replay, expiry, revocation, point-of-use mutation,
  non-effect authority, receipt uncertainty, and terminal-audit tamper.
- `tests/test_terminal_audit_integrity.py`: terminal audit, live chain,
  authorization, 3P, and legacy evidence tamper.

The university must not report these as passed merely because the files exist.
It must capture a clean test run at the pinned revision. New Rust tests must
cover every case in the repository-recorded case inventory, including every signed-field
mutation and proof that no single token/component can permit execution and that
the effect handler is never reached after any failed prerequisite.

The isolated Rust suite contained 34 tests in the dated SHA-512 migration run,
which recorded 34/34 passing. It covers every repository-listed category plus a SHA-512
known-answer vector, legacy 64-character SHA-256-width rejection, an empty
required-token vocabulary, an unproven effect-authority signer, valid
paths through each structured verifier, SKG mutation with a rehashed trace, a
successful already-authorised dispatch exactly once, and request-fingerprint
mutation. This is tested-property evidence for the coded fixtures; it is not a
university result or a production-deployment result.

## 7. Independent experiments the university should perform

### E01 — Source and build reproducibility

Build twice from the pinned revision in clean, separately created environments
using the locked dependencies. Compare binary hashes or document every
non-reproducible section. Inspect feature resolution and ensure test-only
software signer code is absent from the production artifact.

### E02 — Cross-language canonicalization

Generate equivalent and adversarial objects in Python and Rust: reordered keys,
NFC/non-NFC text, boundary integers, exact decimals at applicable integrity
sites, forbidden floats at assurance sites, duplicate normalized keys,
non-finite values, invalid UTF-8, non-string keys, nested arrays, and oversized
inputs. Compare canonical bytes and digests exactly.

### E03 — Signed-envelope mutation matrix

For each signed object, mutate each field independently; delete, duplicate, and
reorder fields; substitute provider metadata, key identity, signature, digest,
request fingerprint, state hash, stage, sequence, time, licence, and evidence
bindings. Require denial and zero handler calls.

### E04 — Token and traversal chronology

Omit, duplicate, substitute, reorder, or transplant every core and conditional
token. Skip/duplicate/reorder each mandatory traversal stage. Attempt validly
signed evidence from the wrong request or stage. Require denial.

### E05 — Hash and terminal-audit attacks

Mutate every chain/audit field; relink without rehashing; append or substitute
an attacker-controlled suffix that is internally and cryptographically
well-formed; transplant an old terminal audit; alter permit/receipt lineage.
Require rejection of non-canonical terminal lineage.

### E06 — Licence/revocation race matrix

Revoke before validation, after validation, after token issuance, before gate,
after gate, after permit mint, after claim, and at immediate pre-effect
revalidation. Attempt rollback, stale snapshots, reordered events, process
restart, concurrent validation/claim, and storage failure. Require monotonic
denial and no handler reach after revocation.

### E07 — Replay and atomic claim

Race at least two processes/threads against one permit, crash at every durable
write boundary, restore old storage snapshots, and retry after restart. Require
at most one accepted claim/effect lineage and safe indeterminate handling if an
effect may have occurred without a receipt.

### E08 — Real Windows TPM exercise

On the target Windows host, provision a dedicated non-exportable TPM-backed
test key through the exact production provider path. Record provider/key
properties without exposing private material. Exercise signing, verification,
wrong key, changed public key, inaccessible key, TPM/provider unavailable,
permission failure, rotation, revocation, and restart. Inspect the production
binary/call path to establish no software fallback. `NTE_DEVICE_NOT_READY` is a
fail-closed test result, not TPM success.

### E09 — Handler non-reachability and deployment bypass

Instrument the only admitted effect handler and demonstrate zero invocations
for every negative case. Enumerate every executable, IPC endpoint, adapter,
service account, import path, and direct API capable of effect. Attempt direct
Python and out-of-process calls. A single reachable bypass is `FAIL` for the
non-bypass property.

### E10 — TLA+ model checking and counterexample retention

Run TLC on the pinned `SBPLEXV2.tla`/`.cfg`; independently inspect all actions
and invariant coverage. Vary meaningful bounds, include success and adversarial
paths, retain every counterexample, document corrections, and rerun. Use trace
fixtures to compare representative TLA+ transitions with Rust/Python tests.

### E11 — Dependency, fuzz, and fault-injection review

Audit Rust dependencies and unsafe/FFI. Fuzz parsers, canonicalization,
signature-envelope, token, chain, audit, and permit verifiers. Inject provider,
clock, store, IPC, memory-allocation, malformed response, timeout, and crash
failures. Require closed failure without partial dispatch.

## 8. Threat model

### Protected assets

- the exclusivity of the effect-dispatch path;
- authority, licence, revocation, token, permit, audit, and request lineage;
- TPM-backed private-key non-disclosure and correct public-key identity;
- one-time permit consumption and terminal audit attribution;
- integrity of the reviewed Rust binary/configuration and durable state.

### Adversaries

- a malicious or compromised Python caller;
- an unauthenticated IPC peer or hostile input producer;
- a holder of valid evidence for another request, stage, role, or expired state;
- a party able to reorder, delete, duplicate, mutate, replay, or append stored
  records;
- a concurrent caller racing revocation or permit claim;
- a wrong, changed, unavailable, or software cryptographic provider;
- a dependency or build-chain attacker;
- a local user attempting direct adapter/handler invocation;
- a host administrator or compromised OS, which must be explicitly treated as
  an external deployment threat rather than claimed solved by application code.

### Security objectives

Authenticity and exact binding of admitted evidence; deterministic parsing;
complete prerequisite traversal; fail-closed uncertainty; monotonic revocation;
one-time permit use; physical non-bypass; attributable terminal lineage; and no
independent authority creation by Rust, tokens, frameworks, or lifecycle
engines.

### Out-of-scope unless separately evaluated

Substantive legal/evidentiary truth, policy correctness, biometric truth,
real-world effect safety/correctness, physical TPM attacks, compromised-host
resistance, side channels, availability, and patent validity.

## 9. Adversarial validation categories

The test register must classify every case under one or more of:

1. schema/type/canonicalization ambiguity;
2. digest and signed-field mutation;
3. signer/key/provider substitution or absence;
4. request/state/evidence transplant;
5. prerequisite omission, duplication, reordering, and bypass;
6. 3P and SKG evidence failure;
7. framework and lifecycle failure/non-authorisation;
8. licence binding, status, and revocation timing;
9. token issuer, stage, payload, chronology, and chain failure;
10. hash-chain and terminal-audit suffix attack;
11. permit mutation, expiry, claim race, and replay;
12. immediate pre-effect time-of-check/time-of-use change;
13. TPM/provider/key lifecycle failure;
14. durable-state rollback, crash, partition, and restart;
15. IPC/confused-deputy/direct-handler bypass;
16. dependency, unsafe/FFI, fuzz, and resource-exhaustion failure;
17. TLA+ omitted-transition, vacuity, counterexample, and bounds review.

## 10. Reproducibility procedure

1. Obtain a read-only copy of the exact repository revision and record commit,
   branch, remotes, submodules, and `git status --short`. Preserve local changes
   as a patch if the evaluated state is intentionally uncommitted.
2. Hash all source, patent, configuration, lock, vector, and evidence files
   with canonical SHA-512 identities of exactly 128 lowercase hexadecimal
   characters. Any retained source SHA-256 is historical, non-authorising
   provenance only and cannot identify or admit this evidence package.
3. Record Windows edition/build, architecture, firmware/TPM information,
   provider enumeration, CPU, locale, code page, timezone, and whether the
   process is elevated.
4. Record exact Python, dependency, Rust, Cargo, Java, and TLC versions.
5. Create clean Python and Rust environments from locked/pinned dependencies.
6. Run the repository Python suite with the repository's supported runner and
   retain complete stdout/stderr and exit code. If using unittest discovery,
   record the exact command rather than assuming equivalence to another runner.
7. Run `cargo test --manifest-path security_core/Cargo.toml --locked` and
   independently reproduce the 34-test result. Run all-target checking,
   formatting, strict Clippy, and the release builds/tests required by the
   security review; capture exact commands, target triples, and outputs. The
   current GNU result does not substitute for an MSVC result.
8. Execute the TPM experiments through the actual Windows provider on the
   target host. Do not substitute a software signer for a TPM result.
9. Run TLC using the exact downloaded/verifiable `tla2tools.jar`, model, and
   config; for example, record the full equivalent of
   `java -cp <tla2tools.jar> tlc2.TLC -config formal/tla/SBPLEXV2.cfg formal/tla/SBPLEXV2.tla`.
10. Run E01-E11, preserving seeds, fixtures, timing, concurrency schedules where
    controllable, and all failures/counterexamples.
11. Repeat the build and core experiments on a second independently prepared
    machine. Reconcile differences without discarding negative results.
12. Produce a signed evidence manifest and report using the criteria below.

Commands containing placeholders are procedural templates, not evidence that
the corresponding dependency or file existed or that a run succeeded.

## 11. Required evidence capture

The university evidence package must contain:

- repository identity, commit/patch, dirty-state report, and full source
  manifest with canonical SHA-512 hashes of exactly 128 lowercase hexadecimal
  characters;
- copies/hashes of any admitted primary source artifacts actually used and the
  exact mapping revision;
- operating-system/hardware/firmware/TPM/provider configuration and permissions;
- exact toolchain and dependency versions, Cargo/Python lock evidence,
  dependency tree, feature graph, unsafe/FFI inventory, and advisory results;
- build commands, stdout/stderr, exit codes, binary hashes, signatures, and
  reproducibility comparison;
- every Python and Rust test command, test identifier, result, duration, and
  unedited log;
- every adversarial fixture, mutation definition, fuzz seed/corpus/crash, and
  handler-invocation count;
- TPM key/provider identity, public-key bytes/digest, non-exportability/provider
  evidence, operation logs, and failure results, excluding all private material;
- revocation/replay durable-store initialization, sequence snapshots,
  concurrency/crash schedule, and recovery logs;
- TLC tool hash/version, exact command/configuration, generated/distinct/explored
  states, depth, invariant/deadlock results, complete counterexamples,
  corrections, reruns, and model limits;
- a model-to-code-to-test traceability table;
- adapter/process/IPC call graph and physical non-bypass experiment evidence;
- named investigators, dates, machine identities, conflicts of interest,
  deviations, unresolved anomalies, and attributable report signatures.

Raw private key material must never be captured.

## 12. Objective PASS, FAIL, and INDETERMINATE criteria

### Per-property PASS

A property is `PASS` only when all of the following applicable conditions hold:

1. Its wording and scope are frozen before testing.
2. Primary-source and implementation-defined bases are distinguished.
3. The identified Python/Rust implementation is present and reviewed.
4. Positive, negative, mutation, replay/revocation, error, and handler
   non-reachability tests applicable to the property pass from a clean build.
5. The named TLA+ invariant passes in a non-vacuous model with recorded bounds
   when a formal claim is made.
6. External dependencies required by the property—especially TPM custody,
   durable state, trusted time, and physical adapter routing—are exercised and
   pass rather than assumed.
7. Results are reproduced on the required independent setup and all anomalies
   are resolved without deleting evidence.

### Per-property FAIL

A property is `FAIL` if any in-scope execution reaches dispatch contrary to the
property; a mutation/replay/revocation/bypass is accepted; a required signer or
TPM property can fall back permissively; the effect handler is reached after a
failed prerequisite; a TLA+ counterexample demonstrates the property false in
the agreed model; or captured implementation behavior contradicts the claim.

An unavailable TPM is a fail-closed behavior result for that test but cannot be
reported as `PASS` for TPM-backed custody/enforcement.

### Per-property INDETERMINATE

A property is `INDETERMINATE` if required code, dependency, hardware,
configuration, evidence, source authority, test coverage, model transition,
tool, result, or reproduction is missing; if the test cannot distinguish safe
denial from an unobserved effect; if model checking is vacuous or bounded too
narrowly for the stated claim; or if external substantive evidence cannot be
validated.

### Overall result

The overall security-boundary result is `PASS` only if every mandatory P01-P22
property passes and no required external dependency remains indeterminate. Any
mandatory failure makes the overall result `FAIL`. Otherwise the overall result
is `INDETERMINATE`. Patent conformance and legal validity are reported
separately and cannot inherit the engineering result.

## 13. External infrastructure dependencies

| Dependency | Required property | Baseline status |
|---|---|---|
| Canonical Python dependency admission remains unsealed | Reproducible Python dependency resolution | `evidence/v2/python311-resolution-evidence.json` binds a clean CPython 3.11.9/win-amd64 environment to 17 exact wheel hashes, sizes, installed versions and active dependency edges; the canonical `python-dependencies.lock.json` remains unavailable until genuine accepted-attempt/rollback history and the final freeze binding exist |
| Canonical launcher | One reproducible university execution entrypoint | `main:app` through Uvicorn is the canonical V2 launcher; independent clean-host execution remains required |
| Windows host with operational TPM and supported provider | Non-exportable key custody and provider-backed signing | Unvalidated; provider returned `NTE_DEVICE_NOT_READY` in current observation |
| Production key provisioning/role registry | Correct signer identity, rotation and revocation | Not present or established in current deployment evidence |
| Trusted monotonic time | Expiry/freshness and point-of-use windows | Not established |
| Durable atomic replay/revocation store | Monotonic sequence and one-time permit use across restart/concurrency | Pending Rust design/deployment |
| Authenticated Python-to-Rust IPC | Peer identity, integrity and confused-deputy resistance | Pending |
| Physical effect adapter choke point | Repository/deployment non-bypass | Missing in current deployment evidence |
| Authoritative 3P/SKG/legal/licence/lifecycle evaluators and evidence | Substantive truth of signed determinations | External/unproven |
| Rust toolchain and locked crates | Repeatable reviewed build | Stable GNU all-target check, format, strict Clippy and 34 tests passed; MSVC linker unavailable; external dependency/advisory review remains required |
| Java and verified TLC distribution | TLA+ model checking | Repository-local Microsoft OpenJDK 21.0.12.1+1 and stable TLA+ tools v1.7.4 were checksum-verified; tool/source hashes and current run metadata are bound in `evidence/v2/tla-model-evidence.json`, pending independent reproduction and sealing |
| Independent second machine/laboratory | Reproduction and TPM comparison | Not performed or evidenced |
| University governance and qualified reviewers | Independent result attribution | Not engaged |

## 14. Properties not yet proven

At baseline, none of P01-P22 has been independently validated by a university.
The dated record states that all 22 invariants passed in both exact bounded TLA+
runs and that the SHA-512 migration run passed 34/34 Rust tests. Those recorded
results do not prove the
following, which must remain explicit:

- complete end-to-end conformance to either provisionally attributed submission;
- the provisionally transcribed first submission's 20 broad capability claims;
- substantive correctness of 3P, SKG, jurisdiction, authority, statutory,
  treaty, lifecycle, Domain, Aurion, licence, or other evaluator results;
- substrate-level externality, hierarchical superiority, irreversibility, and
  physical non-bypass;
- actual TPM-backed non-exportable production signing and secure key lifecycle;
- distributed revocation and durable replay protection under restart,
  concurrency, rollback, partition, and disaster recovery;
- trusted time and bounded time-of-check/time-of-use behavior;
- cryptographic primitive, library, compiler, dependency, Windows, TPM,
  firmware, or hardware correctness;
- absence of unsafe/FFI, parser, side-channel, supply-chain, or denial-of-service
  vulnerabilities until reviewed/tested;
- unbounded formal correctness, formal model completeness, and model-to-code
  correspondence; the TPM-disabled effect path is vacuous, while the separate
  hypothetical-TPM run supplies bounded effect-path non-vacuity only;
- correctness/safety of a dispatched real-world effect;
- secure production build, signing, measured startup, anti-rollback, process
  isolation, access control, logging, monitoring, incident response, and
  recovery.

## 15. Patent-to-code-to-test-to-formal-proof validation matrix

Abbreviations: `Python source` means code/test text exists but no university
run is claimed. `Rust 34/34` means the dated SHA-512 migration record reports
all isolated Rust tests passed; it is not a refreshed current total or a
university or deployment result.
`TLC both` means the named invariant passed in both completed bounded runs: the
8,904-distinct-state TPM-disabled run and the 10,788-distinct-state
hypothetical-TPM non-vacuity run. The `Independent` column remains `NO` until a
university completes this protocol.

| Property | Provisional traceability requirement | V2 implementation-defined mechanism | Implemented mechanism | Tested property | Formally modelled property | Independently validated property | External or unproven dependency |
|---|---|---|---|---|---|---|---|
| P01 3P prerequisite | F2-S3.1 complete 3P constraint | Repeated signed 3P boundaries and lineage digests | Python `three_p_doctrine.py`; Rust `three_p` verifier | Python source plus Rust missing-3P and handler-gating cases; Rust 34/34 | `Inv01_NoEffectWithoutSatisfiedThreeP`; TLC both | NO | Substantive PSE/PIE/PSGC evaluator and evidence truth |
| P02 SKG prerequisite | F2-S6 seven content classes and downstream non-override | Signed seven-class V2 record, fixed placement and token/hash/audit binding | Python `skg_authority.py`; Rust `skg` verifier | Python source; Rust missing/invalid SKG and rehashed-trace mutation; Rust 34/34 | `Inv02_NoEffectWithoutAuthenticatedSKG`; TLC both | NO | Authority corpus, resolver, production provenance/precedence |
| P03 valid authority state | F2-C1/C4/C7 and F2-S3.2/F2-S14 | Request/state/evidence binding across root and tokens | Partial Python root/governance/token; Rust `authority` verifier | Related Python source; Rust valid-boundary and signed-field mutation cases; Rust 34/34 | `Inv03_NoEffectWithoutValidAuthorityState`; TLC both | NO | Dynamic jurisdiction/authority lifecycle, source truth, external non-effect signer roots |
| P04 four frameworks plus Governance | F2-S9; mechanical V2 traversal present, primary-source conformance unverified | PTODF before classification; AJ-SAAF, Governance determination, GALA, ABEGF split placement | Python `filed_frameworks.py`; Rust `filed_framework` verifier | Python source; Rust framework-failure and valid-path cases; Rust 34/34 | `Inv04_NoEffectWithoutMandatoryGovernance`; TLC both | NO | Production evidence/evaluators and physical non-bypass |
| P05 three lifecycle stages | F2-S13 | Exact runtime order/schema explicitly V2-defined; no admitted primary-source order/schema | Python `filed_lifecycle.py`; Rust `filed_lifecycle` verifier | Python source; Rust lifecycle failure and valid-path cases; Rust 34/34 | `Inv05_NoEffectWithoutThreeLifecycleStages`; TLC both | NO | Substantive transition models/providers and complete evaluator-source mapping; F2-S13 Partial |
| P06 active bound licence | F2-C6, F2-S10, F2-S14 | Four repository-configured labels, five bindings, signed records and point-of-use stage | Python `filed_licensing.py`; Rust `licence` verifier | Python source; Rust mismatch and revocation cases; Rust 34/34 | `Inv06_NoEffectWithoutValidActiveLicence`; TLC both | NO | Tier rights not inferred; production authority/distributed state; complete evaluator-source mapping |
| P07 revocation at every point | F2-C7/C13, F2-S10/S14 | Monotonic sequence, invalidation cascade, revalidation and point-of-use probe | Partial Python licence/adapter; Rust `revocation`/`pre_effect` checks | Python source; Rust revocation before validation, after token, and immediately pre-effect; Rust 34/34 | `Inv07_NoEffectAfterRevocation`; TLC both | NO | Distributed authoritative revocation, trusted time, durable rollback-resistant store |
| P08 token chronology | No authenticated primary-source token chronology found; provisionally supports F2-S10/S11 | Required token names and exact issuer/stage/payload/chain ordering | Python `token_stack.py`; Rust `token` verifier | Python source; Rust omission, empty vocabulary, duplication, substitution, reordering; Rust 34/34 | `Inv08_NoEffectWithoutCompleteTokenChronology`; TLC both | NO | Admitted production signers and signer trust roots |
| P09 valid permit | No authenticated primary-source permit schema found; provisionally supports F2-C1/C11 and F2-S11 | V2 permit bound to decision/effect/adapter/evidence | Python controlled-local adapter; Rust `permit`/`dispatch` | Python source; Rust permit mutation, replay, successful existing-authorisation call; Rust 34/34 | `Inv09_NoEffectWithoutValidPermit`; TLC both | NO | Production adapter, effect authority, durable atomic claim, physical choke point, TPM format gap |
| P10 immediate revalidation | F2-C6/C7 and F2-S10/S11; exact sequence V2-defined | Licence/SKG/lifecycle/permit point-of-use rechecks | Python controlled-local path; Rust `pre_effect` | Python late-change source; Rust immediate-revocation and failed-prerequisite gating; Rust 34/34 | `Inv10_NoEffectWithoutImmediateRevalidation`; TLC both | NO | Trusted time/fresh sources, atomicity, deployment routing, durable stores |
| P11 no component creates Governance ALLOW | F2-S6/S9/S13/S11 | Non-authorising flags and veto-only Rust boundary | Python SKG/framework/lifecycle; Rust closed `ClosedDecision` and evidence-gated dispatch | Python source; Rust no-single-component test; Rust 34/34 | `Inv11_OnlyGovernanceDeterminationCreatesAllow`; TLC both | NO | Complete deployment call graph and physical inability to bypass governance |
| P12 no token independently grants | Provisionally supports F2-S10/S11; no authenticated primary-source token rule | Token is authenticated prerequisite only; complete stack/gate required | Python token/gate; Rust `token` plus evidence-gated `dispatch` | Python source; Rust no-single-token/component plus token negative matrix; Rust 34/34 | `Inv12_NoTokenIndependentlyGrantsExecution`; TLC both | NO | Physical gate exclusivity and signer-role governance |
| P13 lifecycle cannot supersede | F2-S13 | Explicit non-supersession and no authority/licence/effect grants | Python lifecycle; Rust lifecycle proof is prerequisite only | Python source; Rust lifecycle failure/non-single-component gating; Rust 34/34 | `Inv13_NoLifecycleSupersedesGovernance`; TLC both | NO | Substantive evaluator behavior, source mapping, and deployment bypass |
| P14 mandatory-stage non-bypass | F2-C1/C11 and F2-S9/S11 | Exact configured order and chain/token stage binding | Python runner/config/gate; Rust structured verifier/proof set | Python ordering source; Rust failed-prerequisite handler-gating; Rust 34/34 | `Inv14_NoFailedMandatoryStageBypassed`; TLC both | NO | OS/process/adapter choke point; F2-S11 remains Missing |
| P15 terminal failure blocks later transition | F2-C1/C11 and F2-S11 | Closed terminal outcomes and fail-closed errors | Python pipeline/gate; Rust closed errors/decisions and dispatch | Python negative source; Rust handler never reached after any failed prerequisite; Rust 34/34 | `Inv15_TerminalFailurePreventsLaterExecution`; TLC both | NO | FFI/IPC/panic/fault deployment behavior and physical handler routing |
| P16 monotonic revocation | Runtime revocation supported by F2-C7/C13; monotonic sequence V2-defined | Increasing sequence and rollback rejection | Python licence; Rust `revocation` verifier | Python source; Rust monotonic rollback case; Rust 34/34 | `Inv16_RevocationIsMonotonic`; TLC both | NO | Production rollback-proof revocation store, restart/partition behavior |
| P17 consumed permit no replay | Supports F2-S11; claim-once schema V2-defined | Injected durable claim-once interface | Python controlled-local record; Rust `DurableReplayStore` trait/claim check | Python source; Rust replay case uses test-only store; Rust 34/34 | `Inv17_ConsumedPermitsCannotBeReplayed`; TLC both | NO | Production atomic store, crash consistency, concurrency/restart and process isolation |
| P18 no skip/duplicate/reorder | F2-S3.2/S9 and F2-C1/C11 | Configured stage and exact token/lifecycle/framework sequences | Python config/contracts; Rust exact chain/token/structured verifiers | Python source; Rust token/order/suffix and failed-prerequisite cases; Rust 34/34 | `Inv18_StagesCannotSkipDuplicateOrReorder`; TLC both | NO | Complete ingress/adapter enforcement and hidden paths |
| P19 audit follows terminal decision | F2-C8/C14 | Terminal audit sequencing and lineage fields | Python runner/audit; Rust `audit` verifier | Python source; Rust audit mutation/valid-path cases; Rust 34/34 | `Inv19_AuditAfterTerminalDecision`; TLC both | NO | Canonical production audit sink, crash/unknown-effect atomic persistence |
| P20 canonical terminal audit/suffix rejection | F2-C8/C14 tamper detection; exact suffix rule V2-defined | Live-chain/audit verification and exact admitted chain/stage lineage | Partial Python mechanism; Rust `hash_chain`/`audit` verifiers | Python source; Rust audit mutation and validly rehashed unauthorised suffix; Rust 34/34 | `Inv20_AuditSuffixCannotBecomeCanonical`; TLC both | NO | Durable canonical-head authority and storage rollback protection |
| P21 unknown/malformed cannot execute | Supports F2-C1/C6/C11 and F2-S11; closed parsing rule V2-defined | Exact schemas, closed enums and fail-closed dependency errors | Partial Python exact checks; Rust `BoundaryError`/`Gap` and verifiers | Python negative source; Rust signer/envelope/mutation/missing-evidence matrix; Rust 34/34 | `Inv21_UnknownEvidenceCannotReachExecution`; TLC both | NO | Parser/resource/fuzz coverage, dependencies, Windows/FFI error completeness |
| P22 one-to-one terminal lineage | F2-C8/C14 and F2-S10/S14; exact tuple V2-defined | Request-decision-permit-claim-receipt-audit lineage | Partial Python adapter/audit; Rust proof/request/permit/replay/audit/dispatch | Python source; Rust successful-once, replay, permit/audit/fingerprint mutation; Rust 34/34 | `Inv22_EffectHasExactlyOneTraceableLineage`; TLC both | NO | Durable IDs/stores, external receipt truth, physical effect uniqueness |

## Required final report form

The university's final report must reproduce the matrix above with evidence
hashes, exact commands, per-property `PASS`/`FAIL`/`INDETERMINATE`, deviations,
and citations to raw artifacts. It must list counterexamples and failed tests
before conclusions, preserve each filing/implementation distinction, and state
that untested or externally dependent properties remain unproven.
