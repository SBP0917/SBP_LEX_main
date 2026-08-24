# Candidate 10 Rust authority integration — test and evidence plan

Status: `AI_PROPOSED_AWAITING_APPROVAL`. This is a generated draft evidence
plan, not a fixed owner-approved acceptance policy, seal, admission decision,
production authorization, live-service authorization, or safety claim. Existing
capture/verifier mechanics are separately `IMPLEMENTATION_DEFINED_V2` facts.
Every gate and evidence-package requirement below is proposed until adopted or
replaced by an explicit bounded V2 design-authority decision.

## Proposed fixed-subject inputs

Evidence generation must begin only after all of these have immutable Git object
identities:

1. successor code commit and tree;
2. test-profile commit and tree, separate from programme profile;
3. authority-capable wire v2 specification, Python codec, independent Rust codec,
   every shared vector and adversarial-case inventory;
4. Rust toolchain/channel and `x86_64-pc-windows-gnullvm` target;
5. Python interpreter and dependency lock;
6. authority binary descriptor with exact HSM/TPM class, profile, key ID, replay
   namespace, oracle, runtime subject/tree, binary hash and wire-contract hash;
7. externally pinned, design-authority-selected trust root, exact role-registry digest and admitted
   A/B/validator/single-state/witness/coordinator/authority/adapter/watchdog
   semantic-provenance expectations.

Those identities are inputs to generated evidence records. They must not be
prospectively written into a source document that is itself part of P.

The test profile must use a deterministic compile-time evidence namespace that
cannot be selected by requests, CLI arguments or the runtime environment.
Programme profile and ordinary replay stores must be byte-identical before and
after evidence-only execution. A failed attempt is preserved; it is never
amended into a pass.

## Build gates

- `cargo fmt --check` for wire v2, trusted core and authority service;
- `cargo clippy --all-targets --all-features -- -D warnings` under gnullvm;
- offline Cargo build with no unreviewed dependency or build script;
- `#![forbid(unsafe_code)]` retained; no FFI, pickle, Node or executable payload;
- independent hash recomputation of every source, manifest, lockfile, binary and
  vector from Git objects rather than the live worktree;
- reproducible binary comparison from two clean clones where the toolchain can
  provide deterministic output; otherwise record and explain every differing
  byte/section and keep the reproducibility gate OPEN.

## Wire and convergence gates

- independent Python and Rust round-trip every Mode 1, 2 and 3 golden vector and
  receipt-success, failed-effect, unknown-effect and no-receipt-timeout tail;
- reject unknown/missing/duplicate fields, noncanonical JSON, truncation,
  trailing bytes, oversize frames, Unicode/escape variants, integer variants,
  replayed nonce, sequence/order mutation and chain mutation;
- verify every signature against the externally pinned root and exact role
  registry; reject wrong role, same key across roles, wrong algorithm/class,
  test fixture as production, wrong key ID and registry substitution;
- Rust recomputes every disclosed execution projection and snapshot/evidence
  digest; caller-supplied equality is never convergence evidence;
- only a service-private opaque `AuthenticatedConvergence` typestate, created
  after full signature/projection/mode/admission verification, may construct the
  core binding/evidence; `ConvergenceEvidence::new` is never an RPC surface and
  no public mapper fabricates three equal bindings from one caller assertion;
- the core whole-wire digest binds the complete verified transcript identity,
  admission policy, registry and mode-proof context even though the small core
  stores one converged binding;
- every smaller trusted-core identifier must either decode an exact normative
  wire field or use a documented domain-separated derivation while the full
  source value remains covered by the whole-wire digest; silent truncation,
  caller-selected defaults and fabricated domain/subject/adapter/effect IDs are
  prohibited;
- Mode 1 must evidence distinct A/B code/callable provenance, distinct workers,
  authority-owned causal rendezvous and actual substantive overlap;
- Mode 2 recomputes validator binding, input/output canonical sets, strict
  non-widening/reduction, and exactly one deterministic rejection reason for
  every removed candidate/pathway;
- Mode 3 recomputes the single-state seal/projection and verifies admitted
  single-state implementation provenance;
- malformed, future, stale, transplanted, mutated, invented-equal and
  mode-inappropriate evidence fails before trusted-core convergence;
- staged validation authenticates each request-ending prefix before the Rust
  authority signs or emits the corresponding result; validation must never
  require a provisional ALLOW signature in order to decide whether the request
  was admissible. A full-transcript audit validator alone is insufficient for
  the live authority state machine;
- the wire library exposes only authenticated request-prefix verification and
  validation of an already constructed result. It exposes no generic callback
  that can invoke a signer. Private, typed, stage-specific service methods own
  result construction and HSM/TPM signing. A malformed, stale or transplanted
  prefix must be proven unable to reach those private signer methods;
- PREPARE proof, capability, lease, watchdog and point-of-use permit digests are
  canonical domain-separated derivations over their authenticated stage
  context, authority identity/class/epoch, exact prior artifact and applicable
  deadline/identifier. Nonzero opaque authority-chosen strings are not accepted
  as artifact identity;

## Authority typestate and replay gates

- PREPARE remains non-authorizing and is accepted only after Rust-derived
  authenticated convergence;
- exact HSM/TPM/evidence authority class and custody technology, availability
  and freshness are checked before PREPARE. A production-labelled PREPARE cannot
  be created by an evidence fixture, unavailable/stale custody or the wrong
  hardware class, and failed PREPARE creates no durable claim;
- Rust separately recomputes the normative wire-v2
  `stable_effect_intent_digest` and `durable_consumption_digest`; the core's
  permanent intent claim uses the full durable-consumption digest and an
  design-authority-admitted replay namespace tied to the authority epoch. Traversal,
  challenge, nonce, time and artifact IDs cannot select a fresh intent. Oracle,
  profile, runtime and role/key identities remain bound by the authenticated
  convergence/admission digests, but ordinary code or key rotation must not by
  itself create a fresh effect-consumption identity;
- fresh traversal/operation/PREPARE/capability/lease IDs cannot authorize an
  already consumed durable-consumption identity;
- durable claims are linearizable under process races, survive restart and fail
  closed after incomplete writes; alternate paths/namespaces are impossible;
- COMMIT is single-use, sole authority-producing transition and cannot occur
  before PREPARE or more than once;
- capability redemption and lease effect/receipt consumption are globally
  single-use and persist across restart;
- rollback/deletion/path substitution must be detected by the eventual external
  monotonic replay anchor. Until that provider exists, production remains OPEN.

## Point-of-use and post-effect gates

- exact request/state/effect/adapter binding, fresh hardware custody, independent
  inhibit and interlock are rechecked at point of use;
- exact persisted watchdog arm is separately revalidated immediately before
  durable effect consumption; general watchdog health is insufficient;
- adapter receives only a lifetime-scoped `EffectDispatch` in one synchronous
  atomic call; no reusable effect permit crosses Rust/Python/wire;
- any public or cloneable wire permit-verification context is non-authorizing
  evidence only. The authority service converts it privately into a move-only,
  non-`Clone` dispatch typestate only while atomically revalidating the fixed
  prefix, trusted time, canonical durable identity and replay claim. Consuming
  that typestate permits exactly one adapter invocation; it cannot be recreated,
  cloned, returned to Python or redeemed through an alternate path/namespace;
- any wire-form permit record is buffered inside that atomic Rust-to-adapter
  operation and becomes externally observable only as post-consumption audit
  evidence after the durable claim and receipt exist; it is never streamed as
  a still-redeemable capability to Python or an untrusted caller;
- the exact authenticated `permit_id` and `permit_digest` pair is retained by
  the private dispatch and must match across permit result, adapter receipt,
  failure acknowledgement, watchdog terminal and watchdog result. A
  tail-consistent transplanted permit ID or digest must fail closed;
- expired/delayed permit, missing/mismatched arm, adapter substitution, mutation,
  duplicate consumption or replay-store ambiguity produces no effect;
- signed receipt binds exact consumption record/time/outcome; missing, late,
  forged, replayed or mismatched receipts cause STOP/BLOCK;
- adapter-consumption digest is recomputed from the exact durable-consumption
  identity, permit, adapter boundary, consumption time and outcome; an
  arbitrary signed digest is not evidence of atomic consumption;
- watchdog terminal result is mandatory for success, failure, unknown and timeout
  branches, and survives authority-process loss by independent custody;
- every earlier successful handoff is validated even when a later transition
  DENYs/BLOCKs; terminal failure cannot sanitize an invalid PREPARE→COMMIT,
  capability→lease, lease→watchdog or permit chain;
- successful receipt/ack/watchdog completion is strictly before the minimum
  applicable lease, permit and watchdog deadlines (deadline equality fails
  closed); receipt grace may delay only fail-closed STOP and cannot extend
  authorization;
- Mode 3 state-seal and proof digests are derived from disclosed canonical state
  and admitted implementation evidence, not accepted as opaque signed strings;
- Mode 1 rendezvous release is signed/bound to the admitted authority/coordinator
  session and is fresh for the same traversal; an ancient or self-only witness
  interval is rejected.

## Proposed production-dependency negative gates

While real adapters are absent, the programme binary must exit code 78 and
emit no authority output. Tests must demonstrate that none of these can be
satisfied by fixtures, labels, caller paths or local process state:

- real non-exportable hardware custody and attestation for the selected
  cryptographic profile;
- rollback-resistant external replay/consumption anchor;
- admitted source credentials and independently pinned role keys;
- independently controlled inhibit/interlock;
- external fail-closed watchdog and consequential stop;
- real adapter with atomic point-of-use effect consumption;
- external append-only audit custody.

Evidence-only artifacts must be structurally classed `TEST_ONLY` /
`NONPRODUCTION_EVIDENCE_ONLY`; every programme consumer rejects them even when
renamed, re-signed, copied or presented under production context.

## Current half-open cross-language checkpoint (pre-seal only)

The mutable working tree has been reconciled to half-open validity intervals
`[issued_at, expires_at)`. These results are a development checkpoint only;
they are not immutable evidence and must be repeated from the eventual fixed
Candidate 10 subject:

- SPARK sources: `spark_safety_monitor/src/sbp_lex_safety_monitor.ads`,
  `spark_safety_monitor/src/sbp_lex_safety_monitor.adb` and
  `spark_safety_monitor/src/spark_safety_monitor.adb`. `alr build` passed, the
  rebuilt executable harness passed its exact-deadline rejection and a receipt
  deadline wider than the lease/permit rejection; GNATprove
  `--mode=all --level=2 --report=all` proved all 53 checks. The current proof log
  is `spark_safety_monitor/obj/gnatprove/gnatprove.out`.
- Separate repository-local Rust verifier sources (not external independent validation):
  `independent_verifier_rust/src/lib.rs`,
  `independent_verifier_rust/tests/adversarial.rs` and
  `independent_verifier_rust/README.md`. Under
  `x86_64-pc-windows-gnullvm`, one unit test and 20 adversarial tests passed;
  `cargo fmt --check` and Clippy with `-D warnings` also passed. Blocked receipt
  exactly at envelope expiry and applied receipt exactly at lease expiry are
  explicit, correctly signed rejection cases.
- Formal sources: `formal/SBPLexAuthority.tla`,
  `formal/SBPLexAuthority.cfg`, `formal/check_model.py` and
  `formal/README.md`. After making successful receipt acceptance strictly
  lease-bound as well as watchdog-bound, the Python explorer passed 98,671
  distinct states, 158,402 transitions, maximum depth 20, a closed frontier,
  17 invariants and all seven exact-equality rejection witnesses. TLC, using
  `runtime_artifacts/toolchains/tla2tools.jar` and
  `runtime_artifacts/toolchains/microsoft-jdk-21-portable/jdk-21.0.12+8/bin/java.exe`,
  passed with 284,175 generated states, 98,671 distinct states, zero queued,
  depth 21 and no errors. The Python/TLC distinct-state counts match exactly.

The earlier inclusive-deadline results are superseded. The fixed-candidate run
must preserve raw stdout/stderr and exit codes as named artifacts rather than
relying on this narrative checkpoint.

## Rust boundary checkpoint rule (pre-seal only)

Earlier mutable runs of the trusted core and service, including the historical
40-test core and 15-unit/2-binary service checkpoint, are builder provenance
only. The service source has since expanded, so those counts must not be
presented as the result of the eventual Candidate 10 subject.

The current candidate source includes crate-private wire-v2 convergence
entrypoints for Modes 1, 2 and 3. Bounded crate-local evidence-fixture tests
exercise fixed-byte checks, private typestates, durable replay, watchdog
tightening, point-of-use dispatch, receipt/ACK terminal handling and fail-closed
terminal dispositions. The repository-pinned Mode 2 and Mode 3 success,
failed-effect, unknown-effect and no-receipt-timeout vectors are non-test
SHA-512-pinned by the same fixed-byte guard as Mode 1; crate-local tests traverse
each complete private typestate tail and reject partial, wrong-order, replayed
and client-supplied permit/tail input. Focused Python client tests separately
exercise the same Mode 2/3 terminal classes while retaining `NOT_ADMITTED` and
non-success-eligible status. The mapping is not exported or reachable from the
production/evidence binaries or the Python route. The public boundary remains
fail-closed on the legacy transport-only wire, the private Mode 1/2/3 mechanics
remain unadmitted, and all physical dependency gates remain explicitly fail
closed.

No mutable checkpoint admits the service. Exact format, lint, test, binary and
negative-case results must be regenerated and inventoried from the externally
identified fixed subject. The live route remains
`RUST_AUTHORITY_ROUTE_NOT_ADMITTED` unless and until a bounded V2
design-authority admission and every applicable external gate are evidenced.

## Proposed evidence package

- immutable code/test/profile commits and trees with exact ancestry;
- dependency, environment, toolchain and command manifests;
- complete path/size/SHA-256 inventory recomputed from the declared subject tree;
- the R4/runtime-subject inventory and assurance orchestrator explicitly cover
  `trusted_core_rust/`, `rust_authority_service/`, the frozen wire-v2 contract,
  focused Python boundary tests and every compiled binary; an evidence report
  that silently excludes these paths is invalid;
- raw stdout/stderr, exit codes and test-case inventory for every suite;
- shared cross-language vector hashes and separately recomputed results;
- positive and adversarial-negative artifacts, including preserved failed trials;
- durable replay/journal before-and-after identities and race/restart evidence;
- programme-store before/after byte hashes proving evidence isolation;
- binary hashes, reproducibility comparison and ML-DSA provider probe;
- signed evidence ledger binding every artifact plus an independent verifier;
- explicit OPEN/FAIL list for physical custody, rollback anchor, source
  credentials, inhibit/watchdog, live adapter and external IV&V/IVVF.

The proposed validation topology assigns one builder to submit only the new
immutable candidate, one independent validator to recompute identities and
rerun the disposable fixed subject with independent negative cases, and one
recorder to preserve chronology, genealogy, decisions, failures and
supersession. This topology itself awaits a bounded V2 design-authority
decision. No whole-candidate admission follows from a test count alone.
