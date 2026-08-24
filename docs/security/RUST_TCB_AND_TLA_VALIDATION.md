# SBP-LEX V2 Rust TCB and TLA+ Validation Boundary

## Document status

This document records a dated, repository-local security and validation
checkpoint for isolated work under `security_core/` and `formal/tla/`. The
checkpoint is `IMPLEMENTATION_DEFINED_V2`; no explicit owner-approval record or
independent validation makes the complete architecture controlling. It does not
approve integration with the active Python pipeline and does not claim
production readiness.

Evidence status updated on 24 August 2026:

| Evidence class | Status |
|---|---|
| Current Python V2 contracts | Present in the repository; not independently validated by this document |
| New isolated Rust TCB under `security_core/` | Present and isolated; the document records a dated self-reported checkpoint of 19 responsibility areas, 35/35 tests, formatting, and strict Clippy; not independently reproduced here |
| New traversal model under `formal/tla/` | Present; two current repository-local bounded runs under checksum-verified stable TLA+ tools v1.7.4 passed `TypeOK` and all 22 invariants with no counterexamples; exact source/tool bindings are recorded but not independently reproduced |
| Actual Windows TPM-backed signing exercised on this host | Unvalidated; provider enumeration reported `NTE_DEVICE_NOT_READY` |
| University validation | Not performed |

The recorded results above concern only the identified isolated paths. Existing Rust projects
(`trusted_core_rust/`, `rust_authority_service/`,
`independent_verifier_rust/`, `wire_protocol/v2/rust/`, and
`polyglot/rust/v2_assurance_kernel/`) and the existing
`formal/SBPLexAuthority.tla` are not treated as the identified isolated Rust TCB or
the new `formal/tla/SBPLEXV2.tla` model. Their presence cannot be substituted
for evidence from those paths.

## Evidence and authority basis

The security boundary below is an AI-generated V2 architecture proposal checked
against repository anchors. The complete boundary remains
`AI_PROPOSED_AWAITING_APPROVAL`; implemented modules are separately
`IMPLEMENTATION_DEFINED_V2` facts.

- `sbp_lex/assurance/envelope.py` defines a restricted canonical JSON profile,
  checkpoint identifiers, envelope sequencing, and SHA-512 envelope chaining.
- `sbp_lex/security/integrity.py` defines exact integrity conversion, canonical
  SHA-512 construction, and structural/cryptographic hash-chain verification.
- `sbp_lex/security/signature_provider.py` and `hybrid_signature.py` define the
  active strict-dual signed-object envelope. The included ML-DSA-87 AND Ed448
  software provider keeps both test keys in process memory, explicitly has no
  effect authority, and is not HSM/TPM evidence. Ed25519 is restricted to the
  explicitly legacy non-effect inspection path.
- `sbp_lex/security/token_stack.py` defines required token names, issuers,
  issuance stages, payload binding, chronology, and token verification.
- `sbp_lex/config/pipeline_config.py` records the current V2 order.
- `sbp_lex/governance/three_p_doctrine.py`, `skg_authority.py`,
  `filed_frameworks.py`, and `filed_lifecycle.py` define the current 3P, SKG,
  four-framework, and three-lifecycle evidence contracts. Their filenames do
  not authenticate filed provenance.
- `sbp_lex/licensing/filed_licensing.py` defines four repository-configured licence labels, five
  signed bindings, validation/revalidation/point-of-use stages, invalidation,
  and revocation checks.
- `sbp_lex/execution/execution_gate.py` and
  `sbp_lex/execution/controlled_local_adapter.py` contain the active Python
  execution gate and controlled-local permit/effect path.
- `sbp_lex/audit/engine.py`, `audit_engine.py`, and `audit_ledger.py` contain the
  current audit record and ledger mechanisms.
- `docs/patent/SBP_LEX_PATENT_TO_BUILD_CONFORMANCE_MATRIX.md` distinguishes the
  two provisionally attributed submission branches from implementation-defined V2 mechanisms and records
  current conformance gaps.
- `docs/patent/V2_IMPLEMENTATION_DEFINED_SKG_LIFECYCLE_CONSTRUCTION.md`
  identifies the SKG and lifecycle ordering, record layout, and token mechanics
  as V2 implementation choices; no admitted primary source in this workspace
  authenticates them as filed schema.

The repository's provisional patent mapping attributes authority-first gating,
revocation, audit, 3P/SKG/framework/licensing/lifecycle constraints and broader
cryptographic-exchange/regulatory-effect concepts to absent or unverified
primary filing artifacts. Those attributions are not authenticated by this
document. The Rust API, TPM API mapping, token wire schema, permit schema and
TLA+ state variables are repository implementation mechanisms and must not be
described as filed text.

## 1. Proposed trusted computing boundary

### 1.1 Intended logical TCB

If this architecture is separately approved and admitted after the isolated work
is complete, the proposed logical Rust TCB would be limited to:

1. The reviewed source, locked Rust dependencies, and built binary produced
   from `security_core/`.
2. Canonical decoding/encoding and deterministic digest construction compatible
   with the admitted current V2 representation.
3. Strict structured-signature-envelope verification.
4. Windows cryptographic-provider calls required to locate an explicitly
   provisioned TPM-backed non-exportable key, sign through that provider, bind
   the public-key identity/digest, and verify signatures.
5. Verification of request fingerprint, 3P, SKG, authority state, the four
   configured frameworks, the three configured lifecycle engines, licence, tokens, hash
   chain, audit, permit, and immediate pre-effect evidence.
6. Monotonic revocation, chronology, replay, and one-time permit-claim state
   maintained by the boundary or by an admitted durable store whose failure is
   treated as denial.
7. The final fail-closed decision and the only admitted call edge to an effect
   dispatcher.

The exact closed result type in `security_core/src/decision.rs` is
`ClosedDecision`: `PermitExistingAuthorization`, `Deny`, `Escalate`, `Revoke`,
`Unsupported`, or `Indeterminate`. It has no Governance `ALLOW` variant.
`PermitExistingAuthorization` is reachable only through the proof-gated
dispatch function for an already-authorised effect; it does not invent
authority, grant a licence, or widen execution rights. `Proof` construction is
crate-restricted and identifies the verified component and request
fingerprint.

The 19 repository-recorded responsibility areas are represented through the reviewed
modules for canonicalization/digest, signature/TPM, request, 3P, SKG,
authority, configured frameworks, configured lifecycle, licence, token, hash chain,
audit, permit, immediate pre-effect revalidation, revocation, replay, and
dispatch, with closed decision/evidence support. `FORMAT_MAP.md` records the
mapping from current V2 representations rather than defining a replacement
format.

### 1.2 Physical enforcement condition

The logical list is not yet a physical TCB. It becomes an enforcement boundary
only if deployment proves that every effect adapter is reachable solely through
the reviewed Rust dispatch edge and that the Python path cannot call an effect
handler directly. No such deployment proof is presently in the repository.

### 1.3 Trusted dependency edge

Rust memory safety narrows memory-corruption risk in safe Rust; it does not
remove the compiler, linked crates, unsafe blocks, Windows APIs, operating
system, TPM, firmware, provisioning, or deployment configuration from the
effective trust base. Dependency versions and any unsafe code must be included
in the validation evidence.

## 2. Everything intentionally outside the boundary

The following remain outside the Rust TCB and are untrusted inputs or external
dependencies unless separately admitted:

- Python orchestration, policy traversal, modelling, research engines, and all
  Python-produced Boolean or categorical determinations.
- The truth or legal correctness of 3P, SKG, authority, jurisdiction,
  statutory, treaty, evidentiary, lifecycle, Domain, Aurion, and licence source
  material.
- Policy selection, legal conflict interpretation, authority creation,
  Governance `ALLOW`, and licence grant decisions.
- Python serialization before Rust independently decodes and canonicalizes it.
- IPC/transport, files, environment variables, registry settings, and caller
  process identity unless independently authenticated inside the boundary.
- Windows kernel, cryptographic services, provider implementation, TPM
  hardware/firmware, boot state, machine administrators, and provisioning.
- Wall clock, monotonic clock, durable replay/revocation storage, and their
  availability unless an admitted implementation proves their properties.
- Effect hardware/service behavior after dispatch, including whether the
  claimed real-world effect matches the requested effect.
- TLA+ tools, model configuration, model-to-code correspondence, and the Java
  runtime used by TLC.
- Patent validity, legal interpretation, legal sufficiency, and independent
  university conclusions.

## 3. Python-to-Rust trust assumptions

Python is not trusted to assert that a prerequisite passed. The boundary may
accept bytes and metadata from Python, but must independently reject any input
that is missing, duplicated, unknown, malformed, non-canonical, out of order,
replayed, stale, revoked, cryptographically invalid, or inconsistent with the
same request lineage.

Compatibility must be demonstrated against the two current canonical profiles:

- `sbp_lex/assurance/envelope.py` forbids floating-point values, NFC-normalizes
  strings, sorts object keys by UTF-16 code units, and emits compact UTF-8 JSON.
- `sbp_lex/security/integrity.py` converts finite Python floats to an
  `{"exact_decimal": "..."}` object before using the assurance canonical JSON
  encoder.

These profiles are related but not identical entry contracts. The Rust code
must map their applicable use sites explicitly. Treating them as one format
without a field-by-field compatibility map is a validation failure.

The repository-defined SHA-512 migration represents every security digest in this
boundary as exactly 128 lowercase hexadecimal characters. It is a breaking
format change: SHA-256-shaped digests are rejected rather than interpreted as
SHA-512 values. SHA-512 raises the generic collision-resistance target of the
digest and hash-chain substrate to 256 bits; it does not make V2 an end-to-end
256-bit system. Active Python now contains the exact strict-dual
`SBP_LEX_V2_ML_DSA_87_ED448_AND_V1`
mechanics, while external custody, Rust-route admission, deployment boundaries
and the other listed dependencies remain separate limits.

The isolated `hybrid_signature_rust` crate implements the same fixed binary
strict-dual preimage
preimage. The repository records a local run in which both Python-produced
signature lanes verified against the shared fixed vector. This is mutable,
repository-local interoperability evidence; it is not integration into the Rust
authority route, immutable Candidate 10 evidence or independent validation.

The runtime-detached local-trust package also contains genuine ML-DSA-87 +
Ed448 signing and an additive exact-byte strict-dual wrapper using the common
envelope and preimage. Those evidence tools do not change this Rust TCB, admit
the Rust wire route, supply production custody or grant effect authority.
ML-KEM-1024 appears only as a non-deployed channel-establishment
capability/evidence contract; no encapsulation, decapsulation, transport
admission or custody deployment is claimed.

Python must supply the exact admitted evidence objects and signatures; it is
not trusted to supply the verification result. A request fingerprint, digest,
token, audit hash, or `verified` field is only a claim until Rust recomputes or
verifies it. An upstream Governance `ALLOW` is a prerequisite fact to
authenticate, never a decision Rust may synthesize.

## 4. TPM trust assumptions

The current AI-proposed production-custody design assumes a Windows TPM-backed,
non-exportable private key used through supported Windows cryptographic APIs.
If that design is selected, the following must all be demonstrated on the
deployment host:

1. The selected provider is the TPM-backed provider, not a software provider.
2. The provisioned key has the required non-export/export-policy attributes.
3. The private operation is performed through the provider and raw private key
   bytes are neither returned to Rust/Python nor written to repository files.
4. The expected key identity and public-key digest are pinned or resolved
   through an authenticated registry and are bound into signed records.
5. Missing TPM, inaccessible key, wrong key, changed public key, provider
   error, invalid signature, and unverifiable provider properties all deny.

Provider enumeration alone is not TPM enforcement. On the inspected host,
`certutil -csplist` listed Microsoft Platform Crypto Provider but reported
`NTE_DEVICE_NOT_READY`; this is evidence of unavailability, not a successful
TPM exercise. Under the current proposal, no software-key fallback is admissible
in the production path.
The process-memory `Ed25519SoftwareProvider` and the `TEST_ONLY` strict-dual software
provider in `sbp_lex/security/signature_provider.py` are explicitly outside
this TPM claim and have no effect authority or external-custody admission.

Even after a successful exercise, the code does not by itself prove TPM
firmware integrity, measured boot, host-administrator exclusion, recovery-key
governance, backup behavior, or physical resistance. Those remain deployment
dependencies.

## 5. Key lifecycle and revocation assumptions

The current proposed boundary requires an external, authenticated lifecycle for
provisioning, activation, rotation, suspension, revocation, recovery, and
destruction. The repository does not establish who is authorised to perform
those operations or how production key-revocation state is distributed.

Validation must establish:

- a unique key identifier and public-key digest for each admitted role;
- role separation between token/evidence authentication and effect authority;
- atomic activation/retirement rules during rotation;
- a monotonically increasing revocation sequence or equivalent rollback-proof
  version bound to request, licence, permit, and point-of-use checks;
- durable rejection of old key identities, old revocation snapshots, replayed
  permits, and already consumed permit claims across restart;
- defined behavior for loss, TPM clear, motherboard replacement, recovery, and
  clock/storage failure;
- audit attribution for every key lifecycle event.

The current Python licence contract tests monotonic revocation values and
point-of-use revocation in a controlled-local path. It does not prove a
distributed, durable production revocation service or TPM key lifecycle.

## 6. Attack surfaces

| Surface | Representative attack | Required boundary response |
|---|---|---|
| Python-to-Rust message | Missing/duplicate fields, ambiguous types, Unicode/key-order variants, non-finite number, oversized object | Reject before evaluation; no dispatch |
| Canonicalization/digest | Cross-language representation mismatch or digest substitution | Recompute with admitted profile; reject mismatch |
| Signature envelope | Wrong/missing signer, metadata substitution, malformed base64, altered signed field | Reject; no fallback verifier/signer |
| Request lineage | Transplant valid evidence from another request/state | Reject fingerprint, state, chronology, or chain mismatch |
| 3P/SKG/framework/lifecycle evidence | Omission, reordering, duplication, stale or forged evidence | Deny/escalate; never infer pass |
| Licence | Identity/jurisdiction/authority/execution-right/autonomy mismatch, inactive status, rollback or late revocation | Revoke/deny and prevent handler reachability |
| Token stack | Omission, duplication, substitution, reordering, issuer/stage/payload mismatch | Reject complete stack |
| Hash/audit chain | Entry mutation or attacker-appended validly rehashed suffix | Require canonical terminal lineage, not structural linkage alone |
| Permit | Mutation, expiry, substitution, double claim, restart replay | Reject and atomically consume exactly once |
| Immediate pre-effect window | Revocation or state change after permit mint | Revalidate at dispatch point; reject change |
| TPM/provider | Provider unavailable, wrong provider/key, changed public key, exportable key | Fail closed; no software fallback |
| IPC/process | Spoofed peer, confused-deputy call, direct Python handler call | Authenticate peer and enforce one physical dispatch choke point |
| Dependencies/build | Compromised crate, compiler, build artifact, DLL/provider loading | Locked/reviewed dependencies, reproducible artifact evidence, deployment controls |
| Resource exhaustion | Oversized input, algorithmic denial, store/clock failure | Bounded parsing; deny safely without partial dispatch |
| Host/platform | Administrator replaces binary/config or compromises OS | External measured deployment and access controls; not proven by Rust logic |

Side-channel resistance, denial-of-service availability, compiler correctness,
and compromised-host resistance are not established by memory-safe Rust alone.

## 7. Fail-closed behaviour

The proposed production rule is: uncertainty cannot become permission. For every
prerequisite the boundary must have an exact affirmative verification result;
absence of an affirmative result produces no dispatch.

At minimum, the following conditions must close the boundary:

- unknown decision/status/enum value;
- missing dependency, evaluator, public key, TPM provider, durable state,
  trusted time source, or required evidence;
- malformed, duplicate, reordered, stale, non-canonical, or oversized input;
- any signature, digest, request-fingerprint, authority-state, chronology,
  chain, licence, permit, or audit mismatch;
- any 3P, SKG, governance framework, lifecycle, licence, Domain, Aurion,
  execution-gate, or immediate revalidation prerequisite that is not proven;
- revocation, sequence rollback, replay, already-consumed permit, or inability
  to establish freshness;
- internal error, panic, provider error, IPC error, storage error, clock error,
  or partial result.

A test-only software signer is allowed only in test code and must not be linked
or selected by a production configuration. A simulated success path or
constant approval is not evidence and must not exist in production code.

The current Python gate generally returns `HALT` with `DENY` or `ESCALATE` on
failed checks, and the pipeline catches runtime/signature-provider errors as
denials. That current behavior is evidence for cross-language fixtures; it is
not proof of the new Rust behavior until Rust negative tests exercise every
listed failure.

## 8. Remaining bypass paths

The new Rust work is intentionally isolated, so the following bypasses remain
open until a separate integration and deployment decision closes them:

1. The active Python path can still reach the controlled-local effect adapter
   without traversing the new Rust boundary because no new integration is
   implemented or admitted yet.
2. Python modules and effect handlers remain importable in the same software
   environment; the repository does not prove an OS/process-level choke point.
3. `PIPELINE_NON_BYPASS = True` in `pipeline_config.py` is a configuration
   declaration, not physical non-bypass evidence.
4. No deployed adapter inventory proves that every real effect target is behind
   a single Rust dispatch interface.
5. No actual TPM-backed production key was successfully exercised on the
   inspected host.
6. Durable cross-restart replay prevention, trusted time, and distributed
   revocation remain unproven unless the new Rust implementation and its
   deployment supply them.
7. External evaluators can sign false substantive determinations if their
   authority, operation, and evidence quality are not independently validated;
   cryptography authenticates the signer and bytes, not their truth.
8. A compromised Windows host or administrator can remain a bypass unless
   binary identity, configuration, process isolation, boot state, access, and
   adapter routing are enforced externally.
9. Model checking cannot close code or deployment bypasses without a reviewed
   refinement/correspondence argument.

These are blockers to a production non-bypass claim, not permission to add a
fallback.

## 9. What the recorded Rust checkpoint supports

The isolated `security_core/` source is present. On the installed stable
`x86_64-pc-windows-gnu` toolchain, `cargo check --all-targets`, `cargo fmt`, and
`cargo clippy --all-targets -- -D warnings` passed, and the current strict-dual
hardening run passed 35/35 Rust tests. The MSVC target was not
validated because `link.exe`/Visual C++ Build Tools were absent.

Those results provide implementation evidence that, for the exercised inputs
admitted by the exact coded contracts:

- canonical bytes and SHA-512 digests are reconstructed deterministically;
- the configured cryptographic provider validates the exact signed bytes and
  key identity presented to it;
- required evidence structures, issuers, stages, field bindings, chronology,
  hash links, and request lineage satisfy the coded predicates;
- revoked, stale, replayed, malformed, incomplete, mutated, reordered, or
  inconsistent inputs do not reach the coded effect-dispatch call edge;
- a permit is accepted only once and only after immediate pre-effect
  revalidation, if the durable atomic state and time dependencies meet their
  contracts;
- the Rust decision vocabulary contains no route that independently creates
  Governance `ALLOW`, policy, authority, licence, or broader rights.

The 34 tests include all requested categories: canonicalization and digest
stability; a SHA-512 known-answer vector and legacy 64-character SHA-256-width
rejection; every signed-payload-field mutation; unproven effect-authority,
wrong/missing signer and malformed envelope; token omission, empty required
vocabulary, duplication, substitution and reordering; hash mutation and a
validly rehashed unauthorised suffix; licence mismatch and revocation at the
three requested times; replay and rollback; missing 3P/SKG evidence;
framework/lifecycle failure; audit/permit mutation; valid paths through each
structured verifier; SKG mutation with a rehashed trace; TPM
unavailable/unsupported; no single token/component granting dispatch; handler
non-reachability after failed prerequisites; one successful already-authorised
handler call; and request-fingerprint mutation.

Rust unit/integration tests provide implementation evidence, not mathematical
proof for all possible inputs. The core cannot prove that signed legal or
governance assertions are substantively true, that the platform really used a
TPM without a successful provider exercise, or that callers cannot bypass a
binary that deployment did not make mandatory.

## 10. What the recorded bounded TLA+ runs support

`formal/tla/SBPLEXV2.tla` models all 23 requested traversal concepts and defines
`TypeOK` plus the 22 named `Inv01`-`Inv22` safety invariants. The current
repository-local rerun used checksum-verified stable TLA+ tools v1.7.4 under
publisher-checksum-verified Microsoft OpenJDK 21.0.12.1+1 on Windows 11 x64.

The primary retained configuration used two request identifiers, two permit
identifiers, `MaxRevocations = 1`, and `HostTPMAvailable = FALSE`. Breadth-first
TLC generated 17,298 states, found 8,904 distinct states, left zero queued,
reached depth 32, and reported no error: `TypeOK` and all 22 invariants passed,
with no counterexamples. Because the host-TPM assumption was false, the effect
path is unreachable in that run and effect-conditional invariants are vacuous
there.

A separate non-vacuity run changed only the model assumption to
`HostTPMAvailable = TRUE`; the repository configuration was restored to
`FALSE`. It generated 20,968 states, found 10,788 distinct states, left zero
queued, reached depth 35, and passed `TypeOK` and all 22 invariants with no
counterexamples. That bounded run reached permit, claim, immediate
revalidation, effect, receipt, and audit states. The `TRUE` assumption is not
evidence of real host TPM availability or enforcement.

Static authoring review corrected invalid TLA+ `EXCEPT` record-field references
before the completed runs. Neither completed run produced an invariant
violation or behavior counterexample, and no completed result was discarded.
Exact tool, source and run bindings are in
`evidence/v2/tla-model-evidence.json`; that evidence is mutable, unsealed and
not independently reproduced.

For the exact checked model and finite configurations, the results show that
every reachable modeled state satisfied the named safety invariants, including
traversal order, non-bypass within the modeled transition relation, revocation
monotonicity, token/permit prerequisites, one-time permit use, terminal
blocking, audit ordering, and one-to-one lineage. The result is limited to:

- the variables, transitions, fairness assumptions, and invariants actually in
  `SBPLEXV2.tla`;
- the constants and bounds in `SBPLEXV2.cfg`;
- the state space TLC actually explores; and
- the correctness of the specification and TLC execution.

TLA+ does not prove SHA-512 or signature security, Rust memory safety, TPM
custody, Python/Rust serialization equivalence, implementation conformance,
legal correctness, or physical deployment non-bypass. A missing transition can
make an invariant pass vacuously; coverage and enabled-transition review are
required. Every counterexample must be retained, explained, corrected if the
model is wrong, and rerun. It must not be rewritten as a successful result.

The model is bounded to one active traversal, two request identifiers, two
permit identifiers, and one revocation increment; it does not model concurrent
requests, distributed replicas, time/TTL/clock rollback, crashes, durable
transactions, filesystems, or network partitions. The separate existing
`formal/SBPLexAuthority.tla` models a different authority
control problem and is not evidence that the required V2 traversal invariants
have been checked.

## 11. What neither proves

Neither Rust verification nor TLA+ model checking establishes:

- patent validity, patent infringement, legal interpretation, or complete
  conformance to either provisionally attributed submission;
- correctness, lawfulness, currency, or completeness of authority, SKG, 3P,
  jurisdiction, licence, statutory, treaty, lifecycle, Domain, Aurion, or other
  externally supplied evidence;
- that an identity or biometric evidence reference belongs to a real person;
- that a signed record was authorised rather than merely signed by a key;
- absence of cryptographic, compiler, dependency, firmware, OS, hardware,
  side-channel, supply-chain, or operational vulnerabilities;
- actual non-exportability or TPM use without host/provider evidence;
- secure provisioning, role separation, administrator controls, measured boot,
  binary integrity, disaster recovery, or key destruction;
- correctness or reversibility of the external real-world effect;
- availability, performance, scalability, or freedom from denial of service;
- equality between the TLA+ abstraction and running Python/Rust code;
- absence of all bypasses in a deployment not independently inspected.

The system must not be described as uncrackable, formally verified as a whole,
TPM-enforced, patent-conformant, or production-safe on the basis of these
artifacts alone.

## 12. Proposed university or deployment validation scope

Under the current proposed protocol, independent validation would include at
least:

1. A source-to-binary and dependency review of `security_core/`, including all
   unsafe code, FFI, Windows API flags, error paths, feature flags, and release
   profile behavior.
2. Cross-language canonicalization/digest/signature vectors for every admitted
   object and every signed-field mutation.
3. Complete negative testing for omission, duplication, substitution,
   reordering, rollback, replay, late revocation, audit suffix replacement,
   permit mutation, provider failure, and handler non-reachability.
4. Real Windows TPM provisioning and signing on the target host, with
   non-exportability evidence, public-key digest binding, changed/wrong-key
   rejection, provider failure, and proof that no production software fallback
   is reachable.
5. Restart, crash, concurrency, partition, rollback, and atomicity experiments
   for replay and revocation state.
6. A physical deployment/adaptor inventory proving that all effect handlers are
   downstream of the Rust boundary and that direct Python invocation is denied.
7. TLC execution for the exact `formal/tla/` model, recording configuration,
   explored/generated/distinct states, invariant outcomes, all
   counterexamples, corrections, reruns, and model limits.
8. A model-to-code correspondence review mapping each TLA+ transition and
   invariant to Rust functions/tests and Python evidence contracts.
9. Independent review of authority/evidence sources, operational procedures,
   key governance, host hardening, build/release controls, logging, monitoring,
   incident response, and recovery.
10. Patent counsel review if any legal claim about the provisionally attributed
    submissions is to be made; the engineering protocol does not supply legal
    advice.

The detailed experiment, evidence-capture, and objective result criteria are in
`docs/validation/UNIVERSITY_VALIDATION_PROTOCOL.md`.

## Final evidence and open-gap register

| Evidence item | Required source | Current status |
|---|---|---|
| Exact Rust module/file inventory and closed decision enum | `security_core/src/`, `FORMAT_MAP.md` | PRESENT: all 19 repository-recorded responsibility areas; `ClosedDecision` has six veto/permit-existing-authority outcomes and no Governance `ALLOW` |
| Cargo dependency and unsafe-code inventory | `security_core/Cargo.toml`, `Cargo.lock`, source review | Dependencies locked; GNU all-target check, formatting and strict Clippy passed; MSVC linker unavailable; full external supply-chain audit remains required |
| Rust test names and results for repository-listed adversarial cases | `security_core/src/tests.rs` and a future sealed Cargo-output artifact | Dated narrative checkpoint records 35/35 passed after strict two-lane custody negatives were added; no sealed, independently reproduced raw-output package is admitted here |
| Windows provider/TPM implementation flags and failure mapping | `security_core/src/tpm.rs`, `FORMAT_MAP.md`, host probe | Real NCrypt provider probe maps `NTE_DEVICE_NOT_READY`; strict-dual production key creation/signing/public verification remains `HybridHardwareCustodyAndPinningUnavailable`; no production fallback |
| Exact TLA+ variables, transitions, and 22 configured invariants | `formal/tla/SBPLEXV2.tla`, `.cfg`, `README.md` | PRESENT: all 23 repository-recorded concepts and `TypeOK` plus all 22 configured invariants |
| TLC bounds, state counts, invariant results, and counterexamples | `formal/tla/SBPLEXV2.cfg`, `README.md`, and `evidence/v2/tla-model-evidence.json` | Hash-bound mutable checkpoint records two completed bounded runs, 8,904 and 10,788 distinct states, all invariants passed and no counterexamples; no sealed, independently reproduced raw-output package is admitted here |
| Python-to-Rust mapped representation | `security_core/FORMAT_MAP.md`, Rust tests | Format map and exercised Rust fixtures present; an independently generated full Python-to-Rust golden-vector corpus remains required |
| Non-effect signer trust roots and lifecycle/licence source mapping | Rust source/deployment policy | External signer roots remain supplied by callers; full evaluator-source mapping for lifecycle/licence is incomplete for production admission |
| Durable replay, revocation, and canonical audit stores | Injected production implementations and deployment tests | Traits/contracts present; production stores undeployed and unvalidated |
| Independent university result | Signed university evidence package | NOT PERFORMED |
