# Wire v2 to Rust authority — private integration map

Status: `AI_PROPOSED_AWAITING_APPROVAL`. This document is a generated pre-freeze
architecture proposal, not a controlling owner-approved design, implementation
admission, seal, production authorization, live-effect authorization, or safety
claim. Existing private source mechanics are separately
`IMPLEMENTATION_DEFINED_V2`; they do not approve the complete production
topology. The live route stays `RUST_AUTHORITY_ROUTE_NOT_ADMITTED`.

Every normative word below (`must`, `only`, `exact`, `fixed`, `forbidden`) is a
proposed Candidate-10 design constraint awaiting a bounded V2 design-authority
decision unless the sentence merely reports existing source behaviour. No such
word proves filed provenance or owner approval.

## Process and API boundary

The programme Python process may send only bounded framed canonical JSON over a
non-executable byte channel. It never imports the Rust core, receives a Rust
typestate, obtains a signing provider, selects a replay path/namespace, or sees
a still-redeemable point-of-use permit.

Inside the persistent Rust service, the only forward path is:

```text
untrusted bytes
  -> independently authenticated v2 request prefix
  -> private AuthenticatedConvergence (move-only)
  -> trusted-core Candidate / Converged
  -> private stage-specific PREPARE method
  -> private stage-specific COMMIT method
  -> private lease/watchdog/permit methods
  -> engine-owned physical watchdog durably tightened to the exact effective
     minimum before permit signing
  -> private AtomicDispatch (move-only, non-Clone)
  -> durable global intent/effect claim + fresh prefix/time revalidation
  -> exactly one synchronous admitted adapter call
  -> signed receipt + watchdog terminal evidence
```

The wire library may expose request-prefix verification and validation of an
already constructed result. It must expose no callback that can invoke a
signer. Service signer methods are private and typed by stage; invalid, stale,
foreign or transplanted prefixes cannot reach them. A public or cloneable wire
permit-verification context is non-authorizing evidence only and cannot itself
invoke an adapter.

## Lossless immutable-field mapping

The service constructs the core `Binding` only after v2 has authenticated all
role signatures, projections, mode evidence, admission policy, trusted time and
the externally pinned registry. No RPC-level constructor or public mapper is
provided.

| Core field | Proposed or implemented v2 source / derivation |
| --- | --- |
| `DomainId[64]` | exact 64-byte SHA-512 `domain_digest` |
| `authority_epoch` | exact nonzero design-authority-admitted u53 `authority_epoch`, widened losslessly to u64 |
| `AuthorityClass` | exact mapping: `TEST_ONLY -> NonproductionEvidenceOnly`, `PRODUCTION_HSM -> ProductionHsm`, `PRODUCTION_TPM -> ProductionTpm`; no fallback |
| `authority_profile_digest` | service-domain SHA-512 of exact admitted authority class/profile and admission-policy digest |
| `authority_build_digest` | service-domain SHA-512 of exact admitted build ID, runtime subject and runtime tree |
| `wire_binding_digest` | exact 64-byte SHA-512 `authenticated_convergence_binding_digest` |
| `OperationId[16]` | exact 16-byte `operation_id` |
| `SubjectId[64]` | exact 64-byte SHA-512 `subject_digest` |
| `state_digest` | exact 64-byte SHA-512 `state_digest` and matching disclosed projection state |
| `policy_digest` | exact matching `projection_policy_digest` after mode-specific verification |
| `configuration_digest` | exact 64-byte SHA-512 `admission_policy_digest`; this binds the complete design-authority-selected configuration rather than a caller default |
| `extension_admission_binding_digest` | distinct exact 64-byte SHA-512 disabled extension carrier from the independently pinned v2 `AdmissionPolicy`; never aliases `configuration_digest` |
| `AdapterId[64]` | exact 64-byte SHA-512 `adapter_digest` and matching projection adapter |
| `EffectId[64]` | exact 64-byte SHA-512 `effect_digest` and matching projection effect |
| `safety_envelope_digest` | exact 64-byte SHA-512 admitted `interlock_digest`; inhibit identity remains independently covered by the full wire binding |

The full admission policy, trust root/registry, oracle, runtime subject/tree,
mode/challenge, request, A/B or validator/single-state provenance, effect intent,
adapter boundary, inhibit, watchdog, audit anchor and replay namespace remain in
the authenticated convergence digest. Nothing is silently dropped or replaced
with a default.

The service admits only wire v2 projection schema
`SBP-LEX-EXEC-PROJECTION/2` and `EXTENSIONS_DISABLED` extension schema
`SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED`. Legacy wire v1 and required
extension mode are unavailable rather than translated.

Authority and adapter receipt `KeyId[64]` values come from the exact admitted
`AUTHORITY` and `ADAPTER` registry entries. Production custody-provider identity
is separately design-authority-selected and physically attested; it is never inferred from a
wire label. Until those providers exist, production construction fails before
PREPARE.

Internal 16-byte PREPARE/capability/lease IDs must be either explicit normative
v2 fields or service-domain-separated 128-bit derivations from the corresponding
authenticated stage context and full 64-byte SHA-512 artifact digest. Any derivation is
specified, collision-tested and covered by the full signed 64-byte identity;
plain truncation or caller selection is forbidden.

## Convergence and stage artifacts

`AuthenticatedConvergence` owns the verified transcript identity, admission
digest, registry digest, projection digest and mode evidence. Its only private
conversion constructs the one core binding after all independent facts have
already been checked. The core equality comparison is subordinate defense in
depth; it is not used to turn caller-provided equal strings into convergence.

For every stage, the service first authenticates the exact request-ending
prefix. Only then may the matching private method construct a core transition
and ask the admitted HSM/TPM to sign. The resulting v2 artifact digest is a
normative domain-separated derivation over:

- the verified stage-context digest and authenticated convergence digest;
- authority class, epoch, admitted signer-key identity, build/profile, request
  transcript and the stage's exact prior artifacts/IDs/deadlines;
- non-circular result metadata required by the normative derivation, including
  result time and nonce and, for the permit, its half-open deadline.

The artifact digest never includes itself, its derived artifact ID or
`signature_hex`. The admitted HSM/TPM wire signature is a separate operation
over the completed canonical result and therefore authenticates the artifact
digest and derived ID without circularity. Service code must reproduce the
frozen wire derivation exactly; it must not add signature bytes to one language
implementation or substitute a service-local formula.

PREPARE proof, capability, lease, watchdog arm and point-of-use permit digests
cannot be arbitrary nonzero strings. The signed result is passed back through
v2 append validation before it becomes the next untrusted transcript prefix.
The service additionally retains the exact authenticated `permit_id` together
with `permit_digest`. Both values must match, without derivation fallback or
tail-local substitution, across the permit result, private atomic dispatch,
adapter receipt, failure acknowledgement, watchdog terminal and final watchdog
result. A tail whose permit ID is transplanted—even if all tail artifacts agree
with one another and their transcript chain is internally valid—fails before
adapter invocation or post-effect acknowledgement.

## Replay and point-of-use consumption

The permanent replay identity is exactly the pair:

```text
(design-authority-admitted authority_epoch, verified durable_consumption_digest[64])
```

The durable digest is independently recomputed from the design-authority-admitted replay
namespace and stable effect intent. Traversal, challenge, nonce, time, process,
worker and artifact IDs cannot refresh it. Production has one configured replay
provider; no request, CLI option, environment variable, current directory,
symlink, alternate file path or new process can select an empty namespace.

Before the service constructs or signs an `effect_permit_result`, the
engine-owned physical watchdog must durably confirm an exact, idempotent
narrowing transition to:

```text
min(signed lease expiry, verified wire watchdog deadline,
    derived permit deadline)
```

The provider may accept the identical already-persisted arm, but it must reject
deadline widening or any binding, capability, lease, expiry or provider-identity
substitution. The service re-verifies that exact persisted arm before continuing.
If persistence is unavailable, mismatched or late, the permit signer and adapter
are never reached. A crash after the durable narrowing—whether before or after
permit signing—therefore still leaves an independently scheduled STOP at the
same half-open deadline. The ephemeral `EffectDispatch` shown to the adapter
also exposes that exact minimum as its expiry; it never advertises the later
underlying lease expiry.

The private `AtomicDispatch` owns, and does not clone, the authenticated permit
ID+digest pair, complete permit context, core effect-side state and exact
adapter binding. Its consuming method
atomically:

1. reauthenticates the fixed prefix and admitted registry at trusted current
   time;
2. recomputes the canonical point-of-use and durable-consumption identities;
3. requires exact fresh hardware custody, inhibit/interlock and persisted
   watchdog arm;
4. claims the permanent effect slot through the one external replay anchor;
5. invokes the admitted adapter exactly once before the minimum permit, lease
   and watchdog deadlines; and
6. durably claims the authenticated receipt while retaining the exact watchdog
   arm; FAILED and UNKNOWN trip STOP without ACK; and
7. for SUCCESS only, constructs/revalidates and durably appends the complete
   signed receipt/ACK/watchdog tail as `PENDING_IN_DOUBT` before a physical
   watchdog ACK is attempted.

A stored pending tail never becomes completed merely because its bytes exist.
If the physical ACK is absent, fails, or its durable proof cannot be established
after restart, the state remains `IN_DOUBT` and cannot re-authorize or repeat the
effect. The bounded evidence sink can record an acknowledgement marker after a
successful live-call ACK, but that does not close the production distributed
atomicity question: production still requires an admitted watchdog whose ACK is
itself durable, queryable and idempotent under independent custody.

A still-redeemable permit is never returned over wire or Python. Compile-time
restriction comes from a non-`Clone` private type whose only adapter method consumes
`self`; runtime negatives cover duplicate call, reconstructed public wire
context, permit-ID or permit-digest transplant, stale prefix, alternate
provider/path/namespace, restart, race and deadline equality.

## Proposed choices awaiting bounded approval

- ML-DSA as the production signing algorithm and the allowed HSM/TPM class;
- trust-role topology, registry format and semantic-provenance policy;
- one global replay namespace and its identity derivation;
- the watchdog narrowing, ACK and terminal-state protocol;
- the adapter/receipt atomicity model; and
- Windows-specific fixed-object IV&V/IVVF as the validation approach.

## Explicit external physical dependencies

- real non-exportable hardware signing custody and independent attestation for
  whichever cryptographic profile is selected;
- authentic source credentials, trust roots and independently governed role
  keys;
- a rollback-resistant global replay/consumption store and trusted time;
- an independently controlled inhibit/interlock and fail-closed watchdog;
- a real atomic live adapter, durable watchdog acknowledgement and external
  append-only audit custody; and
- an actual independent assessment organisation and reproducible fixed subject.

Evidence fixtures may exercise this shape only under a compile-time test class.
Their keys, custody status, replay store and outputs are structurally
nonproduction and programme consumers reject them. They cannot close any OPEN
physical dependency.
