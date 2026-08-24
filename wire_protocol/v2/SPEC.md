# SBP-LEX Authority Evidence Wire Protocol v2

Status: authority-capable integration contract when, and only when, every
signature is independently verified against an externally pinned trust root and
admitted role registry. This specification grants no production authority.

The v1/F084 contract remains preserved as transport-only provenance. Its opaque,
unsigned convergence request must never drive convergence, PREPARE, COMMIT or an
effect. V2 supersedes it for authority-bearing integration.

## Frame and canonical JSON

Each frame is a four-byte unsigned big-endian length followed by exactly that many
payload bytes. Payload length is `1..32768`. A single-frame decoder rejects
truncation and trailing bytes.

The payload is one flat canonical JSON object:

- strict UTF-8, no BOM and printable ASCII content only;
- ASCII keys sorted lexicographically, no whitespace and no JSON escapes;
- duplicate, unknown and missing keys rejected;
- strings only, except `sequence`, nonzero `authority_epoch` and fields ending `_ms`, which are canonical
  unsigned integers in `0..9007199254740991`;
- no floats, signs, leading zeroes, booleans, null, arrays or nested objects;
- decode then encode must reproduce the exact bytes.

There is no pickle, dynamic import, reflection, generic object hook or executable
payload.

## Immutable execution binding

Every message binds the following exact values:

- `protocol=SBP-LEX-AUTH-WIRE/2` and the approved oracle SHA-512;
- runtime subject, runtime tree, authority build/profile/class and owner-admitted
  nonzero authority epoch;
- trust-root and admitted-registry digests;
- traversal, operation, frozen mode and challenge;
- explicit domain and subject digests plus request, state, effect, effect-intent,
  adapter and adapter-boundary digests;
- inhibit, interlock, audit-anchor, replay-namespace and durable-consumption
  digests;
- common not-before and expiry bounds.

`stable_request_digest` identifies the request semantics after removing fresh
transport/artifact metadata. It is not caller-selected: the consumer must first
derive it from the canonical request digest, then derive the effect and replay
identities:

```
stable_request_digest = SHA-512(
  "SBP-LEX-AUTH-WIRE/2\0STABLE-REQUEST\0" || request_digest
)
stable_effect_intent_digest = SHA-512(
  "SBP-LEX-AUTH-WIRE/2\0STABLE-EFFECT-INTENT\0" ||
  stable_request || effect_intent || effect || adapter || adapter_boundary
)
durable_consumption_digest = SHA-512(
  "SBP-LEX-AUTH-WIRE/2\0DURABLE-CONSUMPTION\0" ||
  replay_namespace || stable_effect_intent_digest
)
```

Traversal IDs, challenges and nonces are deliberately not
inputs, so refreshing envelope metadata cannot select a fresh replay identity.

The canonical durable replay key is the pair
`(authority_epoch, durable_consumption_digest)`. The epoch is a nonzero u53
integer pinned by the owner admission policy and signed in every message. It may
not be selected by the caller. Epoch rollover requires a new owner admission and
must carry forward/tombstone all consumed durable identities; an epoch may never
be reused or rolled back. Changing epoch, domain or subject while retaining the
same admission policy is rejection.

These values cannot change within a transcript. Every message also has a unique
nonce, monotonic `message_time_ms`, exact sequence, previous transcript digest,
kind, signer role/class/key, public key, algorithm and signature.

## Signatures and admitted roles

Permitted signer roles are `BRANCH_A`, `BRANCH_B`, `VALIDATOR`, `SINGLE_STATE`,
`WITNESS`, `COORDINATOR`, `AUTHORITY`, `ADAPTER` and `WATCHDOG`. Every message is
signed. Each role maps to exactly one admitted key ID, key class and public key in
the externally supplied role registry. The message registry digest must equal the
canonical registry digest, and its trust-root digest must equal an externally
pinned owner root.

`signer_key_id = SHA-512(public-key-bytes)`. Key classes are `TEST_FIXTURE`,
`PRODUCTION_HSM` and `PRODUCTION_TPM`. Algorithms are `TEST-SHA512`, `ML-DSA-65`
and `ML-DSA-87`; `TEST-SHA512` is accepted only with `TEST_ONLY` authority and
`TEST_FIXTURE` keys. Test signatures cannot be represented as production custody.

Remove `transcript_digest` and `signature_hex`, encode the remainder as canonical
bytes `M`, then calculate:

```
transcript_digest = SHA-512(
  "SBP-LEX-AUTH-WIRE/2" || 00 || "TRANSCRIPT" || 00 || kind || 00 || M
)

signature_input =
  "SBP-LEX-AUTH-WIRE/2" || 00 || "SIGNATURE" || 00 || kind || 00 ||
  transcript_digest_bytes
```

The validator must call its configured cryptographic verifier over that exact
input. A signature label or digest is never treated as verification.

The caller must additionally supply a fixed `AdmissionPolicy`: the exact owner
trust-root digest, registry digest, runtime subject/tree, authority class/profile/
build, mode, traversal/operation/challenge, replay namespace, stable request,
domain/subject/request/state/effect/effect-intent/adapter/adapter-boundary,
authority epoch, inhibit/interlock/
audit-anchor, exact disabled extension-admission mode/schema/configuration/binding,
and admitted semantic-provenance digests for A, B, Validator and the
Mode 3 implementation. Matching `TrustRegistry.root_digest` alone or deriving
this expected context from the incoming transcript is insufficient.

The only admitted extension carrier is `EXTENSIONS_DISABLED` with schema
`SBP_LEX_EXTENSION_ADMISSION_BINDING_V1_DISABLED`. The four mandatory fields
`extension_admission_mode`, `extension_schema`,
`extension_configuration_digest`, and
`extension_admission_binding_digest` are immutable common execution-context
fields. Required-mode values are rejected; omission and downgrade are rejected.
Legacy wire v1 is not admitted at any authority endpoint.

The authority/key/algorithm matrix is exact: `TEST_ONLY` uses only
`TEST_FIXTURE+TEST-SHA512`; `PRODUCTION_HSM` uses only
`PRODUCTION_HSM+ML-DSA-65/87`; and `PRODUCTION_TPM` uses only
`PRODUCTION_TPM+ML-DSA-65/87`. Mixed or downgraded combinations are rejected.

## Disclosed execution projection

Branch, validator and single-state statements disclose the exact fixed projection
fields rather than merely asserting an opaque projection digest:

- schema ID;
- request, state, effect and adapter digests;
- mode-freeze, policy, Domain, Aurion, provider-linkage, candidate, pathway,
  constraints, token-stack, audit-context and outcome digests.
- the exact four extension-admission fields from the independently pinned
  `AdmissionPolicy`.

The consumer recomputes `projection_digest` from those ordered fields using domain
`SBP-LEX-EXEC-PROJECTION/2`. The request/state/effect/adapter and four extension
components must equal the immutable transcript binding and owner-pinned policy.

## Mode-specific evidence prefix

### Mode 1

1. `mode1_release_request`, signed by admitted `COORDINATOR` and binding both
   worker/process checkpoints.
2. `mode1_release_result`, signed by sole `AUTHORITY` and binding the request,
   checkpoints and release instant.
3. `branch_a_statement`, signed by admitted `BRANCH_A`.
4. `branch_b_statement`, signed by admitted `BRANCH_B`.
5. `mode1_overlap_witness`, signed by an independent admitted `WITNESS` and
   binding the authority result.
6. `convergence_request`, signed by `COORDINATOR`.
7. `convergence_result`, signed by sole `AUTHORITY`.

The two statements carry exact disclosed projections, snapshot/code/callable
provenance, distinct worker IDs and substantive start/end times. Their projections
must be byte-for-byte identical. The witness binds both signed statement digests,
the exact worker/times and disclosed causal-rendezvous evidence: distinct process
digests, per-branch checkpoint commitments, the authority release commitment and
per-branch acknowledgements. Workers, processes, code/callable provenance and
role keys must be distinct and admitted. Each branch interval must be bounded by
its statement time; the witness must postdate both completions; the release must
not predate the signed release-request time, must not postdate the signed
release-result time, must precede both substantive starts, and intervals must
overlap (`max(start) < min(end)`). In particular, the authority-enforced causal
order is `release_request.message_time_ms <= rendezvous_released_at_ms <=
release_result.message_time_ms`. The witness's signed
`rendezvous_opened_at_ms` must exactly equal the signed release request's value,
and its signed `rendezvous_released_at_ms` must exactly equal the signed
authority result's value. That actual authority release value must be less than
or equal to the minimum signed branch `substantive_start_ms`. The witness must
also bind the exact request/result, branch-statement, release and acknowledgement
digests; digest equality does not permit timestamp substitution. An opaque or
self-asserted witness digest is insufficient.

A release refusal is not evidence that any release occurred. A DENY
`mode1_release_result` retains the request/checkpoint/opened-at bindings but must
carry the all-zero `rendezvous_release_digest` and numeric
`rendezvous_released_at_ms=0`; no branch statement may follow it.

### Mode 2

1. `branch_a_statement`, signed by admitted `BRANCH_A`.
2. `mode2_validator_certificate`, signed by independent admitted `VALIDATOR`.
3. `convergence_request`, signed by `COORDINATOR`.
4. `convergence_result`, signed by sole `AUTHORITY`.

The certificate binds the signed primary statement; validator code/provenance;
canonical input/output candidate and pathway sets; deterministic rejection
reasons for every removed element; and a disclosed admitted-output projection.
Sets are sorted unique comma-separated SHA-512 values. Both outputs must be
nonempty subsets of their inputs. Equality is valid non-widening and requires
`NONE` removals; every actual removal must have exactly one uppercase reason.
Strict reduction in either space is accepted only with its exact rejection map.
The primary candidate/pathway projection components must equal the input
set digests and the validator components must equal output set digests. This makes
admissibility reduction and no-widening consumer-recomputable.

### Mode 3

1. `mode3_single_state_proof`, signed by admitted `SINGLE_STATE`.
2. `convergence_request`, signed by `COORDINATOR`.
3. `convergence_result`, signed by sole `AUTHORITY`.

The proof carries the disclosed projection, state-seal digest and single-state
proof digest plus admitted callable and implementation-provenance digests. The
consumer derives the state seal from state, frozen mode, projection, traversal
and challenge, then derives the proof from that seal plus callable/provenance;
opaque assertions do not qualify. No B or validator evidence is permitted.

The convergence request references the already verified statement/certificate/
witness transcript digests. The authority produces ALLOW only after re-deriving
all projections, signatures, roles, intervals and set relations.

## Canonical admission and authenticated-convergence digests

`admission_policy_digest` is SHA-512 over domain
`SBP-LEX-AUTH-WIRE/2\0ADMISSION-POLICY\0` followed by canonical flat JSON of
every externally pinned `AdmissionPolicy` field, with keys sorted exactly as for
wire JSON. `authenticated_convergence_binding_digest` is SHA-512 over domain
`SBP-LEX-AUTH-WIRE/2\0AUTHENTICATED-CONVERGENCE\0`, protocol, oracle, projection
schema, admission-policy digest, trust-root digest, registry digest, the
four-byte big-endian prefix count, every independently verified prefix
transcript digest in order, the derived convergence digest and derived
projection digest. This full 64-byte SHA-512 binding is the normative input
when another trusted core needs a compact subordinate identifier; no field may
be silently truncated or reordered. The earlier 32-byte wording was
inconsistent with the authoritative SHA-512 schema and both active
implementations; it did not authorize truncation.

## Staged authority validation

The completed-transcript validator is an audit function. A live authority must
also validate each request prefix *before* constructing or signing its result.
Both implementations expose an opaque, non-serializable verified stage context
for these exact boundaries:

- Mode-1 release request -> authority release result;
- convergence request -> authority convergence result;
- PREPARE request -> non-authorizing result;
- COMMIT request -> sole-authority result;
- lease redemption, watchdog arm and effect-permit requests -> their results;
- effect receipt -> receipt acknowledgement;
- watchdog terminal -> final watchdog result.

The context binds the admission-policy digest, authenticated-convergence binding,
all verified prefix transcript digests, request/chain tip and values derived by
the validator. It cannot itself be encoded as a wire capability. The public wire
API contains no signer callback or generic dispatch. A service-private,
stage-specific authority implementation may sign only after context creation,
then must pass the signed result through `validate_and_append_result`, including
exact kind, sequence, chain, signature, trusted time, stage-derived fields and
artifact semantics. Every completed historical result is revalidated from
untrusted bytes before the next request. Successful authority artifacts are
deterministic semantic commitments rather than arbitrary nonzero labels. For
stage `S`, the semantic digest is `SHA-512(stage-domain || canonical-json(C))`,
where `C` binds the verified stage-context digest, admission-policy digest,
authenticated-convergence digest, exact request transcript digest and handoff
fields, authority class/profile/build/epoch/key ID, fresh authority nonce and
result time, plus the permit deadline for the permit stage. The stage domains
are `PREPARE-PROOF`, `EXECUTION-CAPABILITY`, `EXECUTION-LEASE`, `WATCHDOG-ARM`
and `EFFECT-PERMIT` beneath `SBP-LEX-AUTH-WIRE/2\0...\0`. Python and Rust expose
the same `authority_artifact_digest` calculation and audit replay re-derives it.

The canonical JSON object `C` has these exact common keys:
`admission_policy_digest`, `authenticated_convergence_binding_digest`,
`authority_build_id`, `authority_class`, `authority_epoch`,
`authority_profile`, `context_digest`, `message_time_ms`, `nonce`,
`request_transcript_digest`, `signer_key_id`, and `stage`. `stage` is the exact
request-kind token. It additionally has these exact stage-specific keys:

- `prepare_request`: `request_convergence_digest`;
- `commit_request`: `request_prepare_id`, `request_prepare_proof_digest`;
- `lease_redeem_request`: `request_capability_digest`,
  `request_capability_id`, `request_lease_deadline_ms`;
- `watchdog_arm_request`: `request_lease_digest`, `request_lease_id`,
  `request_watchdog_deadline_ms`;
- `effect_permit_request`: `request_lease_deadline_ms`,
  `request_lease_digest`, `request_lease_id`, `request_point_of_use_digest`,
  `request_watchdog_deadline_ms`, `request_watchdog_digest`, and
  `result_permit_deadline_ms`.

No other key is present. The JSON is encoded by the canonical rules above, so
lexicographic key order is deterministic. The exact five domain byte strings are
`SBP-LEX-AUTH-WIRE/2\0PREPARE-PROOF\0`,
`SBP-LEX-AUTH-WIRE/2\0EXECUTION-CAPABILITY\0`,
`SBP-LEX-AUTH-WIRE/2\0EXECUTION-LEASE\0`,
`SBP-LEX-AUTH-WIRE/2\0WATCHDOG-ARM\0`, and
`SBP-LEX-AUTH-WIRE/2\0EFFECT-PERMIT\0`.

PREPARE, capability, lease and permit also carry exact 16-byte lowercase IDs:

```
artifact_id = first_16_bytes(SHA-512(
  "SBP-LEX-AUTH-WIRE/2\0ARTIFACT-ID\0" || stage || 00 || artifact_digest_bytes
))
```

The ID is subordinate to the full semantic digest; it never replaces the
durable replay key. Each request carries the preceding result's exact ID and
digest. A denied stage carries the all-zero semantic digest and all-zero ID.
Arbitrary nonzero IDs, consistent handoff transplants and nonzero denial IDs are
rejected. A later DENY or BLOCK cannot mask an invalid earlier result.

## Authority and effect lifecycle

After the mode prefix, the exact lifecycle is:

1. `prepare_request` (`COORDINATOR`) and `prepare_result` (`AUTHORITY`);
2. `commit_request` (`COORDINATOR`) and `commit_result` (`AUTHORITY`);
3. `lease_redeem_request` (`ADAPTER`) and result (`AUTHORITY`);
4. `watchdog_arm_request` (`COORDINATOR`) and result (`WATCHDOG`);
5. `effect_permit_request` (`ADAPTER`) and result (`AUTHORITY`);
6. either:
   - receipt path: signed adapter `effect_receipt`, authority `receipt_ack`, signed
     `watchdog_terminal`, authority `watchdog_result`; or
   - no-receipt path: signed STOP/TIMEOUT `watchdog_terminal`, followed by
     authority `watchdog_result=BLOCK`.

PREPARE is non-authorizing. COMMIT alone creates authority. Every message time
must be no later than the externally supplied trusted current time. Lease and permit
deadlines are half-open and linked: equality with a lease, watchdog or permit
deadline is expired. The admitted adapter atomically consumes the bound permit
before the effect and reports the durable consumption digest and consumption
time strictly before the half-open completion bound
`min(lease_deadline, permit_deadline, watchdog_deadline)`. Every present receipt,
receipt ACK, watchdog terminal and watchdog result must occur strictly before
that same three-way bound. This strict-before rule applies to the receipt-present
path. On the no-receipt path, the same three-way minimum is the effective
authority deadline. A signed `TIMEOUT` terminal must be timestamped exactly at
that deadline. A signed `STOP` may trip early, from the permit-result time through
that deadline inclusive. Neither status may be reported after it. The following
non-authorizing `watchdog_result=BLOCK` must be timestamped no earlier than the
terminal and no later than 1,000 ms after it. This bounded record cannot revive
or extend an expired permit, lease or authority. `adapter_consumption_digest`
is recomputed over the durable
consumption identity, permit, effect, adapter, consumption time and outcome. A
successful receipt requires healthy watchdog and `ACK`.
Failed or unknown effects require an explicit non-authorizing `FAILURE_ACK`, then
STOP/BLOCK. A missing receipt becomes
STOP/TIMEOUT/BLOCK. Any DENY/BLOCK ends the transcript.

`effect_receipt.receipt_digest` is not an adapter-selected label. For every
present success, failure or unknown-outcome receipt it is the nonzero SHA-512 of
domain `SBP-LEX-AUTH-WIRE/2\0EFFECT-RECEIPT\0` followed by canonical JSON binding
authority epoch, domain/subject/operation, request/stable-request/state, effect/
effect-intent/stable-effect, adapter/boundary, inhibit/interlock/audit anchor,
durable consumption, adapter-consumption digest/time/outcome, and the exact
permit ID/digest plus watchdog digest. The validator re-derives it. The all-zero
receipt digest is reserved exclusively for a no-receipt STOP/TIMEOUT path.

The receipt canonical JSON contains exactly the string keys
`adapter_boundary_digest`, `adapter_consumption_digest`, `adapter_digest`,
`audit_anchor_digest`, `domain_digest`, `durable_consumption_digest`,
`effect_digest`, `effect_intent_digest`, `effect_outcome`,
`inhibit_binding_digest`, `interlock_digest`, `operation_id`, `permit_digest`,
`permit_id`, `request_digest`, `stable_effect_intent_digest`,
`stable_request_digest`, `state_digest`, `subject_digest`, `watchdog_digest`,
plus integer keys `adapter_consumed_at_ms` and `authority_epoch`; no transport
nonce, message time or transcript digest is part of this stable semantic receipt.

The exact permit ID and full permit digest are carried from the permit result
through the private atomic adapter context, any effect receipt, success or
failure receipt ACK, watchdog terminal and final watchdog result. Tail-local
agreement is insufficient: every value must equal the originating permit result.

`point_of_use_digest` is never an opaque adapter assertion. It is SHA-512 over
domain `SBP-LEX-AUTH-WIRE/2\0POINT-OF-USE\0` followed by canonical flat JSON of
the exact authority class/profile/build/epoch, domain/subject, traversal/
operation, replay namespace, request/stable-request/state/effect/effect-intent/
stable-effect, adapter/boundary, durable-consumption, inhibit/interlock/audit,
lease/watchdog digests and lease/watchdog deadlines carried by the permit
request. The validator recomputes it at request authentication and again at
atomic point of use. A caller-selected value or any linked-field mutation is
rejection.

The permit result is an internal point-of-use artifact. A synchronous Rust
authority/adapter boundary must keep it buffered between permit creation and
atomic adapter consumption; it is not a reusable capability to stream back to
Python. It becomes externally visible only as post-consumption audit evidence
with its durable claim and receipt.

## Fail-closed rule

Parsing success alone has no authority. Missing evidence, a registry/root
mismatch, unverified or cross-role signature, invented equal projections, same
role/key A/B, non-overlap, invalid reduction, stale time, binding mutation,
replay, order/linkage error or incomplete tail is rejection.

A later terminal DENY/BLOCK cannot sanitize an earlier inconsistent successful
transition. Every present PREPARE/COMMIT/lease/watchdog/permit link and deadline
is validated before accepting a terminal denial transcript.
