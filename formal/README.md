# SBP-LEX minimal authority protocol model

This directory is a bounded, design-level safety model for a proposed minimal
authority/effect protocol. It is intentionally separate from the existing
runtime. Nothing here enables a live effect, changes production code, or
establishes production assurance.

## Scope

The modeled successful path is:

1. two post-Aurion observations converge exactly on one request/state/effect/
   adapter binding;
2. a convergence proof is certified;
3. `PREPARE` retains that proof but grants no authority;
4. for an effect classified in `HighestConsequenceEffects`, an abstract
   production-custody/HSM attestation and a separately controlled,
   independently observed SafetyInhibit `CLEAR` state are acquired;
5. the sole `COMMIT` consumes the matching proof and previously unconsumed
   `PREPARE`, and is the only transition that can activate authority. For a
   highest-consequence binding it also revalidates production custody, HSM
   availability/freshness, and the SafetyInhibit's independence, freshness,
   and exact request/state/effect/adapter binding;
6. `COMMIT` can issue one short-lived lease bound to the exact effect and
   adapter;
7. the lease is redeemed once at the point of use, with the same mandatory
   highest-consequence controls revalidated at redemption;
8. an adapter-local safety-envelope interlock independently narrows or blocks
   the requested effect;
9. a separate final-effect-permit transition revalidates those production
   controls again immediately before a highest-consequence effect;
10. an effect can occur only with matching commit, lease, redemption,
    interlock, and, where mandatory, final-effect-permit bindings; and
11. continuation requires a timely, exact, abstractly signature-valid effect
   receipt strictly before both lease expiry and the watchdog deadline. The
   watchdog timeout can bound a later fail-closed STOP, but never extends
   successful authority. A missing, late, duplicated, invalid, or mismatched
   receipt fails closed through the watchdog path.

Production custody and SafetyInhibit observations are conjunctive safety
preconditions. They cannot activate authority, mint a different binding, widen
the committed effect, or replace the sole `COMMIT`. A SafetyInhibit `BLOCK` or
`STOP` can only fail the traversal closed.

The transition system also explicitly explores divergent convergence,
PREPARE/COMMIT/redemption replay, proof/PREPARE/lease expiry, binding mutation,
adapter mismatch, effect mismatch, an unsafe envelope, an effect attempted
without the required lease/interlock, and receipt/watchdog failures. Rejected
inputs are recorded and block the traversal; they are not installed into the
trusted binding state.

Highest-consequence negatives additionally cover fixture custody,
non-production custody, an unavailable or stale HSM observation, SafetyInhibit
`BLOCK`, `STOP`, unavailable, stale, mismatched-binding, or non-independent
states, and a generic attempt to cross a mandatory checkpoint without both
required production controls. These failures revoke active authority/lease use
where present and prevent continuation.

Every freshness and expiry window is canonical half-open time:
`[observed_or_issued_at, expires_at)`. Equality with proof, PREPARE, lease,
HSM, SafetyInhibit, or watchdog expiry is expired and cannot authorize COMMIT,
redemption, an effect, or receipt acceptance. Both executable models retain the
relevant event times in state and check `HalfOpenExpiryNeverAuthorizes`; the
Python explorer additionally emits equality-boundary fail-closed witnesses for
all seven boundary classes, including the distinct case where lease expiry
blocks receipt acceptance after an effect has occurred.

## Files

- `SBPLexAuthority.tla` is the TLA+ transition system and invariant set.
- `SBPLexAuthority.cfg` is a finite TLC configuration with one traversal, eight
  extension-qualified bindings (four base request/state/effect/adapter bindings
  crossed with two extension-binding values), two permitted time units per freshness
  window (including HSM and SafetyInhibit observations), one configured
  highest-consequence effect, and a six-unit clock bound.
- `check_model.py` is an independently executable, standard-library-only
  breadth-first state explorer. It does not invoke or parse TLA+; it mirrors
  the transitions and invariants so the bounded model can be checked where TLC
  is unavailable.

The TLA+ representation uses one tagged record shape for both present and
absent bindings. Real bindings have `present = TRUE`; `NoBinding` has
`present = FALSE` while retaining request/state/effect/adapter fields from the
same finite domains. This avoids heterogeneous string/record equality and
fingerprinting in TLC. Python's `None` is the corresponding explorer sentinel.

The Python checker emits a single JSON document to standard output and returns
zero only when all invariants and exploration-coverage checks pass:

```powershell
python formal\check_model.py
```

Optional bounds are visible with:

```powershell
python formal\check_model.py --help
```

Increasing `--traversals`, time, or depth can expand the state space sharply.
The default depth is sufficient to close the default bounded graph; the JSON
field `exploration.frontier_truncated` must be `false` for that claim.

The repository-local, publisher-checksum-verified Microsoft OpenJDK 21.0.12.1+1
and stable TLA+ tools v1.7.4 run the declarative model from the repository root
with:

```powershell
$portableJava = Resolve-Path `
  runtime_artifacts\toolchains\microsoft-jdk-21-portable\jdk-21.0.12.1+1\bin
$env:Path = $portableJava.Path + ';' + $env:Path
java -Xmx4g -cp runtime_artifacts\toolchains\tla2tools-v1.7.4.jar tlc2.TLC `
  -workers auto -config formal\SBPLexAuthority.cfg `
  formal\SBPLexAuthority.tla
```

`FailClosedStutter` makes the intentional all-traversals-blocked terminal state
explicit to TLC's default deadlock checker. It changes no variable, authority,
binding, invariant, or bound. The Python graph closes blocked terminals without
counting this temporal self-loop.

For the current extension-bound default configuration, the Python explorer
reports 198,651 states, 319,466 enumerated transitions, maximum depth 20, and an
untruncated frontier. It passes all 18 configured safety invariants, including
`ExtensionAdmissionDisabledAndCarried`.

On 24 August 2026, a complete repository-local TLC run of this configuration
generated 674,713 states, found 198,651 distinct states, left zero queued,
reached depth 21, and reported no error. The Python explorer independently
enumerated the same 198,651 distinct states, 319,466 transitions, and a maximum
depth of 20 with an untruncated frontier and all 18 invariants true. These are
mutable, non-independent implementation/model results, not proof of model-to-code
equivalence or production behavior. Exact tool and source hashes are recorded in
`evidence/v2/tla-model-evidence.json`.

## Safety properties

Both executable representations check these properties:

| Property | Meaning |
| --- | --- |
| `ProofCertifiesExactConvergence` | A proof exists only for equal A/B bindings. |
| `PrepareIsNonAuthorizing` / `NoAuthorityBeforeCommit` | PREPARE cannot authorize; active authority implies a COMMIT. |
| `CommitRequiresMatchingUnconsumedPrepare` | Every recorded COMMIT came from the exact retained proof and a PREPARE that was unconsumed at the COMMIT transition; both become consumed. |
| `AtMostOneCommitAndRedemptionPerTraversal` | Commit, redemption, and effect counters never exceed one for a traversal. |
| `NoEffectWithoutMatchingLeaseAndInterlock` | An effect requires an unexpired, exact commit/lease/redemption/interlock chain and an allowed safety envelope. |
| `ExtensionAdmissionDisabledAndCarried` | Every modeled carrier has the exact disabled mode/schema/configuration and its distinct binding is unchanged from convergence through COMMIT, effect, and receipt. |
| `HighestConsequenceCommitRequiresProductionControls` | A highest-consequence COMMIT records fresh production-HSM and exact independent-SafetyInhibit checks. |
| `HighestConsequenceRedemptionRequiresProductionControls` | Point-of-use redemption repeats and records those fresh, exact checks. |
| `HighestConsequenceEffectRequiresFinalPermit` | The effect requires a final permit bound to the same effect and backed by fresh HSM/SafetyInhibit observations. |
| `HalfOpenExpiryNeverAuthorizes` | Retained transition times prove COMMIT, redemption, effect, and receipt occurred strictly before every applicable expiry; equality is never valid. |
| `IndependentControlsCannotGrantOrWidenAuthority` | Only sole COMMIT originates authority, and control/permit bindings cannot differ from the committed binding. |
| `ProductionControlFailureIsFailClosed` | Any modeled custody, HSM, or SafetyInhibit failure blocks the traversal, revokes authority/lease use, and prevents continuation. |
| `WatchdogFailureBlocksContinuation` | A watchdog failure blocks the traversal, revokes authority/lease use, and prevents continuation. |

The model additionally checks exact convergence before PREPARE, that
continuation has an exact accepted receipt, and that every fail-closed state
disables active authority and continuation.

## Assumptions and limits

- This is finite-state safety checking, not an unbounded proof and not a
  liveness or availability proof. The supplied TLC configuration and default
  Python run use one traversal and finite time/value sets.
- Equality of a binding abstracts canonical serialization and digest equality.
  Collision resistance, parser agreement, and canonicalization are assumed,
  not proved.
- Successful proof, capability, lease, custody attestation, SafetyInhibit
  observation, and receipt validation abstracts ideal signature verification,
  admitted identities, immutable key policy, authentic channels, and an
  independently controlled inhibit. Cryptographic algorithms, actual HSM/TPM
  provisioning and non-exportability, rotation, compromise, physical wiring,
  independent organizational custody, and side channels are not proved.
- Durable global single-use storage, atomic compare-and-consume behavior,
  crash consistency, rollback resistance, and cross-node consensus are
  represented as atomic transitions. Their implementations are not proved.
- `clock` is an abstract bounded monotonic clock. Clock rollback, drift, leap,
  and distributed-clock reconciliation are not modeled.
- `SafeEffects` abstracts a correctly specified, independently implemented
  adapter-local envelope. The completeness of a real physical or service
  safety envelope is not established here.
- A rejected mutation transition represents detection of altered submitted
  binding material before trusted state changes. Memory corruption and trusted
  process compromise are outside the model.
- The accepted receipt transition represents a valid independent signature
  check. The watchdog can block future continuation and command fail-closed
  behavior, but no software model can undo an already completed irreversible
  effect.
- The SafetyInhibit protocol state and its exact/fresh checkpoint checks are
  modeled. A real separately controlled hardware/service inhibit, its physical
  stop effectiveness, availability, tamper resistance, and independence remain
  external deployment requirements. Software cannot turn a modeled `STOP`
  into evidence that a physical effect was stopped.
- The Python explorer is useful diversity against TLC availability, but both
  artifacts were derived from the same protocol description. Agreement is not
  evidence of implementation conformance or independent certification.

## Assurance status

These artifacts make **no production claim**. A passing bounded run means only
that no listed invariant violation was found inside the declared abstraction
and bounds. It does not validate the existing Python runtime, provide a Rust or
SPARK trusted core, provision real cryptographic custody, verify an adapter,
install a safety inhibit, or authorize any live deployment or effect.
