# Trusted authority core (Rust)

This directory is an isolated, dependency-free Rust reference core for the final
authority path. It is intentionally small: orchestration, UI, evidence gathering,
serialization, network transport, cryptography, clocks, durable storage, and device
drivers stay outside the trusted core.

This is not a claim of formal verification, certification, cryptographic assurance,
or production readiness. Production use requires an independent security review,
threat model, protocol model, fault-injection testing, and validation of every
external implementation behind the traits.

## What the core enforces

The public typestates form one forward-only authorization path:

```text
Candidate
  -> exact Converged
  -> Prepared (signed, expiring, explicitly non-authorizing)
  -> Committed (the sole capability-producing transition)
  -> AwaitingReceipt (one short-lived adapter/effect-bound lease)
       + adapter reconstructs untrusted lease
       + final effect-side custody + inhibit + signature + exact watchdog-arm
         + replay checks
       -> synchronous atomic adapter consumption (no reusable permit returned)
  -> Completed
                     \
                      -> Stopped (deadline or unsafe watchdog)
```

The implementation enforces:

- exact equality of intended, independently observed, and policy-approved bindings;
- binding of domain, epoch, operation, subject, state, policy, configuration,
  a distinct extension-admission binding, adapter, effect, and safety-envelope
  digests;
- a PREPARE token that expires, authorizes no effect, and can be committed once;
- one domain-separated COMMIT signature as the only capability issuer;
- atomic durable replay claims for PREPARE, capability redemption, and receipts;
- a fresh safety-interlock decision at COMMIT and again at point of use;
- fresh class-matched custody status for the same signing/verifying provider at
  PREPARE, COMMIT, lease redemption, final effect authorization, and receipt
  verification;
- exact authority-class custody: HSM artifacts require HSM status, TPM
  artifacts require TPM status, and evidence fixtures can create only
  structurally nonproduction evidence-class artifacts;
- a mandatory, separately controlled out-of-band inhibit check at COMMIT, lease
  redemption, and the final effect boundary;
- a capability consumed at point of use into one short-lived adapter/effect lease;
- a lease consumed once through a scoped `EffectDispatch` that cannot escape the
  synchronous `AtomicEffectAdapter::consume_once` call in safe Rust;
- watchdog arming before the lease signature is emitted;
- revalidation of that exact persisted watchdog arm immediately before effect
  consumption, rather than accepting general watchdog health alone;
- exact, signed adapter receipts whose claimed completion occurred within the
  lease and whose validation/ACK occurs strictly before the minimum applicable
  lease, point-of-use permit, and watchdog deadlines;
- watchdog trip on invalid, late, mismatched, replayed, or unacknowledgeable receipts;
- immediate watchdog trip when the durable effect slot has been claimed but the
  adapter fails, its post-effect clock is unavailable, or completion falls
  outside the half-open lease interval;
- a later receipt/watchdog grace deadline may bound when the independent STOP is
  asserted after lost delivery, but never extends successful effect authority:
  a receipt at or after lease/permit expiry is rejected and cannot ACK the
  watchdog even when the watchdog timeout itself has not elapsed;
- rejection at expiration boundaries (`now >= expires_at`) and of clock rollback;
- signature-purpose separation for PREPARE, capability, lease, and receipt artifacts.

Rust ownership makes normal duplicate or out-of-order use unavailable through the
safe API: transitions consume the previous state, and only `Committed` has the
point-of-use redemption method. Durable replay claims remain mandatory because
process restart, multiple replicas, restored snapshots, or an FFI bridge can recreate
logical inputs outside Rust's ownership model.

## External production boundaries

`ExternalSignatureProvider` is the only signing/verification boundary. A production
implementation must call an audited provider backed by real HSM/TPM or equivalently
protected remote custody. Private keys must never enter this crate. Key-purpose policy
must keep the authority signing key and adapter receipt key distinct. The provider
must reject unsupported algorithms, invalid encodings, wrong key versions, and
non-canonical signatures as applicable.

The same provider value used for authorizing signing/verification must also implement
`KeyCustodyProvider`. Production classes accept only
`KeyCustodyStatus::ProductionNonExportable` carrying the expected key identity,
the exact class-matched HSM/TPM technology, and a status interval fresh at the
decision time. Evidence class accepts only `NonproductionFixture`; that status
cannot satisfy either production class.
The reported custody-provider identity must exactly match the non-zero identity pinned
in `CorePolicy` separately for the authority and adapter keys.
Wrong-class, `NonProduction`, `Unavailable`, stale, future-dated, mismatched, and provider-error
statuses fail closed. `NonExportableProductionKeyIdentity` is a provider contract,
not physical or cryptographic evidence: the production provider must independently
validate hardware attestation, lifecycle state, non-exportability, and purpose policy.
The unit-test production-status facade explicitly supplies no such evidence.

`ReplayProtector::claim_once` must be linearizable across all authority replicas and
durable across crashes. This core requests `Time::MAX` retention: an identifier is
permanently spent within its authority epoch. If production storage cannot satisfy
that contract, epoch lifecycle and archival need a separately reviewed protocol;
silently expiring claims is unsafe.

`SafetyEnvelopeInterlock` must be independently administered and fail closed. Its
permit must be bound to the exact safety-envelope digest and cover the requested
validity interval. The point-of-use decision must reflect current physical/service
conditions, not a cached COMMIT decision.

`SafetyInhibit` is an additional, separately controlled out-of-band veto. It is
mandatory at COMMIT, authority-side lease redemption, and adapter-side effect
authorization. There is no default or bypass implementation in this crate. Its output
can only echo an exact, fresh permit for the already-bound request, BLOCK it, or demand
STOP; it cannot change a binding, mint a capability, increase a TTL, or widen authority.
Unavailability, stale/future status, mismatched echoes, BLOCK, and STOP all fail closed.
This interface does not itself prove physical independence—the deployment must provide
and assess that independence.

`FailClosedWatchdog` must control the consequential stop from separate hardware or
service custody. `arm` must durably install the deadline before returning. Once armed,
authority process death, network partition, or missing acknowledgement must still
cause the stop without another call into this crate. `poll_watchdog` is supplementary,
not the enforcement mechanism. `verify_armed` must query the separately controlled
durable arm at the final point of use and match the exact binding, capability, lease
and deadlines. A missing, substituted, acknowledged, expired or rolled-back arm must
fail closed.

`Time` must come from a trusted, rollback-resistant source. Identifiers must come from
a CSPRNG or a collision-resistant allocation service and must be globally unique for
the authority epoch. The core rejects all-zero IDs and obvious reuse between adjacent
artifact types, but it cannot manufacture entropy.

The `Digest` values are opaque fixed bytes here. The system specification must define
one canonical representation and one approved collision-resistant digest algorithm
for state, policy, configuration, and safety-envelope inputs. That computation should
be independently testable.

## FFI and IPC integration boundary

Do not export Rust structs directly as a C ABI. They contain Rust-owned vectors and
have no stable layout. Put a small reviewed adapter outside this crate that:

1. decodes a versioned, length-bounded wire schema into the typed constructors;
2. rejects unknown fields, duplicate fields, non-canonical encodings, oversized
   signatures, zero IDs, and trailing data;
3. maps all dependency exceptions/timeouts to `ExternalFailure` and fails closed;
4. preserves the typestate object inside one authority process, exposing opaque
   handles rather than caller-selected phase labels;
5. authenticates the caller and protects transport integrity independently;
6. never treats `PrepareToken` as an authorization response;
7. sends `EffectLease` only to the adapter named in its exact `Binding`;
8. has the adapter reconstruct the untrusted fixed-width `LeaseClaims` and signature,
   then call `EffectLease::dispatch_effect_at_point_of_use` immediately before the
   effect; this verifies exact binding, time, signature purpose, fresh production
   custody, fresh out-of-band inhibit status, the exact persisted watchdog arm, and
   durable one-time lease redemption before a synchronous adapter call;
9. reconstructs incoming signatures only with `ProviderSignature::new` and receipts
   only with `SignedAdapterReceipt::from_untrusted_parts`, then calls
   `accept_receipt` for authoritative validation.

The effect adapter receives only a lifetime-scoped `EffectDispatch` inside
`AtomicEffectAdapter::consume_once`; it cannot receive or retain a reusable permit.
It must stop or decline when lease verification, time, production custody, inhibit,
watchdog arm, local safety, or receipt delivery cannot be completed. A Python layer may
orchestrate this boundary, but it must not be able to mint artifacts, bypass replay
claims, acknowledge the watchdog, or directly invoke the consequential effect.

### Canonical signing messages

The external signer receives an un-hashed canonical byte sequence. If the provider
requires pre-hashing, that operation and algorithm belong to the provider policy.
Every message starts with:

```text
ASCII "trusted-authority-core"
u16 big-endian canonical version (= 1)
u8 signature purpose
```

Operation and internal PREPARE/capability/lease IDs are fixed 16-byte values.
Domain, subject, adapter, effect and key identities are full 32-byte values so
wire-v2 SHA-512 identities are never truncated. Digests are fixed 64-byte values,
times and the authority epoch are unsigned 64-bit big-endian integers, and
`EffectOutcome` is one byte. There are no variable-length claim fields. Field order
is the order used in `src/artifacts.rs`. Any independent verifier should implement
this specification separately and be tested with cross-implementation conformance
vectors; copying the authority encoder does not provide implementation independence.

## Verification

The crate has no external dependencies and is intended to build offline:

```powershell
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
```

The unit-test signer is deliberately named
`NonProductionDeterministicSignatureFixture`. It is a public-input checksum-like test
double with **no cryptographic assurance**. It exists only to test state transitions,
purpose separation, and failure handling. It must never be copied into production or
used as evidence about cryptographic strength. Production authorization explicitly
rejects its `NonproductionFixture` custody status; it can exercise only the
evidence-class typestate. A separately named test-only facade exercises exact
class-matched HSM/TPM status branches, but still delegates to that nonproduction
signer and provides no HSM/TPM attestation, cryptographic assurance, or physical
evidence.

Recommended production gates include `cargo fmt --check`, pinned Rust toolchains,
reproducible builds, dependency-policy enforcement (the dependency list should remain
empty unless explicitly reviewed), fuzzing of the external decoder, model checking of
the protocol, fault injection for every external call boundary, HSM/interlock/watchdog
integration tests, and an independently implemented lease verifier.
