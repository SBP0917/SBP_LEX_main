# V2 impersonation-protection deployment contract

## Status

The impersonation-protection component is integrated into the canonical V2
library traversal between authority-boundary admission and Australian-minor
access. The repository provides concrete durable boundary implementations, but
does not self-admit a production deployment, physical key custody, or an
independently operated trusted-time source.

## Required production pins

The process must set these values before importing
`sbp_lex.identity.impersonation_protection`:

- `SBP_LEX_IMPERSONATION_RUNTIME_MODE=PRODUCTION`
- `SBP_LEX_IMPERSONATION_CONTEXT_ID`
- `SBP_LEX_IMPERSONATION_CONTEXT_DIGEST` (SHA-512)
- `SBP_LEX_IMPERSONATION_OWNER_HYBRID_CONTEXT_DIGEST` (SHA-512)
- `SBP_LEX_IMPERSONATION_REGISTRY_ADMISSION_DIGEST` (SHA-512)
- `SBP_LEX_IMPERSONATION_REPLAY_ADMISSION_DIGEST` (SHA-512)
- `SBP_LEX_IMPERSONATION_TRUSTED_CLOCK_ADMISSION_DIGEST` (SHA-512)
- `SBP_LEX_IMPERSONATION_CLOCK_HEAD_ADMISSION_DIGEST` (SHA-512)

Missing, malformed, substituted, or late-installed pins fail closed. The
production composition must then call
`install_production_impersonation_composition_boundary` exactly once before an
`ImpersonationTrustContext` is constructed or injected into
`FoundationalRequestDependencies`.

## Repository-local durable providers

`sbp_lex.identity` exports:

- `SQLiteOwnerPinnedTrustRegistry`
- `SQLiteImpersonationReplayGuard`
- `AuthenticatedMonotonicClock`
- `SQLiteImpersonationClockHead`

Each SQLite provider uses WAL, `synchronous=FULL`, foreign-key enforcement and
atomic `BEGIN IMMEDIATE` mutation. Store identity is pinned to the context,
signer and role. Each mutation advances a separately persisted signed anchor;
startup and every operation revalidate the database state against that anchor.
Security-current reads and startup validation use `BEGIN IMMEDIATE`, so a read
cannot observe a writer's database and external anchor at different generations.
The boundary fails closed for malformed state, store replacement, identity
mismatch, detected rollback, invalid signatures and database/anchor corruption.
Database, anchor and SQLite WAL/SHM paths are rejected when they traverse a
link/reparse point or resolve to a hard-linked/aliased file. POSIX modes are
restricted to owner read/write. On Windows, `chmod` is applied but is not a
substitute for a deployment-managed owner-only NTFS ACL. Anchor replacement
fsyncs the file and, where supported, its parent directory; SQLite logical
validation includes committed WAL state and WAL/SHM sidecars are revalidated
and permission-hardened after connection setup.

Database and anchor targets must be lexical, normalized absolute paths with
existing resolved parents; `.`/`..`, missing-target aliases and case-normalized
DB/anchor collisions are rejected before creation. Anchor reads are byte
bounded before allocation and verify stable file identity, size and modification
metadata across the read. Store identifiers and registry text/structured inputs
are bounded; mandate lists are bounded, duplicate-free and canonically sorted.

Replay keys are unique per namespace and claimed atomically. Signed replay
heads, claim receipts, head observations and persistence receipts are retained
across restart. Duplicate and concurrent claims are rejected. The authenticated
clock rejects time rollback, rejects a forward jump beyond the positive
`maximum_forward_step_ms` bound pinned into the store identity, and returns the
same signed record for repeated observation of the same admitted time. The
first observation explicitly bootstraps the clock; subsequent observations,
including after restart, are bounded. Clock-head transitions are monotonic,
signed, anchored and restart-safe.

Production hybrid signatures use an exact purpose domain per impersonation
schema (context, registry, possession proof, replay claim/head/persistence,
clock record/head/transition, upstream receipt and durable anchor). Verification
selects the same exact purpose from the closed schema. Legacy Ed25519 fixtures
remain explicitly test-only and are not production-admitted.

The database and anchor must reside on separately protected durable storage for
the rollback detector to provide its intended deployment property. A matched
rollback of the database, WAL sidecars and signed anchor cannot be detected from
those files alone. Detecting that attack requires an independently protected
monotonic external pin/checkpoint; it is outside the local repository guarantee.

The signed anchor is durably replaced before the corresponding SQLite commit.
If a process or host fails in that interval, restart detects an anchor/database
mismatch and fails closed. Recovery is intentionally not automatic: a trusted
operator must reconcile against independently retained evidence before service
is restored.

## External admissions that remain mandatory

Production constructors reject signers unless their strict ML-DSA-87 + Ed448
verification context declares production signer class, external dual-lane
custody admission and no effect authority. Each constructor also requires an
independently supplied owner-pinned signer-context digest; verification uses
that pin and never derives its trust pin from the presented signer. The
production installer admits only the concrete repository durable classes,
revalidates each live store, binds registry/replay stores to the separately
declared providers, and matches each exact store admission record to the four
process-fixed admission digests above. Test-only and in-memory protocol-shaped
objects are rejected. These are software admission checks; the repository does
not prove that an HSM/TPM or independent custodian exists.

`AuthenticatedMonotonicClock` also requires a pinned SHA-512 admission digest
for its supplied time source. The digest records an external admission; it does
not turn the host clock into independently trusted time.

The following therefore remain external deployment evidence:

- private composition-root isolation;
- real HSM/TPM or equivalent dual-lane signing-key custody;
- independent trusted-time operation and its admission;
- operational protection and backup of SQLite databases and signed anchors;
- independent operation/admission of authoritative live-registry and upstream
  verification services.

## Entry-point behavior

Successful admitted traversal is a library composition path. The one-shot CLI
does not accept authority objects, secrets, durable stores, or trust contexts;
it therefore fails closed rather than constructing production authority from
command-line input.
