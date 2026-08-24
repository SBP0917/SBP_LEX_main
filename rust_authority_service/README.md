# SBP-LEX Rust authority service

This package is the process boundary around `trusted_core_rust`. It is not a
production authority in this candidate.

The ordinary `sbp-lex-authority` binary contains no local software signing key,
no local-only replay fallback, no permissive safety interlock or inhibit, and no
process-local watchdog substitute. It exits fail-closed until separately
administered HSM/TPM custody, an external rollback-resistant replay anchor, an
independent inhibit, and an external watchdog are integrated and admitted.

The separately named `sbp-lex-authority-evidence` binary exists only when the
`evidence-only-fixtures` Cargo feature is enabled. Every output from that build
must carry `NONPRODUCTION_EVIDENCE_ONLY`, and programme consumers must reject
that class. Its signature, custody, interlock, inhibit, watchdog, and journal are
simulations that exercise interface shape; none satisfy the corresponding
production requirement.

Evidence replay state is not caller-selectable. The build captures only a known
folder. Runtime code appends the fixed source identity
`SBP_LEX_RUST_AUTHORITY_EVIDENCE_ONLY_V1-94578afd81a13aab` and requires an exact
build descriptor before opening it. Requests, command-line arguments, and the
runtime environment cannot choose another namespace. Claim files use atomic
create-new semantics and are treated as consumed even if a crash leaves an
incomplete final-name record.

The legacy transport-inspection Python/Rust wire protocol lives in
`wire_protocol/`. The public service boundary pins and consumes its separately
implemented Rust codec and specification at SHA-512
`f084a52597df0db1466ef9681273deb7513fa1818b41060f443802aafa8db76c`.
It does not invent a second codec or framing scheme.

That legacy public boundary is intentionally non-authorizing: it hash-binds and
inspects canonical frames but refuses to construct trusted-core convergence
evidence or enter PREPARE/COMMIT.

Separately, `src/wire_v2_private.rs` contains a crate-private mapping of locally
hash-pinned authority wire-v2 candidate bytes into the trusted core. Modes 1, 2
and 3 have private service-owned convergence entrypoints and join the same
private PREPARE path. Crate-local tests exercise private typestates, durable
replay, watchdog tightening, point-of-use dispatch and terminal dispositions
using evidence-only fixtures. The module is not re-exported, no shipped binary
or Python route can invoke it, and its fixture signers, replay store, watchdog
and adapter are nonproduction. These private mechanics do not admit a production
route.

The private mapping is bounded builder implementation evidence only. It is not
an immutable Candidate 10 result, external independent verification,
design-authority admission or a route authorization. The current proposed V2
gate set is `AI_PROPOSED_AWAITING_APPROVAL`, not a controlling owner decision.
Exact test results must be regenerated from the later externally identified
fixed subject; the route remains `NOT_ADMITTED` unless an explicit bounded V2
decision adopts or replaces the applicable gates and the selected physical
dependencies close.
