# V2 Rust assurance kernel

This executable is a veto-only verifier for the V2 assurance-envelope contract.
It reads one JSON envelope from standard input, writes one bounded JSON verdict
to standard output, and exits with code `0` only for a verified envelope.

It cannot issue an SBP-LEX decision, token, or execution capability.

## Activation status

The verifier has been compiled and tested with Rust 1.97.1 using the
self-contained `x86_64-pc-windows-gnu` target. `Cargo.lock` records the resolved
dependency graph. Formatting, unit tests, Clippy with warnings denied, a valid
Python-to-Rust SHA-512/128-lowercase-hex envelope, and a deliberately corrupted
digest have been checked.

The crate pins the GNU Windows target because this workstation does not have the
Microsoft C++ linker required by the MSVC Rust target. A production target change
requires fresh evidence; it is not an automatic equivalence claim.

The bounded Python adapter is now present under `sbp_lex/assurance`. It launches
without a shell, bounds input/output/time, rejects duplicate verdict fields and
requires an accepted verdict to echo the exact request, checkpoint, state and
envelope SHA-512 digests. A local Python-to-Rust checkpoint invocation passes.

Before release admission, also:

1. pass shared malformed, oversized, duplicate-key, Unicode-edge, integer-limit,
   timeout, and crash vectors;
2. record the release binary digest and exact toolchain identity;
3. prove by integrated negative tests that verifier failure cannot be
   interpreted as approval; and
4. move the executable path from local build evidence into an immutable release
   manifest rather than request or environment input.

Do not configure the verifier as `required` until the activation ladder in the
polyglot hardening profile is complete.
