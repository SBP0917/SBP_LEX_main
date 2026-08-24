# SBP-LEX independent Rust verifier

This directory is a separately authored verifier for the high-risk evidence
profile. It is deliberately **node-free**: the crate uses the Rust standard
library only, has no `build.rs`, has no package-manager bridge, and shares no
source code with another verifier or trusted core. Both crate roots forbid
unsafe Rust.

The verifier accepts one canonical, line-oriented format. It rejects unknown
records, unknown or reordered fields, extra fields, blank lines, CRLF input,
non-canonical integers, uppercase/non-64-byte hexadecimal text, duplicate
event IDs, sequence gaps, and broken hash-chain links. The input must end in
exactly one LF.

All validity intervals are half-open: an artifact is valid at `not_before` and
strictly before `expires_at`; equality with `expires_at` is expired. An applied
receipt must also be verified strictly before the effect lease expires, even
when its configured prompt-delay bound has not elapsed. The
`MAX_RECEIPT_DELAY_MS` and `MAX_WATCHDOG_DELAY_MS` constants are inclusive
maximum elapsed durations, so equality with those duration limits is accepted
only while every enclosing half-open artifact deadline is still unexpired.

## Security profile

An accepted `ALLOW` trace proves all of the following:

- every security-bearing record repeats the exact request, state,
  convergence, effect, adapter, disabled extension-admission binding, and
  single-capability binding;
- the safety envelope preserves those bindings and can only reduce the
  request's time/use/lease limits (or choose `BLOCK`);
- `PREPARE` occurs before `COMMIT`;
- the signed proof is unexpired at use and has exactly one permitted use;
- the signed lease is effect/adapter/capability bound, permits one use, and is
  no longer than 30 seconds;
- the one redemption occurs at the bound adapter immediately before commit;
- signed receipt and signed, passing watchdog evidence are both present;
- sequence numbers are exactly `1..N`, event IDs are unique, and every event
  links to the cryptographic hash of the complete preceding canonical line.

A `BLOCK` envelope must grant zero uses and zero lease time, and its trace
terminates without proof, lease, redemption, prepare, or commit. It still
requires a prompt signed `BLOCKED` receipt and signed watchdog.

## Cryptographic boundary and fail-closed CLI

Rust's standard library does not ship a production digital-signature
implementation. Rather than smuggling in an unreviewed algorithm, this crate
defines `VerificationProvider`. Integrators must supply an independently
reviewed provider for 256-bit hashing and signature verification. Calling
`verify` without one returns `ProviderRequired`; provider errors and negative
signature answers are hard failures.

The included CLI reads a trace and invokes the same verifier with no provider.
It therefore fails closed (nonzero) and clearly reports that a production
provider must be linked. A deployed CLI should be a tiny downstream binary
that constructs its approved provider and calls `verify`.

The tests use an explicitly named `NonProductionFixtureProvider`. Its
deterministic mixer/authenticator exists only to make state-machine and
adversarial tests reproducible; it is not cryptography and is not exported by
the library.

## Format

The header is exactly:

```text
SBP-LEX-INDEPENDENT-EVIDENCE-V2
```

It is followed by canonical records in this order:

```text
REQUEST STATE CONVERGENCE ENVELOPE
```

For `ALLOW`, the remainder is:

```text
PROOF PREPARE LEASE REDEEM COMMIT RECEIPT WATCHDOG END
```

For `BLOCK`, the remainder is:

```text
RECEIPT WATCHDOG END
```

The implementation is the normative field-order reference. Signed records
place `signature` last. The signed message is the exact ASCII record prefix,
ending immediately before ` signature=`. Hash-chain links use the exact bytes
of the entire preceding record line and domain
`SBP-LEX-INDEPENDENT-CHAIN-V1`. The first `prev` value is 64 zeroes; `END.head`
is the hash of the final event line. Evidence v1 lacks the mandatory extension
admission binding and is rejected rather than upgraded.

## Build and test

```text
cargo test --manifest-path independent_verifier_rust/Cargo.toml
cargo run --manifest-path independent_verifier_rust/Cargo.toml -- evidence.trace
```

No network access or dependency download is needed.
