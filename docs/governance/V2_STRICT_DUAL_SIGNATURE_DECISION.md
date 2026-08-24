# SBP-LEX V2 Strict Dual-Signature Decision

Status: `OWNER_APPROVED_V2_DESIGN`

Decision date: 24 August 2026

## Decision authority and scope

The owner explicitly instructed the V2 build to use a strict full-strength dual
signature requirement and to harden the two-lane custody and verification
model. The owner then explicitly directed completion of the following seven
items. This record preserves only that bounded decision; it is not filed patent
wording and does not approve unrelated V2 architecture.

1. The admitted high-assurance suite is ML-DSA-87 plus Ed448.
2. Verification is strict AND: both lanes must validate over the identical
   canonical bytes, purpose, epoch and application context.
3. A single lane, missing lane, malformed lane, substituted lane or
   either-lane fallback is never sufficient.
4. The suite has an explicit versioned identifier:
   `SBP_LEX_V2_ML_DSA_87_ED448_AND_V1`.
5. Each lane has an independent key identity, provider identity, custody
   reference, rotation state, revocation state and custody-admission record.
6. In-process software signing is test-only and has no production effect
   authority. Production signing remains unavailable until real external,
   independently admitted, non-exportable custody is provisioned for both
   lanes.
7. Algorithm agility is explicit: changing an algorithm or verification
   semantic requires a new suite identifier and a separate admission decision.
   No existing suite identifier may silently change meaning or fall back.

## Implemented repository contract

The active Python, detached local-trust and Rust verification contracts bind the
suite version, `ALL_LANES_REQUIRED` verification rule,
`FULL_STRENGTH_ML_DSA_87_AND_ED448` profile, required lane order and the
transition rule
`NEW_SUITE_ID_AND_EXPLICIT_ADMISSION_REQUIRED_NO_IMPLICIT_FALLBACK`.

The active Python verification context and Rust security-core signer
expectation bind two distinct custody records. They reject shared lane provider
identities, shared custody references, wrong key epochs, invalid rotation
epochs, non-active or revoked lanes, and unadmitted/exportable production
custody. Production admission requires two distinct per-lane custody
attestations plus a third distinct aggregate admission digest.

The Python and Rust software signers remain test-only. The Rust signature crate
is verification-only under default features; its deterministic software signer
requires the explicit `software-signing` feature for tests and reciprocal
vectors.

## External boundary

This decision approves the repository contract. It does not claim that real
HSMs, TPMs, non-exportable keys, external custody providers, custody
attestations, production routing or independent validation already exist.
Those remain `EXTERNAL_PHYSICAL_DEPENDENCY` items and production effect
authority remains fail-closed until they are actually supplied and admitted.

## Patent boundary

This is an owner-approved V2 engineering decision intended to keep the broader
engine build patent-aligned. It is not represented as an exact filed limitation
or proof of patent conformance. Any patent attribution still requires an
admitted primary filing artifact and exact source mapping.
