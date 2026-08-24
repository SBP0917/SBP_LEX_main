# SBP-LEX V2 SHA-512 Handover Status

## Purpose and scope

This document is a handover record for the beginning of external inspection and validation of the SBP-LEX V2 repository. It records the implemented SHA-512 migration, the verification evidence produced during that migration, its deliberate legacy exceptions, and the material gaps that remain before an end-to-end 256-bit classical-security claim could be considered.

This is not an independent validation report, production-readiness certification, or security guarantee.

## Active V2 SHA-512 contract

The active V2 security-digest contract uses SHA-512. It applies to V2 canonical hashing, signed-object digests, key fingerprints, hash chains, tokens, permits, replay identifiers, audit records, assurance envelopes, the V2 wire protocol, reconciliation artifacts, and the isolated Rust security core.

The migration is deliberately breaking at the digest representation boundary:

| Contract item | Previous V2 value | Current V2 value |
|---|---|---|
| Digest algorithm | SHA-256 | SHA-512 |
| Hexadecimal length | 64 characters | 128 characters |
| Character form | lowercase hexadecimal | lowercase hexadecimal |
| Legacy 64-character value accepted as a V2 SHA-512 value | No | No |

The active V2 contract explicitly rejects legacy 64-character SHA-256 values where a V2 SHA-512 digest is required. One assurance-chain field was correspondingly renamed from `previous_envelope_sha256` to `previous_envelope_sha512`.

## Verification evidence produced

The following results are dated records from the SHA-512 migration run. They are not refreshed current-suite totals and are not admitted as independently reproducible evidence until the exact revision, dirty patch where applicable, command, environment and complete captured log are pinned with them. They are implementation verification records, not independent validation.

| Dated migration-run activity | Recorded result |
|---|---:|
| V2 Python suite as then exercised | 183 passed; 132 subtests passed |
| V2 wire Python suite | 40 passed |
| Cross-language reconciliation | 23 passed |
| Rust `security_core` suite | 34/34 passed |
| V2 Rust wire-contract suite | 30/30 passed |
| Polyglot V2 assurance kernel | 4/4 passed |
| Rust authority service library tests | 34/34 passed |
| Rust authority service binary tests | 2/2 passed |
| Rust `cargo check` | passed |
| Rust formatting | passed |
| Rust strict Clippy | passed |
| TLC retained TPM-disabled run | 17,298 generated states; 8,904 distinct states; depth 32; no errors |

The retained TLC run is a bounded model-checking result. It checks the formal abstraction under its retained configuration; it does not establish equivalence between the formal model and all production code, hardware, operating-system, or deployment behavior.

## Deliberately retained SHA-256 material

SHA-256 references that remain are outside the active V2 SHA-512 security contract. They are retained for compatibility, provenance, or historical evidence and are not silently admitted as V2 SHA-512 values:

- Legacy Wire-v1 protocol and vectors under `wire_protocol/`.
- Historical provenance hashes in evidence and dependency-lock artifacts.
- The explicitly non-authorising legacy Wire-v1 boundary in `rust_authority_service/`.
- Historical documentation references and legacy-rejection tests.

An external reviewer should distinguish these retained legacy or historical references from a defect in the active V2 SHA-512 contract.

Any retained source SHA-256 is historical, non-authorising provenance only. It
must not identify or admit a future university source or evidence manifest.
Every future university source/evidence manifest identity must use the active
canonical SHA-512 contract: exactly 128 lowercase hexadecimal characters.

## Deliberately removed non-evidence

`sbp_lex/security/pqc.py` was deliberately deleted because it was a fake
digest/sign/verify placeholder, not a post-quantum cryptographic implementation.
Its former filename, labels and historical references provide no PQC
implementation, migration or security claim.

## P/T/D/E handover-evidence status

P/T/D/E is defined for V2 as detached, non-authorising committed-Git-object
proof/verification tooling. Its policy and verifier source are under
`contracts/ptde/PTDE_POLICY_V1.json` and `sbp_ptde/`. It is outside runtime
authority, `ALLOW`, licence and effect semantics, while remaining part of the
handover evidence process. That separation is the current
`IMPLEMENTATION_DEFINED_V2` repository status; it is not evidence of blanket
owner approval for every future P/T/D/E design decision.

No completed P/T/D/E campaign is claimed here. In particular, this document
does not admit a P/T/D/E commit chain, campaign manifest, lane result or
external verification result.

## What this work does and does not establish

The SHA-512 migration raises the V2 digest, integrity-binding, and hash-chain collision-security level from approximately 128 bits to approximately 256 bits, assuming the SHA-512 contract is consistently applied at each V2 security boundary.

It does not establish any of the following:

- That V2 is end-to-end 256-bit secure.
- That V2 is TPM-backed or hardware-key-custodied.
- That V2 has 256-bit signature strength.
- That all physical or deployed effect paths are non-bypassable.
- That replay, revocation, permit, and audit stores are durably deployed for production use.
- That trusted roots, time, lifecycle, licence, or evaluator sources are authoritative in a deployment.
- That V2 is production ready or independently validated.
- That the bounded TLA+ model proves the implementation, platform, or deployment.

The active Python signed-object mechanics now implement the exact strict-dual
`SBP_LEX_V2_ML_DSA_87_ED448_AND_V1` contract. Both lanes must verify the same
canonical preimage and no single-lane fallback is admitted. Ed25519 remains
only as an explicitly legacy, non-effect format. The included software provider is genuine
cryptographic code but is `TEST_ONLY`, has process-memory custody and cannot
claim effect authority or external-custody admission. The isolated Rust signature
crate now verifies both Python-produced lanes against the common fixed vector;
that mutable repository-local interoperability result does not admit the Rust
authority route or a production provider. Separately, runtime-detached
local-trust tooling uses the same strict-dual
envelope and preimage for an additive exact-byte wrapper around unchanged
`/1` evidence. That detached wrapper remains non-authorizing and has no
production custody or admission claim.

## Remaining gaps for end-to-end 256-bit classical security

The technology and topology choices in this list are current V2 proposals or
implemented interfaces unless a specific decision record says otherwise. The
real custody, infrastructure, deployment and independent-validation evidence is
an external physical dependency; its absence is not evidence that the owner
failed to supply an AI-generated requirement.

1. **Production strict-dual provider admission:** replace the in-tree `TEST_ONLY`
   process-memory provider with two independently identified and admitted external
   custody providers, each with its own role, epoch, rotation, revocation and
   custody-attestation evidence; the detached wrapper is not that
   admission.
2. **TPM/HSM compatibility and custody:** provision and exercise a real
   non-exportable key path for both lanes of the selected strict-dual suite. The observed Windows
   Platform Provider exposes RSA/ECDSA and no admitted ML-DSA-87 + Ed448
   custody mapping has been demonstrated; no software fallback may be accepted
   for effect authority.
3. **Runtime Rust enforcement:** route the active Python runtime through the reviewed Rust security decision and dispatch boundary.
4. **Authenticated Python-to-Rust boundary:** implement and verify strict canonical-byte agreement, request identity binding, version pinning, replay protection, timeouts, and fail-closed IPC behavior.
5. **Effect choke point:** prove in the deployed system that real effect handlers can only be reached through the admitted enforcement edge, with direct Python, API, IPC, local-handler, administrator, and service-account bypass routes blocked.
6. **Durable state:** deploy and validate atomic, durable replay, revocation, permit-claim, and canonical-audit stores across restart, crash, concurrency, rollback, and partition cases.
7. **Trust material and authoritative inputs:** establish and govern trusted signer roots, trusted time, key rotation and revocation policy, lifecycle/licence evaluator sources, and administrator controls.
8. **Platform and supply-chain hardening:** complete release-platform validation, dependency and supply-chain review, binary signing, measured startup, anti-rollback, process isolation, least privilege, monitoring, incident response, and recovery evidence.
9. **Independent validation:** commission and complete independent review and reproduction, including a second-machine run, real TPM exercise, cross-language golden vectors, fuzzing, fault injection, and model-to-code correspondence work.
10. **Canonical Python dependency admission remains unsealed:**
    `evidence/v2/python311-resolution-evidence.json` now binds the clean CPython
    3.11.9/win-amd64 environment to all 17 exact wheel hashes, sizes, installed
    versions and active dependency edges. The canonical
    `python-dependencies.lock.json` remains unavailable because genuine
    accepted-attempt/rollback history and the final freeze binding do not yet
    exist; neither was fabricated.
11. **Canonical launcher reproduction:** `main:app` through Uvicorn is now the canonical V2 launcher; a clean independent execution remains required.

## External reviewer checklist

The following checklist is for reviewers beginning inspection. No item is asserted here as independently completed.

- [ ] Confirm that every active V2 digest producer emits exactly 128 lowercase hexadecimal characters derived from SHA-512.
- [ ] Confirm that every active V2 digest consumer rejects 64-character SHA-256-shaped values at a SHA-512 boundary.
- [ ] Confirm canonical-byte agreement between Python, Rust, and V2 wire-contract inputs using independently generated vectors.
- [ ] Reproduce each recorded test result in a clean, independently controlled environment.
- [ ] Inspect retained SHA-256 material and confirm it is legacy, historical, or explicitly non-authorising rather than active V2 security input.
- [ ] Review the Rust `security_core` decision and dispatch boundaries for fail-closed behavior and absence of generic authorisation allow paths.
- [ ] Review the formal model configuration, invariant definitions, bounds, and TLC results; determine what additional state-space coverage is required.
- [ ] Trace the active Python runtime to determine whether and where the Rust security core is actually invoked.
- [ ] Review current signature custody, provider behavior, the `TEST_ONLY`
  hybrid software boundary and the absence of an admitted TPM/HSM-backed V2
  hybrid signing path.
- [ ] Validate all real effect-handler entry points and identify every potential bypass path.
- [ ] Evaluate durable storage behavior under restart, crash, concurrency, rollback, and partition fault conditions.
- [ ] Validate trusted root, time, evaluator, rotation, revocation, and administrator-control evidence supplied for the target deployment.
- [ ] Conduct independent threat modelling, fuzzing, fault injection, supply-chain review, and second-machine reproduction before making a production assurance claim.

## Repository state

No commit or push was performed as part of the SHA-512 migration or this handover record.
