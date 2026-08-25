# SBP-LEX V2 Current Repository Validation Status

> Historical mutable validation snapshot. It is preserved for provenance but
> is not the current canonical status. See `V2_CANONICAL_STATUS.md`.

Status date: 24 August 2026

Status: `PASS_REPOSITORY_LOCAL_NON_INDEPENDENT`

This record describes checks performed in the current working repository. It is
mutable, unsealed implementation evidence. It is not a freeze, release,
production admission, university result, legal opinion, patent-conformance
opinion, or proof that external data, identities, authorities, hardware,
services, routes or physical effects are genuine or correctly deployed.

The controlling provenance classifications are in
`docs/governance/V2_AUTHORITY_AND_PROVENANCE_REGISTER.md`. In particular, the
available repository establishes zero authenticated `EXACT_FILED_WORDING` items
and one bounded `OWNER_APPROVED_V2_DESIGN` item: AP-28, the strict dual-signature
and two-lane custody contract. Repository mechanics outside that exact scope can
be `IMPLEMENTATION_DEFINED_V2` without being attributed to a filing or to owner
approval.

## Current results

### Python

| Environment | Command scope | Result |
|---|---|---|
| CPython 3.12.13 development environment | Final exact-revision complete `tests/` suite, cache disabled, repository-local temporary directory | 660 passed; 269 subtests passed; 8,775.79 seconds |
| CPython 3.11.9, `cpython-311`, `win-amd64` clean test environment | Final exact-revision complete `tests/` suite, cache disabled, repository-local temporary directory | 660 passed; 269 subtests passed; 8,778.53 seconds |
| CPython 3.11.9 clean production environment | Exact production installation, `pip check`, and `main` import | 17 exact requirements installed; no broken requirements; application title `SBP-LEX V2`, version `2.0.0` |
| Repository-local hostile local-trust/PTDE/PVPL command | 93-test negative/adversarial scope | 93 passed; 2,150.79 seconds |

The 93-test hostile run exercises tests also present in the complete suite; its
count is not added to the complete-suite total.

`evidence/v2/python311-resolution-evidence.json` binds the target interpreter,
ABI and platform to all 17 exact wheel filenames, SHA-256 hashes, byte sizes,
installed versions and active metadata dependency edges. Its validator reports:
`PASS: 17 target wheels, hashes, sizes, versions, and active dependency edges
match`.

The canonical `python-dependencies.lock.json` is intentionally absent. This
historical snapshot predates the strict dual-history schema `/3` builder. A
genuine PTDE accepted-attempt history, independently signed local-trust
accepted-package history, exact predecessor pin and final repository freeze
binding still do not exist, and none has been invented. The dependency
resolution is reproducible input evidence, not a sealed dependency admission.

### Rust

All current Rust commands used Rust/Cargo 1.97.1 with the explicit
`stable-x86_64-pc-windows-gnu` toolchain, locked dependencies and offline mode.

| Crate | Test result |
|---|---:|
| `wire_protocol/rust` | 5 passed |
| `wire_protocol/v2/rust` | 35 passed |
| `hybrid_signature_rust`, default verification-only features | 3 passed |
| `hybrid_signature_rust`, all features | 7 passed |
| `independent_verifier_rust` | 23 passed |
| `trusted_core_rust` | 40 passed |
| `security_core` | 35 passed |
| `rust_authority_service` | 15 passed |
| `polyglot/rust/v2_assurance_kernel` | 4 passed |

Formatting checks and strict Clippy with warnings denied passed for every crate.
The strict-dual signature crate also passed strict all-feature Clippy. Its default
feature set remains verification-only; repository software signing still
requires the explicit `software-signing` feature and is not production effect
authority.

The default MSVC target was not link-tested because `link.exe`/Visual C++ Build
Tools are absent. The installed GNU target completed all recorded Rust tests,
formatting and strict lint checks. This is a host-toolchain limitation, not a
Rust test failure.

### TLA+ and executable model exploration

The current runs used Microsoft OpenJDK 21.0.12.1+1 and stable TLA+ tools v1.7.4.
The downloaded JDK archive SHA-256 and TLA+ JAR SHA-1 match their publisher and
release-page checksums. A separately downloaded mutable v1.8.0 artifact did not
match the checksum shown on its release page and was rejected without being
used for evidence.

| Model/configuration | Result |
|---|---|
| `formal/tla/SBPLEXV2.cfg`, `HostTPMAvailable = FALSE` | 17,298 generated; 8,904 distinct; zero queued; depth 32; `TypeOK` and all 22 invariants passed; no error |
| `formal/tla/SBPLEXV2_TPM_ADMITTED_NONVACUITY.cfg`, model assumption `HostTPMAvailable = TRUE` | 20,968 generated; 10,788 distinct; zero queued; depth 35; `TypeOK` and all 22 invariants passed; no error |
| `formal/SBPLexAuthority.cfg` | 674,713 generated; 198,651 distinct; zero queued; depth 21; all 18 configured invariants passed; no error |
| `formal/check_model.py` default exhaustive graph | 198,651 states; 319,466 transitions; maximum depth 20; untruncated frontier; all 18 invariants and coverage checks passed |

The explicit `HostTPMAvailable = TRUE` configuration reaches permit, claim,
revalidation, effect, receipt and audit states, preventing the corresponding
effect-path safety checks from passing only because the path is unreachable.
It is a model assumption—not evidence that a TPM, key provider, custody policy
or deployed effect path exists.

Exact tool hashes, formal-source SHA-512 bindings and run metadata are recorded
in `evidence/v2/tla-model-evidence.json`. These finite-state results do not prove
cryptography, code/model equivalence, unbounded concurrency, deployment
non-bypass or physical behavior.

### SPARK/Ada safety monitor

The repository-local Alire 2.1.1 environment completed:

- the SPARK monitor build;
- the executable contract assertions;
- the Python harness; and
- GNATprove `--mode=all --level=2 --report=all` with all 53 checks proved and
  zero unproved checks.

`evidence/v2/spark-proof-evidence.json` records the toolchain and eight verified
SHA-512 bindings for the lockfile, project, sources, proof output and executable.
The proof concerns the typed monitor state machine. It does not prove the truth
or cryptographic validity of external inputs, real HSM/TPM custody, an
independent safety-inhibit circuit, production routing, physical effects or
university validation.

## Material implementation defects corrected during validation

1. The public `main.run_sbp_lex` entry point now accepts and forwards explicit
   `PipelineHybridTrustContexts`; omission remains fail-closed.
2. The controlled local adapter binds an effect to the authenticated
   point-of-use evidence digest rather than to the randomized outer signature
   envelope; signature verification remains a separate mandatory check.
3. SKG pinned verification uses the SKG-specific authority-attestation purpose
   instead of a generic signing purpose, preserving domain separation.
4. Deliberately legacy, non-effect fixtures now use the legacy inspection
   builder and cannot enter CIGA, rule-artifact or exchange authority paths.
5. Rust tests that require in-process software signing are feature-gated; the
   default strict-dual signature build remains verification-only.

These changes repaired integration and binding behavior without adding a
fallback, admitting legacy authority, weakening strict-dual signature checks, or
asserting external trust.

## Remaining admission boundaries

The repository-local implementation and validation work does not supply:

1. authenticated primary filed patent artifacts, exact filed wording, legal
   interpretation, or an owner-approved architecture record;
2. authoritative real SKG, legal, jurisdictional, licence, lifecycle, identity,
   biometric or cognitive-inventory sources and accountable custodians;
3. real independent ML-DSA-87 and Ed448 HSM/TPM custody, provisioning,
   non-exportability, per-lane rotation/revocation,
   attestation, rotation, revocation and destruction evidence;
4. deployed durable atomic replay, revocation, permit-claim and audit stores,
   trusted time, authenticated routing, process isolation, physical choke
   points, watchdogs, safety inhibits and adapter inventories;
5. an admitted runtime route through the reviewed Rust authority boundary for
   every real effect path;
6. a sealed freeze/release package with genuine accepted-attempt history and
   rollback binding; or
7. independent university or third-party reproduction, model-to-code review,
   threat modelling, fuzzing, fault injection, hardware exercise and signed
   validation conclusions.

Those are external, primary-source, deployment or independent-validation
dependencies. Their absence must not be rewritten as owner failure to provide
semantics generated during this build.

## Candidate conclusion

The current V2 working repository passes its complete Python suite on the
declared CPython 3.11 target and the development CPython 3.12 environment; all
recorded Rust GNU tests, formatting and strict lint checks; both V2 TLA+ bounded
configurations; the broader authority model and executable explorer; and all 53
SPARK proof checks. It is suitable for university inspection as a broader-engine
candidate with the assurance boundaries above attached. It is not frozen,
committed, pushed, independently validated or admitted for production.
