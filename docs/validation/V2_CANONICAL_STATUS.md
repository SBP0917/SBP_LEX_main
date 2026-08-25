# SBP-LEX V2 Canonical Status

Status date: 25 August 2026

Status: `ACTIVE_DEVELOPMENT_NOT_PRODUCTION_ADMITTED`

This is the single current repository-wide V2 status record. Older validation,
freeze-readiness and handover documents are preserved as historical snapshots;
component security documents remain subordinate records. None overrides this
file.

## Canonical product surface

- Product name: **SBP-LEX V2**.
- Python target: **CPython 3.12.13**, `cpython-312`, `win-amd64`.
- Canonical library API: `main.run_v2`.
- Canonical one-shot CLI: `python main.py`, also invoked by `start.sh`.
- `main.run_sbp_lex` remains only because current consumers and the PTDE
  callable inventory require compatibility with that name.
- `Procfile` declares a one-shot worker using the CLI and
  `SBP_LEX_REQUEST_JSON`.
- No ASGI application, HTTP endpoint, web service or production web deployment
  is declared.

The CLI accepts request and optional signal JSON only. It cannot inject
authority, custody, effect or deployment providers and therefore remains fail
closed when those dependencies are absent. Library callers must inject every
admitted dependency explicitly.

## Dependency state

`requirements.txt` contains the one direct production dependency identified by
the canonical source imports: `cryptography==50.0.0`.

- `requirements-production.lock.txt`: three exact CPython 3.12/win-amd64
  packages with target-wheel SHA-256 hashes.
- `requirements-test.lock.txt`: the production closure plus pytest, nine exact
  packages with target-wheel SHA-256 hashes.

Fresh official PyPI bytes were resolved without source distributions and all
locked hashes were recomputed. The workspace CPython 3.12.13 environment was
installed offline under pip hash enforcement. The separate governed
`python-dependencies.lock.json` is not present because its two genuine,
independently pinned histories and predecessor binding do not exist; none was
fabricated. Local trust, the repository guard and the P-bound supply-chain
validator enforce the same schema `/3` contract. It separately binds the PTDE
accepted-attempt history and dual-signed local-trust accepted-package history,
the exact predecessor, both committed hash-lock digests, the exact
production/assurance closures and the target environment. Schema `/2` is
rejected. An offline exclusive builder now derives package edges from the exact
hashed wheel metadata and immediately revalidates its canonical output. Both
genuine history snapshots and independent pins must exist first; the resulting
governed lock must then be committed before the owner selects that complete
commit as P. Fixed T cannot add or repair the lock.

A canonical candidate copy of TLA+ tools v1.7.4 now exists at
`runtime_artifacts/toolchains/tla2tools.jar`, copied byte-for-byte from the
official GitHub v1.7.4 release asset. Its SHA-1 matches the publisher's release
page, its SHA-512 is recorded in
`docs/validation/TLA2TOOLS_1_7_4_CANDIDATE_PROVENANCE.md`, and TLC reports
revision `5a47802`. The JAR has no embedded signature. Its inclusion is
candidate dependency inventory only, not an independently approved trust pin,
P selection or formal-result admission.

## PQC state

The active Python signature boundary implements strict dual ML-DSA-87 and
Ed448 signing and verification. Both lanes, the fixed suite/domain, exact key
epoch, external owner-pinned verification context and payload/application
context binding are mandatory. Legacy Ed25519 objects have only an explicitly
named non-effect compatibility inspection path and are rejected by migrated
authority, governance, token and effect-eligible paths.

For the repository-local software boundary, the fixed hybrid profile mechanics,
Python and Rust implementations, cross-language lane verification, hostile
cases and their current tests are locally complete. No known repository-local
PQC mechanics or test defect remains in the stable tree. This local completion
does not admit the implementation for production or assert external custody,
deployment assurance or independent validation.

Real detached strict-dual tooling also exists for exact PTDE, PVPL,
supply-chain and local-trust payload bytes. ML-KEM-1024 is represented only by
a non-admitted channel-capability evidence contract; it is not a signature or
authority mechanism and is not deployed.

The repository software provider uses process-memory test keys and has no
production effect authority. Production ML-DSA-87 and Ed448 custody,
independent lane control, HSM/TPM attestation, rotation, revocation and
destruction evidence remain external blockers.

## Rust and effect-route state

Rust authority, trusted-core, security-core, wire-v2 and formal assets contain
substantial reviewed and tested mechanics. The active Python product route does
not admit the private Rust Mode 1/2/3 route. A validated Rust transcript remains
non-authorising unless a later explicit admission closes authenticated routing,
custody, durable state, deployment identity and physical effect-path controls.

No production physical effect-handler choke point, independent inhibit,
interlock, watchdog, distributed durable permit/replay/revocation/audit
composition or administrator-bypass proof is currently supplied. Repository-
local SQLite implementations now provide bounded same-host durability for the
impersonation registry, replay guard, authenticated monotonic clock, clock head
and segmented-exchange replay guard. They reject corruption, path/link
substitution and rollback conditions covered by their hostile tests, but they
are not distributed stores and cannot detect a matched rollback of every local
database, sidecar and anchor without an independent monotonic pin.

## Substantive governance state

The repository contains deterministic fail-closed mechanics for 3P, SKG,
filed-framework, lifecycle, governance-integrity, licensing, identity,
provenance, token, audit and execution-control surfaces. Their substantive
real-world evaluators, authoritative legal/jurisdictional corpora, complete DTN,
lifecycle intelligence, distributed revocation, exact named inventories and
external identity/biometric/regulatory systems remain outside the repository.

The patent implementation register remains the authority for claim-by-claim
coverage. Repository mechanics must not be restated as complete end-to-end
implementation of the first filing's claims.

## Evidence state

Current tests, Rust/SPARK/TLA+ results, cross-language vectors and reports are
mutable repository-local development evidence. The working repository is not a
clean immutable Candidate 10 subject, sealed release, independent second-machine
reproduction, external IV&V result or university validation.

Historical reports retain their original commands, counts and limitations.
They are not silently promoted into this current record. The clean pre-P
integration commit `0cb1f47c958a30079d84a18e100770de34416577` was independently
rechecked and produced:

- complete `tests/` regression: 790 tests and 274 subtests passed in 933.34
  seconds, with no failures and two Windows symlink-privilege skips;
- independent focused assurance regression: 295 tests and 18 subtests passed,
  with the same two environmental skips;
- all eight Rust crates: 199 tests passed, with locked/offline tests, checks,
  warning-denied Clippy and formatting clean;
- all eight Rust lockfiles passed RustSec audit against the local 1,225-advisory
  database;
- fatal Ruff correctness selection `E9,F63,F7,F82`: clean;
- Bandit over `sbp_lex` and `main.py`: 37 Low, zero Medium, zero High;
- broad MyPy over `sbp_lex` and `main.py`: clean, reduced from 608 findings
  across 47 files at the start of the closing task;
- focused impersonation/foundational/entrypoint regression: 178 tests and 27
  subtests passed;
- local-trust hostile suite: 33 tests passed, with the local-trust package
  MyPy-clean;
- PTDE/PVPL/supply-chain combined scope: 90 tests and 8 subtests passed; and
- the impersonation durable/public files, assigned governance/token files and
  Python V2 wire file are MyPy-clean in their focused checks.

These remain mutable development results and must be regenerated from the
eventual immutable subject. No test count is an admission result.

## Historical `evidence/v2` resolution

All eight files remain tracked for provenance and are therefore blobs in the
Git candidate identity. They are excluded only from the current validation and
admission claims—not from the tree itself. None is current P/T/D/E evidence and
none may be consumed as a production-admission result. Any later selection of
this tree as P requires the owner to approve their exhaustive T-inventory
classification or remove them in a subsequent candidate first.

| Historical file | Resolution for this candidate |
|---|---|
| `host-readiness-inventory-20260824.json` | Retain as a dated, non-admitting host/tool observation. It records no provisioned key, custody or runtime attachment. |
| `host-readiness-platform-provider-20260824.json` | Retain as a dated provider-open observation only. It establishes no algorithm, key, signing or custody capability. |
| `host-readiness-tpm-raw-20260824.json` | Retain as a dated TPM-presence/readiness capture only. It establishes no admitted key or effect authority. |
| `tla-model-evidence.json` | Retain as mutable repository-local formal evidence. All five recorded source/configuration SHA-512 values still match, but the runs remain finite, unsealed and non-independent. |
| `spark-proof-evidence.json` | Retain as mutable repository-local proof evidence. All eight recorded source/project/lock/output SHA-512 values still match, but the evidence remains unsealed and non-independent. |
| `python311-resolution-evidence.json` | Historical only and superseded by the CPython 3.12.13 production/test locks. Its recorded `requirements.txt` SHA-512 no longer matches the candidate. |
| `readiness-validation-20260824.json` | Historical only. It binds old HEAD `015d9009bc58d0e22cb3e32f1bf4d5d9003a7cbf`, an earlier dirty tree and earlier test counts. |
| `unsealed-candidate-release-manifest-20260824.json` | Historical only. It binds the old HEAD and the deleted legacy `requirements.lock`; it is not a candidate manifest for this commit. It also contains dated user-local executable paths and therefore requires explicit review before any public release. |

The historical files are therefore resolved for this pre-P commit without
deletion or regeneration: the bounded host/TLA/SPARK observations are preserved
with their nonclaims, and the three superseded candidate/dependency records are
excluded from current validation claims. This classification is not a P-stage
owner approval.

## Remaining blockers

1. Establish the genuine PTDE accepted-attempt history and the independently
   dual-signed local-trust accepted-package history, including independent
   digest pins, exact sequences and durable persistence locations.
2. Run the offline builder to generate and validate
   `python-dependencies.lock.json` schema `/3` with the exact predecessor pin,
   commit it with the complete candidate tree, and only then allow the owner to
   select that full commit OID as P. Any earlier commit remains pre-P.
3. Generate release-bound raw outputs, exit codes, inventories, hashes, binary
   identities, negative cases, SBOMs and clean-host reproducibility evidence.
4. Admit and authenticate the required Python-to-Rust authority route without
   Python, API, administrator or service-account bypass.
5. Supply independent production custody, trust roots, signer roles, trusted
   rollback-resistant time and durable atomic security stores.
6. Deploy and evidence the physical effect choke point, independent safety
   controls, process isolation, binary identity and anti-rollback controls.
7. Supply authenticated substantive governance authorities and authoritative
   external systems required by the filed-function contracts.
8. Complete independent second-machine, external IV&V and university review.
9. Retire non-fatal Ruff maintenance debt without weakening fail-closed broad
   exception handling or the typed trust boundaries.
10. Approve exact out-of-band SHA-512 pins for Python, Cargo, Java, Alire and
    Git. The locally verified TLC JAR and locally measured executables are not
    self-approving trust anchors.

Until those boundaries close, SBP-LEX V2 is an active, fail-closed development
library/CLI and is **not production admitted**.
