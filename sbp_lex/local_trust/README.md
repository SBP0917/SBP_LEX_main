# SBP-LEX V2 detached local trust

This package is local/private, offline-verifiable, runtime-detached and
non-authorizing. It is not imported by `main.py` or any active Python runtime
authority path. It cannot grant runtime, governance, licence, decision,
execution, effect, audit, hash-chain, publication, network, cloud, blockchain
or ledger authority.

## Exact cryptographic contract

Every signed value uses the detached copy of the exact V2 canonical integrity
profile: NFC strings and keys, UTF-16 key ordering, exact-decimal wrappers for
finite floats, whitespace-free UTF-8 JSON and lowercase 128-character SHA-512.
The local-trust package does not import the active runtime integrity module.

Every signature requires both ML-DSA-87 and Ed448. Algorithm names, signature
shape, signing purpose, provider/context/key/custody identity, raw-public-key
fingerprints and the owner-pinned context digest are exact. There is no
single-lane, legacy-algorithm or test-to-production fallback.

The existing local-trust `/1` contract retains its original serialized
fingerprint fields and bytes. For additive `/2` interoperability, each lane
also exposes a non-serialized key ID equal to `SHA-512(raw-public-key-bytes)`.
`pqc_wrapper.py` can place any exact `/1` document bytes inside
`sbp.lex.v2.detached-strict-dual-signed-wrapper/1`. The wrapper uses profile
`SBP_LEX_V2_ML_DSA_87_ED448_AND_V1`, requires both lanes over identical bytes,
binds purpose,
domain, key epoch, owner-pin digest and payload SHA-512, and obtains public keys
only from owner pins supplied out of band. It contains no public keys, remains
`NOT_ADMITTED`, has no authority effect or runtime attachment, and does not
alter the enclosed bytes.

The wrapper uses the common Python/Rust strict-dual `/1` binary preimage: fixed preimage
domain, suite and NUL delimiter; u16be UTF-8 purpose length and purpose; u64be
key epoch; then SHA-512 of the raw ML-DSA-87 key, raw Ed448 key, exact payload
and external application-context bytes. Both lanes use their plain/raw
sign/verify APIs. The nested signature value has the exact common strict-dual
envelope field and lane shape. Lane providers, custody references, rotation,
revocation and custody admissions are independent and bound per lane. The
retired suite is rejected; a future algorithm change requires a new suite ID
and explicit admission.

`pqc_channel.py` defines separate ML-KEM-1024 capability evidence for channel
establishment only. It performs no encapsulation or decapsulation, provides no
signature or authority capability, and is fixed to `NOT_ADMITTED` and
`NOT_DEPLOYED`. Operational use still requires separately admitted transport
and custody systems.

Three distinct out-of-band trust roots are mandatory:

1. local-trust artifact signing;
2. trusted monotonic clock signing; and
3. accepted-package live-head/history signing.

All six raw public keys must be distinct. Packages contain only the three
owner-pinned context digests; they contain no public-key record and cannot
select their own trust roots.

## Deployment identity, time and history

`RepositoryIdentity` pins the exact deployment repository directory and its
`.git` metadata directory by deployment identifier, canonical path and
filesystem identity. The root manifest binds its SHA-512 digest.

Each stage binds independently signed clock evidence with a strictly increasing
sequence, strictly increasing observed time and signed predecessor digest. A
TEST_ONLY clock is labelled exactly as such. Production composition requires an
admitted external trusted-clock provider; this package does not simulate one.

The accepted-package history is an independently strict-dual-signed external live
head. It enforces snapshot sequence, package predecessor, record predecessor,
unique package/replay/time heads, exact repository identity, a minimum durable
sequence and an out-of-band expected history digest. Building a package only
binds the supplied current history. It does not accept the package or advance
the history. The CLI deliberately has no build or admit command.

TEST_ONLY composition is explicit and requires three TEST_ONLY contexts.
Production composition is rejected by this package. The external-admission
record shape is defined, but no production HSM/TPM custody, trusted-clock or
durable-history provider is integrated here, so supplying strings or software
keys cannot promote TEST_ONLY evidence. Those remain external deployment
dependencies and are not claimed or fabricated here.

## Evidence and stages

The exact stage chain is:

1. manifest;
2. execution envelope;
3. evidence chain;
4. regression matrix;
5. constitutional gates;
6. toolchain guard;
7. capstone;
8. release integrity;
9. adversarial harness; and
10. university dossier (claims/evidence index).

Policy commands use argv-only `Popen` with `shell=False`, closed stdin, bounded
concurrent stdout/stderr readers, finite timeout and kill-on-overflow. Passing
results retain the complete stdout/stderr bytes in base64 plus byte counts and
SHA-512 digests. Truncation, timeout and overflow fail closed.

Rust, TLA+ and SPARK may be classified only as
`PRESENT_TESTED_BUT_INACTIVE` when the signed manifest supplies source and
status measurements and the signed execution envelope supplies the matching
native command’s full-byte transcript (`cargo test`, TLC over the measured
`tla2tools.jar`, or `alr gnatprove`). A Python mirror or executable harness is
not accepted as the native TLA+/SPARK proof lane. This classification never
claims that those assets are active in the Python runtime.

`requirements.txt` is a direct dependency declaration and `requirements.lock`
is a resolved version manifest; neither is the assurance dependency lock. The
toolchain guard requires the separate canonical
`python-dependencies.lock.json` artifact before Python dependency assurance can
be `PASS` / `PRESENT_TESTED`. The lock contract requires exact direct pins,
SHA-256 artifact hashes, production/development scope, a complete reachable
dependency graph, exact interpreter/version/ABI/platform binding, and
accepted-history/sequence rollback evidence. Missing, unpinned, unhashed,
mismatched, extra, duplicate, case-variant, non-canonical or rollback-invalid
evidence fails closed. No canonical lock artifact is currently supplied by this
package.

Filesystem evidence rejects non-canonical, case-ambiguous, ADS, reserved,
escaping and overlong paths; symlinks, reparse points, hardlinks and special
files; and identity changes across lstat/open/fstat/post-lstat measurement.
Receipt/report creation is no-follow, exclusive, fsynced and never overwrites.
Output directories must already exist and pass the same safe-directory checks.

The ten signed artifacts, package container, history records and reviewer
report all retain the same no-authority and runtime-detachment boundary.
