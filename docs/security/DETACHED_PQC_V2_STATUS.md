# SBP-LEX V2 detached PQC status

## Implemented boundary

The repository contains genuine runtime-detached strict dual signing through the
`cryptography` ML-DSA-87 and Ed448 implementations. The additive contract is:

- wrapper schema: `sbp.lex.v2.detached-strict-dual-signed-wrapper/1`;
- owner-pin schema: `sbp.lex.v2.detached-strict-dual-owner-pin/1`;
- signature profile: `SBP_LEX_V2_ML_DSA_87_ED448_AND_V1`;
- suite version: `1`;
- verification rule: `ALL_LANES_REQUIRED`;
- envelope schema: `sbp.lex.v2.strict-dual-signature-envelope/1`;
- envelope domain: `SBP-LEX/V2/STRICT-DUAL-SIGNATURE/PREIMAGE/1`;
- lane key ID: lowercase SHA-512 of the exact raw public-key bytes; and
- ordered key-set digest: separately named SHA-512 over the fixed key-ID
  domain, profile and the two ordered lane key IDs; and
- payload binding: lowercase SHA-512 of the exact opaque payload bytes.

Both signature lanes are mandatory over the same canonical bytes, purpose,
epoch and application context. A missing, malformed, substituted or invalid
lane rejects the whole signature; there is no one-lane or either-lane fallback.
The shared Python/Rust `/1` preimage is
exactly the binary preimage domain, profile and NUL delimiter, a u16be UTF-8
purpose length and purpose, a u64be key epoch, then SHA-512 digests of the raw
ML-DSA-87 public key, raw Ed448 public key, exact payload bytes and exact
application-context bytes. Both algorithms use plain/raw sign and verify APIs;
the preimage owns all domain separation. The application context binds the
owner-pin record, including its ID, non-admission status, independent lane
provider identities, independent custody references, two lane custody
attestations and a distinct aggregate custody attestation. Verification
uses public keys supplied through `DetachedHybridOwnerPins`; the wrapper does
not contain public keys and cannot select or admit its own trust root. A signer
whose private keys do not correspond to the external pins is rejected before
signing.

The wrapper is fixed to `NOT_ADMITTED`, `NOT_ACTIVATED`, no runtime attachment
and no authority effect. Verification authenticates only the exact detached
bytes against the supplied pins. It does not validate the semantic correctness
of the enclosed PTDE, PVPL, supply-chain or local-trust document.

The focused detached test contains a separately recomputed fixed preimage
digest and asserts byte equality with the active Python `/1` preimage function.
Separate reciprocal frozen vectors in the isolated Rust signature crate exercise
the same exact contract and verify both Python-produced signature lanes. These
mutable repository-local tests are not an immutable Candidate 10 evidence
package, independent second-machine reproduction, external IV&V or university
validation.

## Existing-payload compatibility

No existing PTDE, PVPL, supply-chain or local-trust `/1` schema or serialized
field was changed. The wrapper base64-encodes already-produced exact bytes and
returns those same bytes after successful verification. Existing local-trust
`mldsa87_fingerprint` and `ed448_fingerprint` fields remain byte-compatible.
Additive non-serialized `mldsa87_key_id` and `ed448_key_id` properties provide
the strict-dual `SHA-512(raw-public-key-bytes)` identity rule. The retired suite
identifier is not admitted as an alias. Any future algorithm change requires a
new suite identifier and explicit admission.

## ML-KEM-1024 capability evidence

`sbp.lex.v2.ml-kem-1024-channel-capability-evidence/2` binds one externally
pinned ML-KEM-1024 public-key identity, key epoch, transport binding, custody
attestation, observation time and evidence sequence. It is restricted to
`CHANNEL_ESTABLISHMENT_ONLY`, with `signature_capability=false`,
`authority_capability=false`, `admission_state=NOT_ADMITTED` and
`deployment_state=NOT_DEPLOYED`.

The module does not implement ML-KEM encapsulation or decapsulation. It cannot
be used as a signature, token, licence, governance, execution, effect or audit
authority. It remains `NOT_DEPLOYED` unless a bounded V2 design decision selects
a transport and custody composition and the required external evidence exists.

## Boundaries not closed here

This detached implementation does not itself change or close:

- active Python production-provider custody and admission;
- the Rust authority/security-core/wire admission boundary;
- production Rust wire-v2 ML-DSA signing and verification;
- authenticated Python-to-Rust routing;
- HSM/TPM-backed non-exportable custody and attestation;
- physical execution of the enforced per-lane rotation, revocation and recovery records;
- durable replay, permit, audit and revocation stores;
- a physical non-bypass effect-handler choke point; or
- independent second-machine or external validation.

The detached PQC code is substantive cryptographic tooling, but it is not
production admission evidence until those separate integration and deployment
dependencies are completed and independently validated.
