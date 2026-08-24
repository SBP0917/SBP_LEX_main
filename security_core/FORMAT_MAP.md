# V2 format map used by the isolated Rust boundary

This map is descriptive of the current repository. The Rust core does not
create a replacement policy or wire format.

| Boundary | Current V2 representation mapped | Rust treatment |
|---|---|---|
| Canonical assurance JSON | NFC strings; UTF-16 code-unit key ordering; compact UTF-8 JSON; floats forbidden | `canonical::canonical_assurance_bytes` |
| Integrity JSON | finite non-integer numbers converted to `{"exact_decimal":"..."}` before assurance canonicalization | `canonical::canonical_integrity_bytes` |
| Digest | lowercase SHA-512 hexadecimal over canonical bytes | `digest` |
| Signed object | payload plus `digest`, exact `signature` metadata envelope, and `verified: false` | `signature` verifies mapped Ed25519 objects |
| Request fingerprint | canonical integrity digest of the request | `request` |
| Hash chain | exact `stage`, `previous_hash`, `payload_hash`, `hash`; `GENESIS` first link | `hash_chain` recomputes every entry and can enforce an exact repository-configured stage list |
| 3P | `SBP_LEX_3P_CORE_FINAL_MASTER_SPEC_4_3_26`; signed P1/P2/P3 determinations and evidence references | `three_p`; substantive evidence truth remains external |
| SKG | `SBP_LEX_SKG_AUTHORITY_V2`; implementation-defined V2 mechanical record and trace | `skg`; substantive SKG rules remain external |
| Framework mechanics | PTODF, AJ-SAAF, GALA, ABEGF with current V2 stage names and signed sources | `filed_framework`; the historical identifier does not authenticate filed provenance |
| Lifecycle mechanics | three named engines in `V2_IMPLEMENTATION_DEFINED_ORDER_NOT_FILED_ORDER` | `filed_lifecycle`; order is implementation-defined, not authenticated as a filed order |
| Licence mechanics | four repository-configured tiers; five bindings; root-binding, validation, and revalidation chronology; ACTIVE/VALID state | `licence` |
| Tokens | current issuer/stage contracts, issuance chain index/hash/stage, signed payload, and token trace | `token` |
| Audit | canonical audit hash, audited chain prefix, live binding, and chained terminal ledger entry | `audit` |
| Effect permit | `SBP_LEX_LOCAL_EFFECT_PERMIT_V1` exact field set and immediate time/chain/binding checks | `permit` and `pre_effect` |
| Revocation | `ACTIVE`/`REVOKED` with non-decreasing sequence | `revocation` |
| Replay | durable injected claim-once interface | `replay`; no production in-memory implementation |
| Final decision | permit an already-authorised effect, deny, escalate, revoke, unsupported, or indeterminate | `decision` and `dispatch`; no governance `ALLOW` variant |

## Closed format gap

The current V2 signed-object provider is Ed25519. Microsoft Platform Crypto
Provider documents TPM-backed RSA/ECDSA rather than the mapped Ed25519 format.
Selecting RSA/ECDSA would create a new signature format, which this task forbids.
The Rust module therefore probes the real NCrypt provider but returns
`TpmEd25519FormatUndefined` from production key creation, signing, and TPM public
verification. It contains no software fallback. A bounded V2 design decision
must select a compatible signed-object format before those operations can be
implemented; real device compatibility and custody evidence remain external.
