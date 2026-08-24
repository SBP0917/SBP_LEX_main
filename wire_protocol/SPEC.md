# SBP-LEX Authority Wire Protocol v1

Status: integration contract, not an authority grant and not production-key evidence.

The protocol transports already-derived execution-control facts between separately
implemented components. Parsing a message never authorizes an effect. A consumer
must independently validate every cryptographic assertion, policy decision and
single-use state before acting.

## Transport frame

Each message is one frame:

1. four-byte unsigned big-endian payload length;
2. exactly that many payload bytes.

The permitted payload length is `1..16384` bytes. A zero length, an oversized
length, truncation or trailing bytes in a single-frame API is an error. There is
no line framing, pickle, object serialization, dynamic import or generic object
hook.

## Canonical payload

The payload is strict UTF-8 containing exactly one flat JSON object.

- No BOM, leading/trailing whitespace or whitespace between tokens.
- Keys are ASCII and bytewise lexicographically sorted.
- Duplicate, unknown and missing keys are errors.
- All values except `sequence` and fields ending in `_ms` are JSON strings.
- Strings contain printable ASCII only and use no JSON escapes.
- Integers are unsigned base-10 JSON integers in `0..9007199254740991`.
- Zero is written `0`; all other integers have no leading zero.
- Floats, negative numbers, booleans, null, arrays and nested objects are errors.
- Re-encoding the parsed object must reproduce the input bytes exactly.

These rules intentionally reject alternative but normally equivalent JSON
spellings. They also reject Unicode surrogate escapes and parser differentials.

## Common fields

Every message contains these fields, plus the exact kind-specific fields below:

| Field | Rule |
|---|---|
| `adapter_digest` | 64 lowercase hexadecimal characters |
| `adapter_boundary_digest` | admitted consuming-adapter boundary digest |
| `adapter_key_class`, `adapter_key_id` | admitted adapter custody class and public-key ID |
| `audit_anchor_digest` | 64 lowercase hexadecimal characters |
| `authority_build_id` | 64 lowercase hexadecimal characters |
| `authority_class` | `TEST_ONLY`, `SOFTWARE`, `HSM`, or `TPM` |
| `authority_key_class` | `TEST_FIXTURE`, `PRODUCTION_HSM`, or `PRODUCTION_TPM` |
| `authority_key_id` | 64 lowercase hexadecimal characters |
| `authority_profile` | uppercase profile identifier |
| `challenge` | 64 lowercase hexadecimal characters; constant for a transcript |
| `crypto_evidence_digest` | 64 lowercase hexadecimal characters |
| `crypto_key_class` | `NONE`, `TEST_FIXTURE`, `PRODUCTION_HSM`, or `PRODUCTION_TPM` |
| `crypto_result` | `NOT_CHECKED` or `SIGNATURE_PRESENT`; verification is consumer-derived |
| `durable_consumption_digest` | protected replay/consumption-record digest |
| `effect_digest` | 64 lowercase hexadecimal characters |
| `effect_intent_digest` | 64 lowercase hexadecimal characters |
| `error_code` | `NONE` or an uppercase fail-closed code |
| `expires_at_ms` | canonical integer UTC Unix milliseconds |
| `inhibit_binding_digest` | 64 lowercase hexadecimal characters |
| `interlock_digest` | 64 lowercase hexadecimal characters |
| `issued_at_ms` | canonical integer UTC Unix milliseconds |
| `kind` | one exact kind below |
| `message_time_ms` | producer time for this message; consumer checks trusted time separately |
| `mode` | `MODE_1`, `MODE_2`, or `MODE_3` |
| `not_before_ms` | canonical integer UTC Unix milliseconds |
| `nonce` | 64 lowercase hexadecimal characters; unique in a transcript |
| `operation_id` | 32 lowercase hexadecimal characters |
| `oracle_sha256` | `94578afd81a13aab31904f1fb3c8733addd8718658602f638ad4086d2e9d4df0` |
| `prior_transcript_digest` | previous message digest; 64 zeroes for sequence zero |
| `protocol` | `SBP-LEX-WIRE/1` |
| `request_digest` | 64 lowercase hexadecimal characters |
| `replay_namespace` | 64 lowercase hexadecimal characters |
| `runtime_subject` | 40 or 64 lowercase hexadecimal characters |
| `runtime_tree` | 40 or 64 lowercase hexadecimal characters |
| `sequence` | canonical integer described above |
| `signature_algorithm` | `NONE`, `ML-DSA-65`, or `ML-DSA-87` |
| `signature_hex` | lowercase hexadecimal signature or `NONE` |
| `signer_key_id`, `signer_role` | derived signer identity and `NONE`, `AUTHORITY`, `ADAPTER`, or `WATCHDOG` |
| `signing_public_key_hex` | lowercase hexadecimal public key or `NONE` |
| `state_digest` | 64 lowercase hexadecimal characters |
| `transcript_digest` | digest defined below |
| `traversal_id` | 32 lowercase hexadecimal characters |
| `watchdog_key_class`, `watchdog_key_id` | independently admitted watchdog custody class and key ID |

`not_before_ms <= issued_at_ms < expires_at_ms` is mandatory. A consumer also
supplies its own trusted current time and rejects messages outside the interval.
Time equality or caller assertion alone is not freshness proof.

`NONE`/`NOT_CHECKED` requires a zero `crypto_evidence_digest`, `signature_algorithm
= NONE`, `signature_hex = NONE`, and `signing_public_key_hex = NONE`. A checked
message says `SIGNATURE_PRESENT` and requires an admitted key class, nonzero evidence digest, supported
algorithm, public key and signature. The signature is over the transcript digest
bytes with domain `SBP-LEX-WIRE/1\0SIGNATURE\0<kind>\0`. The consumer must verify
the signature and derive `signer_key_id = SHA-256(public-key-bytes)` against the
role-specific admitted key ID/class. Labels and digests are never accepted as cryptographic
proof. Golden vectors use `TEST_FIXTURE` with deterministic synthetic signature
bytes and therefore may be checked structurally but never as production evidence.

## Kinds and exact additions

The permitted successful lifecycle order is:

| Sequence | Kind | Additional fields |
|---:|---|---|
| 0 | `convergence_request` | branch provenance; A/B/policy projections; mode evidence type/digest; candidate/pathway input/output sets; validator/no-widening certificates; snapshot digests |
| 1 | `convergence_result` | `convergence_digest`, `decision` |
| 2 | `prepare_request` | `convergence_digest` |
| 3 | `prepare_result` | `decision`, `prepare_proof_digest` |
| 4 | `commit_request` | `prepare_proof_digest` |
| 5 | `commit_result` | `capability_digest`, `decision` |
| 6 | `lease_redeem_request` | `capability_digest`, `lease_deadline_ms`, `lease_digest` |
| 7 | `lease_redeem_result` | `decision`, `lease_deadline_ms`, `lease_digest` |
| 8 | `watchdog_arm_request` | `lease_digest`, `watchdog_deadline_ms` |
| 9 | `watchdog_arm_result` | `decision`, `watchdog_deadline_ms`, `watchdog_digest` |
| 10 | `effect_permit_request` | `lease_deadline_ms`, `lease_digest`, `point_of_use_digest`, `watchdog_deadline_ms`, `watchdog_digest` |
| 11 | `effect_permit_result` | `decision`, `permit_deadline_ms`, `permit_digest`, `watchdog_digest` |
| 12 | `effect_receipt` | `adapter_consumed_at_ms`, `adapter_consumption_digest`, `effect_outcome`, `permit_digest`, `receipt_digest`, `watchdog_digest` |
| 13 | `receipt_ack` | `decision`, `receipt_digest`, `receipt_status`, `watchdog_digest` |
| 14 | `watchdog_terminal` | `permit_digest`, `receipt_digest`, `watchdog_digest`, `watchdog_status` |
| 15 | `watchdog_result` | `decision`, `watchdog_digest` |

All fields ending in `_digest` use 64 lowercase hexadecimal characters. Decisions
are `ALLOW`, `ACK`, `DENY` or `BLOCK`. Successful results use `ALLOW` or `ACK` and
`error_code=NONE`. `DENY` or `BLOCK` requires a non-`NONE` error code. Effect
outcomes are `SUCCEEDED`, `FAILED` or `UNKNOWN`; watchdog status is `HEALTHY`,
`STOP` or `TIMEOUT`.

For Mode 1, the consumer requires three-way exact equality of
`projection_a_digest`, `projection_b_digest`, and `policy_projection_digest`, plus
distinct admitted branch-provenance digests. For Mode 2, `projection_b_digest` is
the independently recomputed admitted-output projection and
`mode_evidence_digest` binds validator, no-widening, pathway-space subset and
admissibility-reduction evidence; the output must equal the policy projection.
The Mode 2 input/output sets are sorted, unique comma-separated SHA-256 values;
both candidate and pathway outputs must be nonempty strict subsets of their
inputs. This makes reduction and no-widening directly checkable. For Mode 3, both projection fields equal the single sealed-state projection and
`mode_evidence_digest` binds the single-state proof. A mode-inappropriate relation
is rejected.

The deadline integers must remain within the common validity interval. Lease,
watchdog and permit deadline handoffs must be exactly equal. The watchdog is armed
before point-of-use permit issuance. `watchdog_terminal` represents either the
bound receipt (`HEALTHY`) or the absence/failure condition (`STOP`/`TIMEOUT`) and
is always required. A healthy terminal requires a nonzero receipt digest. A
no-receipt STOP/TIMEOUT tail branches directly from the permit into
`watchdog_terminal` then `watchdog_result=BLOCK`; it uses a zero receipt digest.
A recorded failed/unknown receipt uses the receipt tail, `receipt_ack=ACK` with
`FAILURE_RECORDED`/`UNKNOWN_BLOCKED`, then STOP and BLOCK.

`effect_permit_result` is not itself reusable authority transport. The admitted
adapter must atomically check trusted current time, exact adapter boundary,
capability/lease/permit/watchdog bindings and protected single-use state, consume
the permit in the durable replay namespace, and emit `adapter_consumption_digest`
in the immediately following receipt. The receipt digest binds that consumption
record. Missing, delayed, duplicate or mismatched consumption fails closed.

A denial terminates the lifecycle. Continuing after denial is invalid and must
fail closed. The v1 happy-path order above is deliberately finite; retries require
a new traversal identifier, challenge and nonces.

## Transcript digest and binding

Remove both `transcript_digest` and `signature_hex`, canonically encode the
remaining object as `M`, then:

```
SHA-256(
  ASCII("SBP-LEX-WIRE/1") || 0x00 ||
  ASCII("TRANSCRIPT")     || 0x00 ||
  ASCII(kind)             || 0x00 ||
  M
)
```

The lowercase hexadecimal result is `transcript_digest`. The kind in the domain
prefix must equal the kind inside `M`.

Transcript validation additionally requires:

- exact sequence and kind order;
- a continuous `prior_transcript_digest` chain;
- one immutable protocol/oracle/runtime/traversal/mode/challenge and exact
  request/state/effect/adapter binding;
- a unique nonce for every message;
- equality of each hand-off digest at its next use (convergence, PREPARE proof,
  capability, lease, permit, receipt and watchdog);
- no message after a denial.

Any parsing, canonicalization, digest, binding, linkage, order, replay or status
failure is an error. There is no permissive recovery mode.
