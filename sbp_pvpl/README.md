# SBP-LEX V2 detached Public Verification Publication Layer

`sbp_pvpl` is a local, read-only verifier and privacy-minimal claim exporter.
It has its own explicit V2 contract (`SBP_LEX_V2_PVPL_V1` and
`sbp.lex.v2.pvpl.* /1` schemas). It does not reuse or silently relabel the
historical PVPL-02 contract.

An optional additive `/2` hybrid wrapper is available in
`sbp_lex.local_trust.pqc_wrapper`. It preserves the exact PVPL `/1` document
bytes and SHA-512 digest, requires externally supplied owner pins and both
ML-DSA-87 and Ed448 signatures, and grants no admission, activation, runtime
attachment or authority. It does not replace any PVPL `/1` validation step.

## Input trust boundary

PVPL accepts exactly two canonical redacted result artifacts, in locked order:
PTDE and local trust. Each result must bind the SHA-512 digest of the complete
source verifier result, its evidence head, accepted-history snapshot, monotonic
sequence and current head. A separate detached independent-verification receipt
must bind those exact values and a verifier trust-root digest.

Neither a package's own PASS claim nor a receipt's own VERIFIED label is enough.
Every result, receipt, trust-root digest, source-history digest and current head
must match a separately supplied canonical external-acceptance pin document.
The pins are an out-of-band trust input. This module deliberately does not
create, authenticate or pretend to host an independent verifier trust root.

An externally pinned accepted-publication history is also mandatory. Its exact
SHA-512 digest, sequence and current head must match. Previously accepted result,
receipt or claim digests are rejected as replay; a lower source-history sequence
is stale; a changed current head or publication-history pin is rejected as
rollback or mismatch. PVPL does not advance or persist accepted history.

## Redaction and claim scope

All schemas are exact: missing, malformed, unknown and extra fields fail closed.
The output allowlist contains only fixed vocabulary, integers and lowercase
SHA-512 digests. Source paths, secrets, keys, credentials, personal identities,
host/device identifiers, network identifiers and runtime/toolchain/OS
fingerprints are not publishable fields and are rejected.

The only successful result is
`PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED`. The claim always states
`NOT_ADMITTED`, `NOT_ACTIVATED`, and no runtime, governance, licence, execution,
effect, audit, token, hash-chain or publication-activation authority.

## Local CLI

The only commands are:

```text
python -m sbp_pvpl validate <six required input flags>
python -m sbp_pvpl show <six required input flags>
python -m sbp_pvpl export-redacted <six required input flags> --output FILE
```

Required inputs are `--ptde-result`, `--ptde-receipt`,
`--local-trust-result`, `--local-trust-receipt`, `--external-pins` and
`--accepted-history`. Inputs must be exact canonical JSON documents. Export is
local only, creates a new regular file exclusively, fsyncs it, and never
overwrites an existing object. No command performs network access, external
publication, publication activation, runtime attachment or repository mutation.

The earlier DUAL_V6 Desktop V1 PVPL implementation was not present in this
workspace, its Git history, or the available Desktop V1 reconstruction. This
V2 package therefore retains compatibility only at the non-authorizing concept
level; it makes no claim of byte/schema compatibility with unavailable V1 code.
