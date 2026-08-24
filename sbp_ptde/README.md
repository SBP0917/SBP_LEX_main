# SBP-LEX V2 P/T/D/E verifier core

This package verifies explicit immutable Git objects from a bare repository or
object database. It never selects commits through `HEAD`, branches, tags,
abbreviations, replacement refs, grafts, or a working tree. The verifier takes
four full commit OIDs, a separately supplied out-of-band expected P OID, an
out-of-band SHA-512 pin for the exact Git executable, and an immutable accepted
attempt-history snapshot with a separately supplied out-of-band SHA-512 pin.
The verifier is read-only. Deployment must durably advance and re-pin that
history after accepting a successful E result; the verifier never derives the
history from E or silently persists it itself.

P contains the fixed policy and the source subject. T is P's sole child and
adds only `ptde_subjects/T_TEST_BUILD_PROFILE.json`. D is T's sole child and
adds only `ptde_subjects/D_RUNTIME_DESCRIPTOR.json`. E is D's sole child and
adds only the manifest and its exact declared blobs beneath the selected
`evidence/ptde/<campaign_id>/` subtree.

The verifier does not build a subject, execute evidence lanes, choose an
architecture, create authority, admit production, or mutate source, a ledger,
runtime state, or an evidence repository. A verified chain returns only
`PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED` with the policy's exact narrow
claim text.

Each T lane fixes its own exact command and output contract. Whole-lane elapsed
time is bounded by 7200 seconds including setup and cleanup. E rejects every
timed-out lane. A timeout must be retained as `TIMEOUT_FAIL_CLOSED` evidence;
it cannot be relabelled as a successful attempt.
Each successful lane also requires an exact canonical committed transcript
under `sbp.lex.v2.ptde.lane-transcript/1`. The transcript binds the lane
contract, D, attempt, timing, full stdout/stderr bytes, artifacts, cleanup and
non-mutation assertions. This proves only what the committed bytes state; it
is not independent external command-execution attestation.

Public Python APIs are `verify_ptde_chain`, `verify_ptde_result`,
`validate_verification_result`, `expected_policy`, and
`policy_document_bytes`. The CLI entry is `python -m sbp_ptde verify ...`.
The accepted-history value types are `AcceptedAttemptHistory` and
`AcceptedAttemptRecord`.

## Additive detached PQC wrapper

PTDE `/1` schemas, canonical bytes and result digests are unchanged. A caller
may treat an already-produced exact PTDE canonical document as opaque payload
bytes for `sbp.lex.v2.detached-hybrid-signed-wrapper/2` in
`sbp_lex.local_trust.pqc_wrapper`. That outer ML-DSA-87 + Ed448 wrapper is a
separate, non-authorizing `/2` artifact; PTDE does not create its owner pins,
admit it, or reinterpret it as PTDE verification evidence.
