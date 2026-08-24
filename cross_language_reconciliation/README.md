# Candidate 10 cross-language semantic reconciliation

Status: local assurance tooling only. It grants no execution, production, live,
deployment, safety, owner-admission, or external-IV&V authority.

This package compares lifecycle **meaning**, not test counts. Its normalized
observation covers:

- exact convergence and the mode-specific evidence shape;
- PREPARE as a single non-authorizing result;
- one sole-authority COMMIT result;
- the stable replay identity `(authority_epoch, durable_consumption_digest)`;
- lease, watchdog-arm and point-of-use permit handoffs;
- atomic permit revalidation immediately before consumption;
- half-open lease, watchdog and permit deadlines;
- success, failure, unknown-outcome and no-receipt timeout tails; and
- receipt acknowledgement, signed watchdog terminal and final watchdog result.

`observation_schema.json` fixes the normalized lifecycle fields and invariants.
`case_catalog.json` fixes the required three-mode by four-outcome matrix, exact
deadline-boundary cases, and executable replay/transplant/confusion negatives.
The Python adapter validates the existing shared wire-v2 JSONL with the wire-v2
validator before normalizing it. It never treats a matching count as semantic
equivalence.

The Rust wire-v2/raw-authority adapter already parses exact bounded native frame
output and derives the normalized observations from those frames. A matching
Rust matrix remains exactly
`OPEN_NATIVE_OUTPUT_ADAPTER_BINARY_IDENTITY_UNATTESTED`: the output carries a
claimed binary SHA-512, but this local parser does not authenticate the binary
identity. A semantic mismatch is still a hard FAIL.

No repository-defined machine-readable GNATprove or TLC output format currently
maps native tool output to the normalized lifecycle observation schema. SPARK
and formal/TLA captures may instead use the strict
`native_tool_raw_output_bundle` container. It binds, without interpreting:

- the complete stdout, stderr and tool-identity output bytes by exact size and
  SHA-512;
- the process exit status and `COMPLETE_UNTRUNCATED` terminal marker;
- the exact candidate commit and tree;
- the exact SPARK or formal component source-aggregate SHA-512; and
- the expected tool name and an observed, nonzero claimed binary SHA-512.

The container is bounded and canonical. It rejects truncation, malformed or
duplicate-key JSON, hash/size mismatches, absent output, missing identity output,
wrong candidate/source bindings, and any claim that this parser verified binary
identity attestation. Its only admitted attestation value is `UNAVAILABLE`, and
its only lane status is
`OPEN_NATIVE_OUTPUT_ADAPTER_SEMANTIC_MAPPING_UNAVAILABLE`. A zero exit status,
matching text, or invariant count cannot change that OPEN status.

Exact raw-bundle tool/lane pairs are `spark_safety_monitor` / `gnatprove` and
`formal_model` / `tlc2.TLC`. The canonical bundle schema is
`SBP-LEX-C10-RAW-NATIVE-TOOL-OUTPUT-BUNDLE/1` with the structural shape below
(blob objects contain the entire byte sequence as lowercase hexadecimal). The
placeholders are illustrative only; an admitted file is compact, sorted,
newline-terminated canonical JSON with exact numeric sizes and digests.

```json
{
  "candidate": {
    "commit": "<Git object id>",
    "source_aggregate_sha512": "<128 lowercase hex>",
    "tree": "<Git object id>"
  },
  "execution": {
    "exit_status": 0,
    "stderr": {"bytes_hex": "", "sha512": "<SHA-512 of empty bytes>", "size": 0},
    "stdout": {"bytes_hex": "<full output hex>", "sha512": "<128 lowercase hex>", "size": 1}
  },
  "lane": "spark_safety_monitor",
  "producer": {
    "claimed_binary_sha512": "<nonzero 128 lowercase hex>",
    "identity_attestation": "UNAVAILABLE",
    "tool": "gnatprove",
    "tool_identity_output": {"bytes_hex": "<full identity output hex>", "sha512": "<128 lowercase hex>", "size": 1}
  },
  "schema": "SBP-LEX-C10-RAW-NATIVE-TOOL-OUTPUT-BUNDLE/1",
  "termination": "COMPLETE_UNTRUNCATED"
}
```

Other canonical observation sets remain OPEN even when exact hashes and values
match because no native-output adapter proves their provenance. Opaque output
also remains OPEN. The independent-verifier V1 text adapter can parse its strict
record sequence, but that profile lacks the full wire-v2 three-mode matrix, so a
lone trace remains OPEN.

## Usage

Explicit non-evidentiary synthetic run (allowed in a dirty builder worktree):

```text
python -I cross_language_reconciliation/reconcile.py \
  --synthetic-non-evidentiary --output <empty-or-new-directory>
python -I cross_language_reconciliation/verify_report.py \
  <directory>/reconciliation_report.json
```

An evidentiary run requires `--evidentiary`, an exact clean Git subject commit
and tree, an exact-hash capture manifest, and complete semantically comparable
lane observations. It refuses a dirty worktree and refuses an incomplete lane
set. Synthetic output is always labelled
`NON_EVIDENTIARY_SYNTHETIC_LOCAL_ASSURANCE`; it can never be upgraded by renaming
files or editing the report.

The output directory is closed: it contains exactly the canonical report and
its SHA-512 sidecar. The detached verifier uses only the Python standard library,
rejects duplicate-key/non-canonical JSON, checks the exact output path set,
re-hashes every bound source and capture, independently re-normalizes all shared
vectors, and rejects missing or extra cases.

## Copied-package detached verification

`detached_semantic_verifier.verify_detached_report` verifies copied report bytes
without consulting Git `HEAD` or a mutable worktree.  Its caller must provide:

- the exact expected subject commit and tree;
- the report and its exact canonical sidecar bytes; and
- an explicit `SemanticContentResolver` backed by an already authenticated
  immutable-object or closed-package inventory.

The resolver must contain every source named by `source_inventory`—including
the fixed case catalog, observation schema and vector bytes—and exactly one
nonempty capture for every required external lane. Missing closure returns the
typed `OPEN_OBSERVATION_ONLY` result with the exact missing paths, hashes and
sizes. Altered, extra, ambiguous or semantically inconsistent bytes are a hard
failure. `OPEN_OBSERVATION_ONLY` is not evidence readiness, production or live
authority, even when the copied report and sidecar are internally consistent.
