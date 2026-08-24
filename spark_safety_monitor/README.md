# SBP-LEX SPARK Safety Monitor

This directory is an independently implemented, node-free SPARK/Ada safety
monitor for the highest-consequence execution path. It supplements the Rust
trusted core; it does not replace that core and it cannot grant SBP-LEX
authority on its own.

The monitor enforces a fail-closed sequence:

1. exact convergence and a signed, expiring, non-authorizing PREPARE proof;
2. single-use COMMIT under fresh production non-exportable HSM/TPM custody and
   a separately controlled, fresh, exact-binding safety-inhibit PERMIT;
3. issuance of a short-lived, exact adapter/effect lease;
4. one-use point-of-use redemption and a separate final effect-permit check;
5. an exact signed post-effect receipt strictly before a receipt deadline that
   cannot exceed either lease or point-of-use permit expiry, or watchdog
   fail-close at the deadline.

Every transition binds the same request, state, effect and adapter identifiers
and a strictly increasing sequence number. Failure, uncertainty, expiry,
mutation, replay, fixture custody, unavailable custody, inhibit BLOCK/STOP,
identity mismatch or missing receipt leads to `Fail_Closed`. The inhibit can
hold the current state or block it; it cannot create or widen authority.
The watchdog timeout may determine when STOP is asserted after a lost receipt,
but it cannot extend successful authorization beyond the lease/permit window;
deadline equality is expired.

## Verification

From this directory:

```powershell
alr build
alr gnatprove -P spark_safety_monitor.gpr --mode=all --level=2 --report=all
```

The executable contains positive and negative contract assertions. GNATprove
is the controlling check for the SPARK contracts; compilation alone is not a
proof.

On 24 August 2026, the repository-local Alire 2.1.1 toolchain completed the
build, executable assertions, Python harness, and GNATprove
`--mode=all --level=2 --report=all`; GNATprove reported all 53 checks proved.
Exact tool, lockfile, source and executable hashes are recorded in
`evidence/v2/spark-proof-evidence.json`. This is mutable, non-independent
repository evidence and is not a university result or production admission.

## Assurance boundary

This source proves properties of the monitor state machine once GNATprove
passes. Cryptographic verification results and hardware attestations are typed
inputs to the monitor. The source does **not** prove that a real HSM/TPM or
out-of-band circuit exists, is independently controlled, or is correctly
integrated. Those remain OPEN until physical custody, device configuration,
independent verification and immutable evidence are supplied. This component
is not production authority and makes no uncrackability or safety claim.
