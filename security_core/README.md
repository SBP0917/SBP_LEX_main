# SBP-LEX V2 isolated Rust security core

This workspace is isolated from the active Python pipeline. It verifies the
mapped V2 formats and returns a closed, veto-only decision. It never creates a
governance `ALLOW` or a licence.

The current V2 signed-object format is the fixed
`SBP_LEX_V2_ML_DSA_87_ED448_AND_V1` suite. Verification is strict AND: the
ML-DSA-87 and Ed448 lanes must both verify the same canonical bytes, purpose,
epoch and application context. The envelope binds the active suite policy and
two distinct lane-custody records. Shared provider identities, shared custody
references, revoked lanes, unadmitted production custody and retired-suite
metadata fail closed.

In-process signing exists only in test builds. Production effect authority is
deliberately unsupported until two independent, externally admitted,
non-exportable custody providers and their real attestations are supplied.
Windows provider probing does not establish that custody. There is no
production software-signing or single-lane fallback, and an algorithm change
requires a new suite identifier plus explicit admission.

Run with:

```powershell
C:\Users\LeighMC\.cargo\bin\cargo.exe test --manifest-path security_core\Cargo.toml
```
