# SBP-LEX authority evidence wire v2

V2 supersedes the F084 v1 contract for authority-bearing integration. V1 remains
transport-only evidence and must not authorize convergence or effects.

The fixed carrier uses execution projection schema
`SBP-LEX-EXEC-PROJECTION/2`. Every message and disclosed projection binds the
exact disabled extension-admission mode, schema, configuration digest, and
extension-admission binding digest from the owner-pinned `AdmissionPolicy`.
Required extension mode is unreachable; omission and downgrade are rejected.

- `SPEC.md` is normative.
- `python/` and `rust/` are independent implementations.
- `vectors/` contains deterministic TEST_ONLY Mode 1/2/3, success, failed,
  unknown-outcome and timeout lifecycles, explicit fixture registry, staged-
  context digests and cross-language lifecycle/artifact derivations.
- `vectors/adversarial_cases.txt` names cross-language negative requirements.

The implementations require a caller-provided signature verifier and externally
pinned role registry/trust root. Their included deterministic fixture verifier is
test-only and cannot represent HSM/TPM or production ML-DSA custody.

`validate_request_prefix` produces a language-local verified stage context before
any authority response. `validate_and_append_result` accepts only an already
signed result and revalidates request context, result chain/signature/time and
every stage-derived field. The wire exposes no signer callback or generic
authority dispatch; signing is a private, stage-specific service concern. A permit
must remain buffered inside the future
synchronous Rust authority-to-adapter operation until atomic consumption; this
contract does not route or expose one to Python.

The returned point-of-use context is verification-only and non-authorizing.
Rust intentionally makes it non-`Clone`; the future service must wrap it in a
private move-only typestate that couples final prefix revalidation, durable
single-use claim and exactly one adapter invocation. The wire package does not
perform or authorize that invocation.

Python isolated test lane:

```powershell
python -I -B wire_protocol/v2/run_python_tests.py
```

Rust test lane:

```powershell
cargo test --manifest-path wire_protocol/v2/rust/Cargo.toml
```

V2 is a self-contained contract only. It does not change live Python authority
routing and does not itself provision a production owner root, ML-DSA key, HSM,
TPM, adapter or external service.
