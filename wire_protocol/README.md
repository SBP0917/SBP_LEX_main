# SBP-LEX Python-Rust wire contract

This directory is a self-contained, node-free integration contract for the future
Python orchestration to Rust authority boundary. It does not alter current live
authority routing.

- `SPEC.md` is normative.
- `python/sbp_lex_wire.py` is the Python implementation.
- `rust/` is an independently written dependency-free Rust implementation.
- `vectors/golden_transcript.jsonl` is the shared positive transcript.
- `vectors/adversarial_cases.txt` is the mandatory shared negative-vector set.

The implementations do not invoke each other and share no parser or encoder code.
Both must accept every golden line, reproduce every byte, reproduce every SHA-256
transcript digest, validate the same complete transcript, and reject every named
adversarial vector.

The transport uses a four-byte big-endian length prefix and a maximum payload of
16 KiB. Payloads are strict canonical flat JSON, never pickle or executable object
serialization.

The vectors use `TEST_FIXTURE` cryptographic status only. A parser success is not
a signature verification, key-custody statement, authorization or production
admission.

Run the Python lane without installation, `PYTHONPATH`, site packages or ambient
imports:

```powershell
python -I -B wire_protocol/run_python_tests.py
```

Run the independent Rust lane from `wire_protocol/rust` with `cargo test`.

The Rust implementation verifies canonical bytes, SHA-256 transcript digests,
bindings, lifecycle and structural cryptographic evidence independently. It does
not contain an ML-DSA provider. `crypto_result=SIGNATURE_PRESENT` is intentionally
not a verified result. Before any production use, a consumer must use
`signature_preimage`, verify each signature with an admitted independently
provisioned public key, and require the declared role-specific HSM/TPM custody
class. `TEST_FIXTURE` vectors are deliberately non-interchangeable with production
artifacts.
