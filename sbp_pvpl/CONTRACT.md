# V2 PVPL contract index

- `sbp.lex.v2.pvpl.verified-redacted-result/1`: privacy-minimal result of a
  separately completed PTDE or local-trust verification.
- `sbp.lex.v2.pvpl.detached-verification-receipt/1`: exact binding receipt for
  that redacted result and its externally selected verifier trust-root digest.
- `sbp.lex.v2.pvpl.external-acceptance-pins/1`: caller-supplied out-of-band pins
  for both sources, both receipts and the accepted-publication history.
- `sbp.lex.v2.pvpl.accepted-publication-history/1`: externally persisted replay
  and rollback snapshot; PVPL verifies but never changes it.
- `sbp.lex.v2.pvpl.public-verification-claim/1`: deterministic redacted local
  export candidate with no authority and no publication activation.
- `sbp.lex.v2.pvpl.validation-report/1`: local validation acknowledgement only.

All digest fields use lowercase 128-character SHA-512 over canonical JSON with
the digest field omitted. Receipt `bindings_sha512` covers exactly the locked
binding field set. Canonical documents are UTF-8, NFC, UTF-16-key-ordered,
whitespace-free JSON followed by one LF; floats, duplicate keys, non-finite
numbers and non-canonical encodings are rejected.

The additive `sbp.lex.v2.detached-hybrid-signed-wrapper/2` contract does not
change any PVPL `/1` object. It signs the exact canonical PVPL document bytes as
an opaque payload using both ML-DSA-87 and Ed448 and externally supplied owner
pins. The outer wrapper remains `NOT_ADMITTED`, `NOT_ACTIVATED`, runtime
detached and non-authorizing; PVPL does not accept the wrapper as publication
activation or as a substitute for its existing external acceptance pins.
