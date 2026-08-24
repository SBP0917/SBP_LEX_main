"""Generate the Python half of the strict dual-signature reciprocal vectors."""

from __future__ import annotations

import base64
import json
from hashlib import sha512
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
    hybrid_signature_preimage,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "hybrid_signature_rust" / "tests" / "vectors" / "python_v2.json"
PURPOSE = "SBP_LEX_V2_TEST_VECTOR"
PAYLOAD = {"n": 7, "schema_id": "sbp.lex.v2.test-payload/1"}


def generate() -> dict[str, object]:
    provider = HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
        MLDSA87PrivateKey.from_seed_bytes(bytes(range(32))),
        Ed448PrivateKey.from_private_bytes(bytes(range(57))),
        provider_id="TEST_ONLY:PYTHON_HYBRID_VECTOR",
        key_epoch=7,
        key_version="vector-1",
    )
    context = provider.hybrid_verification_context(allow_test_only=True)
    signed = build_hybrid_signed_object(PAYLOAD, provider=provider, purpose=PURPOSE)
    protected = {
        key: value
        for key, value in signed["signature"].items()
        if key != "signatures"
    }
    preimage = hybrid_signature_preimage(PAYLOAD, protected)
    payload_bytes = canonical_json_bytes(PAYLOAD)
    signatures = signed["signature"]["signatures"]
    return {
        "suite": HYBRID_SUITE_ID,
        "verification_rule": STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
        "purpose": PURPOSE,
        "authority_epoch": context.key_epoch,
        "payload_b64": base64.b64encode(payload_bytes).decode("ascii"),
        "application_context_b64": base64.b64encode(
            canonical_json_bytes(context.public_record())
        ).decode("ascii"),
        "preimage_b64": base64.b64encode(preimage).decode("ascii"),
        "preimage_sha512": sha512(preimage).hexdigest(),
        "mldsa87_public_key_b64": base64.b64encode(
            context.mldsa87_public_key_bytes
        ).decode("ascii"),
        "ed448_public_key_b64": base64.b64encode(
            context.ed448_public_key_bytes
        ).decode("ascii"),
        "mldsa87_signature_b64": signatures[0]["signature_b64"],
        "ed448_signature_b64": signatures[1]["signature_b64"],
    }


def main() -> None:
    OUTPUT.write_text(
        json.dumps(generate(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    print(OUTPUT.relative_to(ROOT).as_posix())


if __name__ == "__main__":
    main()
