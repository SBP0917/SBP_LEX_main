from __future__ import annotations

import base64
import json
from copy import deepcopy
from hashlib import sha512
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.security.application_integrity import (
    _trust_provider_identity,
    _verify_signed_object_with_pinned_ed25519_key,
)
from sbp_lex.security.authority_trust import (
    AUTHORITY_TRUST_ROLE_SKG,
    role_pin_from_provider,
    verify_pinned_signed_object,
)
from sbp_lex.security.hybrid_signature import (
    ED448_SIGNATURE_BYTES,
    HYBRID_DOMAIN,
    HYBRID_ENVELOPE_SCHEMA_ID,
    HYBRID_PREIMAGE_DOMAIN,
    HYBRID_SUITE_ID,
    ML_DSA_87_SIGNATURE_BYTES,
    PRODUCTION_DUAL_CUSTODY_CLASS,
    PRODUCTION_SIGNER,
    RETIRED_HYBRID_SUITE_ID,
    STRICT_DUAL_SIGNATURE_SUITE_ID,
    STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
    TEST_ONLY_CUSTODY_CLASS,
    TEST_ONLY_SIGNER,
    DualSignatureLaneCustody,
    HybridMLDSA87Ed448SoftwareProvider,
    HybridSignatureError,
    HybridVerificationContext,
    hybrid_signature_preimage,
    verify_hybrid_signed_object,
)
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    SignatureProviderUnavailable,
    build_legacy_non_effect_signed_object,
    build_signed_object,
    verify_legacy_non_effect_signed_object,
    verify_signed_object,
)
from sbp_lex.security.token_stack import _signature_envelope_exact


def fixed_provider() -> HybridMLDSA87Ed448SoftwareProvider:
    return HybridMLDSA87Ed448SoftwareProvider.from_private_keys(
        MLDSA87PrivateKey.from_seed_bytes(bytes(range(32))),
        Ed448PrivateKey.from_private_bytes(bytes(range(57))),
        provider_id="TEST_ONLY:PYTHON_HYBRID_VECTOR",
        key_epoch=7,
        key_version="vector-1",
        three_p_attestation_admitted=True,
        skg_attestation_admitted=True,
    )


def production_lane_custody(
    *, algorithm: str, provider_id: str, reference: str, admission: str
) -> DualSignatureLaneCustody:
    return DualSignatureLaneCustody(
        algorithm=algorithm,
        provider_id=provider_id,
        key_version="production-1",
        key_epoch=11,
        rotation_epoch=11,
        custody_class=f"EXTERNAL_NON_EXPORTABLE_{algorithm}",
        custody_reference=reference,
        signer_class=PRODUCTION_SIGNER,
        external_custody_admitted=True,
        custody_admission_sha512=admission,
        non_exportable=True,
    )


def test_exact_hybrid_round_trip_and_locked_metadata() -> None:
    provider = fixed_provider()
    purpose = "SBP_LEX_V2_TEST_VECTOR"
    value = build_signed_object(
        {"schema_id": "sbp.lex.v2.test-payload/1", "value": "e\u0301", "n": 7},
        provider=provider,
        purpose=purpose,
    )
    context = provider.hybrid_verification_context(allow_test_only=True)
    envelope = value["signature"]

    assert envelope["schema_id"] == HYBRID_ENVELOPE_SCHEMA_ID
    assert envelope["suite"] == HYBRID_SUITE_ID
    assert envelope["suite"] == STRICT_DUAL_SIGNATURE_SUITE_ID
    assert envelope["verification_rule"] == STRICT_DUAL_SIGNATURE_VERIFICATION_RULE
    assert envelope["lane_independence_required"] is True
    assert envelope["domain"] == HYBRID_DOMAIN
    assert envelope["purpose"] == purpose
    assert envelope["key_epoch"] == 7
    assert envelope["context_digest"] == context.context_digest
    assert envelope["ordered_key_set_digest"] == context.ordered_key_set_digest
    assert [lane["algorithm"] for lane in envelope["lanes"]] == [
        "ML-DSA-87",
        "Ed448",
    ]
    assert envelope["lanes"][0]["key_id"] == sha512(
        context.mldsa87_public_key_bytes
    ).hexdigest()
    assert envelope["lanes"][1]["key_id"] == sha512(
        context.ed448_public_key_bytes
    ).hexdigest()
    assert len(base64.b64decode(envelope["signatures"][0]["signature_b64"])) == (
        ML_DSA_87_SIGNATURE_BYTES
    )
    assert len(base64.b64decode(envelope["signatures"][1]["signature_b64"])) == (
        ED448_SIGNATURE_BYTES
    )
    assert _signature_envelope_exact(envelope)
    assert not verify_signed_object(
        value,
        provider=provider,
        purpose=purpose,
    )
    assert not verify_hybrid_signed_object(
        value,
        trust_context=None,
        owner_pinned_context_digest=context.context_digest,
        expected_purpose=purpose,
    )
    assert verify_signed_object(
        value,
        provider=None,
        purpose=purpose,
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        allow_legacy_non_effect=False,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["signature"]["signatures"].pop(),
        lambda value: value["signature"]["signatures"].reverse(),
        lambda value: value["signature"]["signatures"].__setitem__(
            1, deepcopy(value["signature"]["signatures"][0])
        ),
        lambda value: value["signature"]["lanes"].__setitem__(
            1, deepcopy(value["signature"]["lanes"][0])
        ),
        lambda value: value["signature"]["lanes"][0].update(algorithm="ML-DSA-65"),
        lambda value: value["signature"].update(suite=RETIRED_HYBRID_SUITE_ID),
        lambda value: value["signature"].update(verification_rule="ANY_LANE"),
        lambda value: value["signature"].update(purpose="OTHER_PURPOSE"),
        lambda value: value["signature"].update(key_epoch=6),
        lambda value: value["signature"].update(context_digest="0" * 128),
        lambda value: value["signature"].update(payload_sha512="0" * 128),
        lambda value: value["signature"]["signatures"][0].update(
            signature_b64=base64.b64encode(b"x" * ML_DSA_87_SIGNATURE_BYTES).decode()
        ),
        lambda value: value["signature"]["signatures"][1].update(
            signature_b64=base64.b64encode(b"x" * ED448_SIGNATURE_BYTES).decode()
        ),
        lambda value: value.update(value="tampered"),
    ],
)
def test_hybrid_rejects_partial_downgraded_or_mutated_objects(mutation) -> None:
    provider = fixed_provider()
    context = provider.hybrid_verification_context(allow_test_only=True)
    value = build_signed_object(
        {"schema_id": "sbp.lex.v2.test-payload/1", "value": "original"},
        provider=provider,
        purpose="SBP_LEX_V2_HOSTILE_TEST",
    )
    hostile = deepcopy(value)
    mutation(hostile)
    assert not verify_signed_object(
        hostile,
        provider=None,
        purpose="SBP_LEX_V2_HOSTILE_TEST",
        trust_context=context,
        owner_pinned_context_digest=context.context_digest,
        allow_legacy_non_effect=False,
    )


def test_identical_binary_preimage_contract() -> None:
    provider = fixed_provider()
    purpose = "SBP_LEX_V2_TEST_VECTOR"
    value = build_signed_object(
        {"schema_id": "sbp.lex.v2.test-payload/1", "n": 7},
        provider=provider,
        purpose=purpose,
    )
    protected = {
        key: item
        for key, item in value["signature"].items()
        if key != "signatures"
    }
    preimage = hybrid_signature_preimage(
        {"schema_id": "sbp.lex.v2.test-payload/1", "n": 7},
        protected,
    )
    assert preimage.startswith(
        HYBRID_PREIMAGE_DOMAIN + HYBRID_SUITE_ID.encode("ascii") + b"\x00"
    )
    offset = len(HYBRID_PREIMAGE_DOMAIN) + len(HYBRID_SUITE_ID) + 1
    purpose_length = int.from_bytes(preimage[offset : offset + 2], "big")
    assert purpose_length == len(purpose.encode("utf-8"))
    assert preimage[offset + 2 : offset + 2 + purpose_length] == purpose.encode()
    assert sha512(preimage).hexdigest() == (
        "5aa72dcb91c9a88c3442c0b9a95b97c2788e393ccc46e448f218bb67281a1a42"
        "cd998f23e1b182318ba84e3335d6f6f3b574def3779b5f90ef70e46490c9dd84"
    )


def test_python_verifies_frozen_rust_signature_vector() -> None:
    vector_path = (
        Path(__file__).resolve().parents[1]
        / "hybrid_signature_rust"
        / "tests"
        / "vectors"
        / "rust_v2.json"
    )
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    assert set(vector) == {
        "suite",
        "verification_rule",
        "purpose",
        "authority_epoch",
        "payload_b64",
        "preimage_sha512",
        "mldsa87_signature_b64",
        "ed448_signature_b64",
    }
    assert vector["suite"] == STRICT_DUAL_SIGNATURE_SUITE_ID
    assert vector["verification_rule"] == STRICT_DUAL_SIGNATURE_VERIFICATION_RULE

    payload_bytes = base64.b64decode(vector["payload_b64"], validate=True)
    payload = json.loads(payload_bytes)
    assert canonical_json_bytes(payload) == payload_bytes

    provider = fixed_provider()
    signed = build_signed_object(
        payload,
        provider=provider,
        purpose=vector["purpose"],
    )
    protected = {
        key: item
        for key, item in signed["signature"].items()
        if key != "signatures"
    }
    assert protected["key_epoch"] == vector["authority_epoch"]
    preimage = hybrid_signature_preimage(payload, protected)
    assert sha512(preimage).hexdigest() == vector["preimage_sha512"]

    mldsa87_signature = base64.b64decode(
        vector["mldsa87_signature_b64"], validate=True
    )
    ed448_signature = base64.b64decode(
        vector["ed448_signature_b64"], validate=True
    )
    assert len(mldsa87_signature) == ML_DSA_87_SIGNATURE_BYTES
    assert len(ed448_signature) == ED448_SIGNATURE_BYTES

    context = provider.hybrid_verification_context(allow_test_only=True)
    context.mldsa87_public_key.verify(mldsa87_signature, preimage)
    context.ed448_public_key.verify(ed448_signature, preimage)


def test_partial_provider_result_has_no_fallback() -> None:
    provider = fixed_provider()

    class PartialProvider:
        algorithm = HYBRID_SUITE_ID

        def __getattr__(self, name):
            return getattr(provider, name)

        def hybrid_verification_context(self, *, allow_test_only=False):
            return provider.hybrid_verification_context(
                allow_test_only=allow_test_only
            )

        def sign_hybrid_preimage(self, preimage, *, purpose, context_digest):
            ml, _ = provider.sign_hybrid_preimage(
                preimage,
                purpose=purpose,
                context_digest=context_digest,
            )
            return ml, b""

    with pytest.raises(SignatureProviderUnavailable):
        build_signed_object(
            {"payload": "partial"},
            provider=PartialProvider(),
        )


def test_cross_message_or_cross_lane_signature_substitution_has_no_fallback() -> None:
    provider = fixed_provider()
    context = provider.hybrid_verification_context(allow_test_only=True)
    first = build_signed_object(
        {"schema_id": "sbp.lex.v2.test-payload/1", "value": "first"},
        provider=provider,
        purpose="SBP_LEX_V2_CROSS_MESSAGE_TEST",
    )
    second = build_signed_object(
        {"schema_id": "sbp.lex.v2.test-payload/1", "value": "second"},
        provider=provider,
        purpose="SBP_LEX_V2_CROSS_MESSAGE_TEST",
    )
    for ordinal in (0, 1):
        hostile = deepcopy(first)
        hostile["signature"]["signatures"][ordinal] = deepcopy(
            second["signature"]["signatures"][ordinal]
        )
        assert not verify_signed_object(
            hostile,
            provider=None,
            purpose="SBP_LEX_V2_CROSS_MESSAGE_TEST",
            trust_context=context,
            owner_pinned_context_digest=context.context_digest,
            allow_legacy_non_effect=False,
        )


def test_legacy_v1_is_explicitly_non_effect_only() -> None:
    provider = Ed25519SoftwareProvider.from_private_key(
        Ed25519PrivateKey.generate()
    )
    with pytest.raises(
        SignatureProviderUnavailable,
        match="HYBRID_SIGNATURE_PROVIDER_REQUIRED",
    ):
        build_signed_object({"payload": "legacy"}, provider=provider)
    value = build_legacy_non_effect_signed_object(
        {"payload": "legacy"},
        provider=provider,
    )
    assert set(value["signature"]) == {
        "provider_id",
        "algorithm",
        "key_id",
        "custody_class",
        "effect_authority",
        "signature_b64",
    }
    assert value["signature"]["algorithm"] == "Ed25519"
    assert value["signature"]["effect_authority"] is False
    assert verify_legacy_non_effect_signed_object(value, provider=provider)
    assert not verify_signed_object(value, provider=provider)
    assert not verify_signed_object(
        value,
        provider=provider,
        allow_legacy_non_effect=False,
    )
    assert not verify_signed_object(
        value,
        provider=provider,
        require_effect_authority=True,
    )
    value.pop("verified")
    assert not verify_signed_object(value, provider=provider)


def test_test_only_custody_is_explicit_and_production_without_custody_fails() -> None:
    provider = fixed_provider()
    test_context = provider.hybrid_verification_context(allow_test_only=True)
    assert test_context.signer_class == TEST_ONLY_SIGNER
    assert test_context.custody_class == TEST_ONLY_CUSTODY_CLASS
    assert test_context.effect_authority is False
    assert test_context.external_custody_admitted is False
    assert test_context.mldsa87_custody is not None
    assert test_context.ed448_custody is not None
    assert (
        test_context.mldsa87_custody.provider_id
        != test_context.ed448_custody.provider_id
    )
    assert (
        test_context.mldsa87_custody.custody_reference
        != test_context.ed448_custody.custody_reference
    )

    with pytest.raises(
        HybridSignatureError,
        match="DUAL_SIGNATURE_TWO_LANE_CUSTODY_REQUIRED",
    ):
        HybridVerificationContext(
            provider_id="production-provider",
            key_epoch=1,
            key_version="1",
            custody_class="PRODUCTION_HSM",
            signer_class=PRODUCTION_SIGNER,
            mldsa87_public_key=test_context.mldsa87_public_key,
            ed448_public_key=test_context.ed448_public_key,
        )

    production_context = HybridVerificationContext(
        provider_id="production-dual-coordinator",
        key_epoch=11,
        key_version="suite-1",
        custody_class=PRODUCTION_DUAL_CUSTODY_CLASS,
        signer_class=PRODUCTION_SIGNER,
        mldsa87_public_key=test_context.mldsa87_public_key,
        ed448_public_key=test_context.ed448_public_key,
        effect_authority=True,
        external_custody_admitted=True,
        external_custody_admission_sha512="3" * 128,
        mldsa87_custody=production_lane_custody(
            algorithm="ML-DSA-87",
            provider_id="production-mldsa87-provider",
            reference="production-mldsa87-custody",
            admission="1" * 128,
        ),
        ed448_custody=production_lane_custody(
            algorithm="Ed448",
            provider_id="production-ed448-provider",
            reference="production-ed448-custody",
            admission="2" * 128,
        ),
    )
    assert production_context.effect_authority is True
    assert production_context.external_custody_admitted is True

    with pytest.raises(
        HybridSignatureError,
        match="DUAL_SIGNATURE_LANE_CUSTODY_NOT_INDEPENDENT",
    ):
        HybridVerificationContext(
            provider_id="production-dual-coordinator",
            key_epoch=11,
            key_version="suite-1",
            custody_class=PRODUCTION_DUAL_CUSTODY_CLASS,
            signer_class=PRODUCTION_SIGNER,
            mldsa87_public_key=test_context.mldsa87_public_key,
            ed448_public_key=test_context.ed448_public_key,
            effect_authority=True,
            external_custody_admitted=True,
            external_custody_admission_sha512="3" * 128,
            mldsa87_custody=production_lane_custody(
                algorithm="ML-DSA-87",
                provider_id="shared-provider",
                reference="shared-custody",
                admission="1" * 128,
            ),
            ed448_custody=production_lane_custody(
                algorithm="Ed448",
                provider_id="shared-provider",
                reference="shared-custody",
                admission="2" * 128,
            ),
        )


def test_authority_pin_verifies_hybrid_and_rejects_legacy_admission() -> None:
    provider = fixed_provider()
    pin = role_pin_from_provider(
        role=AUTHORITY_TRUST_ROLE_SKG,
        provider=provider,
        evaluator_id="TEST_ONLY_EVALUATOR",
        evaluator_version="1",
        authority_credential_id="TEST_ONLY_CREDENTIAL",
    )
    value = build_signed_object({"payload": "authority"}, provider=provider)
    assert pin.algorithm == HYBRID_SUITE_ID
    assert pin.ed25519_public_key is None
    assert verify_pinned_signed_object(value, role_pin=pin)


def test_application_integrity_direct_pin_uses_hybrid_context() -> None:
    provider = fixed_provider()

    class ReleaseProvider:
        algorithm = HYBRID_SUITE_ID
        release_integrity_attestation_admitted = True
        release_integrity_signer_class = "TEST_ONLY"

        def __getattr__(self, name):
            return getattr(provider, name)

        def hybrid_verification_context(self, *, allow_test_only=False):
            return provider.hybrid_verification_context(
                allow_test_only=allow_test_only
            )

        def sign_hybrid_preimage(self, preimage, *, purpose, context_digest):
            return provider.sign_hybrid_preimage(
                preimage,
                purpose=purpose,
                context_digest=context_digest,
            )

    wrapper = ReleaseProvider()
    value = build_signed_object({"payload": "release"}, provider=wrapper)
    identity = _trust_provider_identity(wrapper, admission=False)
    context = wrapper.hybrid_verification_context(allow_test_only=True)
    assert identity["algorithm"] == HYBRID_SUITE_ID
    assert identity["ed25519_public_key_fingerprint"] == context.context_digest
    assert _verify_signed_object_with_pinned_ed25519_key(
        value,
        provider=wrapper,
        expected_fingerprint=context.context_digest,
    )
