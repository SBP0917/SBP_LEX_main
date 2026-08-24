from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import replace
from hashlib import sha512

import pytest
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA87PrivateKey

from sbp_lex.assurance.envelope import canonical_json_bytes
from sbp_lex.local_trust.digests import canonical_bytes as local_trust_bytes
from sbp_lex.local_trust.digests import digest
from sbp_lex.local_trust.pqc_channel import (
    CHANNEL_CAPABILITY,
    MLKEM1024_ALGORITHM,
    MLKEM1024_PUBLIC_KEY_BYTES,
    NOT_ADMITTED,
    NOT_DEPLOYED,
    MlKem1024CapabilityError,
    MlKem1024ExternalPins,
    build_mlkem1024_capability_evidence,
    validate_mlkem1024_capability_evidence,
)
from sbp_lex.local_trust.pqc_wrapper import (
    AUTHORITY_EFFECT,
    DETACHED_HYBRID_DOMAIN,
    ED448_PUBLIC_KEY_BYTES,
    ED448_SIGNATURE_BYTES,
    HYBRID_ENVELOPE_SCHEMA_ID,
    HYBRID_KEY_ID_DOMAIN,
    HYBRID_PREIMAGE_DOMAIN,
    HYBRID_SIGNATURE_PROFILE_V2,
    ML_DSA_87_PUBLIC_KEY_BYTES,
    ML_DSA_87_SIGNATURE_BYTES,
    DetachedHybridOwnerPins,
    DetachedHybridSigningKeys,
    DetachedHybridWrapperError,
    hybrid_signature_preimage,
    verified_detached_payload,
    verify_detached_hybrid_wrapper,
    wrap_detached_payload,
)
from sbp_lex.local_trust.signing import raw_public_key_key_id
from sbp_lex.security.hybrid_signature import (
    HYBRID_DOMAIN as ACTIVE_HYBRID_DOMAIN,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_KEY_ID_DOMAIN as ACTIVE_HYBRID_KEY_ID_DOMAIN,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_PREIMAGE_DOMAIN as ACTIVE_HYBRID_PREIMAGE_DOMAIN,
)
from sbp_lex.security.hybrid_signature import (
    HYBRID_SUITE_ID,
    STRICT_DUAL_SIGNATURE_SECURITY_PROFILE,
    STRICT_DUAL_SIGNATURE_SUITE_VERSION,
    STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
    STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
)
from sbp_lex.security.hybrid_signature import (
    hybrid_envelope_shape_exact,
)
from sbp_lex.security.hybrid_signature import (
    hybrid_signature_preimage as active_hybrid_signature_preimage,
)
from sbp_lex.supply_chain.canonical import canonical_document_bytes as supply_chain_bytes
from sbp_ptde.canonical import canonical_json_document_bytes as ptde_bytes
from sbp_pvpl.canonical import canonical_document_bytes as pvpl_bytes


@pytest.fixture(scope="module")
def wrapper_material() -> tuple[DetachedHybridSigningKeys, DetachedHybridOwnerPins]:
    ml = MLDSA87PrivateKey.generate()
    ed = Ed448PrivateKey.generate()
    signing_keys = DetachedHybridSigningKeys(
        mldsa87_private_key=ml,
        ed448_private_key=ed,
    )
    owner_pins = DetachedHybridOwnerPins(
        owner_pin_id="OWNER-PIN-001",
        key_epoch=7,
        purpose="DETACHED_ASSURANCE_ARTIFACT",
        domain=DETACHED_HYBRID_DOMAIN,
        custody_attestation_sha512=sha512(b"external-custody-attestation").hexdigest(),
        mldsa87_provider_id="OWNER-PIN-001:ML-DSA-87",
        ed448_provider_id="OWNER-PIN-001:ED448",
        mldsa87_custody_reference="OWNER-PIN-001:ML-DSA-87:CUSTODY",
        ed448_custody_reference="OWNER-PIN-001:ED448:CUSTODY",
        mldsa87_custody_attestation_sha512=sha512(
            b"mldsa87-custody-attestation"
        ).hexdigest(),
        ed448_custody_attestation_sha512=sha512(
            b"ed448-custody-attestation"
        ).hexdigest(),
        mldsa87_public_key=ml.public_key(),
        ed448_public_key=ed.public_key(),
    )
    return signing_keys, owner_pins


def _corrupt_signature_lane(value: dict, ordinal: int) -> None:
    lane = value["signature"]["signatures"][ordinal]
    signature = bytearray(base64.b64decode(lane["signature_b64"]))
    signature[-1] ^= 1
    lane["signature_b64"] = base64.b64encode(signature).decode("ascii")


def test_raw_public_key_ids_are_reconciled_without_changing_v1_record(
    signers: dict,
) -> None:
    context = signers["artifact"].verification_context(allow_test_only=True)
    before = context.public_record()
    assert context.mldsa87_key_id == sha512(context.mldsa87_public_key_bytes).hexdigest()
    assert context.ed448_key_id == sha512(context.ed448_public_key_bytes).hexdigest()
    assert context.mldsa87_key_id == raw_public_key_key_id(context.mldsa87_public_key)
    assert context.ed448_key_id == raw_public_key_key_id(context.ed448_public_key)
    assert context.public_record() == before
    assert "mldsa87_key_id" not in before
    assert "ed448_key_id" not in before
    assert before["mldsa87_fingerprint"] == digest(
        {
            "algorithm": "ML-DSA-87",
            "raw_public_key": base64.b64encode(
                context.mldsa87_public_key_bytes
            ).decode("ascii"),
        }
    )


def test_detached_wrapper_requires_external_pins_and_both_exact_lanes(
    wrapper_material: tuple[DetachedHybridSigningKeys, DetachedHybridOwnerPins],
) -> None:
    signing_keys, owner_pins = wrapper_material
    payload = b'{"schema_id":"preserved-v1","value":1}\n'
    payload_sha512 = sha512(payload).hexdigest()
    wrapper = wrap_detached_payload(
        payload,
        signing_keys=signing_keys,
        owner_pins=owner_pins,
    )
    assert wrapper["signature_profile"] == HYBRID_SIGNATURE_PROFILE_V2
    assert wrapper["authority_effect"] == AUTHORITY_EFFECT
    assert wrapper["admission_state"] == NOT_ADMITTED
    assert wrapper["runtime_attachment"] == "NONE"
    assert wrapper["publication_state"] == "NOT_ACTIVATED"
    assert wrapper["payload_sha512"] == payload_sha512
    assert not any("public_key" in key for key in wrapper)
    envelope = wrapper["signature"]
    assert envelope["schema_id"] == HYBRID_ENVELOPE_SCHEMA_ID
    assert envelope["suite"] == HYBRID_SIGNATURE_PROFILE_V2
    assert envelope["payload_sha512"] == payload_sha512
    assert envelope["context_digest"] == owner_pins.context_digest
    assert envelope["ordered_key_set_digest"] == owner_pins.ordered_key_set_digest
    assert hybrid_envelope_shape_exact(envelope)
    assert envelope["lanes"] == owner_pins.lane_descriptors
    assert len(base64.b64decode(envelope["signatures"][0]["signature_b64"])) == (
        ML_DSA_87_SIGNATURE_BYTES
    )
    assert len(base64.b64decode(envelope["signatures"][1]["signature_b64"])) == (
        ED448_SIGNATURE_BYTES
    )
    assert all("public_key_b64" not in lane for lane in envelope["lanes"])
    assert verify_detached_hybrid_wrapper(
        wrapper,
        owner_pins=owner_pins,
        expected_payload_sha512=payload_sha512,
    )
    assert verified_detached_payload(
        wrapper,
        owner_pins=owner_pins,
        expected_payload_sha512=payload_sha512,
    ) == payload

    hostile_mutations = (
        lambda value: value["signature"]["signatures"].pop(),
        lambda value: value["signature"]["signatures"][0].update(
            algorithm="ML-DSA-65"
        ),
        lambda value: value["signature"]["signatures"][1].update(
            key_id="0" * 128
        ),
        lambda value: _corrupt_signature_lane(value, 0),
        lambda value: _corrupt_signature_lane(value, 1),
        lambda value: value["signature"].update(key_epoch=8),
        lambda value: value["signature"].update(
            suite="SBP_LEX_V2_HYBRID_ML_DSA_87_ED448_V2"
        ),
        lambda value: value["signature"].update(
            verification_rule="ANY_LANE_SUFFICIENT"
        ),
        lambda value: value["signature"].update(
            lane_independence_required=False
        ),
        lambda value: value["signature"]["lanes"][1].update(
            provider_id=value["signature"]["lanes"][0]["provider_id"]
        ),
        lambda value: value["signature"]["lanes"][1].update(
            custody_reference=value["signature"]["lanes"][0]["custody_reference"]
        ),
        lambda value: value["signature"].update(purpose="OTHER_PURPOSE"),
        lambda value: value["signature"].update(domain="OTHER_DOMAIN"),
        lambda value: value["signature"].update(context_digest="0" * 128),
        lambda value: value.update(key_epoch=8),
        lambda value: value.update(purpose="OTHER_PURPOSE"),
        lambda value: value.update(domain="SBP-LEX-V2-OTHER-DOMAIN/2"),
        lambda value: value.update(payload_b64=base64.b64encode(b"changed").decode("ascii")),
        lambda value: value.update(extra="not-allowed"),
    )
    for mutate in hostile_mutations:
        hostile = deepcopy(wrapper)
        mutate(hostile)
        assert not verify_detached_hybrid_wrapper(hostile, owner_pins=owner_pins)

    other_ml = MLDSA87PrivateKey.generate()
    wrong_pins = replace(
        owner_pins,
        mldsa87_public_key=other_ml.public_key(),
    )
    assert not verify_detached_hybrid_wrapper(wrapper, owner_pins=wrong_pins)
    wrong_context_pins = replace(
        owner_pins,
        custody_attestation_sha512=sha512(b"different-custody-evidence").hexdigest(),
    )
    assert not verify_detached_hybrid_wrapper(
        wrapper, owner_pins=wrong_context_pins
    )
    assert not verify_detached_hybrid_wrapper(
        wrapper,
        owner_pins=owner_pins,
        expected_payload_sha512="0" * 128,
    )

    for invalid_pins in (
        {"ed448_provider_id": owner_pins.mldsa87_provider_id},
        {"ed448_custody_reference": owner_pins.mldsa87_custody_reference},
        {
            "ed448_custody_attestation_sha512": (
                owner_pins.mldsa87_custody_attestation_sha512
            )
        },
        {
            "custody_attestation_sha512": (
                owner_pins.mldsa87_custody_attestation_sha512
            )
        },
    ):
        with pytest.raises(DetachedHybridWrapperError):
            replace(owner_pins, **invalid_pins)


def test_binary_preimage_has_exact_cross_language_vector_and_recomputes_wrapper(
    wrapper_material: tuple[DetachedHybridSigningKeys, DetachedHybridOwnerPins],
) -> None:
    ml_public = bytes(index % 251 for index in range(ML_DSA_87_PUBLIC_KEY_BYTES))
    ed_public = bytes((index * 3) % 251 for index in range(ED448_PUBLIC_KEY_BYTES))
    payload = b"SBP-LEX detached vector payload\x00/1-exact"
    application_context = b"owner-pinned-external-context"
    purpose = "DETACHED_VECTOR"
    epoch = 0x0102030405060708
    observed = hybrid_signature_preimage(
        payload,
        purpose=purpose,
        key_epoch=epoch,
        mldsa87_public_key_bytes=ml_public,
        ed448_public_key_bytes=ed_public,
        application_context=application_context,
    )
    purpose_bytes = purpose.encode("utf-8")
    independently_recomputed = b"".join(
        (
            HYBRID_PREIMAGE_DOMAIN,
            HYBRID_SIGNATURE_PROFILE_V2.encode("ascii"),
            b"\x00",
            len(purpose_bytes).to_bytes(2, "big"),
            purpose_bytes,
            epoch.to_bytes(8, "big"),
            sha512(ml_public).digest(),
            sha512(ed_public).digest(),
            sha512(payload).digest(),
            sha512(application_context).digest(),
        )
    )
    assert observed == independently_recomputed
    assert sha512(observed).hexdigest() == (
        "c96dbdbae3b9f529fef94c6107547f548ea5b4cb5c0fc6889bbefa4a00ba9a77"
        "93c5312c6fa5e642fc18b947a88274ed0099f73a5ba24b982b5ece9a9f9f4522"
    )

    assert DETACHED_HYBRID_DOMAIN == ACTIVE_HYBRID_DOMAIN
    assert HYBRID_PREIMAGE_DOMAIN == ACTIVE_HYBRID_PREIMAGE_DOMAIN
    assert HYBRID_KEY_ID_DOMAIN == ACTIVE_HYBRID_KEY_ID_DOMAIN
    assert HYBRID_SIGNATURE_PROFILE_V2 == HYBRID_SUITE_ID
    payload_value = {"schema_id": "sbp.lex.v2.detached-vector/1", "n": 7}
    canonical_payload = canonical_json_bytes(payload_value)
    active_protected = {
        "suite": HYBRID_SUITE_ID,
        "suite_version": STRICT_DUAL_SIGNATURE_SUITE_VERSION,
        "verification_rule": STRICT_DUAL_SIGNATURE_VERIFICATION_RULE,
        "security_profile": STRICT_DUAL_SIGNATURE_SECURITY_PROFILE,
        "transition_policy": STRICT_DUAL_SIGNATURE_TRANSITION_POLICY,
        "lane_independence_required": True,
        "domain": ACTIVE_HYBRID_DOMAIN,
        "purpose": purpose,
        "key_epoch": epoch,
        "payload_sha512": sha512(canonical_payload).hexdigest(),
        "context_digest": sha512(application_context).hexdigest(),
        "lanes": [
            {
                "algorithm": "ML-DSA-87",
                "ordinal": 0,
                "key_epoch": epoch,
                "key_id": sha512(ml_public).hexdigest(),
                "provider_id": "VECTOR:ML-DSA-87",
                "custody_reference": "VECTOR:CUSTODY:ML-DSA-87",
                "lifecycle_status": "ACTIVE",
                "revoked_at_epoch": None,
            },
            {
                "algorithm": "Ed448",
                "ordinal": 1,
                "key_epoch": epoch,
                "key_id": sha512(ed_public).hexdigest(),
                "provider_id": "VECTOR:Ed448",
                "custody_reference": "VECTOR:CUSTODY:Ed448",
                "lifecycle_status": "ACTIVE",
                "revoked_at_epoch": None,
            },
        ],
    }
    assert active_hybrid_signature_preimage(
        payload_value, active_protected
    ) == hybrid_signature_preimage(
        canonical_payload,
        purpose=purpose,
        key_epoch=epoch,
        mldsa87_public_key_bytes=ml_public,
        ed448_public_key_bytes=ed_public,
        application_context=application_context,
    )

    signing_keys, owner_pins = wrapper_material
    wrapper = wrap_detached_payload(
        payload,
        signing_keys=signing_keys,
        owner_pins=owner_pins,
    )
    wrapper_preimage = hybrid_signature_preimage(
        payload,
        purpose=owner_pins.purpose,
        key_epoch=owner_pins.key_epoch,
        mldsa87_public_key_bytes=owner_pins.mldsa87_public_key_bytes,
        ed448_public_key_bytes=owner_pins.ed448_public_key_bytes,
        application_context=owner_pins.application_context,
    )
    signatures = wrapper["signature"]["signatures"]
    owner_pins.mldsa87_public_key.verify(
        base64.b64decode(signatures[0]["signature_b64"]), wrapper_preimage
    )
    owner_pins.ed448_public_key.verify(
        base64.b64decode(signatures[1]["signature_b64"]), wrapper_preimage
    )


def test_wrapper_preserves_exact_cross_surface_v1_payload_bytes(
    wrapper_material: tuple[DetachedHybridSigningKeys, DetachedHybridOwnerPins],
) -> None:
    signing_keys, owner_pins = wrapper_material
    value = {"schema_id": "unchanged-v1", "sequence": 1, "status": "NOT_ADMITTED"}
    payloads = {
        "local_trust": local_trust_bytes(value),
        "ptde": ptde_bytes(value),
        "pvpl": pvpl_bytes(value),
        "supply_chain": supply_chain_bytes(value),
    }
    for payload in payloads.values():
        before = bytes(payload)
        before_sha512 = sha512(before).hexdigest()
        wrapper = wrap_detached_payload(
            before,
            signing_keys=signing_keys,
            owner_pins=owner_pins,
        )
        after = verified_detached_payload(
            wrapper,
            owner_pins=owner_pins,
            expected_payload_sha512=before_sha512,
        )
        assert after == before
        assert sha512(after).hexdigest() == before_sha512
        assert payload == before


def test_signer_cannot_substitute_keys_for_external_owner_pins(
    wrapper_material: tuple[DetachedHybridSigningKeys, DetachedHybridOwnerPins],
) -> None:
    _, owner_pins = wrapper_material
    hostile_keys = DetachedHybridSigningKeys(
        mldsa87_private_key=MLDSA87PrivateKey.generate(),
        ed448_private_key=Ed448PrivateKey.generate(),
    )
    with pytest.raises(DetachedHybridWrapperError, match="not_owner_pinned"):
        wrap_detached_payload(
            b"payload",
            signing_keys=hostile_keys,
            owner_pins=owner_pins,
        )


def _mlkem_pins(*, public_key: bytes | None = None) -> MlKem1024ExternalPins:
    return MlKem1024ExternalPins(
        owner_pin_id="MLKEM-OWNER-PIN-001",
        key_epoch=4,
        public_key_bytes=public_key
        if public_key is not None
        else bytes(index % 251 for index in range(MLKEM1024_PUBLIC_KEY_BYTES)),
        transport_id="DETACHED-TRANSPORT-001",
        transport_binding_sha512=sha512(b"transport-binding").hexdigest(),
        custody_provider_id="EXTERNAL-CUSTODY-001",
        custody_attestation_sha512=sha512(b"custody-attestation").hexdigest(),
    )


def test_mlkem1024_contract_is_channel_only_not_admitted_and_not_deployed() -> None:
    pins = _mlkem_pins()
    evidence = build_mlkem1024_capability_evidence(
        external_pins=pins,
        observed_at_ms=1_900_000_000_000,
        evidence_sequence=1,
    )
    assert evidence["kem_algorithm"] == MLKEM1024_ALGORITHM
    assert evidence["capability"] == CHANNEL_CAPABILITY
    assert evidence["key_id"] == sha512(pins.public_key_bytes).hexdigest()
    assert evidence["signature_capability"] is False
    assert evidence["authority_capability"] is False
    assert evidence["admission_state"] == NOT_ADMITTED
    assert evidence["deployment_state"] == NOT_DEPLOYED
    assert evidence["external_transport_admission_required"] is True
    assert evidence["external_custody_admission_required"] is True
    assert validate_mlkem1024_capability_evidence(evidence, external_pins=pins)

    for field, hostile_value in (
        ("kem_algorithm", "ML-KEM-768"),
        ("capability", "SIGNATURE"),
        ("signature_capability", True),
        ("authority_capability", True),
        ("admission_state", "ADMITTED"),
        ("deployment_state", "DEPLOYED"),
        ("transport_binding_sha512", "0" * 128),
        ("custody_attestation_sha512", "0" * 128),
        ("key_id", "0" * 128),
    ):
        hostile = deepcopy(evidence)
        hostile[field] = hostile_value
        assert not validate_mlkem1024_capability_evidence(hostile, external_pins=pins)

    other_pins = _mlkem_pins(public_key=b"x" * MLKEM1024_PUBLIC_KEY_BYTES)
    assert not validate_mlkem1024_capability_evidence(evidence, external_pins=other_pins)
    with pytest.raises(MlKem1024CapabilityError, match="public_key_invalid"):
        _mlkem_pins(public_key=b"too-short")
