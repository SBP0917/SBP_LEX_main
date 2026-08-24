from __future__ import annotations

import base64
from copy import deepcopy
from hashlib import sha512
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sbp_lex.exchange.segmented_exchange import (
    EXCHANGE_ACTIVE,
    EXCHANGE_AUTHORITY_ROLE,
    EXCHANGE_REVOKED,
    EXCHANGE_SIGNING_PURPOSE,
    InMemoryExchangeReplayGuard,
    SegmentedExchangeRejected,
    build_segmented_exchange,
    verify_and_decrypt_segmented_exchange,
)
from sbp_lex.security.integrity import canonical_integrity_hash
from sbp_lex.security.hybrid_signature import (
    HybridMLDSA87Ed448SoftwareProvider,
    build_hybrid_signed_object,
)
from sbp_lex.security.signature_provider import (
    Ed25519SoftwareProvider,
    build_legacy_non_effect_signed_object,
    verify_legacy_non_effect_signed_object,
)


class ExchangeAuthority:
    exchange_authority_id = "segmented-exchange-envelope-authority"
    exchange_authority_version = "1"
    exchange_authority_role = EXCHANGE_AUTHORITY_ROLE
    exchange_authority_credential_id = "exchange-envelope-credential"


class ExchangeSigningProvider:
    def __init__(self, *, admitted: bool = True) -> None:
        self._provider = HybridMLDSA87Ed448SoftwareProvider.generate(
            provider_id="SEGMENTED_EXCHANGE_TEST_ONLY_HYBRID",
            key_epoch=1,
        )
        self.exchange_attestation_admitted = admitted

    def __getattr__(self, name):
        return getattr(self._provider, name)


class LegacyExchangeSigningProvider:
    exchange_attestation_admitted = True

    def __init__(self) -> None:
        self._provider = Ed25519SoftwareProvider.from_private_key(
            Ed25519PrivateKey.generate()
        )

    def __getattr__(self, name):
        return getattr(self._provider, name)


class ExchangeKeyResolver:
    key_resolver_id = "in-process-aes256-segment-key-resolver"

    def __init__(self) -> None:
        self.keys: dict[str, bytes] = {}
        self.unavailable = False

    def resolve_segment_key(self, *, exchange_id: str, segment_id: str, **_: str):
        if self.unavailable:
            return None
        key_id = f"{exchange_id}:{segment_id}:aes256"
        key = self.keys.setdefault(
            key_id,
            sha512(key_id.encode("utf-8")).digest()[:32],
        )
        return key_id, key


class SegmentedExchangeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.authority = ExchangeAuthority()
        self.provider = ExchangeSigningProvider()
        self.trust_context = self.provider.hybrid_verification_context(
            allow_test_only=True
        )
        self.resolver = ExchangeKeyResolver()
        self.policy_digest = canonical_integrity_hash(
            {"policy": "cross-jurisdiction-review", "version": 1}
        )

    def build(self, **overrides):
        values = {
            "exchange_id": "exchange-0001",
            "request_fingerprint": canonical_integrity_hash(
                {"request": "exchange-0001"}
            ),
            "evaluation_time": 1_700_000_000,
            "sender_id": "department-alpha",
            "recipient_id": "department-beta",
            "jurisdiction": "AU",
            "policy_id": "cross-jurisdiction-review-v1",
            "policy_digest": self.policy_digest,
            "revocation_status": EXCHANGE_ACTIVE,
            "revocation_sequence": 1,
            "segments": [
                {"segment_id": "segment-a", "plaintext": b"alpha payload"},
                {"segment_id": "segment-b", "plaintext": b"beta payload"},
            ],
            "authority": self.authority,
            "attestation_provider": self.provider,
            "attestation_trust_context": self.trust_context,
            "owner_pinned_context_digest": self.trust_context.context_digest,
            "key_resolver": self.resolver,
        }
        values.update(overrides)
        return build_segmented_exchange(**values)

    def open(self, record, *, guard=None, **overrides):
        values = {
            "expected_sender_id": "department-alpha",
            "expected_recipient_id": "department-beta",
            "expected_jurisdiction": "AU",
            "expected_policy_id": "cross-jurisdiction-review-v1",
            "expected_policy_digest": self.policy_digest,
            "authority": self.authority,
            "attestation_provider": self.provider,
            "attestation_trust_context": self.trust_context,
            "owner_pinned_context_digest": self.trust_context.context_digest,
            "key_resolver": self.resolver,
            "replay_guard": guard or InMemoryExchangeReplayGuard(),
        }
        values.update(overrides)
        return verify_and_decrypt_segmented_exchange(record, **values)

    @staticmethod
    def resign(record, provider):
        payload = {
            key: deepcopy(value)
            for key, value in record["envelope"].items()
            if key not in {"digest", "signature", "verified"}
        }
        envelope = build_hybrid_signed_object(
            payload,
            provider=provider,
            purpose=EXCHANGE_SIGNING_PURPOSE,
        )
        record["envelope"] = envelope
        record["envelope_digest"] = canonical_integrity_hash(envelope)
        record["audit_digests"] = {
            "binding_digest": envelope["binding_digest"],
            "segment_manifest_digest": envelope["segment_manifest_digest"],
            "envelope_digest": record["envelope_digest"],
        }

    def test_real_per_segment_aesgcm_round_trip_grants_no_authority(self) -> None:
        record = self.build()
        envelope = record["envelope"]
        self.assertEqual(len(envelope["segments"]), 2)
        self.assertNotIn("alpha payload", envelope["segments"][0]["ciphertext_b64"])
        self.assertNotEqual(
            envelope["segments"][0]["nonce_b64"],
            envelope["segments"][1]["nonce_b64"],
        )

        opened = self.open(record)

        self.assertEqual(
            opened["segments"],
            [
                {"segment_id": "segment-a", "plaintext": b"alpha payload"},
                {"segment_id": "segment-b", "plaintext": b"beta payload"},
            ],
        )
        self.assertEqual(
            envelope["external_boundaries"],
            {
                "transport": "EXTERNAL_AND_UNPROVEN",
                "durable_key_custody": "EXTERNAL_AND_UNPROVEN",
                "distributed_enforcement": "EXTERNAL_AND_UNPROVEN",
            },
        )
        self.assertTrue(
            all(value is False for value in opened["authorization_effect"].values())
        )

    def test_missing_or_unadmitted_provider_and_key_resolver_fail_closed(self) -> None:
        for field, value in (
            ("attestation_provider", None),
            ("attestation_provider", ExchangeSigningProvider(admitted=False)),
            ("key_resolver", None),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(SegmentedExchangeRejected):
                    self.build(**{field: value})

        record = self.build()
        with self.assertRaises(SegmentedExchangeRejected):
            self.open(record, key_resolver=None)

    def test_owner_pin_is_independent_and_legacy_cannot_seal_exchange(self) -> None:
        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        ):
            self.build(
                attestation_trust_context=None,
                owner_pinned_context_digest=None,
            )
        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_OWNER_PIN_NOT_INJECTED_OR_INVALID",
        ):
            self.build(owner_pinned_context_digest="0" * 128)

        wrong_provider = ExchangeSigningProvider()
        wrong_pin = wrong_provider.hybrid_verification_context(
            allow_test_only=True
        )
        with self.assertRaisesRegex(
            SegmentedExchangeRejected, "EXCHANGE_SIGNER_NOT_OWNER_PINNED"
        ):
            self.build(
                attestation_trust_context=wrong_pin,
                owner_pinned_context_digest=wrong_pin.context_digest,
            )

        legacy = LegacyExchangeSigningProvider()
        legacy_object = build_legacy_non_effect_signed_object(
            {"legacy_test_only_non_effect": True}, provider=legacy
        )
        self.assertTrue(
            verify_legacy_non_effect_signed_object(
                legacy_object, provider=legacy
            )
        )
        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_ATTESTATION_PROVIDER_NOT_INJECTED_OR_ADMITTED",
        ):
            self.build(attestation_provider=legacy)

    def test_ciphertext_tamper_fails_aesgcm_even_if_resigned(self) -> None:
        record = self.build()
        segment = record["envelope"]["segments"][0]
        ciphertext = bytearray(base64.b64decode(segment["ciphertext_b64"]))
        ciphertext[-1] ^= 1
        segment["ciphertext_b64"] = base64.b64encode(ciphertext).decode("ascii")
        segment["ciphertext_digest"] = sha512(ciphertext).hexdigest()
        record["envelope"]["segment_manifest_digest"] = canonical_integrity_hash(
            record["envelope"]["segments"]
        )
        self.resign(record, self.provider)

        with self.assertRaisesRegex(
            SegmentedExchangeRejected, "EXCHANGE_SEGMENT_AUTHENTICATION_FAILED"
        ):
            self.open(record)

    def test_recipient_jurisdiction_and_policy_live_mismatch_fail_closed(self) -> None:
        record = self.build()
        mutations = {
            "expected_recipient_id": "department-gamma",
            "expected_jurisdiction": "NZ",
            "expected_policy_id": "different-policy",
            "expected_policy_digest": canonical_integrity_hash(
                {"policy": "different"}
            ),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    SegmentedExchangeRejected, "EXCHANGE_LIVE_BINDING_MISMATCH"
                ):
                    self.open(record, **{field: value})

    def test_replay_is_rejected_after_first_successful_decryption(self) -> None:
        record = self.build()
        guard = InMemoryExchangeReplayGuard()
        self.open(record, guard=guard)

        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_REPLAY_OR_REVOCATION_ROLLBACK",
        ):
            self.open(record, guard=guard)

        changed_record = self.build(
            segments=[
                {"segment_id": "segment-a", "plaintext": b"changed payload"}
            ]
        )
        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_REPLAY_OR_REVOCATION_ROLLBACK",
        ):
            self.open(changed_record, guard=guard)

    def test_revoked_status_and_revocation_sequence_rollback_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            SegmentedExchangeRejected, "EXCHANGE_AUTHORITY_REVOKED"
        ):
            self.build(revocation_status=EXCHANGE_REVOKED)

        guard = InMemoryExchangeReplayGuard()
        current = self.build(revocation_sequence=5)
        self.open(current, guard=guard)
        older = self.build(
            exchange_id="exchange-0002",
            request_fingerprint=canonical_integrity_hash(
                {"request": "exchange-0002"}
            ),
            revocation_sequence=4,
        )
        with self.assertRaisesRegex(
            SegmentedExchangeRejected,
            "EXCHANGE_REPLAY_OR_REVOCATION_ROLLBACK",
        ):
            self.open(older, guard=guard)

    def test_reordered_missing_and_duplicate_segments_fail_closed(self) -> None:
        mutations = ("reordered", "missing", "duplicate")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                record = self.build()
                envelope = record["envelope"]
                if mutation == "reordered":
                    envelope["segments"].reverse()
                elif mutation == "missing":
                    envelope["segments"].pop()
                else:
                    envelope["segments"][1]["segment_id"] = "segment-a"
                envelope["segment_manifest_digest"] = canonical_integrity_hash(
                    envelope["segments"]
                )
                self.resign(record, self.provider)
                with self.assertRaises(SegmentedExchangeRejected):
                    self.open(record)

        with self.assertRaisesRegex(
            SegmentedExchangeRejected, "EXCHANGE_SEGMENT_INPUT_INVALID"
        ):
            self.build(
                segments=[
                    {"segment_id": "same", "plaintext": b"one"},
                    {"segment_id": "same", "plaintext": b"two"},
                ]
            )

    def test_missing_or_wrong_segment_key_fails_closed(self) -> None:
        record = self.build()
        self.resolver.unavailable = True
        with self.assertRaises(SegmentedExchangeRejected):
            self.open(record)


if __name__ == "__main__":
    unittest.main()
