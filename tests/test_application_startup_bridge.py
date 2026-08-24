from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from unittest.mock import patch

from sbp_lex.baseline.application_startup import (
    APPLICATION_INTEGRITY_STARTUP_STAGE,
    APPLICATION_STARTUP_STATE_FIELDS,
    ApplicationIntegrityRuntimeBundle,
    ApplicationStartupRejected,
    admit_application_startup,
    application_startup_hash_payload,
    verify_and_project_application_startup,
)
from sbp_lex.security.application_integrity import (
    NO_AUTHORIZATION_EFFECT,
    ApplicationIntegrityRejected,
)
from sbp_lex.security.integrity import canonical_integrity_hash


class _TrustContext:
    def resolve_application_integrity_trust(self, context_id: str) -> dict:
        raise AssertionError("The mocked hardened verifier owns trust resolution")


def _pass_result() -> dict:
    return {
        "result": "PASS",
        "result_digest": "1" * 128,
        "receipt": {"digest": "2" * 128},
        "manifest_digest": "3" * 128,
        "runtime_measurement_digest": "4" * 128,
        "trust_context_digest": "5" * 128,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
    }


class ApplicationStartupBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = {"signed_release": {"sequence": 1}}
        self.trusted_admission = {"signed_admission": {"sequence": 1}}
        self.context = _TrustContext()
        self.bundle = ApplicationIntegrityRuntimeBundle(
            manifest=self.manifest,
            trusted_admission=self.trusted_admission,
            release_root=Path("deployment/release"),
            trust_context=self.context,
            fixed_context_id="deployment-context",
            owner_pinned_context_digest="a" * 128,
        )
        self.result = _pass_result()

    def test_bundle_is_frozen_deep_copied_and_not_request_constructed(self) -> None:
        self.manifest["signed_release"]["sequence"] = 9
        self.trusted_admission["signed_admission"]["sequence"] = 9

        self.assertEqual(self.bundle.manifest["signed_release"]["sequence"], 1)
        self.assertEqual(
            self.bundle.trusted_admission["signed_admission"]["sequence"],
            1,
        )
        self.assertEqual(
            {field.name for field in fields(ApplicationIntegrityRuntimeBundle)},
            {
                "manifest",
                "trusted_admission",
                "release_root",
                "trust_context",
                "fixed_context_id",
                "owner_pinned_context_digest",
            },
        )
        with self.assertRaises(FrozenInstanceError):
            self.bundle.fixed_context_id = "request-selected"  # type: ignore[misc]

    def test_admission_returns_the_hardened_verifiers_exact_pass(self) -> None:
        with patch(
            "sbp_lex.baseline.application_startup.verify_application_integrity",
            return_value=self.result,
        ) as verifier:
            observed = admit_application_startup(self.bundle)

        self.assertIs(observed, self.result)
        args, kwargs = verifier.call_args
        self.assertEqual(args, (self.bundle.manifest,))
        self.assertEqual(kwargs["trusted_admission"], self.bundle.trusted_admission)
        self.assertIsNot(kwargs["trusted_admission"], self.bundle.trusted_admission)
        self.assertIs(kwargs["trust_context"], self.context)
        self.assertEqual(kwargs["fixed_context_id"], "deployment-context")
        self.assertEqual(kwargs["owner_pinned_context_digest"], "a" * 128)

    def test_exact_projection_writes_only_six_locked_fields(self) -> None:
        state = {"unrelated": "preserved"}
        before_keys = set(state)
        with patch(
            "sbp_lex.baseline.application_startup.verify_application_integrity_result",
            return_value=True,
        ) as verifier:
            returned = verify_and_project_application_startup(
                state,
                bundle=self.bundle,
                result=self.result,
            )

        self.assertIsNone(returned)
        self.assertEqual(set(state) - before_keys, set(APPLICATION_STARTUP_STATE_FIELDS))
        self.assertEqual(state["unrelated"], "preserved")
        self.assertEqual(state["application_integrity_result"], "PASS")
        self.assertEqual(
            state["application_integrity_result_digest"],
            self.result["result_digest"],
        )
        self.assertEqual(
            state["application_integrity_receipt_digest"],
            self.result["receipt"]["digest"],
        )
        self.assertEqual(
            state["application_integrity_manifest_digest"],
            self.result["manifest_digest"],
        )
        self.assertEqual(
            state["application_integrity_runtime_measurement_digest"],
            self.result["runtime_measurement_digest"],
        )
        self.assertEqual(
            state["application_integrity_trust_context_digest"],
            self.result["trust_context_digest"],
        )
        self.assertTrue(verifier.called)

    def test_tamper_replay_and_locked_projection_fail_closed(self) -> None:
        for reason in (
            "APPLICATION_INTEGRITY_RESULT_DIGEST_INVALID",
            "RELEASE_ANTI_ROLLBACK_HEAD_MISMATCH",
        ):
            state: dict = {}
            with self.subTest(reason=reason), patch(
                "sbp_lex.baseline.application_startup.verify_application_integrity_result",
                side_effect=ApplicationIntegrityRejected(reason),
            ):
                with self.assertRaises(ApplicationStartupRejected) as caught:
                    verify_and_project_application_startup(
                        state,
                        bundle=self.bundle,
                        result=deepcopy(self.result),
                    )
                self.assertEqual(caught.exception.dependency_code, reason)
                self.assertEqual(state, {})

        state = {}
        with patch(
            "sbp_lex.baseline.application_startup.verify_application_integrity_result",
            return_value=True,
        ):
            verify_and_project_application_startup(
                state,
                bundle=self.bundle,
                result=self.result,
            )
            state["application_integrity_result_digest"] = "f" * 128
            before = deepcopy(state)
            with self.assertRaisesRegex(
                ApplicationStartupRejected,
                "APPLICATION_STARTUP_PROJECTION_LOCKED",
            ):
                verify_and_project_application_startup(
                    state,
                    bundle=self.bundle,
                    result=self.result,
                )
            self.assertEqual(state, before)

    def test_missing_or_malformed_trust_fails_with_structured_denial(self) -> None:
        with self.assertRaises(ApplicationStartupRejected) as caught:
            ApplicationIntegrityRuntimeBundle(
                manifest={},
                trusted_admission={},
                release_root=Path("deployment/release"),
                trust_context=None,  # type: ignore[arg-type]
                fixed_context_id="deployment-context",
                owner_pinned_context_digest="a" * 128,
            )

        denial = caught.exception.as_dict()
        self.assertEqual(denial["result"], "DENY")
        self.assertEqual(
            denial["reason"],
            "APPLICATION_STARTUP_TRUST_CONTEXT_INVALID",
        )
        self.assertFalse(any(denial["authorization_effect"].values()))

    def test_no_request_trust_key_or_authority_data_is_retained_in_state(self) -> None:
        state: dict = {}
        with patch(
            "sbp_lex.baseline.application_startup.verify_application_integrity_result",
            return_value=True,
        ):
            verify_and_project_application_startup(
                state,
                bundle=self.bundle,
                result=self.result,
            )

        forbidden = {
            "manifest",
            "trusted_admission",
            "release_root",
            "trust_context",
            "fixed_context_id",
            "owner_pinned_context_digest",
            "request_fingerprint",
            "request",
            *NO_AUTHORIZATION_EFFECT,
        }
        self.assertTrue(forbidden.isdisjoint(state))
        self.assertEqual(set(state), set(APPLICATION_STARTUP_STATE_FIELDS))

    def test_hash_payload_is_exact_deterministic_and_no_authority(self) -> None:
        state: dict = {}
        with patch(
            "sbp_lex.baseline.application_startup.verify_application_integrity_result",
            return_value=True,
        ):
            verify_and_project_application_startup(
                state,
                bundle=self.bundle,
                result=self.result,
            )

        first = application_startup_hash_payload(state)
        second = application_startup_hash_payload(deepcopy(state))
        self.assertEqual(first, second)
        self.assertEqual(
            canonical_integrity_hash(first),
            canonical_integrity_hash(second),
        )
        self.assertEqual(
            set(first),
            {
                "stage",
                *APPLICATION_STARTUP_STATE_FIELDS,
                "authorization_effect",
            },
        )
        self.assertEqual(first["stage"], APPLICATION_INTEGRITY_STARTUP_STAGE)
        self.assertEqual(first["authorization_effect"], NO_AUTHORIZATION_EFFECT)
        self.assertFalse(any(first["authorization_effect"].values()))

        missing = deepcopy(state)
        missing.pop("application_integrity_receipt_digest")
        with self.assertRaisesRegex(
            ApplicationStartupRejected,
            "APPLICATION_STARTUP_PROJECTION_MISSING",
        ):
            application_startup_hash_payload(missing)


if __name__ == "__main__":
    unittest.main()
