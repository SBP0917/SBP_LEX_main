"""Application-integrity startup bridge for the SBP-LEX V2 baseline.

This bridge projects only verified integrity digests.  It does not grant any
authority and it does not construct deployment trust from request data.

Same-verified-file-handle execution, private composition-root isolation, an
OS-enforced immutable release root, and TPM/platform code-signing assurance
remain deployment dependencies and are not established by this module.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sbp_lex.security.application_integrity import (
    NO_AUTHORIZATION_EFFECT,
    ApplicationIntegrityRejected,
    ApplicationIntegrityTrustContext,
    verify_application_integrity,
    verify_application_integrity_result,
)
from sbp_lex.security.integrity import is_sha512


APPLICATION_INTEGRITY_STARTUP_STAGE = "application_integrity:startup"
APPLICATION_STARTUP_STATE_FIELDS = (
    "application_integrity_result",
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
)
APPLICATION_STARTUP_DEPLOYMENT_DEPENDENCIES = {
    "same_verified_file_handle_execution": "NOT_PROVEN",
    "private_composition_root_isolation": "NOT_PROVEN",
    "os_immutable_release_root": "NOT_PROVEN",
    "tpm_measurement": "NOT_PROVEN",
    "platform_code_signing": "NOT_PROVEN",
}

_EMPTY_PROJECTION = {
    "application_integrity_result": "",
    "application_integrity_result_digest": None,
    "application_integrity_receipt_digest": None,
    "application_integrity_manifest_digest": None,
    "application_integrity_runtime_measurement_digest": None,
    "application_integrity_trust_context_digest": None,
}


class ApplicationStartupRejected(ValueError):
    """Structured fail-closed rejection at the application-startup boundary."""

    __slots__ = ("code", "dependency_code")

    def __init__(self, code: str, *, dependency_code: str | None = None) -> None:
        self.code = code
        self.dependency_code = dependency_code
        message = code
        if dependency_code is not None:
            message = f"{code}:{dependency_code}"
        super().__init__(message)

    def as_dict(self) -> dict[str, Any]:
        return {
            "result": "DENY",
            "reason": self.code,
            "dependency_reason": self.dependency_code,
            "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
        }


def _reject(
    code: str,
    *,
    dependency_code: str | None = None,
) -> ApplicationStartupRejected:
    return ApplicationStartupRejected(
        code,
        dependency_code=dependency_code,
    )


def _strict_text(value: Any) -> bool:
    return type(value) is str and bool(value) and value == value.strip()


def _copy_dict_evidence(value: Any, *, code: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise _reject(code)
    try:
        copied = deepcopy(value)
    except Exception as exc:
        raise _reject(code) from exc
    if type(copied) is not dict:
        raise _reject(code)
    return copied


def _valid_release_root(value: Any) -> bool:
    if isinstance(value, Path):
        return True
    return _strict_text(value)


def _valid_trust_context(value: Any) -> bool:
    if value is None or type(value) is dict:
        return False
    try:
        resolver = getattr(value, "resolve_application_integrity_trust")
    except Exception:
        return False
    return callable(resolver)


@dataclass(frozen=True, slots=True)
class ApplicationIntegrityRuntimeBundle:
    """Deployment-composed integrity inputs; never derived from a request."""

    manifest: dict[str, Any]
    trusted_admission: dict[str, Any]
    release_root: str | Path
    trust_context: ApplicationIntegrityTrustContext
    fixed_context_id: str
    owner_pinned_context_digest: str

    def __post_init__(self) -> None:
        manifest = _copy_dict_evidence(
            self.manifest,
            code="APPLICATION_STARTUP_MANIFEST_INVALID",
        )
        trusted_admission = _copy_dict_evidence(
            self.trusted_admission,
            code="APPLICATION_STARTUP_TRUSTED_ADMISSION_INVALID",
        )
        if not _valid_release_root(self.release_root):
            raise _reject("APPLICATION_STARTUP_RELEASE_ROOT_INVALID")
        if not _valid_trust_context(self.trust_context):
            raise _reject("APPLICATION_STARTUP_TRUST_CONTEXT_INVALID")
        if not _strict_text(self.fixed_context_id):
            raise _reject("APPLICATION_STARTUP_FIXED_CONTEXT_ID_INVALID")
        if not is_sha512(self.owner_pinned_context_digest):
            raise _reject("APPLICATION_STARTUP_OWNER_CONTEXT_PIN_INVALID")
        object.__setattr__(self, "manifest", manifest)
        object.__setattr__(self, "trusted_admission", trusted_admission)


def _bundle_arguments(
    bundle: ApplicationIntegrityRuntimeBundle,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    if type(bundle) is not ApplicationIntegrityRuntimeBundle:
        raise _reject("APPLICATION_STARTUP_RUNTIME_BUNDLE_INVALID")
    manifest = _copy_dict_evidence(
        bundle.manifest,
        code="APPLICATION_STARTUP_MANIFEST_INVALID",
    )
    trusted_admission = _copy_dict_evidence(
        bundle.trusted_admission,
        code="APPLICATION_STARTUP_TRUSTED_ADMISSION_INVALID",
    )
    if (
        not _valid_release_root(bundle.release_root)
        or not _valid_trust_context(bundle.trust_context)
        or not _strict_text(bundle.fixed_context_id)
        or not is_sha512(bundle.owner_pinned_context_digest)
    ):
        raise _reject("APPLICATION_STARTUP_RUNTIME_BUNDLE_INVALID")
    keyword_arguments = {
        "release_root": bundle.release_root,
        "trusted_admission": trusted_admission,
        "trust_context": bundle.trust_context,
        "fixed_context_id": bundle.fixed_context_id,
        "owner_pinned_context_digest": bundle.owner_pinned_context_digest,
    }
    return manifest, trusted_admission, keyword_arguments


def _projection_from_result(result: Any) -> dict[str, Any]:
    if type(result) is not dict or result.get("result") != "PASS":
        raise _reject("APPLICATION_STARTUP_PASS_RESULT_INVALID")
    receipt = result.get("receipt")
    if (
        type(receipt) is not dict
        or result.get("authorization_effect") != NO_AUTHORIZATION_EFFECT
    ):
        raise _reject("APPLICATION_STARTUP_PASS_RESULT_INVALID")
    projection = {
        "application_integrity_result": result.get("result"),
        "application_integrity_result_digest": result.get("result_digest"),
        "application_integrity_receipt_digest": receipt.get("digest"),
        "application_integrity_manifest_digest": result.get("manifest_digest"),
        "application_integrity_runtime_measurement_digest": result.get(
            "runtime_measurement_digest"
        ),
        "application_integrity_trust_context_digest": result.get(
            "trust_context_digest"
        ),
    }
    if any(
        not is_sha512(projection[field])
        for field in APPLICATION_STARTUP_STATE_FIELDS[1:]
    ):
        raise _reject("APPLICATION_STARTUP_PASS_RESULT_INVALID")
    return projection


def admit_application_startup(
    bundle: ApplicationIntegrityRuntimeBundle,
) -> dict[str, Any]:
    """Admit the deployment-composed application and return its exact PASS."""

    manifest, _, arguments = _bundle_arguments(bundle)
    try:
        result = verify_application_integrity(manifest, **arguments)
    except ApplicationIntegrityRejected as exc:
        raise _reject(
            "APPLICATION_STARTUP_ADMISSION_REJECTED",
            dependency_code=str(exc),
        ) from exc
    except Exception as exc:
        raise _reject("APPLICATION_STARTUP_ADMISSION_DEPENDENCY_FAILED") from exc
    _projection_from_result(result)
    return result


def verify_and_project_application_startup(
    state: dict[str, Any],
    *,
    bundle: ApplicationIntegrityRuntimeBundle,
    result: dict[str, Any],
) -> None:
    """Reverify a PASS and atomically project its six locked digest fields."""

    if type(state) is not dict:
        raise _reject("APPLICATION_STARTUP_STATE_INVALID")
    manifest, trusted_admission, arguments = _bundle_arguments(bundle)
    try:
        verified = verify_application_integrity_result(
            result,
            manifest=manifest,
            trusted_admission=trusted_admission,
            release_root=arguments["release_root"],
            trust_context=arguments["trust_context"],
            fixed_context_id=arguments["fixed_context_id"],
            owner_pinned_context_digest=arguments[
                "owner_pinned_context_digest"
            ],
        )
    except ApplicationIntegrityRejected as exc:
        raise _reject(
            "APPLICATION_STARTUP_RESULT_REJECTED",
            dependency_code=str(exc),
        ) from exc
    except Exception as exc:
        raise _reject("APPLICATION_STARTUP_RESULT_DEPENDENCY_FAILED") from exc
    if verified is not True:
        raise _reject("APPLICATION_STARTUP_RESULT_NOT_VERIFIED")
    projection = _projection_from_result(result)
    try:
        for field, expected in projection.items():
            if field not in state:
                continue
            current = state[field]
            if current != _EMPTY_PROJECTION[field] and current != expected:
                raise _reject("APPLICATION_STARTUP_PROJECTION_LOCKED")
    except ApplicationStartupRejected:
        raise
    except Exception as exc:
        raise _reject("APPLICATION_STARTUP_PROJECTION_INVALID") from exc
    state.update(projection)


def application_startup_hash_payload(state: dict[str, Any]) -> dict[str, Any]:
    """Return the exact no-authority startup payload for canonical hashing."""

    if type(state) is not dict:
        raise _reject("APPLICATION_STARTUP_STATE_INVALID")
    try:
        projection = {
            field: state[field] for field in APPLICATION_STARTUP_STATE_FIELDS
        }
    except Exception as exc:
        raise _reject("APPLICATION_STARTUP_PROJECTION_MISSING") from exc
    if (
        projection["application_integrity_result"] != "PASS"
        or any(
            not is_sha512(projection[field])
            for field in APPLICATION_STARTUP_STATE_FIELDS[1:]
        )
    ):
        raise _reject("APPLICATION_STARTUP_PROJECTION_INVALID")
    return {
        "stage": APPLICATION_INTEGRITY_STARTUP_STAGE,
        **projection,
        "authorization_effect": dict(NO_AUTHORIZATION_EFFECT),
    }


__all__ = [
    "APPLICATION_INTEGRITY_STARTUP_STAGE",
    "APPLICATION_STARTUP_DEPLOYMENT_DEPENDENCIES",
    "APPLICATION_STARTUP_STATE_FIELDS",
    "ApplicationIntegrityRuntimeBundle",
    "ApplicationStartupRejected",
    "admit_application_startup",
    "application_startup_hash_payload",
    "verify_and_project_application_startup",
]
