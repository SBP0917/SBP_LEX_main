from __future__ import annotations

"""Isolated local-effect fixture retained for non-live tests only.

The public runner no longer calls this module.  Its software keys, host clock,
SQLite journal, and importable Python handlers are not a production Rust
authority route or a physical effect choke point.
"""

import hmac
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from sbp_lex.baseline.application_startup import (
    APPLICATION_STARTUP_STATE_FIELDS,
    ApplicationIntegrityRuntimeBundle,
    verify_and_project_application_startup,
)
from sbp_lex.baseline.foundational_baseline import (
    verify_foundational_baseline,
)
from sbp_lex.baseline.request_controls import (
    FoundationalRequestDependencies,
    verify_foundational_request_controls,
)
from sbp_lex.config.pipeline_config import EXECUTION_APPROVED
from sbp_lex.governance.three_p_doctrine import verify_three_p_core
from sbp_lex.governance.authority_provenance import (
    authority_provenance_token_bindings,
    verify_authority_provenance,
)
from sbp_lex.governance.skg_authority import (
    SKGAuthorityEvaluator,
    verify_skg_authority,
)
from sbp_lex.governance.filed_frameworks import (
    FiledFrameworkEvaluator,
    verify_filed_frameworks,
)
from sbp_lex.governance.filed_lifecycle import (
    FiledLifecycleEvaluator,
    verify_filed_lifecycle,
)
from sbp_lex.governance.filed_governance_integrity import (
    FiledGovernanceIntegrityEvaluator,
    GOVERNANCE_INTEGRITY_PASS,
    verify_filed_governance_integrity,
)
from sbp_lex.licensing.filed_licensing import (
    FiledLicenceEvaluator,
    probe_filed_licence_current,
    verify_filed_licence,
)
from sbp_lex.security.integrity import (
    canonical_integrity_hash,
    is_sha512,
    verify_hash_chain_entries,
)
from sbp_lex.security.hybrid_signature import HybridVerificationContext
from sbp_lex.security.signature_provider import (
    SignatureProvider,
    SignatureProviderUnavailable,
    build_signed_object,
    verify_signed_object,
)
from sbp_lex.security.token_stack import (
    REQUIRED_CORE_TOKENS,
    get_required_threshold_tokens,
    verify_token,
)


PERMIT_SCHEMA = "SBP_LEX_LOCAL_EFFECT_PERMIT_V1"
RECEIPT_SCHEMA = "SBP_LEX_LOCAL_EFFECT_RECEIPT_V1"
ADAPTER_SCHEMA = "SBP_LEX_CONTROLLED_LOCAL_ADAPTER_V1"
ADAPTER_CLASSIFICATION = "ISOLATED_TEST_ONLY_NOT_LIVE"
LOCAL_EFFECT_PERMIT_PURPOSE = "SBP_LEX_V2_LOCAL_EFFECT_PERMIT"
LOCAL_EFFECT_RECEIPT_PURPOSE = "SBP_LEX_V2_LOCAL_EFFECT_RECEIPT"

_FOUNDATIONAL_EFFECT_FIELDS = (
    "application_integrity_result_digest",
    "application_integrity_receipt_digest",
    "application_integrity_manifest_digest",
    "application_integrity_runtime_measurement_digest",
    "application_integrity_trust_context_digest",
    "digital_provenance_digest",
    "digital_provenance_verification_receipt_digest",
    "sovereign_identity_digest",
    "authority_boundary_digest",
    "authority_boundary_trace_digest",
    "impersonation_protection_digest",
    "australian_minor_access_record_digest",
    "foundational_baseline_digest",
)
_AUTHORITY_PROVENANCE_EFFECT_FIELDS = (
    "authority_provenance_digest",
    "authority_provenance_trace_digest",
    "authority_provenance_trust_context_digest",
    "authority_provenance_clock_receipt_digest",
    "authority_provenance_registry_head_digest",
)
_GOVERNANCE_INTEGRITY_EFFECT_FIELDS = (
    "filed_governance_integrity_result",
    "filed_governance_integrity_digest",
    "filed_governance_integrity_revocation_status",
    "filed_governance_integrity_revocation_sequence",
    "filed_governance_integrity_revocation_digest",
    "filed_governance_integrity_authority_granted",
    "filed_governance_integrity_licence_granted",
    "filed_governance_integrity_execution_authority_granted",
    "filed_governance_integrity_effect_granted",
    "filed_governance_integrity_bypass_permitted",
)


class LocalEffectError(RuntimeError):
    """Fail-closed local effect-boundary rejection."""


class LocalEffectInDoubtError(LocalEffectError):
    """The one-use slot is spent and the effect outcome cannot be closed."""


class LocalEffectOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class LocalEffectResult:
    outcome: LocalEffectOutcome
    evidence: dict[str, Any]


@dataclass(frozen=True, slots=True)
class LocalEffectHybridTrustContexts:
    """Caller-owned trust roots for every authenticated adapter dependency."""

    authority: HybridVerificationContext
    authority_owner_pin: str
    receipt: HybridVerificationContext
    receipt_owner_pin: str
    three_p: HybridVerificationContext
    three_p_owner_pin: str
    skg: HybridVerificationContext
    skg_owner_pin: str
    filed_framework: HybridVerificationContext
    filed_framework_owner_pin: str
    filed_licence: HybridVerificationContext
    filed_licence_owner_pin: str
    filed_lifecycle: HybridVerificationContext
    filed_lifecycle_owner_pin: str
    filed_governance_integrity: HybridVerificationContext
    filed_governance_integrity_owner_pin: str

    def __post_init__(self) -> None:
        pairs = (
            (self.authority, self.authority_owner_pin),
            (self.receipt, self.receipt_owner_pin),
            (self.three_p, self.three_p_owner_pin),
            (self.skg, self.skg_owner_pin),
            (self.filed_framework, self.filed_framework_owner_pin),
            (self.filed_licence, self.filed_licence_owner_pin),
            (self.filed_lifecycle, self.filed_lifecycle_owner_pin),
            (
                self.filed_governance_integrity,
                self.filed_governance_integrity_owner_pin,
            ),
        )
        if any(
            not isinstance(context, HybridVerificationContext)
            or type(owner_pin) is not str
            or not hmac.compare_digest(context.context_digest, owner_pin)
            for context, owner_pin in pairs
        ):
            raise LocalEffectError("LOCAL_EFFECT_HYBRID_TRUST_CONTEXT_INVALID")


@dataclass(frozen=True, slots=True)
class LocalEffectCommand:
    permit_id: str
    effect_id: str
    request_fingerprint: str
    action: str
    payload: dict[str, Any]
    current_candidate: dict[str, Any]
    issued_at_ms: int
    expires_at_ms: int


class LocalEffectHandler(Protocol):
    handler_id: str
    action: str

    def apply(self, command: LocalEffectCommand) -> LocalEffectResult: ...


class LocalClock(Protocol):
    def now_ms(self) -> int: ...


class EffectAdapter(Protocol):
    """Exact point-of-use interface accepted by the active V2 pipeline."""

    @property
    def adapter_id(self) -> str: ...

    @property
    def max_permit_ttl_ms(self) -> int: ...

    def build_permit(
        self,
        state: dict[str, Any],
        *,
        authority_provider: SignatureProvider | None,
        three_p_attestation_provider: SignatureProvider | None,
        ttl_ms: int,
        skg_evaluator: SKGAuthorityEvaluator | None,
        skg_attestation_provider: SignatureProvider | None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None,
        filed_framework_attestation_provider: SignatureProvider | None,
        filed_licence_evaluator: FiledLicenceEvaluator | None,
        filed_licence_attestation_provider: SignatureProvider | None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None,
        filed_lifecycle_attestation_provider: SignatureProvider | None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ),
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ),
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
        application_integrity_result: dict[str, Any] | None,
        foundational_request_dependencies: FoundationalRequestDependencies | None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts | None,
    ) -> dict[str, Any]: ...

    def dispatch(
        self,
        state: dict[str, Any],
        permit: dict[str, Any],
        *,
        authority_provider: SignatureProvider | None,
        three_p_attestation_provider: SignatureProvider | None,
        skg_evaluator: SKGAuthorityEvaluator | None,
        skg_attestation_provider: SignatureProvider | None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None,
        filed_framework_attestation_provider: SignatureProvider | None,
        filed_licence_evaluator: FiledLicenceEvaluator | None,
        filed_licence_attestation_provider: SignatureProvider | None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None,
        filed_lifecycle_attestation_provider: SignatureProvider | None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ),
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ),
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
        application_integrity_result: dict[str, Any] | None,
        foundational_request_dependencies: FoundationalRequestDependencies | None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts | None,
    ) -> dict[str, Any]: ...


class SystemLocalClock:
    """The real host clock used by the controlled local boundary."""

    def now_ms(self) -> int:
        return time.time_ns() // 1_000_000


def _strict_text(value: Any, code: str) -> str:
    if type(value) is not str or not value:
        raise LocalEffectError(code)
    return value


def _strict_positive_int(value: Any, code: str) -> int:
    if type(value) is not int or value <= 0:
        raise LocalEffectError(code)
    return value


def _is_lower_hex(value: Any, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _provider_identity(provider: SignatureProvider | None) -> dict[str, str]:
    if provider is None:
        raise LocalEffectError("ADAPTER_RECEIPT_PROVIDER_NOT_INJECTED")
    identity = {
        "provider_id": getattr(provider, "provider_id", None),
        "algorithm": getattr(provider, "algorithm", None),
        "key_id": getattr(provider, "key_id", None),
        "custody_class": getattr(provider, "custody_class", None),
    }
    if not all(type(value) is str and value for value in identity.values()):
        raise LocalEffectError("ADAPTER_RECEIPT_PROVIDER_METADATA_INVALID")
    if getattr(provider, "token_signing_admitted", None) is not True:
        raise LocalEffectError("ADAPTER_RECEIPT_PROVIDER_NOT_ADMITTED")
    return identity


def _foundational_current_and_unchanged(
    state: dict[str, Any],
    *,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
    application_integrity_result: dict[str, Any] | None,
    foundational_request_dependencies: FoundationalRequestDependencies | None,
) -> bool:
    try:
        if (
            not isinstance(
                application_integrity_bundle,
                ApplicationIntegrityRuntimeBundle,
            )
            or type(application_integrity_result) is not dict
            or not isinstance(
                foundational_request_dependencies,
                FoundationalRequestDependencies,
            )
        ):
            return False
        before = tuple(
            (field in state, state.get(field))
            for field in APPLICATION_STARTUP_STATE_FIELDS
        )
        verify_and_project_application_startup(
            state,
            bundle=application_integrity_bundle,
            result=application_integrity_result,
        )
        after = tuple(
            (field in state, state.get(field))
            for field in APPLICATION_STARTUP_STATE_FIELDS
        )
        return (
            before == after
            and verify_foundational_request_controls(
                state,
                dependencies=foundational_request_dependencies,
            )
            and verify_foundational_baseline(
                state,
                require_hash_binding=True,
            )
            and verify_authority_provenance(
                state,
                dependencies=(
                    foundational_request_dependencies.authority_provenance_dependencies
                ),
                require_hash_binding=True,
            )
        )
    except Exception:
        return False


def _foundational_effect_bindings(
    state: dict[str, Any],
) -> dict[str, str]:
    record = state.get("foundational_baseline_record")
    if type(record) is not dict:
        raise LocalEffectError("EFFECT_BINDING_FOUNDATIONAL_RECORD_INVALID")
    bindings = {
        field: (
            state.get(field)
            if field.startswith("application_integrity_")
            or field == "foundational_baseline_digest"
            else record.get(field)
        )
        for field in _FOUNDATIONAL_EFFECT_FIELDS
    }
    if not all(is_sha512(value) for value in bindings.values()):
        raise LocalEffectError("EFFECT_BINDING_FOUNDATIONAL_DIGEST_INVALID")
    return bindings


def _effect_binding(
    state: dict[str, Any],
    *,
    adapter_id: str,
    handler_id: str,
    licence_point_of_use_evidence: dict[str, Any],
) -> dict[str, Any]:
    request_fingerprint = state.get("request_fingerprint")
    issued_state_hash = state.get("state_hash")
    action = state.get("action")
    payload = state.get("payload")
    current_candidate = state.get("current_candidate")
    tokens = state.get("tokens")
    three_p_core_digest = state.get("three_p_core_digest")
    three_p_trace_hash = state.get("three_p_trace_hash")
    skg_authority_digest = state.get("skg_authority_digest")
    skg_authority_trace_digest = state.get("skg_authority_trace_digest")
    filed_lifecycle_digest = state.get("filed_lifecycle_digest")
    filed_governance_integrity_digest = state.get(
        "filed_governance_integrity_digest"
    )
    governance_integrity_revocation = state.get(
        "filed_governance_integrity_revocation_binding"
    )
    filed_licence_digest = state.get("filed_licence_digest")
    license_tier = state.get("license_tier")
    licence_id = state.get("licence_id")
    licence_revocation_status = state.get("licence_revocation_status")
    licence_revocation_sequence = state.get("licence_revocation_sequence")
    licence_bindings = state.get("filed_licence_record", {}).get(
        "evaluation_snapshot", {}
    ).get("bindings")
    point_of_use_determination = licence_point_of_use_evidence.get(
        "determination"
    )
    if not is_sha512(request_fingerprint):
        raise LocalEffectError("EFFECT_BINDING_REQUEST_FINGERPRINT_INVALID")
    if not is_sha512(issued_state_hash):
        raise LocalEffectError("EFFECT_BINDING_STATE_HASH_INVALID")
    if type(action) is not str or not action:
        raise LocalEffectError("EFFECT_BINDING_ACTION_INVALID")
    if type(payload) is not dict:
        raise LocalEffectError("EFFECT_BINDING_PAYLOAD_INVALID")
    if type(current_candidate) is not dict or not current_candidate:
        raise LocalEffectError("EFFECT_BINDING_CANDIDATE_INVALID")
    if type(tokens) is not dict or not tokens:
        raise LocalEffectError("EFFECT_BINDING_TOKEN_STACK_INVALID")
    if not is_sha512(three_p_core_digest) or not is_sha512(
        three_p_trace_hash
    ):
        raise LocalEffectError("EFFECT_BINDING_THREE_P_INVALID")
    if not is_sha512(skg_authority_digest) or not is_sha512(
        skg_authority_trace_digest
    ):
        raise LocalEffectError("EFFECT_BINDING_SKG_AUTHORITY_INVALID")
    authority_provenance_bindings = authority_provenance_token_bindings(state)
    if authority_provenance_bindings is None:
        raise LocalEffectError("EFFECT_BINDING_AUTHORITY_PROVENANCE_INVALID")
    if not is_sha512(filed_lifecycle_digest):
        raise LocalEffectError("EFFECT_BINDING_FILED_LIFECYCLE_INVALID")
    if (
        state.get("filed_governance_integrity_result")
        != GOVERNANCE_INTEGRITY_PASS
        or not is_sha512(filed_governance_integrity_digest)
        or type(governance_integrity_revocation) is not dict
        or set(governance_integrity_revocation)
        != {"status", "sequence", "digest"}
        or governance_integrity_revocation.get("status") != "ACTIVE"
        or type(governance_integrity_revocation.get("sequence")) is not int
        or governance_integrity_revocation.get("sequence") < 0
        or governance_integrity_revocation.get("digest")
        != canonical_integrity_hash(
            {
                "status": governance_integrity_revocation.get("status"),
                "sequence": governance_integrity_revocation.get("sequence"),
            }
        )
        or any(
            state.get(field) is not False
            for field in (
                "filed_governance_integrity_authority_granted",
                "filed_governance_integrity_licence_granted",
                "filed_governance_integrity_execution_authority_granted",
                "filed_governance_integrity_effect_granted",
                "filed_governance_integrity_bypass_permitted",
            )
        )
    ):
        raise LocalEffectError(
            "EFFECT_BINDING_FILED_GOVERNANCE_INTEGRITY_INVALID"
        )
    if (
        not is_sha512(filed_licence_digest)
        or type(license_tier) is not str
        or not license_tier
        or type(licence_id) is not str
        or not licence_id
        or licence_revocation_status != "ACTIVE"
        or type(licence_revocation_sequence) is not int
        or type(licence_bindings) is not dict
        or not licence_bindings
        or type(point_of_use_determination) is not dict
        or point_of_use_determination.get("revocation_status") != "ACTIVE"
        or type(
            point_of_use_determination.get("revocation_sequence")
        ) is not int
    ):
        raise LocalEffectError("EFFECT_BINDING_FILED_LICENCE_INVALID")
    if not is_sha512(adapter_id):
        raise LocalEffectError("EFFECT_BINDING_ADAPTER_ID_INVALID")
    _strict_text(handler_id, "EFFECT_BINDING_HANDLER_ID_INVALID")
    binding = {
        "request_fingerprint": request_fingerprint,
        "issued_state_hash": issued_state_hash,
        "action": action,
        "payload_digest": canonical_integrity_hash(payload),
        "candidate_digest": canonical_integrity_hash(current_candidate),
        "authority_digest": canonical_integrity_hash(
            state.get("resolved_authority")
        ),
        "jurisdiction_digest": canonical_integrity_hash(
            state.get("jurisdiction")
        ),
        **_foundational_effect_bindings(state),
        **authority_provenance_bindings,
        "three_p_core_digest": three_p_core_digest,
        "three_p_trace_hash": three_p_trace_hash,
        "skg_authority_digest": skg_authority_digest,
        "skg_authority_trace_digest": skg_authority_trace_digest,
        "filed_lifecycle_digest": filed_lifecycle_digest,
        "filed_governance_integrity_result": GOVERNANCE_INTEGRITY_PASS,
        "filed_governance_integrity_digest": (
            filed_governance_integrity_digest
        ),
        "filed_governance_integrity_revocation_status": (
            governance_integrity_revocation["status"]
        ),
        "filed_governance_integrity_revocation_sequence": (
            governance_integrity_revocation["sequence"]
        ),
        "filed_governance_integrity_revocation_digest": (
            governance_integrity_revocation["digest"]
        ),
        "filed_governance_integrity_authority_granted": False,
        "filed_governance_integrity_licence_granted": False,
        "filed_governance_integrity_execution_authority_granted": False,
        "filed_governance_integrity_effect_granted": False,
        "filed_governance_integrity_bypass_permitted": False,
        "filed_licence_digest": filed_licence_digest,
        "license_tier": license_tier,
        "licence_id": licence_id,
        "licence_bindings_digest": canonical_integrity_hash(
            licence_bindings
        ),
        "licence_revocation_status": licence_revocation_status,
        "licence_revocation_sequence": licence_revocation_sequence,
        # Bind the authenticated payload digest, not the complete hybrid
        # envelope. ML-DSA signatures may be randomized, so two fresh valid
        # attestations over identical point-of-use facts can have different
        # signature bytes while retaining the same signed payload digest.
        "licence_point_of_use_evidence_digest": (
            licence_point_of_use_evidence["digest"]
        ),
        "licence_point_of_use_revocation_sequence": (
            point_of_use_determination["revocation_sequence"]
        ),
        "filed_framework_digest": state.get("filed_framework_digest"),
        "token_stack_digest": canonical_integrity_hash(tokens),
        "adapter_id": adapter_id,
        "handler_id": handler_id,
    }
    binding["effect_id"] = canonical_integrity_hash(binding)
    return binding


class ControlledLocalAdapter:
    """Durable, fail-closed, one-use boundary for registered local effects.

    The adapter has no default action and no no-op success path. A successful
    receipt is possible only when an explicitly registered handler returns a
    strict ``LocalEffectResult(SUCCESS, evidence)`` after being invoked once.
    """

    def __init__(
        self,
        *,
        adapter_name: str,
        journal_path: str | Path,
        max_permit_ttl_ms: int,
        receipt_provider: SignatureProvider,
        handlers: Sequence[LocalEffectHandler],
        clock: LocalClock | None = None,
        skg_evaluator: SKGAuthorityEvaluator | None = None,
        skg_attestation_provider: SignatureProvider | None = None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
        filed_framework_attestation_provider: SignatureProvider | None = None,
        filed_licence_evaluator: FiledLicenceEvaluator | None = None,
        filed_licence_attestation_provider: SignatureProvider | None = None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
        filed_lifecycle_attestation_provider: SignatureProvider | None = None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ) = None,
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ) = None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts | None = None,
    ) -> None:
        self._adapter_name = _strict_text(
            adapter_name,
            "ADAPTER_NAME_INVALID",
        )
        self._max_permit_ttl_ms = _strict_positive_int(
            max_permit_ttl_ms,
            "ADAPTER_MAX_TTL_INVALID",
        )
        self._receipt_provider = receipt_provider
        self._skg_evaluator = skg_evaluator
        self._skg_attestation_provider = skg_attestation_provider
        self._filed_framework_evaluator = filed_framework_evaluator
        self._filed_framework_attestation_provider = (
            filed_framework_attestation_provider
        )
        self._filed_licence_evaluator = filed_licence_evaluator
        self._filed_licence_attestation_provider = (
            filed_licence_attestation_provider
        )
        self._filed_lifecycle_evaluator = filed_lifecycle_evaluator
        self._filed_lifecycle_attestation_provider = (
            filed_lifecycle_attestation_provider
        )
        self._filed_governance_integrity_evaluator = (
            filed_governance_integrity_evaluator
        )
        self._filed_governance_integrity_attestation_provider = (
            filed_governance_integrity_attestation_provider
        )
        if hybrid_trust_contexts is not None and not isinstance(
            hybrid_trust_contexts,
            LocalEffectHybridTrustContexts,
        ):
            raise LocalEffectError("LOCAL_EFFECT_HYBRID_TRUST_CONTEXT_INVALID")
        self._hybrid_trust_contexts = hybrid_trust_contexts
        receipt_identity = _provider_identity(receipt_provider)
        self._clock = clock if clock is not None else SystemLocalClock()
        if not callable(getattr(self._clock, "now_ms", None)):
            raise LocalEffectError("ADAPTER_CLOCK_INVALID")

        journal = Path(journal_path)
        if not journal.is_absolute():
            raise LocalEffectError("ADAPTER_JOURNAL_PATH_NOT_ABSOLUTE")
        if not journal.parent.is_dir():
            raise LocalEffectError("ADAPTER_JOURNAL_PARENT_MISSING")
        if journal.exists() and not journal.is_file():
            raise LocalEffectError("ADAPTER_JOURNAL_NOT_FILE")
        self._journal_path = journal

        admitted: dict[str, LocalEffectHandler] = {}
        contracts: list[dict[str, str]] = []
        if type(handlers) not in (list, tuple) or not handlers:
            raise LocalEffectError("ADAPTER_HANDLERS_REQUIRED")
        for handler in handlers:
            action = _strict_text(
                getattr(handler, "action", None),
                "ADAPTER_HANDLER_ACTION_INVALID",
            )
            handler_id = _strict_text(
                getattr(handler, "handler_id", None),
                "ADAPTER_HANDLER_ID_INVALID",
            )
            if not callable(getattr(handler, "apply", None)):
                raise LocalEffectError("ADAPTER_HANDLER_METHOD_MISSING")
            if action in admitted:
                raise LocalEffectError("ADAPTER_HANDLER_ACTION_DUPLICATE")
            admitted[action] = handler
            contracts.append({"action": action, "handler_id": handler_id})
        self._handlers = admitted

        self._adapter_id = canonical_integrity_hash(
            {
                "schema": ADAPTER_SCHEMA,
                "adapter_name": self._adapter_name,
                "receipt_provider": receipt_identity,
                "handler_contracts": sorted(
                    contracts,
                    key=lambda item: (item["action"], item["handler_id"]),
                ),
            }
        )
        self._lock = threading.RLock()
        self._initialize_journal()

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def max_permit_ttl_ms(self) -> int:
        return self._max_permit_ttl_ms

    def _require_hybrid_trust_contexts(
        self,
        supplied: LocalEffectHybridTrustContexts | None,
    ) -> LocalEffectHybridTrustContexts:
        contexts = supplied or self._hybrid_trust_contexts
        if not isinstance(contexts, LocalEffectHybridTrustContexts):
            raise LocalEffectError("LOCAL_EFFECT_HYBRID_TRUST_CONTEXT_REQUIRED")
        return contexts

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self._journal_path,
            isolation_level=None,
            timeout=30.0,
        )
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize_journal(self) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS adapter_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS permit_revocations (
                    permit_id TEXT PRIMARY KEY,
                    reason_digest TEXT NOT NULL,
                    revoked_at_ms INTEGER NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS permit_consumption (
                    permit_id TEXT PRIMARY KEY,
                    permit_digest TEXT NOT NULL,
                    effect_id TEXT NOT NULL,
                    claimed_at_ms INTEGER NOT NULL,
                    completed_at_ms INTEGER,
                    status TEXT NOT NULL,
                    receipt_digest TEXT,
                    evidence_digest TEXT
                )
                """
            )
            row = connection.execute(
                "SELECT value FROM adapter_metadata WHERE key = 'adapter_id'"
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO adapter_metadata(key, value) VALUES('adapter_id', ?)",
                    (self._adapter_id,),
                )
            elif row[0] != self._adapter_id:
                raise LocalEffectError("ADAPTER_JOURNAL_IDENTITY_MISMATCH")

    def _observe_time(self) -> int:
        observed = self._clock.now_ms()
        if type(observed) is not int or observed < 0:
            raise LocalEffectError("ADAPTER_CLOCK_RETURN_INVALID")
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT value FROM adapter_metadata WHERE key = 'last_time_ms'"
                ).fetchone()
                if row is not None and observed < int(row[0]):
                    raise LocalEffectError("ADAPTER_CLOCK_ROLLBACK")
                connection.execute(
                    """
                    INSERT INTO adapter_metadata(key, value)
                    VALUES('last_time_ms', ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (str(observed),),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return observed

    def _handler_for_state(
        self,
        state: dict[str, Any],
    ) -> LocalEffectHandler:
        action = state.get("action")
        if type(action) is not str or action not in self._handlers:
            raise LocalEffectError("LOCAL_EFFECT_ACTION_NOT_ADMITTED")
        return self._handlers[action]

    def build_permit(
        self,
        state: dict[str, Any],
        *,
        authority_provider: SignatureProvider | None,
        three_p_attestation_provider: SignatureProvider | None,
        ttl_ms: int,
        skg_evaluator: SKGAuthorityEvaluator | None = None,
        skg_attestation_provider: SignatureProvider | None = None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
        filed_framework_attestation_provider: SignatureProvider | None = None,
        filed_licence_evaluator: FiledLicenceEvaluator | None = None,
        filed_licence_attestation_provider: SignatureProvider | None = None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
        filed_lifecycle_attestation_provider: SignatureProvider | None = None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ) = None,
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ) = None,
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
        application_integrity_result: dict[str, Any] | None = None,
        foundational_request_dependencies: FoundationalRequestDependencies | None = None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts | None = None,
    ) -> dict[str, Any]:
        trust = self._require_hybrid_trust_contexts(hybrid_trust_contexts)
        skg_evaluator = skg_evaluator or self._skg_evaluator
        skg_attestation_provider = (
            skg_attestation_provider or self._skg_attestation_provider
        )
        filed_framework_evaluator = (
            filed_framework_evaluator
            or self._filed_framework_evaluator
        )
        filed_framework_attestation_provider = (
            filed_framework_attestation_provider
            or self._filed_framework_attestation_provider
        )
        filed_licence_evaluator = (
            filed_licence_evaluator or self._filed_licence_evaluator
        )
        filed_licence_attestation_provider = (
            filed_licence_attestation_provider
            or self._filed_licence_attestation_provider
        )
        filed_lifecycle_evaluator = (
            filed_lifecycle_evaluator or self._filed_lifecycle_evaluator
        )
        filed_lifecycle_attestation_provider = (
            filed_lifecycle_attestation_provider
            or self._filed_lifecycle_attestation_provider
        )
        filed_governance_integrity_evaluator = (
            filed_governance_integrity_evaluator
            or self._filed_governance_integrity_evaluator
        )
        filed_governance_integrity_attestation_provider = (
            filed_governance_integrity_attestation_provider
            or self._filed_governance_integrity_attestation_provider
        )
        ttl = _strict_positive_int(ttl_ms, "EFFECT_PERMIT_TTL_INVALID")
        if ttl > self._max_permit_ttl_ms:
            raise LocalEffectError("EFFECT_PERMIT_TTL_EXCEEDS_ADAPTER_MAXIMUM")
        if getattr(authority_provider, "effect_authority", None) is not True:
            raise LocalEffectError("EFFECT_AUTHORITY_PROVIDER_NOT_ADMITTED")
        if (
            not trust.authority.effect_authority
            or not trust.authority.external_custody_admitted
        ):
            raise LocalEffectError("EFFECT_AUTHORITY_TRUST_CONTEXT_NOT_ADMITTED")
        if getattr(authority_provider, "key_id", None) == getattr(
            self._receipt_provider,
            "key_id",
            None,
        ):
            raise LocalEffectError("AUTHORITY_AND_ADAPTER_RECEIPT_KEYS_NOT_SEPARATE")
        if state.get("execution_result") != "EXECUTE" or state.get(
            "decision"
        ) != EXECUTION_APPROVED:
            raise LocalEffectError("EXECUTION_GATE_NOT_APPROVED")
        if not verify_hash_chain_entries(
            state.get("hash_chain"),
            state.get("state_hash"),
        ):
            raise LocalEffectError("EFFECT_PERMIT_HASH_CHAIN_INVALID")
        if not _foundational_current_and_unchanged(
            state,
            application_integrity_bundle=application_integrity_bundle,
            application_integrity_result=application_integrity_result,
            foundational_request_dependencies=(
                foundational_request_dependencies
            ),
        ):
            raise LocalEffectError("EFFECT_PERMIT_FOUNDATIONAL_BASELINE_INVALID")
        if not verify_three_p_core(
            state,
            attestation_provider=three_p_attestation_provider,
            require_hash_binding=True,
            trust_context=trust.three_p,
            owner_pinned_context_digest=trust.three_p_owner_pin,
        ):
            raise LocalEffectError("EFFECT_PERMIT_THREE_P_INVALID")
        if not verify_skg_authority(
            state,
            evaluator=skg_evaluator,
            attestation_provider=skg_attestation_provider,
            attestation_trust_context=trust.skg,
            owner_pinned_context_digest=trust.skg_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError("EFFECT_PERMIT_SKG_AUTHORITY_INVALID")
        if not verify_filed_frameworks(
            state,
            evaluator=filed_framework_evaluator,
            attestation_provider=filed_framework_attestation_provider,
            attestation_trust_context=trust.filed_framework,
            owner_pinned_context_digest=trust.filed_framework_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError("EFFECT_PERMIT_FILED_FRAMEWORKS_INVALID")
        if not verify_filed_licence(
            state,
            evaluator=filed_licence_evaluator,
            attestation_provider=filed_licence_attestation_provider,
            require_revalidation=True,
            require_hash_binding=True,
            trust_context=trust.filed_licence,
            owner_pinned_context_digest=trust.filed_licence_owner_pin,
        ):
            raise LocalEffectError("EFFECT_PERMIT_FILED_LICENCE_INVALID")
        if not verify_filed_lifecycle(
            state,
            evaluator=filed_lifecycle_evaluator,
            attestation_provider=filed_lifecycle_attestation_provider,
            attestation_trust_context=trust.filed_lifecycle,
            owner_pinned_context_digest=trust.filed_lifecycle_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError("EFFECT_PERMIT_FILED_LIFECYCLE_INVALID")
        if not verify_filed_governance_integrity(
            state,
            evaluator=filed_governance_integrity_evaluator,
            attestation_provider=(
                filed_governance_integrity_attestation_provider
            ),
            attestation_trust_context=trust.filed_governance_integrity,
            owner_pinned_context_digest=(
                trust.filed_governance_integrity_owner_pin
            ),
            require_hash_binding=True,
        ):
            raise LocalEffectError(
                "EFFECT_PERMIT_FILED_GOVERNANCE_INTEGRITY_INVALID"
            )
        point_of_use_evidence, point_of_use_error = (
            probe_filed_licence_current(
                state,
                evaluator=filed_licence_evaluator,
                attestation_provider=filed_licence_attestation_provider,
                trust_context=trust.filed_licence,
                owner_pinned_context_digest=trust.filed_licence_owner_pin,
            )
        )
        if point_of_use_error is not None or point_of_use_evidence is None:
            raise LocalEffectError(
                f"EFFECT_PERMIT_FILED_LICENCE_NOT_CURRENT:{point_of_use_error}"
            )
        required_tokens = list(REQUIRED_CORE_TOKENS)
        required_tokens.extend(get_required_threshold_tokens(state))
        if not all(
            verify_token(
                state,
                token_name,
                provider=authority_provider,
                require_effect_authority=True,
                trust_context=trust.authority,
                owner_pinned_context_digest=trust.authority_owner_pin,
            )
            for token_name in required_tokens
        ):
            raise LocalEffectError("EFFECT_PERMIT_TOKEN_STACK_INVALID")

        handler = self._handler_for_state(state)
        issued_at_ms = self._observe_time()
        binding = _effect_binding(
            state,
            adapter_id=self._adapter_id,
            handler_id=handler.handler_id,
            licence_point_of_use_evidence=point_of_use_evidence,
        )
        chain = state["hash_chain"]
        permit_body = {
            "schema": PERMIT_SCHEMA,
            "permit_id": secrets.token_hex(16),
            **binding,
            "issued_chain_index": len(chain) - 1,
            "issued_chain_stage": chain[-1]["stage"],
            "issued_at_ms": issued_at_ms,
            "expires_at_ms": issued_at_ms + ttl,
        }
        try:
            permit = build_signed_object(
                permit_body,
                provider=authority_provider,
                purpose=LOCAL_EFFECT_PERMIT_PURPOSE,
            )
        except SignatureProviderUnavailable as exc:
            raise LocalEffectError(str(exc)) from exc
        if not verify_signed_object(
            permit,
            provider=authority_provider,
            require_effect_authority=True,
            purpose=LOCAL_EFFECT_PERMIT_PURPOSE,
            trust_context=trust.authority,
            owner_pinned_context_digest=trust.authority_owner_pin,
        ):
            raise LocalEffectError("EFFECT_PERMIT_SIGNATURE_INVALID")
        return permit

    def revoke(self, permit_id: str, *, reason: Mapping[str, Any]) -> None:
        if not _is_lower_hex(permit_id, 32):
            raise LocalEffectError("EFFECT_PERMIT_ID_INVALID")
        identifier = permit_id
        if type(reason) is not dict or not reason:
            raise LocalEffectError("EFFECT_PERMIT_REVOCATION_REASON_INVALID")
        reason_digest = canonical_integrity_hash(reason)
        revoked_at_ms = self._observe_time()
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                consumed = connection.execute(
                    "SELECT 1 FROM permit_consumption WHERE permit_id = ?",
                    (identifier,),
                ).fetchone()
                if consumed is not None:
                    raise LocalEffectError("EFFECT_PERMIT_ALREADY_CONSUMED")
                connection.execute(
                    """
                    INSERT INTO permit_revocations(
                        permit_id, reason_digest, revoked_at_ms
                    ) VALUES(?, ?, ?)
                    ON CONFLICT(permit_id) DO NOTHING
                    """,
                    (identifier, reason_digest, revoked_at_ms),
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def _verify_permit(
        self,
        state: dict[str, Any],
        permit: dict[str, Any],
        *,
        authority_provider: SignatureProvider | None,
        three_p_attestation_provider: SignatureProvider | None,
        skg_evaluator: SKGAuthorityEvaluator | None,
        skg_attestation_provider: SignatureProvider | None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None,
        filed_framework_attestation_provider: SignatureProvider | None,
        filed_licence_evaluator: FiledLicenceEvaluator | None,
        filed_licence_attestation_provider: SignatureProvider | None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None,
        filed_lifecycle_attestation_provider: SignatureProvider | None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ),
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ),
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None,
        application_integrity_result: dict[str, Any] | None,
        foundational_request_dependencies: FoundationalRequestDependencies | None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts,
        now_ms: int,
    ) -> LocalEffectHandler:
        trust = hybrid_trust_contexts
        expected_payload_fields = {
            "schema",
            "permit_id",
            "request_fingerprint",
            "issued_state_hash",
            "action",
            "payload_digest",
            "candidate_digest",
            "authority_digest",
            "jurisdiction_digest",
            *_FOUNDATIONAL_EFFECT_FIELDS,
            *_AUTHORITY_PROVENANCE_EFFECT_FIELDS,
            "three_p_core_digest",
            "three_p_trace_hash",
            "skg_authority_digest",
            "skg_authority_trace_digest",
            "filed_lifecycle_digest",
            *_GOVERNANCE_INTEGRITY_EFFECT_FIELDS,
            "filed_licence_digest",
            "license_tier",
            "licence_id",
            "licence_bindings_digest",
            "licence_revocation_status",
            "licence_revocation_sequence",
            "licence_point_of_use_evidence_digest",
            "licence_point_of_use_revocation_sequence",
            "filed_framework_digest",
            "token_stack_digest",
            "adapter_id",
            "handler_id",
            "effect_id",
            "issued_chain_index",
            "issued_chain_stage",
            "issued_at_ms",
            "expires_at_ms",
        }
        if type(permit) is not dict or set(permit) != expected_payload_fields | {
            "digest",
            "signature",
            "verified",
        }:
            raise LocalEffectError("EFFECT_PERMIT_SHAPE_INVALID")
        if permit.get("schema") != PERMIT_SCHEMA:
            raise LocalEffectError("EFFECT_PERMIT_SCHEMA_INVALID")
        if not _is_lower_hex(permit.get("permit_id"), 32):
            raise LocalEffectError("EFFECT_PERMIT_ID_INVALID")
        if not verify_signed_object(
            permit,
            provider=authority_provider,
            require_effect_authority=True,
            purpose=LOCAL_EFFECT_PERMIT_PURPOSE,
            trust_context=trust.authority,
            owner_pinned_context_digest=trust.authority_owner_pin,
        ):
            raise LocalEffectError("EFFECT_PERMIT_SIGNATURE_INVALID")
        issued_at_ms = permit.get("issued_at_ms")
        expires_at_ms = permit.get("expires_at_ms")
        if (
            type(issued_at_ms) is not int
            or type(expires_at_ms) is not int
            or issued_at_ms < 0
            or expires_at_ms <= issued_at_ms
            or expires_at_ms - issued_at_ms > self._max_permit_ttl_ms
            or now_ms < issued_at_ms
            or now_ms >= expires_at_ms
        ):
            raise LocalEffectError("EFFECT_PERMIT_EXPIRED_OR_TIME_INVALID")
        if not verify_hash_chain_entries(
            state.get("hash_chain"),
            state.get("state_hash"),
        ):
            raise LocalEffectError("EFFECT_POINT_OF_USE_HASH_CHAIN_INVALID")
        if not _foundational_current_and_unchanged(
            state,
            application_integrity_bundle=application_integrity_bundle,
            application_integrity_result=application_integrity_result,
            foundational_request_dependencies=(
                foundational_request_dependencies
            ),
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FOUNDATIONAL_BASELINE_INVALID"
            )
        if not verify_three_p_core(
            state,
            attestation_provider=three_p_attestation_provider,
            require_hash_binding=True,
            trust_context=trust.three_p,
            owner_pinned_context_digest=trust.three_p_owner_pin,
        ):
            raise LocalEffectError("EFFECT_POINT_OF_USE_THREE_P_INVALID")
        if not verify_skg_authority(
            state,
            evaluator=skg_evaluator,
            attestation_provider=skg_attestation_provider,
            attestation_trust_context=trust.skg,
            owner_pinned_context_digest=trust.skg_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_SKG_AUTHORITY_INVALID"
            )
        if not verify_filed_frameworks(
            state,
            evaluator=filed_framework_evaluator,
            attestation_provider=filed_framework_attestation_provider,
            attestation_trust_context=trust.filed_framework,
            owner_pinned_context_digest=trust.filed_framework_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FILED_FRAMEWORKS_INVALID"
            )
        if not verify_filed_licence(
            state,
            evaluator=filed_licence_evaluator,
            attestation_provider=filed_licence_attestation_provider,
            require_revalidation=True,
            require_hash_binding=True,
            trust_context=trust.filed_licence,
            owner_pinned_context_digest=trust.filed_licence_owner_pin,
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FILED_LICENCE_INVALID"
            )
        if not verify_filed_lifecycle(
            state,
            evaluator=filed_lifecycle_evaluator,
            attestation_provider=filed_lifecycle_attestation_provider,
            attestation_trust_context=trust.filed_lifecycle,
            owner_pinned_context_digest=trust.filed_lifecycle_owner_pin,
            require_hash_binding=True,
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FILED_LIFECYCLE_INVALID"
            )
        if not verify_filed_governance_integrity(
            state,
            evaluator=filed_governance_integrity_evaluator,
            attestation_provider=(
                filed_governance_integrity_attestation_provider
            ),
            attestation_trust_context=trust.filed_governance_integrity,
            owner_pinned_context_digest=(
                trust.filed_governance_integrity_owner_pin
            ),
            require_hash_binding=True,
        ):
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FILED_GOVERNANCE_INTEGRITY_INVALID"
            )
        point_of_use_evidence, point_of_use_error = (
            probe_filed_licence_current(
                state,
                evaluator=filed_licence_evaluator,
                attestation_provider=filed_licence_attestation_provider,
                trust_context=trust.filed_licence,
                owner_pinned_context_digest=trust.filed_licence_owner_pin,
            )
        )
        if point_of_use_error is not None or point_of_use_evidence is None:
            raise LocalEffectError(
                "EFFECT_POINT_OF_USE_FILED_LICENCE_NOT_CURRENT:"
                f"{point_of_use_error}"
            )
        if state.get("execution_result") != "EXECUTE" or state.get(
            "decision"
        ) != EXECUTION_APPROVED:
            raise LocalEffectError("EFFECT_POINT_OF_USE_NOT_APPROVED")

        handler = self._handler_for_state(state)
        expected_binding = _effect_binding(
            state,
            adapter_id=self._adapter_id,
            handler_id=handler.handler_id,
            licence_point_of_use_evidence=point_of_use_evidence,
        )
        for field, expected in expected_binding.items():
            if permit.get(field) != expected:
                raise LocalEffectError(f"EFFECT_PERMIT_BINDING_MISMATCH:{field}")
        chain = state["hash_chain"]
        issued_index = permit.get("issued_chain_index")
        if (
            type(issued_index) is not int
            or issued_index < 0
            or issued_index >= len(chain)
            or chain[issued_index].get("hash") != permit.get("issued_state_hash")
            or chain[issued_index].get("stage") != permit.get("issued_chain_stage")
        ):
            raise LocalEffectError("EFFECT_PERMIT_CHAIN_BINDING_INVALID")
        required_tokens = list(REQUIRED_CORE_TOKENS)
        required_tokens.extend(get_required_threshold_tokens(state))
        if not all(
            verify_token(
                state,
                token_name,
                provider=authority_provider,
                require_effect_authority=True,
                trust_context=trust.authority,
                owner_pinned_context_digest=trust.authority_owner_pin,
            )
            for token_name in required_tokens
        ):
            raise LocalEffectError("EFFECT_POINT_OF_USE_TOKEN_STACK_INVALID")
        return handler

    def _claim_once(
        self,
        permit: dict[str, Any],
        *,
        claimed_at_ms: int,
    ) -> None:
        permit_id = permit["permit_id"]
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                revoked = connection.execute(
                    "SELECT 1 FROM permit_revocations WHERE permit_id = ?",
                    (permit_id,),
                ).fetchone()
                if revoked is not None:
                    raise LocalEffectError("EFFECT_PERMIT_REVOKED")
                connection.execute(
                    """
                    INSERT INTO permit_consumption(
                        permit_id, permit_digest, effect_id,
                        claimed_at_ms, status
                    ) VALUES(?, ?, ?, ?, 'CLAIMED')
                    """,
                    (
                        permit_id,
                        permit["digest"],
                        permit["effect_id"],
                        claimed_at_ms,
                    ),
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                connection.execute("ROLLBACK")
                raise LocalEffectError("EFFECT_PERMIT_REPLAYED") from exc
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def _complete_claim(
        self,
        permit_id: str,
        *,
        completed_at_ms: int,
        status: str,
        receipt_digest: str | None,
        evidence_digest: str,
    ) -> None:
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = connection.execute(
                    """
                    UPDATE permit_consumption
                    SET completed_at_ms = ?, status = ?,
                        receipt_digest = ?, evidence_digest = ?
                    WHERE permit_id = ? AND status = 'CLAIMED'
                    """,
                    (
                        completed_at_ms,
                        status,
                        receipt_digest,
                        evidence_digest,
                        permit_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise LocalEffectError("EFFECT_CLAIM_STATE_INVALID")
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def dispatch(
        self,
        state: dict[str, Any],
        permit: dict[str, Any],
        *,
        authority_provider: SignatureProvider | None,
        three_p_attestation_provider: SignatureProvider | None,
        skg_evaluator: SKGAuthorityEvaluator | None = None,
        skg_attestation_provider: SignatureProvider | None = None,
        filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
        filed_framework_attestation_provider: SignatureProvider | None = None,
        filed_licence_evaluator: FiledLicenceEvaluator | None = None,
        filed_licence_attestation_provider: SignatureProvider | None = None,
        filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
        filed_lifecycle_attestation_provider: SignatureProvider | None = None,
        filed_governance_integrity_evaluator: (
            FiledGovernanceIntegrityEvaluator | None
        ) = None,
        filed_governance_integrity_attestation_provider: (
            SignatureProvider | None
        ) = None,
        application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
        application_integrity_result: dict[str, Any] | None = None,
        foundational_request_dependencies: FoundationalRequestDependencies | None = None,
        hybrid_trust_contexts: LocalEffectHybridTrustContexts | None = None,
    ) -> dict[str, Any]:
        trust = self._require_hybrid_trust_contexts(hybrid_trust_contexts)
        skg_evaluator = skg_evaluator or self._skg_evaluator
        skg_attestation_provider = (
            skg_attestation_provider or self._skg_attestation_provider
        )
        filed_framework_evaluator = (
            filed_framework_evaluator
            or self._filed_framework_evaluator
        )
        filed_framework_attestation_provider = (
            filed_framework_attestation_provider
            or self._filed_framework_attestation_provider
        )
        filed_licence_evaluator = (
            filed_licence_evaluator or self._filed_licence_evaluator
        )
        filed_licence_attestation_provider = (
            filed_licence_attestation_provider
            or self._filed_licence_attestation_provider
        )
        filed_lifecycle_evaluator = (
            filed_lifecycle_evaluator or self._filed_lifecycle_evaluator
        )
        filed_lifecycle_attestation_provider = (
            filed_lifecycle_attestation_provider
            or self._filed_lifecycle_attestation_provider
        )
        filed_governance_integrity_evaluator = (
            filed_governance_integrity_evaluator
            or self._filed_governance_integrity_evaluator
        )
        filed_governance_integrity_attestation_provider = (
            filed_governance_integrity_attestation_provider
            or self._filed_governance_integrity_attestation_provider
        )
        claimed_at_ms = self._observe_time()
        handler = self._verify_permit(
            state,
            permit,
            authority_provider=authority_provider,
            three_p_attestation_provider=three_p_attestation_provider,
            skg_evaluator=skg_evaluator,
            skg_attestation_provider=skg_attestation_provider,
            filed_framework_evaluator=filed_framework_evaluator,
            filed_framework_attestation_provider=(
                filed_framework_attestation_provider
            ),
            filed_licence_evaluator=filed_licence_evaluator,
            filed_licence_attestation_provider=(
                filed_licence_attestation_provider
            ),
            filed_lifecycle_evaluator=filed_lifecycle_evaluator,
            filed_lifecycle_attestation_provider=(
                filed_lifecycle_attestation_provider
            ),
            filed_governance_integrity_evaluator=(
                filed_governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=(
                filed_governance_integrity_attestation_provider
            ),
            application_integrity_bundle=application_integrity_bundle,
            application_integrity_result=application_integrity_result,
            foundational_request_dependencies=(
                foundational_request_dependencies
            ),
            hybrid_trust_contexts=trust,
            now_ms=claimed_at_ms,
        )
        self._claim_once(permit, claimed_at_ms=claimed_at_ms)

        command = LocalEffectCommand(
            permit_id=permit["permit_id"],
            effect_id=permit["effect_id"],
            request_fingerprint=permit["request_fingerprint"],
            action=permit["action"],
            payload=deepcopy(state.get("payload")),
            current_candidate=deepcopy(state.get("current_candidate")),
            issued_at_ms=permit["issued_at_ms"],
            expires_at_ms=permit["expires_at_ms"],
        )

        # Revalidate every external constitutional and licence dependency after
        # the one-time claim and immediately before invoking the effect handler.
        point_of_use_ms = self._observe_time()
        handler = self._verify_permit(
            state,
            permit,
            authority_provider=authority_provider,
            three_p_attestation_provider=three_p_attestation_provider,
            skg_evaluator=skg_evaluator,
            skg_attestation_provider=skg_attestation_provider,
            filed_framework_evaluator=filed_framework_evaluator,
            filed_framework_attestation_provider=(
                filed_framework_attestation_provider
            ),
            filed_licence_evaluator=filed_licence_evaluator,
            filed_licence_attestation_provider=(
                filed_licence_attestation_provider
            ),
            filed_lifecycle_evaluator=filed_lifecycle_evaluator,
            filed_lifecycle_attestation_provider=(
                filed_lifecycle_attestation_provider
            ),
            filed_governance_integrity_evaluator=(
                filed_governance_integrity_evaluator
            ),
            filed_governance_integrity_attestation_provider=(
                filed_governance_integrity_attestation_provider
            ),
            application_integrity_bundle=application_integrity_bundle,
            application_integrity_result=application_integrity_result,
            foundational_request_dependencies=(
                foundational_request_dependencies
            ),
            hybrid_trust_contexts=trust,
            now_ms=point_of_use_ms,
        )

        try:
            result = handler.apply(command)
            if type(result) is not LocalEffectResult:
                raise LocalEffectError("LOCAL_EFFECT_HANDLER_RESULT_INVALID")
            if type(result.outcome) is not LocalEffectOutcome:
                raise LocalEffectError("LOCAL_EFFECT_HANDLER_OUTCOME_INVALID")
            if type(result.evidence) is not dict or not result.evidence:
                raise LocalEffectError("LOCAL_EFFECT_HANDLER_EVIDENCE_REQUIRED")
            evidence = deepcopy(result.evidence)
            outcome = result.outcome
        except Exception as exc:
            evidence = {
                "error_type": type(exc).__name__,
                "error_code": (
                    str(exc)
                    if isinstance(exc, LocalEffectError)
                    else "LOCAL_EFFECT_HANDLER_EXCEPTION"
                ),
            }
            outcome = LocalEffectOutcome.UNKNOWN

        try:
            completed_at_ms = self._observe_time()
        except Exception as exc:
            raise LocalEffectInDoubtError(
                "LOCAL_EFFECT_COMPLETION_TIME_UNAVAILABLE"
            ) from exc
        if completed_at_ms >= permit["expires_at_ms"]:
            outcome = LocalEffectOutcome.UNKNOWN
            evidence = {
                "error_code": "LOCAL_EFFECT_COMPLETED_AFTER_EXPIRY",
                "prior_evidence_digest": canonical_integrity_hash(evidence),
            }
        evidence_digest = canonical_integrity_hash(evidence)
        receipt_body = {
            "schema": RECEIPT_SCHEMA,
            "permit_id": permit["permit_id"],
            "permit_digest": permit["digest"],
            "effect_id": permit["effect_id"],
            "adapter_id": self._adapter_id,
            "handler_id": handler.handler_id,
            "request_fingerprint": permit["request_fingerprint"],
            **{
                field: permit[field]
                for field in (
                    *_FOUNDATIONAL_EFFECT_FIELDS,
                    *_AUTHORITY_PROVENANCE_EFFECT_FIELDS,
                    *_GOVERNANCE_INTEGRITY_EFFECT_FIELDS,
                )
            },
            "outcome": outcome.value,
            "claimed_at_ms": claimed_at_ms,
            "completed_at_ms": completed_at_ms,
            "evidence_digest": evidence_digest,
        }

        try:
            receipt = build_signed_object(
                receipt_body,
                provider=self._receipt_provider,
                purpose=LOCAL_EFFECT_RECEIPT_PURPOSE,
            )
            if not verify_signed_object(
                receipt,
                provider=self._receipt_provider,
                purpose=LOCAL_EFFECT_RECEIPT_PURPOSE,
                trust_context=trust.receipt,
                owner_pinned_context_digest=trust.receipt_owner_pin,
            ):
                raise LocalEffectError("LOCAL_EFFECT_RECEIPT_SIGNATURE_INVALID")
        except Exception as exc:
            try:
                self._complete_claim(
                    permit["permit_id"],
                    completed_at_ms=completed_at_ms,
                    status="IN_DOUBT",
                    receipt_digest=None,
                    evidence_digest=evidence_digest,
                )
            except Exception:
                pass
            raise LocalEffectInDoubtError(
                "LOCAL_EFFECT_RECEIPT_UNAVAILABLE"
            ) from exc

        status = {
            LocalEffectOutcome.SUCCESS: "SUCCESS",
            LocalEffectOutcome.FAILED: "FAILED",
            LocalEffectOutcome.UNKNOWN: "IN_DOUBT",
        }[outcome]
        try:
            self._complete_claim(
                permit["permit_id"],
                completed_at_ms=completed_at_ms,
                status=status,
                receipt_digest=receipt["digest"],
                evidence_digest=evidence_digest,
            )
        except Exception as exc:
            raise LocalEffectInDoubtError(
                "LOCAL_EFFECT_JOURNAL_COMPLETION_UNAVAILABLE"
            ) from exc
        return receipt


def run_controlled_local_effect(
    state: dict[str, Any],
    *,
    adapter: EffectAdapter | None,
    authority_provider: SignatureProvider | None,
    three_p_attestation_provider: SignatureProvider | None,
    permit_ttl_ms: int | None,
    skg_evaluator: SKGAuthorityEvaluator | None = None,
    skg_attestation_provider: SignatureProvider | None = None,
    filed_framework_evaluator: FiledFrameworkEvaluator | None = None,
    filed_framework_attestation_provider: SignatureProvider | None = None,
    filed_licence_evaluator: FiledLicenceEvaluator | None = None,
    filed_licence_attestation_provider: SignatureProvider | None = None,
    filed_lifecycle_evaluator: FiledLifecycleEvaluator | None = None,
    filed_lifecycle_attestation_provider: SignatureProvider | None = None,
    filed_governance_integrity_evaluator: (
        FiledGovernanceIntegrityEvaluator | None
    ) = None,
    filed_governance_integrity_attestation_provider: (
        SignatureProvider | None
    ) = None,
    application_integrity_bundle: ApplicationIntegrityRuntimeBundle | None = None,
    application_integrity_result: dict[str, Any] | None = None,
    foundational_request_dependencies: FoundationalRequestDependencies | None = None,
    hybrid_trust_contexts: LocalEffectHybridTrustContexts | None = None,
) -> dict[str, Any]:
    state.setdefault("effect_trace", [])
    if adapter is None:
        raise LocalEffectError("CONTROLLED_LOCAL_ADAPTER_NOT_INJECTED")
    if type(permit_ttl_ms) is not int:
        raise LocalEffectError("EFFECT_PERMIT_TTL_NOT_INJECTED")

    permit = adapter.build_permit(
        state,
        authority_provider=authority_provider,
        three_p_attestation_provider=three_p_attestation_provider,
        ttl_ms=permit_ttl_ms,
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_attestation_provider,
        filed_framework_evaluator=filed_framework_evaluator,
        filed_framework_attestation_provider=(
            filed_framework_attestation_provider
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        filed_governance_integrity_evaluator=(
            filed_governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        application_integrity_bundle=application_integrity_bundle,
        application_integrity_result=application_integrity_result,
        foundational_request_dependencies=foundational_request_dependencies,
        hybrid_trust_contexts=hybrid_trust_contexts,
    )
    state["effect_adapter_id"] = adapter.adapter_id
    state["effect_id"] = permit["effect_id"]
    state["effect_permit"] = permit
    state["effect_trace"].append(
        {
            "event": "permit_issued",
            "permit_id": permit["permit_id"],
            "permit_digest": permit["digest"],
            "effect_id": permit["effect_id"],
            "adapter_id": adapter.adapter_id,
        }
    )

    receipt = adapter.dispatch(
        state,
        permit,
        authority_provider=authority_provider,
        three_p_attestation_provider=three_p_attestation_provider,
        skg_evaluator=skg_evaluator,
        skg_attestation_provider=skg_attestation_provider,
        filed_framework_evaluator=filed_framework_evaluator,
        filed_framework_attestation_provider=(
            filed_framework_attestation_provider
        ),
        filed_licence_evaluator=filed_licence_evaluator,
        filed_licence_attestation_provider=(
            filed_licence_attestation_provider
        ),
        filed_lifecycle_evaluator=filed_lifecycle_evaluator,
        filed_lifecycle_attestation_provider=(
            filed_lifecycle_attestation_provider
        ),
        filed_governance_integrity_evaluator=(
            filed_governance_integrity_evaluator
        ),
        filed_governance_integrity_attestation_provider=(
            filed_governance_integrity_attestation_provider
        ),
        application_integrity_bundle=application_integrity_bundle,
        application_integrity_result=application_integrity_result,
        foundational_request_dependencies=foundational_request_dependencies,
        hybrid_trust_contexts=hybrid_trust_contexts,
    )
    state["effect_receipt"] = receipt
    state["effect_result"] = receipt["outcome"]
    state["effect_trace"].append(
        {
            "event": "effect_completed",
            "permit_id": permit["permit_id"],
            "receipt_digest": receipt["digest"],
            "outcome": receipt["outcome"],
        }
    )
    return state


def verify_local_effect_receipt(
    state: dict[str, Any],
    *,
    receipt_provider: SignatureProvider | None,
    receipt_trust_context: HybridVerificationContext | None = None,
    receipt_owner_pinned_context_digest: str | None = None,
) -> bool:
    receipt = state.get("effect_receipt")
    permit = state.get("effect_permit")
    if type(receipt) is not dict or type(permit) is not dict:
        return False
    expected_receipt_fields = {
        "schema",
        "permit_id",
        "permit_digest",
        "effect_id",
        "adapter_id",
        "handler_id",
        "request_fingerprint",
        *_FOUNDATIONAL_EFFECT_FIELDS,
        *_AUTHORITY_PROVENANCE_EFFECT_FIELDS,
        *_GOVERNANCE_INTEGRITY_EFFECT_FIELDS,
        "outcome",
        "claimed_at_ms",
        "completed_at_ms",
        "evidence_digest",
        "digest",
        "signature",
        "verified",
    }
    if set(receipt) != expected_receipt_fields:
        return False
    if not verify_signed_object(
        receipt,
        provider=receipt_provider,
        purpose=LOCAL_EFFECT_RECEIPT_PURPOSE,
        trust_context=receipt_trust_context,
        owner_pinned_context_digest=receipt_owner_pinned_context_digest,
    ):
        return False
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("permit_id") != permit.get("permit_id")
        or receipt.get("permit_digest") != permit.get("digest")
        or receipt.get("effect_id") != permit.get("effect_id")
        or receipt.get("adapter_id") != permit.get("adapter_id")
        or receipt.get("request_fingerprint")
        != state.get("request_fingerprint")
        or any(
            receipt.get(field) != permit.get(field)
            for field in (
                *_FOUNDATIONAL_EFFECT_FIELDS,
                *_AUTHORITY_PROVENANCE_EFFECT_FIELDS,
                *_GOVERNANCE_INTEGRITY_EFFECT_FIELDS,
            )
        )
        or receipt.get("outcome") != state.get("effect_result")
        or receipt.get("effect_id") != state.get("effect_id")
        or receipt.get("adapter_id") != state.get("effect_adapter_id")
    ):
        return False
    if not is_sha512(receipt.get("evidence_digest")):
        return False
    claimed = receipt.get("claimed_at_ms")
    completed = receipt.get("completed_at_ms")
    issued = permit.get("issued_at_ms")
    expires = permit.get("expires_at_ms")
    return (
        type(claimed) is int
        and type(completed) is int
        and type(issued) is int
        and type(expires) is int
        and issued <= claimed <= completed
        and completed < expires
    )
