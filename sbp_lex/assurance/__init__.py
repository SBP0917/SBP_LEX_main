"""Cross-language assurance contracts for the V2 single pipeline.

The package constructs verifier inputs. It does not grant execution authority.
"""

from .envelope import (
    ASSURANCE_ENVELOPE_VERSION,
    AssuranceContractError,
    assurance_envelope_digest,
    build_assurance_envelope,
    canonical_json_bytes,
)
from .verifier import (
    AssuranceMode,
    VerifierInvocation,
    invoke_veto_verifier,
    mode_requires_denial,
)

__all__ = [
    "ASSURANCE_ENVELOPE_VERSION",
    "AssuranceContractError",
    "assurance_envelope_digest",
    "build_assurance_envelope",
    "canonical_json_bytes",
    "AssuranceMode",
    "VerifierInvocation",
    "invoke_veto_verifier",
    "mode_requires_denial",
]
