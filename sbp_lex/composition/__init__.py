"""Implementation-defined V2 CIGA composition-attestation boundary."""

from .ciga_composition import (
    CIGA_CAPABILITY_CLASSES,
    CIGA_COMPOSITION_ATTESTATION_STAGE,
    CIGA_COMPOSITION_REVALIDATION_STAGE,
    CIGA_COMPOSITION_ROLE,
    COMPOSITION_DENY,
    COMPOSITION_PASS,
    CompositionAttestationRejected,
    evaluate_ciga_composition,
    verify_ciga_composition,
)

__all__ = [
    "CIGA_CAPABILITY_CLASSES",
    "CIGA_COMPOSITION_ATTESTATION_STAGE",
    "CIGA_COMPOSITION_REVALIDATION_STAGE",
    "CIGA_COMPOSITION_ROLE",
    "COMPOSITION_DENY",
    "COMPOSITION_PASS",
    "CompositionAttestationRejected",
    "evaluate_ciga_composition",
    "verify_ciga_composition",
]
