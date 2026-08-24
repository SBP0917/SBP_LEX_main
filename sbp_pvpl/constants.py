"""Locked public contract values for the detached SBP-LEX V2 PVPL."""

from __future__ import annotations


CONTRACT_VERSION = "SBP_LEX_V2_PVPL_V1"
SOURCE_RESULT_SCHEMA_ID = "sbp.lex.v2.pvpl.verified-redacted-result/1"
RECEIPT_SCHEMA_ID = "sbp.lex.v2.pvpl.detached-verification-receipt/1"
EXTERNAL_PINS_SCHEMA_ID = "sbp.lex.v2.pvpl.external-acceptance-pins/1"
HISTORY_SCHEMA_ID = "sbp.lex.v2.pvpl.accepted-publication-history/1"
CLAIM_SCHEMA_ID = "sbp.lex.v2.pvpl.public-verification-claim/1"
VALIDATION_SCHEMA_ID = "sbp.lex.v2.pvpl.validation-report/1"

SOURCE_KINDS = ("PTDE", "LOCAL_TRUST")
SOURCE_RESULT_SCHEMAS = {
    "PTDE": "sbp.lex.v2.ptde.verification-result/1",
    "LOCAL_TRUST": "SBP_LEX_V2_LOCAL_TRUST_PACKAGE_V1",
}
SOURCE_OUTCOMES = {
    "PTDE": "PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED",
    "LOCAL_TRUST": "PASS",
}

CLAIM_RESULT = "PASS_INTERNAL_SOFTWARE_EVIDENCE_NOT_ADMITTED"
CLAIM_SCOPE = "INTERNAL_SOFTWARE_EVIDENCE_ONLY"
ADMISSION_STATE = "NOT_ADMITTED"
PUBLICATION_STATE = "NOT_ACTIVATED"
CLAIM_TEXT = (
    "The exact redacted PTDE and local-trust result artifacts bound here were "
    "independently verified and matched caller-supplied external acceptance "
    "pins. This is internal software evidence only, is NOT_ADMITTED, and "
    "confers NO_AUTHORITY."
)

NO_AUTHORITY = {
    "audit_authority": False,
    "decision_authority": False,
    "effect_authority": False,
    "execution_authority": False,
    "governance_authority": False,
    "hash_chain_authority": False,
    "licence_authority": False,
    "publication_activation_authority": False,
    "runtime_authority": False,
    "token_authority": False,
}

LIMITATIONS = (
    "EXTERNAL_PUBLICATION_HOSTING_NOT_PERFORMED",
    "EXTERNAL_VERIFIER_TRUST_ROOT_AUTHENTICATION_NOT_PERFORMED",
    "EXTERNAL_ACCEPTED_HISTORY_PERSISTENCE_REQUIRED",
    "NO_RUNTIME_GOVERNANCE_LICENCE_EXECUTION_EFFECT_AUDIT_TOKEN_OR_HASH_CHAIN_AUTHORITY",
)

MAX_DOCUMENT_BYTES = 1_048_576
MAX_DEPTH = 24
MAX_FIELDS = 256
MAX_LIST_ITEMS = 100_000
MAX_STRING_BYTES = 16_384
MAX_HISTORY_ITEMS = 100_000
SHA512_HEX_LENGTH = 128


__all__ = [
    "ADMISSION_STATE",
    "CLAIM_RESULT",
    "CLAIM_SCHEMA_ID",
    "CLAIM_SCOPE",
    "CLAIM_TEXT",
    "CONTRACT_VERSION",
    "EXTERNAL_PINS_SCHEMA_ID",
    "HISTORY_SCHEMA_ID",
    "LIMITATIONS",
    "MAX_DOCUMENT_BYTES",
    "MAX_HISTORY_ITEMS",
    "NO_AUTHORITY",
    "PUBLICATION_STATE",
    "RECEIPT_SCHEMA_ID",
    "SOURCE_KINDS",
    "SOURCE_OUTCOMES",
    "SOURCE_RESULT_SCHEMA_ID",
    "SOURCE_RESULT_SCHEMAS",
    "VALIDATION_SCHEMA_ID",
]
