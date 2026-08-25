"""Implementation-defined V2 cryptographically segmented exchange boundary."""

from .durable_replay import DurableExchangeReplayError, SQLiteExchangeReplayGuard
from .segmented_exchange import (
    EXCHANGE_ACTIVE,
    EXCHANGE_AUTHORITY_ROLE,
    EXCHANGE_REVOKED,
    InMemoryExchangeReplayGuard,
    SegmentedExchangeRejected,
    build_segmented_exchange,
    verify_and_decrypt_segmented_exchange,
)

__all__ = [
    "EXCHANGE_ACTIVE",
    "EXCHANGE_AUTHORITY_ROLE",
    "EXCHANGE_REVOKED",
    "DurableExchangeReplayError",
    "InMemoryExchangeReplayGuard",
    "SQLiteExchangeReplayGuard",
    "SegmentedExchangeRejected",
    "build_segmented_exchange",
    "verify_and_decrypt_segmented_exchange",
]
