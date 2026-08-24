from __future__ import annotations

import math
import unittest

from sbp_lex.security.integrity import (
    GENESIS_HASH,
    IntegrityContractError,
    build_hash_chain_entry,
    canonical_integrity_hash,
    verify_hash_chain_entries,
)


class IntegrityChainTests(unittest.TestCase):
    def chain(self) -> list[dict[str, str]]:
        first = build_hash_chain_entry(
            previous_hash=GENESIS_HASH,
            stage="one",
            payload={"b": 2, "a": 1.25},
        )
        second = build_hash_chain_entry(
            previous_hash=first["hash"],
            stage="two",
            payload={"decision": "DENY"},
        )
        return [first, second]

    def test_hash_is_key_order_independent_and_float_exact(self) -> None:
        left = canonical_integrity_hash({"b": 2, "a": 1.25})
        right = canonical_integrity_hash({"a": 1.25, "b": 2})

        self.assertEqual(left, right)
        self.assertNotEqual(left, canonical_integrity_hash({"a": 1, "b": 2}))

    def test_nonfinite_numbers_are_rejected(self) -> None:
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                with self.assertRaises(IntegrityContractError):
                    canonical_integrity_hash({"value": value})

    def test_chain_recomputes_every_entry(self) -> None:
        chain = self.chain()

        self.assertTrue(verify_hash_chain_entries(chain, chain[-1]["hash"]))
        chain[0]["stage"] = "altered"
        self.assertFalse(verify_hash_chain_entries(chain, chain[-1]["hash"]))

    def test_relinked_but_unrecomputed_chain_is_rejected(self) -> None:
        chain = self.chain()
        chain[0]["hash"] = "0" * 128
        chain[1]["previous_hash"] = "0" * 128

        self.assertFalse(verify_hash_chain_entries(chain, chain[-1]["hash"]))


if __name__ == "__main__":
    unittest.main()
