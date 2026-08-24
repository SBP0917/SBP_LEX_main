from __future__ import annotations

import pathlib
import unittest

from .golden import build_golden_transcript
from .sbp_lex_wire import (
    MAX_FRAME_BYTES,
    WireError,
    decode_frame,
    encode_frame,
    encode_message,
    parse_message,
    seal_message,
    signature_preimage,
    transcript_digest,
    validate_transcript,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "vectors" / "golden_transcript.jsonl"
CASES = ROOT / "vectors" / "adversarial_cases.txt"


class WireContractTests(unittest.TestCase):
    def _golden_lines(self) -> list[bytes]:
        return [line for line in GOLDEN.read_bytes().splitlines() if line]

    def test_shared_golden_vectors_round_trip_and_chain(self) -> None:
        generated = [encode_message(item) for item in build_golden_transcript()]
        self.assertEqual(generated, self._golden_lines())
        parsed = [parse_message(line) for line in generated]
        validate_transcript(parsed, trusted_now_ms=1_900_000_000_100)
        for message in parsed:
            self.assertEqual(decode_frame(encode_frame(message)), message)

    def test_shared_adversarial_vectors_fail_closed(self) -> None:
        names = {line for line in CASES.read_text("ascii").splitlines() if line}
        self.assertEqual(
            names,
            {
                "binding_mutation",
                "duplicate_field",
                "extra_field",
                "kind_mismatch",
                "missing_field",
                "noncanonical_integer",
                "order_mismatch",
                "oversize",
                "replay_nonce",
                "surrogate_escape",
            },
        )
        lines = self._golden_lines()
        first = lines[0]

        mutation = first.replace(b'"state_digest":"', b'"state_digest":"f', 1)
        duplicate = first[:-1] + b',"state_digest":"' + b"0" * 64 + b'"}'
        extra = first[:-1] + b',"unexpected":"value"}'
        missing_start = first.index(b'"adapter_digest"')
        missing_end = first.index(b",", missing_start) + 1
        missing = first[:missing_start] + first[missing_end:]
        noncanonical = first.replace(b'"sequence":0', b'"sequence":00', 1)
        surrogate = first.replace(b'"mode":"MODE_1"', b'"mode":"\\ud800"', 1)
        oversized = b"{" + b"x" * MAX_FRAME_BYTES + b"}"
        for payload in (mutation, duplicate, extra, missing, noncanonical, surrogate, oversized):
            with self.assertRaises(WireError):
                parse_message(payload)

        messages = [parse_message(line) for line in lines]
        replay = list(messages)
        replay[1] = dict(replay[1])
        replay[1]["nonce"] = replay[0]["nonce"]
        replay[1] = seal_message(replay[1])
        with self.assertRaises(WireError):
            validate_transcript(replay)

        wrong_kind = list(messages)
        wrong_kind[2] = dict(wrong_kind[2])
        wrong_kind[2]["kind"] = "commit_request"
        with self.assertRaises(WireError):
            validate_transcript(wrong_kind)

        wrong_order = list(messages)
        wrong_order[2], wrong_order[3] = wrong_order[3], wrong_order[2]
        with self.assertRaises(WireError):
            validate_transcript(wrong_order)

        stale = [dict(item) for item in messages]
        with self.assertRaises(WireError):
            validate_transcript(stale, trusted_now_ms=1_900_000_001_000)

        denial = [dict(item) for item in messages[:2]]
        denial[1]["decision"] = "DENY"
        denial[1]["error_code"] = "CONVERGENCE_FAILED"
        denial[1] = seal_message(denial[1])
        validate_transcript(denial, trusted_now_ms=1_900_000_000_100)

        downgrade = [dict(item) for item in messages]
        downgrade[2]["authority_class"] = "SOFTWARE"
        downgrade[2] = seal_message(downgrade[2])
        with self.assertRaises(WireError):
            validate_transcript(downgrade)

        failed_effect = [dict(item) for item in messages]
        failed_effect[12]["effect_outcome"] = "FAILED"
        failed_effect[12] = seal_message(failed_effect[12])
        with self.assertRaises(WireError):
            validate_transcript(failed_effect)

        stopped = [dict(item) for item in messages]
        stopped[14]["watchdog_status"] = "STOP"
        stopped[14] = seal_message(stopped[14])
        with self.assertRaises(WireError):
            validate_transcript(stopped)

    def test_frame_failures_are_not_recovered(self) -> None:
        message = build_golden_transcript()[0]
        frame = encode_frame(message)
        for bad in (frame[:3], frame[:-1], frame + b"x", b"\x00\x00\x00\x00"):
            with self.assertRaises(WireError):
                decode_frame(bad)

    def test_timeout_failure_modes_and_signature_preimage(self) -> None:
        messages = build_golden_transcript()
        timeout = [dict(item) for item in messages[:12]]
        terminal = dict(messages[14])
        terminal.update(
            {
                "sequence": 12,
                "message_time_ms": terminal["expires_at_ms"] - 400,
                "prior_transcript_digest": timeout[-1]["transcript_digest"],
                "receipt_digest": "0" * 64,
                "watchdog_status": "TIMEOUT",
            }
        )
        terminal = seal_message(terminal)
        result = dict(messages[15])
        result.update(
            {
                "sequence": 13,
                "message_time_ms": terminal["message_time_ms"] + 10,
                "prior_transcript_digest": terminal["transcript_digest"],
                "decision": "BLOCK",
                "error_code": "WATCHDOG_TIMEOUT",
            }
        )
        timeout.extend((terminal, seal_message(result)))
        validate_transcript(timeout)

        failed = [dict(item) for item in messages]
        failed[12]["effect_outcome"] = "FAILED"
        failed[13]["receipt_status"] = "FAILURE_RECORDED"
        failed[14]["watchdog_status"] = "STOP"
        failed[15]["decision"] = "BLOCK"
        failed[15]["error_code"] = "EFFECT_FAILED"
        prior = failed[11]["transcript_digest"]
        for index in range(12, 16):
            failed[index]["prior_transcript_digest"] = prior
            failed[index] = seal_message(failed[index])
            prior = failed[index]["transcript_digest"]
        validate_transcript(failed)

        signed = dict(messages[1])
        digest = transcript_digest(signed)
        signed["signature_hex"] = "ab" * 32
        self.assertEqual(transcript_digest(signed), digest)
        self.assertEqual(signature_preimage(signed)[-32:], bytes.fromhex(digest))
        encode_message(signed)  # structure is valid; an admitted ML-DSA verifier must decide it.
        signed["authority_key_id"] = "cd" * 32
        with self.assertRaises(WireError):
            seal_message(signed)

    def test_mode2_reduction_is_directly_checkable(self) -> None:
        message = dict(build_golden_transcript()[0])
        candidates = sorted(("1" * 64, "2" * 64))
        pathways = sorted(("3" * 64, "4" * 64))
        message.update(
            {
                "mode": "MODE_2",
                "mode_evidence_type": "VALIDATOR_REDUCTION_PROOF",
                "candidate_input_set": ",".join(candidates),
                "candidate_output_set": candidates[0],
                "pathway_input_set": ",".join(pathways),
                "pathway_output_set": pathways[0],
                "validator_certificate_digest": "5" * 64,
                "no_widening_proof_digest": "6" * 64,
            }
        )
        encode_message(seal_message(message))
        message["candidate_output_set"] = "7" * 64
        with self.assertRaises(WireError):
            seal_message(message)


if __name__ == "__main__":
    unittest.main()
