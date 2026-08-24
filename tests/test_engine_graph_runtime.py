from __future__ import annotations

import unittest
from unittest import mock

from sbp_lex.aurion15.core import load_aurion_catalog
from sbp_lex.aurion15.runtime.engine_graph import (
    EngineGraphError,
    run_registered_engine_graph,
)
from sbp_lex.shared.state_builder import build_state


class EngineGraphRuntimeTests(unittest.TestCase):
    def build_state(self) -> dict:
        state = build_state(
            {
                "action": "inspect",
                "payload": {},
                "resolved_authority": "owner",
                "jurisdiction": "AU",
            }
        )
        state.update(
            {
                "boundary_status": "clear",
                "legitimacy_status": "valid",
                "procedural_truth_status": "valid",
            }
        )
        return state

    def test_every_registered_class_engine_executes(self) -> None:
        registry = load_aurion_catalog()
        state = run_registered_engine_graph(self.build_state())
        executed = {record["engine"] for record in state["engine_graph_trace"]}
        self.assertEqual(executed, set(registry.names()))
        self.assertEqual(len(executed), 31)

    def test_known_cycle_reaches_a_recorded_fixed_point(self) -> None:
        state = run_registered_engine_graph(self.build_state())
        trace = state["engine_convergence_trace"]
        self.assertEqual(len(trace), 2)
        self.assertFalse(trace[0]["matches_previous"])
        self.assertTrue(trace[1]["matches_previous"])
        self.assertEqual(trace[0]["projection_digest"], trace[1]["projection_digest"])

    def test_undeclared_engine_write_fails_closed(self) -> None:
        registry = load_aurion_catalog()
        engine = registry.get("procedural_validation_engine")
        original = type(engine).execute

        def mutate(instance, state):
            result = original(instance, state)
            result["undeclared_authority"] = True
            return result

        with mock.patch.object(type(engine), "execute", mutate):
            with self.assertRaisesRegex(EngineGraphError, "ENGINE_UNDECLARED_WRITE"):
                run_registered_engine_graph(self.build_state())


if __name__ == "__main__":
    unittest.main()
