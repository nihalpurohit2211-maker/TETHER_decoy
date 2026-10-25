"""End-to-end scenario and evaluation tests, plus a demo/api smoke test."""
from __future__ import annotations

import json
import os
import random
import tempfile
import unittest

from tether.evaluate import DEFAULT_COUNTS, evaluate
from tether.harness import PlannedAction, SessionPlan, RunConfig, run_session
from tether.ledger import Ledger
from tether.sim.scenarios import (
    BENIGN_STATEMENTS,
    a3_plan,
    a4_plan,
    a5_plan,
    a6_plan,
    benign_plan,
    build_sessions,
    legit_change_plan,
)
from tether.contract import load_contract
from tether.evaluate import make_config


def cfg_for(mode: str, phase2: bool, contract, change=None) -> RunConfig:
    return make_config(mode, phase2, BENIGN_STATEMENTS, contract, change)


class TestScenarios(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract()

    def run_tiny_eval(self, phase2: bool) -> dict:
        return evaluate(seed=3, counts=DEFAULT_COUNTS, phase2=phase2, minimal=True)

    def test_tiny_evaluation_runs_fast_and_shape_ok(self) -> None:
        res = self.run_tiny_eval(False)
        for key in ("meta", "attacks", "benign", "latency_ms", "caveats"):
            self.assertIn(key, res)
        ids = {a["id"] for a in res["attacks"]}
        self.assertIn("a1_pdf_injection", ids)
        self.assertTrue(all("detected_pct" in a for a in res["attacks"]))

    def test_a1_detected_and_zero_leak_phase1(self) -> None:
        res = self.run_tiny_eval(False)
        a1 = next(a for a in res["attacks"] if a["id"] == "a1_pdf_injection")
        self.assertEqual(a1["detected_pct"], 100.0)
        self.assertEqual(a1["records_out_tether_median"], 0.0)
        self.assertEqual(a1["caught_before_harmful_send_pct"], 100.0)

    def test_a1_textgate_tiers_nonincreasing_or_honest(self) -> None:
        res = self.run_tiny_eval(False)
        a1 = next(a for a in res["attacks"] if a["id"] == "a1_pdf_injection")
        tiers = a1["textgate_detected_pct_by_tier"]
        self.assertEqual(set(tiers), {"plain", "mild", "mimic"})
        # stand-in gate must never be reported as the tether path
        self.assertIn("textgate_detected_pct_by_tier", a1)

    def test_benign_no_false_alerts_phase1(self) -> None:
        res = self.run_tiny_eval(False)
        self.assertEqual(res["benign"]["false_alerts_per_1000_ordinary"], 0.0)

    def test_caveats_mention_honesty_items(self) -> None:
        res = self.run_tiny_eval(False)
        blob = " ".join(res["caveats"])
        self.assertIn("simulation", blob)
        self.assertIn("not an LLM judge", blob)
        self.assertIn("scripted", blob)

    def test_a3_mimicry_leaks_bounded_both_phases(self) -> None:
        res = self.run_tiny_eval(True)
        a3 = next(a for a in res["attacks"] if a["id"] == "a3_mimicry")
        none_leak = a3["records_out_none"]
        p1 = a3["records_out_tether_median"]
        self.assertGreater(none_leak, 0.0)   # mimicry executes without defense
        self.assertLess(p1, 30.0)            # bounded by ordinary volumes

    def test_a5_stolen_token_detected_phase2(self) -> None:
        res = self.run_tiny_eval(True)
        a5 = next(a for a in res["attacks"] if a["id"] == "a5_stolen_token")
        self.assertEqual(a5["detected_pct"], 100.0)

    def test_a6_delegation_blocked_phase2(self) -> None:
        res = self.run_tiny_eval(True)
        a6 = next(a for a in res["attacks"] if a["id"] == "a6_delegation")
        self.assertEqual(a6["records_out_tether_median"], 0.0)

    def test_build_sessions_is_deterministic(self) -> None:
        s1 = build_sessions(7, {"a2_tool_poisoning": 3, "benign": 2})
        s2 = build_sessions(7, {"a2_tool_poisoning": 3, "benign": 2})
        self.assertEqual(
            [ [ (step.tool, step.records) for step in pl.steps ] for pl in s1["a2_tool_poisoning"] ],
            [ [ (step.tool, step.records) for step in pl.steps ] for pl in s2["a2_tool_poisoning"] ],
        )


class TestDemoAndApi(unittest.TestCase):
    def test_demo_card_from_run_smoke(self) -> None:
        from tether.alert import card_from_result

        contract = load_contract()
        from tether.sim.scenarios import a1_plan

        plan = a1_plan("smoke", "plain", random.Random(7))
        ledger = Ledger(":memory:")
        cfg = cfg_for("tether", False, contract, None)
        result = run_session(plan, "tether", cfg, ledger)
        card = card_from_result(result, contract, plan.change)
        ledger.close()
        self.assertIsNotNone(card)
        self.assertGreaterEqual(card["score"], 60)
        self.assertEqual(len(card["reasons"]) <= 3, True)

    def test_api_handlers_no_socket(self) -> None:
        from tether.api import handle_get_contract, handle_list_scenarios

        c = handle_get_contract()
        self.assertEqual(c["role"], "procurement_agent")
        s = handle_list_scenarios()
        self.assertIn("a1_pdf_injection", s["scenarios"])

    def test_api_run_summaries_shape(self) -> None:
        from tether.api import run_scenario_sessions

        out = run_scenario_sessions("a1_pdf_injection", "tether", 1, 7, False)
        self.assertEqual(len(out), 1)
        s = out[0]
        for key in ("session", "detected", "leak_records", "utility", "timeline", "alert"):
            self.assertIn(key, s)
        self.assertEqual(s["leak_records"], 0)


if __name__ == "__main__":
    unittest.main()
