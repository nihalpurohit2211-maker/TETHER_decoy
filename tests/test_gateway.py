"""Detector and gateway behavior tests."""
from __future__ import annotations

import unittest

from tether.contract import APPROVED_CHANGE_101, load_contract
from tether.detectors import (
    BaselineTracker,
    DriftBudget,
    contract_check,
    delegation_check,
    drift_check,
)
from tether.evaluate import _drift_anchor
from tether.fusion import confidence, fusion_score, impact_multiplier
from tether.gateway import Gateway
from tether.harness import PlannedAction, SessionPlan, run_session
from tether.ledger import Ledger
from tether.response import choose_action, narrow_from_contract
from tether.sim.scenarios import BENIGN_STATEMENTS, a1_plan, a2_plan, benign_plan, legit_change_plan
from tether.types import DetectorResult

from tests.test_core import make_event


def fresh_gateway(phase2: bool = False) -> tuple[Gateway, Ledger]:
    contract = load_contract()
    tracker = BaselineTracker(contract)
    from tether.evaluate import make_config

    cfg = make_config("tether", phase2, BENIGN_STATEMENTS, contract, None)
    gateway = Gateway(contract, tracker, gate=cfg.gate, budget=cfg.budget, phase2=phase2)
    return gateway, Ledger(":memory:"), cfg


class TestDetectors(unittest.TestCase):
    def test_contract_flags_restricted_and_tool(self) -> None:
        contract = load_contract()
        from tether.gateway import SessionState

        state = SessionState(session="t1")
        res = contract_check(make_event(tool="hr_db.query", data_class="hr_salary",
                                        records=10), contract, state)
        self.assertEqual(res.score, 1.0)
        self.assertTrue(any("not in the permitted set" in r for r in res.reasons))

    def test_baseline_cold_start_does_not_flag_contract_work(self) -> None:
        contract = load_contract()
        tracker = BaselineTracker(contract)
        ev = make_event()
        res = tracker.score_event(ev, 0.0, 0.0)
        self.assertEqual(res.score, 0.0)

    def test_baseline_flags_unseen_tool_pair(self) -> None:
        contract = load_contract()
        tracker = BaselineTracker(contract)
        res = tracker.score_event(make_event(tool="hr_db.query", data_class="hr_salary"), 0.0, 0.0)
        self.assertEqual(res.score, 0.6)

    def test_impact_multiplier_bounds(self) -> None:
        self.assertEqual(impact_multiplier(False, False), 1.0)
        self.assertEqual(impact_multiplier(True, True), 1.4)

    def test_fusion_floors_are_canonical(self) -> None:
        results = {"contract": DetectorResult("contract", 1.0, 0.9)}
        self.assertEqual(
            fusion_score(results, True, False, False, False),
            70.0,
        )
        self.assertEqual(
            fusion_score(results, True, True, False, True),
            90.0,
        )

    def test_confidence_is_zero_without_signals(self) -> None:
        self.assertEqual(confidence({"contract": DetectorResult("contract", 0, 0.9)}, 0.5), 0.0)


class TestResponse(unittest.TestCase):
    def test_rungs(self) -> None:
        self.assertEqual(choose_action(10, False), ("allow", "log"))
        self.assertEqual(choose_action(45, False), ("hold", "annotate"))
        self.assertEqual(choose_action(70, False), ("narrow", "narrow"))
        self.assertEqual(choose_action(85, False), ("quarantine", "quarantine"))
        self.assertEqual(choose_action(95, True), ("isolate", "isolate"))
        # uncorroborated 95 caps at quarantine (D12)
        self.assertEqual(choose_action(95, False), ("quarantine", "quarantine"))

    def test_narrowed_capsule_denies(self) -> None:
        contract = load_contract()
        caps = narrow_from_contract(contract)
        self.assertTrue(caps.denies_tool_class_ext("http.post", "hr_salary",
                                                   "attacker.example", contract))
        self.assertFalse(caps.denies_tool_class_ext("email.send", "supplier_pricing",
                                                    "mail.internal", contract))


class TestGateway(unittest.TestCase):
    def test_a1_blocked_before_bytes_leave(self) -> None:
        ledger, cfg, na = self._run_a1("plain")
        self.assertEqual(na.leak_bytes, 0)
        self.assertEqual(na.leak_records, 0)
        self.assertTrue(na.detected)

    def _run_a1(self, tier: str):
        contract = load_contract()
        tracker = BaselineTracker(contract)
        from tether.evaluate import make_config

        cfg = make_config("tether", False, BENIGN_STATEMENTS, contract, None)
        plan = a1_plan("a1-test", tier, __import__("random").Random(7))
        ledger = Ledger(":memory:")
        result = run_session(plan, "tether", cfg, ledger)
        ledger.close()
        return ledger, cfg, result

    def test_a1_same_result_all_tiers(self) -> None:
        for tier in ("plain", "mild", "mimic"):
            with self.subTest(tier=tier):
                _, _, result = self._run_a1(tier)
                # the send step must be cut in every tier with the same action
                send_steps = [(s[2], s[3]) for s in result.steps if s[1] == "http.post"]
                self.assertEqual(send_steps, [("block", 70.0)])

    def test_legit_change_no_high_severity_alert(self) -> None:
        contract = load_contract()
        from tether.evaluate import make_config

        cfg = make_config("tether", False, BENIGN_STATEMENTS, contract, None)
        plan = legit_change_plan("legit-test", __import__("random").Random(3))
        ledger = Ledger(":memory:")
        result = run_session(plan, "tether", cfg, ledger)
        ledger.close()
        self.assertFalse(result.detected)

    def test_benign_sessions_no_alerts(self) -> None:
        contract = load_contract()
        from tether.evaluate import make_config

        cfg = make_config("tether", False, BENIGN_STATEMENTS, contract, None)
        import random

        rng = random.Random(11)
        ledger = Ledger(":memory:")
        for i in range(5):
            plan = benign_plan(f"benign-t{i}", rng)
            result = run_session(plan, "tether", cfg, ledger)
            self.assertFalse(result.detected, f"benign session {i} flagged: {result.steps}")
        ledger.close()

    def test_brand_new_session_first_action_guarded(self) -> None:
        gateway, ledger, _cfg = fresh_gateway()
        ev = make_event(session="brand-new-1", tool="http.post", action="post",
                        data_class="hr_salary", destination="attacker.example",
                        bytes=9000, records=50, carries=["hr_salary:q"])
        dec, state = gateway.evaluate(ev)
        # a first action that violates the contract must never be allowed
        self.assertIn(dec.action, ("narrow", "quarantine", "hold", "isolate"))
        self.assertGreaterEqual(dec.score, 70.0)

    def test_no_baseline_learning_from_attack_session(self) -> None:
        contract = load_contract()
        from tether.evaluate import make_config

        cfg = make_config("tether", False, BENIGN_STATEMENTS, contract, None)
        plan = a2_plan("a2-test", __import__("random").Random(5))
        ledger = Ledger(":memory:")
        run_session(plan, "tether", cfg, ledger)
        self.assertEqual(cfg.tracker.learned_sessions, 0)
        ledger.close()


class TestDriftAndDelegation(unittest.TestCase):
    def test_drift_budget_fires_on_repeated_high_volume(self) -> None:
        budget = DriftBudget(_drift_anchor())
        score = 0.0
        for _ in range(3):
            ev = make_event(tool="email.send", action="send",
                            data_class="supplier_pricing",
                            destination="supplier-portal.example",
                            bytes=40000, records=20)
            score = drift_check(ev, budget).score
        self.assertEqual(score, 1.0)
        shrunk = DriftBudget(_drift_anchor())
        score = DriftBudget(_drift_anchor()).observe("supplier-portal.example", 3000)
        self.assertLess(score, 0.5)

    def test_delegation_authority_intersection(self) -> None:
        contract = load_contract()
        ev = make_event(tool="inter_agent.send", action="send",
                        resource="delegation_task:x", data_class="hr_salary",
                        destination="agent://hr_agent", records=150,
                        carries=["hr_salary:batch"], labels=["CARRY"],
                        lineage=["procurement_agent", "hr_agent"])
        res = delegation_check(ev, contract, None)
        self.assertGreaterEqual(res.score, 0.5)
        res2 = delegation_check(ev, contract, ["pricing_api.read"])
        self.assertEqual(res2.score, 1.0)


if __name__ == "__main__":
    unittest.main()
