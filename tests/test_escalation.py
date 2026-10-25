"""Ladder + escalation tests (M10).

H4: every rung fires and is counted. H8: benign identities are never isolated.
H9: a8 is sequence-illegal while every individual step is contract-legal.
"""
from __future__ import annotations

import random
import unittest

from tether.contract import load_contract
from tether.detectors import contract_check
from tether.escalation import EscalationState
from tether.evaluate import evaluate
from tether.gateway import SessionState
from tether.harness import _event_for
from tether.identity import new_authority
from tether.response import choose_action
from tether.sim.scenarios import a8_plan, a7_plan


class TestEscalationPolicy(unittest.TestCase):
    def test_fresh_identity_keeps_v1_bands(self) -> None:
        st = EscalationState()
        st.begin_session()
        self.assertEqual(st.level, 0)
        for base in ("allow", "hold", "narrow", "quarantine"):
            self.assertEqual(st.next_action(base)[0], base)

    def test_repeat_narrow_becomes_quarantine_then_isolate(self) -> None:
        st = EscalationState()
        st.begin_session()
        st.record("narrow", "s1")
        st.begin_session()
        self.assertEqual(st.level, 1)
        self.assertEqual(st.next_action("narrow")[0], "quarantine")
        st.record("quarantine", "s2")
        st.begin_session()
        self.assertEqual(st.level, 2)
        self.assertEqual(st.next_action("narrow")[0], "isolate")

    def test_quiet_window_clears_history(self) -> None:
        st = EscalationState(window=3)
        st.begin_session()
        st.record("narrow", "s1")
        for _ in range(3):
            st.begin_session()          # three quiet sessions
        self.assertEqual(st.level, 0)
        self.assertEqual(st.next_action("narrow")[0], "narrow")

    def test_blocked_probes_count_once_per_session(self) -> None:
        st = EscalationState()
        st.begin_session()
        st.record("block", "s1")
        st.record("block", "s1")
        st.record("block", "s1")
        self.assertEqual(st.severity, 1.0)
        st.begin_session()
        st.record("block", "s2")
        self.assertEqual(st.severity, 2.0)

    def test_hold_does_not_escalate(self) -> None:
        st = EscalationState()
        st.begin_session()
        st.record("hold", "s1")
        self.assertEqual(st.level, 0)

    def test_bands_are_unchanged(self) -> None:
        self.assertEqual(choose_action(29.9, False)[0], "allow")
        self.assertEqual(choose_action(30.0, False)[0], "hold")
        self.assertEqual(choose_action(60.0, False)[0], "narrow")
        self.assertEqual(choose_action(80.0, False)[0], "quarantine")
        self.assertEqual(choose_action(92.0, True)[0], "isolate")
        self.assertEqual(choose_action(92.0, False)[0], "quarantine")


class TestLadderCoverage(unittest.TestCase):
    """H4 on the a7 corpus: a rung with count 0 is a defect."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.res = evaluate(seed=7, counts={"a7_persistent": 20}, phase2=True)

    def test_every_rung_fires_in_a7(self) -> None:
        actions = self.res["ladder_usage"]["a7_persistent"]["actions"]
        for rung in ("allow", "hold", "narrow", "quarantine", "isolate"):
            self.assertGreaterEqual(actions.get(rung, 0), 1, f"{rung} never fired")

    def test_hard_return_blocks_the_exfil_chain(self) -> None:
        """The hr->attacker chain is blocked. The allowlisted-destination drip is
        still bounded-but-allowed by policy (same as a3) and is reported."""
        from tether.evaluate import make_config
        from tether.harness import run_session
        from tether.ledger import Ledger
        from tether.sim.scenarios import BENIGN_STATEMENTS

        a7 = next(a for a in self.res["attacks"] if a["id"] == "a7_persistent")
        self.assertLessEqual(a7["records_out_tether_median"], 6.0)
        plan = a7_plan("a7_persistent-0030", random.Random(7))  # hard phase
        cfg = make_config("tether", True, BENIGN_STATEMENTS, load_contract(), None)
        res = run_session(plan, "tether", cfg, Ledger(":memory:"))
        self.assertTrue(res.detected)
        exfil = [d for ev, d in res.decision_events if ev.tool == "http.post"]
        self.assertTrue(exfil, "the exfil step was never evaluated")
        self.assertNotEqual(exfil[0].action, "allow")


class TestBenignNeverIsolated(unittest.TestCase):
    """H8: escalation must not leak into legitimate work."""

    def test_benign_and_legit_change_never_escalate(self) -> None:
        res = evaluate(seed=7, counts={"benign": 80, "legit_change": 30}, phase2=True)
        for corpus in ("benign", "legit_change"):
            actions = res["ladder_usage"][corpus]["actions"]
            self.assertEqual(set(actions), {"allow"}, corpus)
        self.assertEqual(res["benign"]["false_alerts_per_1000_incl_legit_change"], 0.0)


class TestCompositionAttack(unittest.TestCase):
    """H9: a8's steps are all contract-legal; only the sequence is illegal."""

    def setUp(self) -> None:
        self.contract = load_contract()
        self.authority = new_authority(self.contract)

    def test_every_a8_step_passes_the_contract_check(self) -> None:
        plan = a8_plan("a8-test", random.Random(7))
        state = SessionState(session="a8-test")
        for idx, step in enumerate(plan.steps, start=1):
            ev = _event_for(plan, idx, step, self.contract, self.authority)
            res = contract_check(ev, self.contract, state)
            self.assertEqual(res.score, 0.0, f"step {idx} ({step.tool}) is a contract violation")
            state.executed_records += step.records

    def test_a8_is_caught_with_zero_leak(self) -> None:
        res = evaluate(seed=7, counts={"a8_composition": 10}, phase2=True)
        a8 = next(a for a in res["attacks"] if a["id"] == "a8_composition")
        self.assertEqual(a8["detected_pct"], 100.0)
        self.assertEqual(a8["records_out_tether_median"], 0.0)
        self.assertEqual(a8["caught_before_harmful_send_pct"], 100.0)


if __name__ == "__main__":
    unittest.main()
