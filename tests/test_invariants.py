"""Fuzz / invariant tests for the v2 pipeline (PREREG M11 deliverable).

These do not assert *good* detection numbers. They assert that the machinery
cannot silently leave its declared bounds: scores stay in [0,100], actions and
rungs stay in the ladder's vocabulary, the ledger chain survives arbitrary
sessions, malformed envelopes never crash or authorize a tampered payload, and
the statistics helpers stay ordered.
"""
from __future__ import annotations

import random
import unittest

from tether.contract import load_contract
from tether.evaluate import make_config
from tether.harness import PlannedAction, SessionPlan, run_session
from tether.identity import identity_check, new_authority
from tether.ledger import Ledger
from tether.report import results_digest
from tether.response import RUNG_FOR
from tether.sim.scenarios import BENIGN_STATEMENTS
from tether.stats import cdf_points, percentile, wilson_ci

ACTIONS = {"allow", "hold", "narrow", "quarantine", "isolate", "block"}
RUNGS = set(RUNG_FOR.values())
TOOLS = ["pricing_api.read", "pdf.read", "purchase_request.create", "email.send",
         "hr_db.query", "http.post"]
CLASSES = ["supplier_pricing", "supplier_docs", "hr_salary", "unknown_class"]
DESTS = ["", "mail.internal", "supplier-portal.example", "vps-attacker.example"]


def random_plan(rng: random.Random, idx: int) -> SessionPlan:
    steps = []
    for step in range(rng.randint(1, 7)):
        tool = rng.choice(TOOLS)
        steps.append(PlannedAction(
            tool=tool,
            action="read" if tool.endswith(".read") or tool == "hr_db.query" else "send",
            resource=f"fuzz:{idx}:{step}",
            data_class=rng.choice(CLASSES),
            destination=rng.choice(DESTS),
            bytes=rng.randint(0, 20000),
            records=rng.randint(0, 250),
            carries=[f"fuzz:{idx}:{rng.randrange(5)}"] if rng.random() < 0.3 else [],
            statement="fuzz step",
            legitimate=rng.random() < 0.4,
            leak=rng.random() < 0.2,
        ))
    return SessionPlan(session=f"fuzz-{idx}", attack="fuzz", steps=steps,
                       host=rng.choice(["agent-run01.internal", "elsewhere.example"]),
                       network="corp" if rng.random() < 0.5 else "internet")


class TestGatewayInvariants(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        contract = load_contract()
        cls.ledger = Ledger(":memory:")
        cfg = make_config("tether", True, BENIGN_STATEMENTS, contract, None)
        rng = random.Random(1234)
        cls.results = [run_session(random_plan(rng, i), "tether", cfg, cls.ledger)
                       for i in range(15)]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.ledger.close()

    def test_scores_actions_and_rungs_stay_in_bounds(self) -> None:
        decisions = 0
        for res in self.results:
            for _ev, dec in res.decision_events:
                decisions += 1
                self.assertGreaterEqual(dec.score, 0.0)
                self.assertLessEqual(dec.score, 100.0)
                self.assertIn(dec.action, ACTIONS)
                self.assertIn(dec.rung, RUNGS)
                self.assertGreaterEqual(dec.confidence, 0.0)
                self.assertLessEqual(dec.confidence, 1.0)
        self.assertGreater(decisions, 0)

    def test_ledger_hash_chain_survives_random_sessions(self) -> None:
        self.assertTrue(self.ledger.verify_chain())

    def test_leak_and_utility_accounting_are_non_negative(self) -> None:
        for res in self.results:
            self.assertGreaterEqual(res.leak_records, 0)
            self.assertGreaterEqual(res.leak_bytes, 0)
            self.assertGreaterEqual(res.legit_executed, 0)
            self.assertLessEqual(res.legit_executed, res.legit_total)

    def test_random_run_is_deterministic(self) -> None:
        contract = load_contract()

        def once() -> str:
            ledger = Ledger(":memory:")
            cfg = make_config("tether", True, BENIGN_STATEMENTS, contract, None)
            rng = random.Random(99)
            res = [run_session(random_plan(rng, i), "tether", cfg, ledger)
                   for i in range(6)]
            ledger.close()
            return repr([(r.session, r.detected, r.first_alert_step, r.leak_records,
                          [(d.action, d.score) for _e, d in r.decision_events])
                         for r in res])

        self.assertEqual(once(), once())


class TestIdentityFuzz(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract()
        self.auth = new_authority(self.contract)

    def test_garbage_envelopes_never_raise(self) -> None:
        from tests.test_core import make_event

        garbage = [
            None, {}, {"payload": None}, {"payload": {}},
            {"payload": {}, "alg": "HS256", "key_id": "nope", "sig": "x"},
            {"payload": {"agent": "procurement_agent"}, "alg": "none",
             "key_id": "key-procurement_agent", "sig": ""},
            {"payload": "not-a-dict", "alg": "HS256",
             "key_id": "key-procurement_agent", "sig": "00"},
        ]
        for env in garbage:
            ev = make_event(envelope=env)
            res = identity_check(ev, self.auth)          # must not raise
            self.assertIn(res.score, (0.0, 0.8, 0.9, 1.0))

    def test_tampering_with_any_payload_field_breaks_the_signature(self) -> None:
        env = self.auth.issue_envelope(
            agent="procurement_agent", claimed_role="procurement_agent",
            claimed_blueprint="1.0.0", session="s", step=1, nonce="n-fuzz",
            tool="pricing_api.read", resource="pricing:1",
            data_class="supplier_pricing", destination="",
        )
        from tests.test_core import make_event

        for field in ("agent", "session", "tool", "data_class", "destination"):
            bad = {"payload": dict(env["payload"]), "alg": env["alg"],
                   "key_id": env["key_id"], "sig": env["sig"]}
            bad["payload"][field] = "tampered"
            res = identity_check(make_event(envelope=bad), self.auth)
            self.assertGreater(res.score, 0.0, field)


class TestStatsInvariants(unittest.TestCase):
    def test_wilson_ordering_for_every_n_up_to_30(self) -> None:
        for n in range(1, 31):
            for k in (0, n // 2, n):
                lo, hi = wilson_ci(k, n)
                self.assertGreaterEqual(lo, 0.0)
                self.assertLessEqual(hi, 100.0)
                self.assertLessEqual(lo, hi)
                self.assertLessEqual(lo, 100.0 * k / n + 1e-9)
                self.assertGreaterEqual(hi, 100.0 * k / n - 1e-9)

    def test_percentile_is_monotone_in_p(self) -> None:
        vals = list(range(101))
        last = -1.0
        for p in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
            v = percentile(vals, p)
            self.assertGreaterEqual(v, last)
            last = v

    def test_cdf_is_monotone_for_random_vectors(self) -> None:
        rng = random.Random(7)
        for _ in range(20):
            vals = [rng.random() * 100 for _ in range(rng.randint(1, 50))]
            pts = cdf_points(vals, 25)
            self.assertEqual(pts[-1][1], 100.0)
            self.assertTrue(all(b >= a for a, b in zip(
                [p for _, p in pts], [p for _, p in pts][1:]
            )))


class TestDigestInvariant(unittest.TestCase):
    def test_same_input_same_digest_and_volatile_changes_ignored(self) -> None:
        a = {"meta": {"seed": 7}, "attacks": [{"id": "a1", "detected_pct": 100.0}],
             "wall_seconds": 1.0, "latency_ms": {"p95": 0.9}}
        b = {"meta": {"seed": 7}, "attacks": [{"id": "a1", "detected_pct": 100.0}],
             "wall_seconds": 999.0, "latency_ms": {"p95": 123.0}}
        self.assertEqual(results_digest(a), results_digest(b))
        b["attacks"][0]["detected_pct"] = 99.0
        self.assertNotEqual(results_digest(a), results_digest(b))


if __name__ == "__main__":
    unittest.main()
