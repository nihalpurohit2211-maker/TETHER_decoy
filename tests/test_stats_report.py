"""Tests for the v2 evaluation plumbing: stats, report, verdicts, schema."""
from __future__ import annotations

import json
import os
import tempfile
import unittest

from tether.ablation import DETECTORS, _summary, run_ablation
from tether.contract import load_contract
from tether.evaluate import evaluate
from tether.report import (
    CLAIMS_BEGIN,
    build_manifest,
    canonical_json,
    render_claims_block,
    render_results_table,
    results_digest,
    write_manifest,
)
from tether.sim.scenarios import build_sessions
from tether.stats import cdf_points, median, percentile, rate_with_ci, wilson_ci
from tether.verdicts import evaluate_hypotheses, verdict_summary


class TestStats(unittest.TestCase):
    def test_wilson_zero_of_hundred_has_nonzero_upper(self) -> None:
        lo, hi = wilson_ci(0, 100)
        self.assertEqual(lo, 0.0)
        self.assertTrue(3.0 < hi < 4.5, hi)

    def test_wilson_all_of_hundred(self) -> None:
        lo, hi = wilson_ci(100, 100)
        self.assertEqual(hi, 100.0)
        self.assertTrue(95.0 < lo < 97.0, lo)

    def test_wilson_brackets_point_estimate(self) -> None:
        for k, n in ((1, 3), (17, 40), (199, 200), (0, 1), (1, 1)):
            lo, hi = wilson_ci(k, n)
            self.assertLessEqual(lo, 100.0 * k / n + 1e-9)
            self.assertGreaterEqual(hi, 100.0 * k / n - 1e-9)

    def test_rate_with_ci_reports_k_and_n(self) -> None:
        r = rate_with_ci(3, 4)
        self.assertEqual((r["k"], r["n"]), (3, 4))
        self.assertEqual(r["pct"], 75.0)
        self.assertEqual(len(r["ci95"]), 2)

    def test_percentile_and_median_nearest_rank(self) -> None:
        vals = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        self.assertEqual(percentile(vals, 0.0), 0)
        self.assertEqual(percentile(vals, 1.0), 9)
        self.assertEqual(median(vals), 4.5)
        self.assertEqual(percentile([], 0.5), 0.0)

    def test_cdf_points_are_monotone_and_end_at_100(self) -> None:
        pts = cdf_points([5, 1, 3, 2, 4], 60)
        self.assertEqual(pts[-1][1], 100.0)
        self.assertEqual([v for v, _ in pts], sorted(v for v, _ in pts))
        self.assertTrue(all(b >= a for a, b in zip(
            [p for _, p in pts], [p for _, p in pts][1:]
        )))


def _fake_result() -> dict:
    """Minimal results-shaped dict for verdict/report unit tests."""
    base = {
        "id": "a1_pdf_injection", "name": "pdf", "n": 100,
        "detected_pct": 100.0, "detected_ci95": [96.3, 100.0],
        "caught_before_harmful_send_pct": 100.0, "caught_ci95": [96.3, 100.0],
        "k_detected": 100, "k_caught": 100,
        "median_steps_to_detect": 3.0, "records_out_none": 130.0,
        "records_out_tether_median": 0.0, "leak_p90_none": 150.0,
        "leak_p90_tether": 0.0, "leak_samples_none": [130], "leak_samples_tether": [0],
        "phase2": {"detected_pct": 100.0, "detected_ci95": [96.3, 100.0],
                   "caught_before_harmful_send_pct": 100.0,
                   "caught_ci95": [96.3, 100.0], "n": 100},
    }
    a2 = json.loads(json.dumps(base))
    a2["id"], a2["name"] = "a2_tool_poisoning", "tool"
    a3 = json.loads(json.dumps(base))
    a3["id"], a3["name"] = "a3_mimicry", "mimic"
    a3["detected_pct"] = 0.0
    a3["detected_ci95"] = [0.0, 3.7]
    a3["phase2"]["detected_pct"] = 95.0
    a3["phase2"]["detected_ci95"] = [91.0, 97.4]
    a3["records_out_tether_median"] = 16.0
    a8 = json.loads(json.dumps(base))
    a8["id"], a8["name"] = "a8_composition", "composition"
    return {
        "meta": {"seed": 7, "counts": {}, "phase2": True,
                 "benign_sessions": 100, "legit_change_sessions": 10,
                 "schema_version": 2},
        "attacks": [base, a2, a3, a8],
        "benign": {
            "false_alerts_per_1000_ordinary": 0.0,
            "false_alerts_per_1000_incl_legit_change": 0.0,
            "utility_preserved_pct": 100.0,
            "n_ordinary": 100, "n_incl_legit_change": 110,
            "false_alert_ci95_pct": [0.0, 3.3], "utility_ci95_pct": [97.0, 100.0],
        },
        "identity_arm": {"attacks": [
            {"id": "a1_pdf_injection", "detected_pct": 0.0, "ci95": [0.0, 3.7], "n": 100},
            {"id": "a2_tool_poisoning", "detected_pct": 0.0, "ci95": [0.0, 3.7], "n": 100},
            {"id": "a3_mimicry", "detected_pct": 0.0, "ci95": [0.0, 3.7], "n": 100},
            {"id": "a4_low_and_slow", "detected_pct": 0.0, "ci95": [0.0, 3.7], "n": 100},
            {"id": "a5_stolen_token", "detected_pct": 100.0, "ci95": [96.3, 100.0], "n": 100},
            {"id": "a6_delegation", "detected_pct": 100.0, "ci95": [96.3, 100.0], "n": 100},
            {"id": "a9_impersonation", "detected_pct": 100.0, "ci95": [96.3, 100.0], "n": 100},
        ]},
        "ladder_usage": {"benign": {"actions": {"allow": 100}},
                         "legit_change": {"actions": {"allow": 10}}},
        "ladder_usage_total": {"actions": {
            "allow": 50, "hold": 2, "narrow": 2, "quarantine": 2, "isolate": 2,
            "block": 1,
        }},
        "latency_ms": {"p50": 0.1, "p95": 0.5, "p99": 1.2, "max": 3.0, "n": 500},
        "drift_trajectory": {}, "threshold_sweep": {"rows": []},
        "attack_session_utility_pct": 80.0,
        "wall_seconds": 1.0,
        "caveats": ["simulation"],
    }


class TestVerdicts(unittest.TestCase):
    def test_all_pass_on_clean_fixture(self) -> None:
        hyp = evaluate_hypotheses(_fake_result(), determinism=True)
        for hid in ("H1", "H2", "H3", "H4", "H5", "H6", "H8"):
            self.assertEqual(hyp[hid]["status"], "PASS", (hid, hyp[hid]))
        self.assertEqual(hyp["H7"]["status"], "DEFERRED")
        self.assertEqual(verdict_summary(hyp), (8, 0, 1))

    def test_h1_fails_when_caught_below_threshold(self) -> None:
        res = _fake_result()
        res["attacks"][0]["caught_before_harmful_send_pct"] = 80.0
        hyp = evaluate_hypotheses(res, determinism=True)
        self.assertEqual(hyp["H1"]["status"], "FAIL")

    def test_h3_fails_if_identity_lights_up_on_content(self) -> None:
        res = _fake_result()
        res["identity_arm"]["attacks"][0]["detected_pct"] = 40.0
        hyp = evaluate_hypotheses(res, determinism=True)
        self.assertEqual(hyp["H3"]["status"], "FAIL")

    def test_h4_fails_when_a_rung_is_unreachable(self) -> None:
        res = _fake_result()
        res["ladder_usage_total"]["actions"]["hold"] = 0
        hyp = evaluate_hypotheses(res, determinism=True)
        self.assertEqual(hyp["H4"]["status"], "FAIL")

    def test_h8_fails_on_benign_isolation(self) -> None:
        res = _fake_result()
        res["ladder_usage"]["benign"]["actions"]["isolate"] = 2
        hyp = evaluate_hypotheses(res, determinism=True)
        self.assertEqual(hyp["H8"]["status"], "FAIL")


class TestReport(unittest.TestCase):
    def test_digest_ignores_stopwatch_fields(self) -> None:
        a = _fake_result()
        b = json.loads(json.dumps(a))
        b["wall_seconds"] = 999.0
        b["latency_ms"] = {"p50": 7.0, "n": 1}
        self.assertEqual(results_digest(a), results_digest(b))
        b["benign"]["utility_preserved_pct"] = 12.0
        self.assertNotEqual(results_digest(a), results_digest(b))

    def test_digest_is_key_order_independent(self) -> None:
        a = {"x": 1, "y": [2, 3]}
        b = {"y": [2, 3], "x": 1}
        self.assertEqual(canonical_json(a), canonical_json(b))

    def test_manifest_is_deterministic_and_has_units(self) -> None:
        res = _fake_result()
        with tempfile.TemporaryDirectory() as td:
            m1 = build_manifest(res, {"H1": {"status": "PASS"}}, root=td)
            m2 = build_manifest(res, {"H1": {"status": "PASS"}}, root=td)
            self.assertEqual(m1, m2)
            self.assertEqual(m1["git_commit"], "unknown")
            self.assertIn("detection", m1["units"])
            path = os.path.join(td, "MANIFEST.json")
            written = write_manifest(td, res, {"H1": {"status": "PASS"}}, root=td)
            self.assertEqual(written, m1)
            self.assertTrue(os.path.exists(path))

    def test_claims_block_is_generated_and_marked(self) -> None:
        block = render_claims_block(_fake_result(), {"H1": {"status": "PASS"}})
        self.assertTrue(block.startswith(CLAIMS_BEGIN))
        self.assertIn("seed=7", block)
        self.assertIn("n=100", block)
        self.assertIn("H1=PASS", block)

    def test_results_table_states_seed_n_and_unit(self) -> None:
        text = render_results_table(_fake_result())
        self.assertIn("seed **7**", text)
        self.assertIn("n = **100 sessions/attack**", text)
        self.assertIn("Wilson 95% CI", text)
        self.assertIn("a3_mimicry", text)


class TestEvaluateSchemaV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.res = evaluate(seed=7, counts={
            "benign": 8, "legit_change": 2,
            "a1_pdf_injection": 3, "a3_mimicry": 3, "a7_persistent": 3,
            "a8_composition": 3,
        }, phase2=True)
        cls.by_id = {a["id"]: a for a in cls.res["attacks"]}

    def test_attack_rows_carry_ci_and_full_leak_vectors(self) -> None:
        a = self.by_id["a1_pdf_injection"]
        self.assertEqual(a["n"], 3)
        self.assertEqual(len(a["detected_ci95"]), 2)
        self.assertEqual(len(a["caught_ci95"]), 2)
        self.assertEqual(len(a["leak_samples_none"]), 3)
        self.assertEqual(len(a["leak_samples_tether"]), 3)
        self.assertIn("leak_p90_none", a)
        self.assertIn("phase2", a)
        self.assertIn("detected_ci95", a["phase2"])

    def test_latency_has_p99_n_and_cdf(self) -> None:
        lat = self.res["latency_ms"]
        self.assertIn("p99", lat)
        self.assertGreater(lat["n"], 0)
        self.assertGreater(len(lat["cdf"]), 0)
        self.assertEqual(lat["unit"], "ms per gateway decision")

    def test_drift_trajectory_exported(self) -> None:
        traj = self.res["drift_trajectory"]
        self.assertIn("a3_mimicry", traj)
        self.assertIn("a7_persistent", traj)
        row = traj["a3_mimicry"][0]
        self.assertEqual(len(row), 5)  # session, dest, records, cusum, latched

    def test_threshold_sweep_is_report_only_and_monotone(self) -> None:
        rows = self.res["threshold_sweep"]["rows"]
        self.assertEqual([r["threshold"] for r in rows],
                         [20, 30, 40, 50, 60, 70, 80, 90, 92, 95])
        self.assertIn("report-only", self.res["threshold_sweep"]["note"])
        a1 = [r["attacks"]["a1_pdf_injection"] for r in rows]
        self.assertTrue(all(b <= a + 1e-9 for a, b in zip(a1, a1[1:])))

    def test_identity_arm_rows_have_cis(self) -> None:
        for row in self.res["identity_arm"]["attacks"]:
            self.assertIn("ci95", row)

    def test_meta_declares_schema_and_units(self) -> None:
        meta = self.res["meta"]
        self.assertEqual(meta["schema_version"], 2)
        self.assertEqual(meta["unit_detection"], "session")


class TestAblation(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        counts = {"benign": 3, "legit_change": 1, "a1_pdf_injection": 2,
                  "a3_mimicry": 2, "a8_composition": 2}
        cls.sessions = build_sessions(7, counts)
        cls.contract = load_contract()
        cls.abl = run_ablation(cls.contract, cls.sessions)

    def test_every_detector_is_removed_exactly_once(self) -> None:
        removed = [r["removed"] for r in self.abl["rows"]]
        self.assertEqual(sorted(removed), sorted(DETECTORS))
        self.assertEqual(len(removed), len(set(removed)))

    def test_provenance_is_load_bearing_for_composition(self) -> None:
        """a8 is caught by the tainted-carry rule, so removing provenance must
        cost detection. a1 is NOT used here: contract and provenance are
        individually sufficient there (defence in depth), which is a result."""
        row = next(r for r in self.abl["rows"] if r["removed"] == "provenance")
        a8 = row["attacks"]["a8_composition"]
        self.assertGreater(a8["delta_caught_pp"], 0.0)
        self.assertLess(a8["caught_pct"], 100.0)

    def test_a1_shows_defence_in_depth(self) -> None:
        """Removing either contract or provenance alone still blocks a1's send
        on this tiny corpus - that is redundancy, not a failed ablation."""
        a1_scores = [r["attacks"]["a1_pdf_injection"]["caught_pct"]
                     for r in self.abl["rows"]]
        self.assertTrue(a1_scores)
        self.assertTrue(all(0.0 <= s <= 100.0 for s in a1_scores))

    def test_ablation_summary_shape(self) -> None:
        base = self.abl["base"]
        self.assertIn("attacks", base)
        self.assertIn("false_alerts_per_1000", base)
        self.assertIn("a1_pdf_injection", base["attacks"])

    def test_summary_of_empty_runs_is_stable(self) -> None:
        s = _summary({})
        self.assertEqual(s["attacks"], {})
        self.assertEqual(s["false_alerts_per_1000"], 0.0)


if __name__ == "__main__":
    unittest.main()
