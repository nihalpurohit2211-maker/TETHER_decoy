"""Generated exhibits and exhibit API tests (M12)."""
from __future__ import annotations

import glob
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET

from tether import exhibits
from tether.api import handle_get_exhibit, handle_get_exhibits
from tether.report import results_digest


class TestExhibitGeneration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.result = exhibits.load_results()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = cls.tmp.name
        cls.index = exhibits.write_all(cls.out, cls.result)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_all_nine_exhibits_are_declared_and_written(self) -> None:
        self.assertEqual(len(exhibits.EXHIBIT_ORDER), 9)
        self.assertEqual([e["id"] for e in self.index["exhibits"]],
                         [f"E{i}" for i in range(1, 10)])
        for name in exhibits.EXHIBIT_ORDER:
            path = os.path.join(self.out, f"{name}.svg")
            self.assertTrue(os.path.exists(path), path)
            self.assertGreater(os.path.getsize(path), 500, path)

    def test_every_svg_is_well_formed_and_dark_themed(self) -> None:
        for path in glob.glob(os.path.join(self.out, "*.svg")):
            root = ET.parse(path).getroot()
            self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIn(exhibits.BG, text, path)
            self.assertIn(exhibits.ACCENT, text, path)
            self.assertNotIn("None", text, path)

    def test_svg_numbers_are_drawn_from_results(self) -> None:
        def read(name: str) -> str:
            with open(os.path.join(self.out, f"{name}.svg"), "r",
                      encoding="utf-8") as fh:
                return fh.read()

        by_id = {a["id"]: a for a in self.result["attacks"]}
        detection = read("detection")
        self.assertIn(f"{by_id['a1_pdf_injection']['detected_pct']:.1f}%", detection)
        self.assertIn(f"{by_id['a3_mimicry']['phase2']['detected_pct']:.1f}%", detection)

        latency = read("latency")
        self.assertIn(f"{self.result['latency_ms']['p95']:.3f}", latency)
        self.assertIn(f"{self.result['latency_ms']['max']:.3f}", latency)

        ladder = read("ladder")
        total = sum(self.result["ladder_usage_total"]["actions"].values())
        self.assertIn(f"{total:,}", ladder)
        self.assertIn(f"{self.result['ladder_usage_total']['actions']['isolate']:,}",
                      ladder)

        utility = read("utility")
        self.assertIn(f"{self.result['attack_session_utility_pct']:.1f}%", utility)
        self.assertIn(f"{self.result['benign']['utility_preserved_pct']:.1f}%", utility)

        identity = read("identity")
        self.assertIn("0.0%", identity)
        self.assertIn("100.0%", identity)

        ablation = read("ablation")
        max_delta = max(cell["delta_caught_pp"]
                        for row in self.result["ablation"]["rows"]
                        for cell in row["attacks"].values())
        self.assertIn(f"+{max_delta:.1f}", ablation)

    def test_captions_state_seed_n_and_unit(self) -> None:
        seed = self.result["meta"]["seed"]
        for entry in self.index["exhibits"]:
            caption = entry["caption"]
            self.assertIn(f"Seed {seed}", caption, entry["name"])
            self.assertIn(f"n = {entry['n']}", caption, entry["name"])
            self.assertIn(f"unit = {entry['unit']}", caption, entry["name"])
            self.assertTrue(entry["source"], entry["name"])

    def test_index_is_tied_to_the_measured_results_digest(self) -> None:
        self.assertEqual(self.index["results_sha256"],
                         results_digest(self.result))
        self.assertEqual(self.index["summary"]["seed"],
                         self.result["meta"]["seed"])
        self.assertEqual(self.index["summary"]["attack_n"],
                         self.result["attacks"][0]["n"])

    def test_attackmap_covers_every_frozen_attack_id(self) -> None:
        self.assertEqual(set(exhibits.ATTACK_MAP),
                         {a["id"] for a in self.result["attacks"]})
        with open(os.path.join(self.out, "attackmap.svg"), "r",
                  encoding="utf-8") as fh:
            text = fh.read()
        for aid in exhibits.ATTACK_MAP:
            self.assertIn(aid.split("_")[0], text)

    def test_check_passes_then_fails_on_caption_tamper(self) -> None:
        self.assertEqual(exhibits.check(self.out, self.result), [])
        index_path = os.path.join(self.out, "INDEX.json")
        with open(index_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        data["exhibits"][0]["caption"] += " 999.9% hand-typed"
        with open(index_path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        errors = exhibits.check(self.out, self.result)
        self.assertTrue(errors)
        self.assertTrue(any("INDEX.json" in e for e in errors), errors)

    def test_missing_results_is_an_explicit_error(self) -> None:
        with self.assertRaises(FileNotFoundError):
            exhibits.load_results(os.path.join(self.out, "does-not-exist.json"))


class TestExhibitApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        # The API serves the repository artifacts; make sure they exist and are
        # current before the route tests. This is deterministic output.
        exhibits.write_all()

    def test_index_route_returns_generated_index(self) -> None:
        ok, payload = handle_get_exhibits()
        self.assertTrue(ok)
        self.assertIsInstance(payload, dict)
        self.assertEqual(len(payload["exhibits"]), 9)
        self.assertEqual(payload["exhibits"][0]["name"], "detection")

    def test_svg_route_returns_svg_bytes(self) -> None:
        ok, payload, content_type = handle_get_exhibit("detection.svg")
        self.assertTrue(ok)
        self.assertIn("image/svg+xml", content_type)
        self.assertIsInstance(payload, bytes)
        self.assertTrue(payload.startswith(b"<svg"))

    def test_route_rejects_traversal_and_unknown_names(self) -> None:
        bad = [
            "", "detection", "detection.txt", "nope.svg", "/detection.svg",
            "../detection.svg", "..\\detection.svg",
            "%2e%2e%2fdetection.svg", "C:\\detection.svg",
            "detection.svg/../results.json",
        ]
        for name in bad:
            ok, payload, content_type = handle_get_exhibit(name)
            self.assertFalse(ok, name)
            self.assertIn("json", content_type)
            self.assertIn("error", payload)


class TestDashboardContract(unittest.TestCase):
    def test_dashboard_has_no_hardcoded_measured_numbers(self) -> None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "dashboard.html")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        for value in ("58.8", "0.873", "99.5", "130.682", "4,517", "1,105"):
            self.assertNotIn(value, text, value)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)

    def test_dashboard_contract_markers(self) -> None:
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "dashboard.html")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("/exhibits", text)
        self.assertIn("?exhibit=", text)
        self.assertIn("NO MEASURED RESULTS", text)
        self.assertIn("export alert JSON", text)
        for token in ("#0d0d12", "#c41e3a", "#16161e", "#3a1f25",
                      "#e0e0e0", "#ff6b6b"):
            self.assertIn(token, text)


if __name__ == "__main__":
    unittest.main()
