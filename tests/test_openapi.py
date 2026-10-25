"""OpenAPI contract tests (M13a).

The spec is a judge-facing artifact: it must describe only routes that exist,
only a local server, and exactly the generated exhibits in tether.exhibits.INDEX.
"""
from __future__ import annotations

import json
import os
import unittest

from tether import exhibits

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC_PATH = os.path.join(ROOT, "openapi.json")

EXPECTED_PATHS = {
    "/", "/dashboard", "/health", "/contract", "/scenarios", "/run", "/stream",
    "/results", "/exhibits", "/exhibits/{name}.svg",
}


class TestOpenApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        with open(SPEC_PATH, "r", encoding="utf-8") as fh:
            cls.doc = json.load(fh)

    def test_version_and_paths_match_the_server(self) -> None:
        self.assertTrue(self.doc["openapi"].startswith("3.1"))
        self.assertEqual(set(self.doc["paths"]), EXPECTED_PATHS)
        self.assertEqual(self.doc["info"]["version"], "2.0.0")

    def test_only_the_local_server_is_documented(self) -> None:
        urls = [s["url"] for s in self.doc["servers"]]
        self.assertTrue(urls)
        for url in urls:
            self.assertTrue(
                url.startswith(("http://127.0.0.1", "http://localhost")), url
            )

    def test_exhibit_enum_matches_generated_exhibits(self) -> None:
        params = self.doc["paths"]["/exhibits/{name}.svg"]["get"]["parameters"]
        enum = []
        for param in params:
            if param.get("name") == "name":
                enum = param["schema"]["enum"]
        self.assertEqual(set(enum), set(exhibits.EXHIBIT_ORDER))
        self.assertEqual(len(enum), 9)

    def test_every_operation_is_described(self) -> None:
        for path, item in self.doc["paths"].items():
            for method, operation in item.items():
                if method in ("parameters", "servers"):
                    continue
                self.assertIn("summary", operation, f"{method} {path}")
                self.assertIn("responses", operation, f"{method} {path}")

    def test_run_has_both_read_and_write_forms(self) -> None:
        run = self.doc["paths"]["/run"]
        self.assertIn("get", run)
        self.assertIn("post", run)
        self.assertIn("requestBody", run["post"])
        self.assertIn("parameters", run["get"])

    def test_no_external_refs(self) -> None:
        text = json.dumps(self.doc)
        self.assertNotIn('"$ref": "http', text)
        self.assertNotIn('"$ref": "//', text)


if __name__ == "__main__":
    unittest.main()
