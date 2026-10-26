"""Vercel serverless function: live replay on the hosted website.

Serves GET /run (rewritten from vercel.json) by reusing the exact simulator
code the local API uses (`tether.api.run_scenario_sessions`), so the hosted
replay is byte-for-byte the same behaviour as `python -m tether.api`. Pure
stdlib only - no framework, no external dependencies (HARD RULE: Python stays
stdlib-only).

Routing: Vercel maps api/run.py -> /api/run; vercel.json rewrites /run ->
/api/run so the dashboard's existing `fetch("/run?...")` keeps working
unchanged.

The /run code path opens only tether/contract.json (via load_contract); it
does NOT need contract.sig.json. The whole `tether/` package plus
tether/contract.json are bundled with this function.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

# Make the repo root importable so `import tether` resolves inside the
# function regardless of how the runtime sets up sys.path. The repo root is
# the parent of this api/ directory.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tether.api import (  # noqa: E402  (import after sys.path fix)
    known_scenario,
    parse_run_params,
    run_scenario_sessions,
)

# Hosted guard: the local API clamps n to 20, but a public endpoint should not
# let a stranger burn function seconds on big batch runs. The dashboard only
# ever sends n=1; capping here is a deployment safeguard, not a behaviour
# change to the simulator or the dashboard. Raise deliberately if needed.
_HOSTED_MAX_N = 4


def _json(handler: "handler", obj, status: int = 200) -> None:
    body = json.dumps(obj).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class handler(BaseHTTPRequestHandler):
    """Vercel dispatches do_GET for GET requests; mirrors tether.api.Handler."""

    server_version = "TetherRun/0.1"

    def log_message(self, fmt, *args):  # quiet (no per-request logging)
        return

    def do_GET(self) -> None:  # noqa: N802 (stdlib API)
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path not in ("/run", "/api/run"):
            _json(self, {"error": "not found"}, 404)
            return

        # Flatten the query string into the dict shape parse_run_params expects.
        flat = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        try:
            scenario, mode, n, seed, phase2 = parse_run_params(flat)
        except ValueError as exc:
            _json(self, {"error": str(exc)}, 400)
            return
        if not known_scenario(scenario):
            _json(self, {"error": "unknown scenario"}, 404)
            return

        # Hosted cap (see _HOSTED_MAX_N); parse_run_params already clamped >=1.
        n = max(1, min(n, _HOSTED_MAX_N))
        try:
            sessions = run_scenario_sessions(scenario, mode, n, seed, phase2)
        except Exception as exc:  # surface as a clean 500, not a stack trace
            _json(self, {"error": f"run failed: {exc}"}, 500)
            return
        _json(self, {"sessions": sessions})
