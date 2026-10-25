"""Stdlib http.server JSON API + SSE event stream + static dashboard.

Run: `python -m tether.api` (default port 8765) then open
http://127.0.0.1:8765/ for the dashboard.

Pure handler functions (formula below) are unit-testable without sockets;
the HTTP shell only parses paths and serializes responses.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tether import exhibits
from tether.contract import load_contract
from tether.evaluate import DEFAULT_COUNTS, make_config, seed_plan_replays
from tether.harness import run_session
from tether.ledger import Ledger
from tether.sim.scenarios import (
    ATTACK_BUILDERS,
    ATTACK_NAMES,
    BENIGN_STATEMENTS,
    benign_plan,
    legit_change_plan,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DASHBOARD_PATH = os.path.join(ROOT, "dashboard.html")

# ---------------------------------------------------------------- handlers


def handle_list_scenarios() -> dict:
    scenarios = {"benign": "ordinary procurement work", "legit_change": "approved change traffic"}
    for key in ATTACK_BUILDERS:
        scenarios[key] = ATTACK_NAMES.get(key, key)
    return {"scenarios": scenarios}


def _build_plans(scenario: str, n: int, seed: int) -> list:
    """Deterministic plan list for one scenario (shared by /run and /stream)."""
    if scenario == "benign":
        return [benign_plan(f"api-benign-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]
    if scenario == "legit_change":
        return [legit_change_plan(f"api-legit-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]
    builder = ATTACK_BUILDERS.get(scenario)
    if builder is None:
        return []
    return [builder(f"api-{scenario}-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]


def run_scenario_sessions(scenario: str, mode: str, n: int, seed: int, phase2: bool) -> list[dict]:
    contract = load_contract()
    plans = _build_plans(scenario, n, seed)
    from tether.alert import card_from_result

    ledger = Ledger(":memory:")
    cfg = make_config(mode, phase2, BENIGN_STATEMENTS, contract, None)
    for plan in plans:
        seed_plan_replays(cfg.identity, plan)
    summaries = []
    for plan in plans:
        if scenario == "a1_pdf_injection" and plan.tier == "":
            plan.tier = "plain"
        res = run_session(plan, mode, cfg, ledger)
        summaries.append({
            "session": plan.session,
            "tier": plan.tier,
            "attack": plan.attack,
            "mode": mode,
            "detected": res.detected,
            "first_alert_step": res.first_alert_step,
            "leak_records": res.leak_records,
            "utility": f"{res.legit_executed}/{res.legit_total}",
            "timeline": _timeline(res),
            "alert": card_from_result(res, contract, plan.change,
                                      learned_sessions=cfg.tracker.learned_sessions),
        })
    ledger.close()
    return summaries


def _api_rng(seed: int, i: int):
    import random

    return random.Random(seed * 1000 + i)


def _timeline(res) -> list[dict]:
    """Timeline entries from decision_events (real decisions, taint labels,
    detector reasons). Steps that were never evaluated — quarantined injected
    steps or steps after isolation — are marked `skipped`."""
    by_step = {ev.step: (ev, dec) for ev, dec in res.decision_events}
    out = []
    for step_idx, tool, _action, _score in res.steps:
        pair = by_step.get(step_idx)
        if pair is None:
            out.append({"step": step_idx, "tool": tool, "action": "skipped",
                        "score": 0.0, "labels": [], "reasons": []})
        else:
            ev, dec = pair
            out.append({"step": step_idx, "tool": ev.tool, "action": dec.action,
                        "score": dec.score, "labels": list(ev.labels),
                        "reasons": list(dec.reasons)[:2]})
    return out


def handle_get_results() -> tuple[bool, dict | None]:
    path = os.path.join(ROOT, "results", "results.json")
    if not os.path.exists(path):
        return False, {"error": "results not written yet; run `python -m tether.evaluate --seed 7`"}
    with open(path, "r", encoding="utf-8") as fh:
        return True, json.load(fh)


def handle_get_exhibits() -> tuple[bool, dict | None]:
    """Generated exhibit index. Absence is an explicit empty state, not 0.0."""
    path = os.path.join(ROOT, "results", "exhibits", "INDEX.json")
    if not os.path.exists(path):
        return False, {
            "error": "exhibits not generated yet; run "
                     "`python -m tether.exhibits --write`"
        }
    with open(path, "r", encoding="utf-8") as fh:
        return True, json.load(fh)


EXHIBIT_NAME = re.compile(r"^[a-z]+\.svg$")


def handle_get_exhibit(name: str) -> tuple[bool, bytes | dict, str]:
    """Serve one generated SVG.

    Only a lowercase basename that is a declared exhibit is allowed. Rejecting
    separators, dot-dot and URL escapes before any filesystem join keeps the
    route from becoming a path traversal primitive.
    """
    raw = str(name or "")
    if (not EXHIBIT_NAME.fullmatch(raw)
            or raw != os.path.basename(raw)
            or "/" in raw or "\\" in raw or ".." in raw):
        return False, {"error": "unknown exhibit"}, "application/json"
    stem = raw[:-4]
    if stem not in exhibits.INDEX:
        return False, {"error": "unknown exhibit"}, "application/json"
    path = os.path.join(ROOT, "results", "exhibits", raw)
    if not os.path.exists(path):
        return False, {"error": "exhibit not generated; run "
                                "`python -m tether.exhibits --write`"}, "application/json"
    with open(path, "rb") as fh:
        return True, fh.read(), "image/svg+xml; charset=utf-8"


def handle_get_contract() -> dict:
    contract = load_contract()
    return {"role": contract.role, "blueprint_version": contract.blueprint_version,
            "permitted_tools": contract.permitted_tools,
            "data_classes": contract.data_classes,
            "egress_allowlist": contract.egress_allowlist,
            "ceilings": {"records_per_session": contract.records_per_session,
                         "bytes_out_per_session": contract.bytes_out_per_session}}


VALID_MODES = ("none", "textgate", "tether")


def parse_run_params(params: dict) -> tuple[str, str, int, int, bool]:
    """Parse and validate /run parameters (GET query or POST JSON body).

    Returns (scenario, mode, n, seed, phase2). Raises ValueError with a
    human-readable message on malformed input — the HTTP shell maps that to
    a clean 400 instead of an unhandled 500. Unknown scenario names are NOT
    raised here; callers keep their existing 404 for those.
    """
    scenario = str(params.get("scenario", "a1_pdf_injection"))
    mode = str(params.get("mode", "tether"))
    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of {', '.join(VALID_MODES)}")
    try:
        n = int(params.get("n", 1))
    except (TypeError, ValueError):
        raise ValueError("n must be an integer")
    try:
        seed = int(params.get("seed", 7))
    except (TypeError, ValueError):
        raise ValueError("seed must be an integer")
    raw_phase2 = params.get("phase2", True)
    if isinstance(raw_phase2, str):
        phase2 = raw_phase2.lower() != "false"
    else:
        phase2 = bool(raw_phase2)
    return scenario, mode, max(1, min(n, 20)), seed, phase2


def known_scenario(scenario: str) -> bool:
    return scenario in ("benign", "legit_change", *ATTACK_BUILDERS)


# ------------------------------------------------------------------- shell
class Handler(BaseHTTPRequestHandler):
    server_version = "TetherAPI/0.1"

    def log_message(self, fmt, *args):  # quiet
        return

    def _json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bytes(self, body: bytes, content_type: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib API)
        path, _, query = self.path.partition("?")
        if path in ("/", "/dashboard"):
            self._dashboard()
        elif path == "/health":
            self._json({"ok": True, "time": time.time()})
        elif path == "/contract":
            self._json(handle_get_contract())
        elif path == "/scenarios":
            self._json(handle_list_scenarios())
        elif path == "/results":
            ok, obj = handle_get_results()
            self._json(obj, 200 if ok else 404)
        elif path in ("/exhibits", "/exhibits/"):
            ok, obj = handle_get_exhibits()
            self._json(obj, 200 if ok else 404)
        elif path.startswith("/exhibits/"):
            ok, payload, content_type = handle_get_exhibit(path[len("/exhibits/"):])
            if ok:
                self._bytes(payload, content_type)
            else:
                self._json(payload, 404)
        elif path == "/stream":
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            self._stream(params)
        elif path in ("/run", "/run/"):
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            try:
                scenario, mode, n, seed, phase2 = parse_run_params(params)
            except ValueError as exc:
                self._json({"error": str(exc)}, 400)
                return
            if not known_scenario(scenario):
                self._json({"error": "unknown scenario"}, 404)
                return
            self._json({"sessions": run_scenario_sessions(scenario, mode, n, seed, phase2)})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if not isinstance(body, dict):
            body = {}
        try:
            scenario, mode, n, seed, phase2 = parse_run_params(body)
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
            return
        if not known_scenario(scenario):
            self._json({"error": "unknown scenario"}, 404)
            return
        self._json({"sessions": run_scenario_sessions(scenario, mode, n, seed, phase2)})

    def _stream(self, params: dict) -> None:
        """Server-sent events: run one session in the chosen mode, stream it."""
        scenario = params.get("scenario", "a1_pdf_injection")
        mode = params.get("mode", "tether")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

        def emit(obj) -> None:
            chunk = ("data: " + json.dumps(obj) + "\n\n").encode("utf-8")
            self.wfile.write(chunk)
            self.wfile.flush()

        try:
            contract = load_contract()
            import random

            from tether.alert import card_from_result

            plans = _build_plans(scenario, 1, 7)
            if not plans:
                emit({"type": "error", "message": "unknown scenario"})
                return
            plan = plans[0]
            if scenario == "a1_pdf_injection" and plan.tier == "":
                plan.tier = "plain"
            cfg = make_config(mode, True, BENIGN_STATEMENTS, contract, plan.change)
            ledger = Ledger(":memory:")
            res = run_session(plan, mode, cfg, ledger)
            for ev, dec in res.decision_events:
                emit({
                    "type": "event", "step": ev.step, "tool": ev.tool,
                    "labels": ev.labels,
                    "decision": {"action": dec.action, "rung": dec.rung,
                                 "score": dec.score, "reasons": dec.reasons[:2]},
                })
            card = card_from_result(res, contract, plan.change,
                                    learned_sessions=cfg.tracker.learned_sessions)
            if card is not None:
                emit({"type": "alert", "alert": card})
            emit({"type": "done", "leak_records": res.leak_records,
                  "utility": f"{res.legit_executed}/{res.legit_total}"})
            ledger.close()
        except (BrokenPipeError, ConnectionResetError):
            return

    def _dashboard(self) -> None:
        if not os.path.exists(DASHBOARD_PATH):
            self._json({"error": "dashboard.html missing"}, 404)
            return
        with open(DASHBOARD_PATH, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    httpd = make_server(args.port)
    print(f"Tether API + dashboard on http://127.0.0.1:{args.port}/ (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
