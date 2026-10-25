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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tether.contract import load_contract
from tether.evaluate import DEFAULT_COUNTS, make_config
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


def run_scenario_sessions(scenario: str, mode: str, n: int, seed: int, phase2: bool) -> list[dict]:
    contract = load_contract()
    rng_seed = seed
    if scenario == "benign":
        plans = [benign_plan(f"api-benign-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]
    elif scenario == "legit_change":
        plans = [legit_change_plan(f"api-legit-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]
    else:
        builder = ATTACK_BUILDERS.get(scenario)
        if builder is None:
            return []
        plans = [builder(f"api-{scenario}-{seed}-{i}", _api_rng(seed, i)) for i in range(n)]
    from tether.sim.scenarios import BENIGN_STATEMENTS as _B
    from tether.alert import card_from_result

    ledger = Ledger(":memory:")
    cfg = make_config(mode, phase2, _B, contract, None)
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
            "timeline": [
                {"step": s[0], "tool": s[1], "action": s[2], "score": s[3]} for s in res.steps
            ],
            "alert": card_from_result(res, contract, plan.change,
                                      learned_sessions=cfg.tracker.learned_sessions),
        })
    ledger.close()
    return summaries
    ledger.close()
    return summaries


def _api_rng(seed: int, i: int):
    import random

    return random.Random(seed * 1000 + i)


def handle_get_results() -> tuple[bool, dict | None]:
    path = os.path.join(ROOT, "results", "results.json")
    if not os.path.exists(path):
        return False, {"error": "results not written yet; run `python -m tether.evaluate --seed 7`"}
    with open(path, "r", encoding="utf-8") as fh:
        return True, json.load(fh)


def handle_get_contract() -> dict:
    contract = load_contract()
    return {"role": contract.role, "blueprint_version": contract.blueprint_version,
            "permitted_tools": contract.permitted_tools,
            "data_classes": contract.data_classes,
            "egress_allowlist": contract.egress_allowlist,
            "ceilings": {"records_per_session": contract.records_per_session,
                         "bytes_out_per_session": contract.bytes_out_per_session}}


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
        elif path == "/stream":
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            self._stream(params)
        elif path.startswith("/run"):
            params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
            scenario = params.get("scenario", "a1_pdf_injection")
            mode = params.get("mode", "tether")
            n = max(1, min(int(params.get("n", "1")), 20))
            seed = int(params.get("seed", "7"))
            phase2 = params.get("phase2", "true").lower() != "false"
            if scenario not in ("benign", "legit_change") and scenario not in ATTACK_BUILDERS:
                self._json({"error": "unknown scenario"}, 404)
                return
            self._json({"sessions": run_scenario_sessions(scenario, mode, n, seed, phase2)})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        path, _, query = self.path.partition("?")
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        scenario = body.get("scenario", "a1_pdf_injection")
        mode = body.get("mode", "tether")
        n = max(1, min(int(body.get("n", 1)), 20))
        seed = int(body.get("seed", 7))
        phase2 = bool(body.get("phase2", True))
        if scenario not in ("benign", "legit_change", *ATTACK_BUILDERS):
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

            rng = random.Random(7)
            from tether.sim.scenarios import a1_plan, a2_plan

            if scenario == "a2_tool_poisoning":
                plan = a2_plan("stream-demo", rng)
            else:
                plan = a1_plan("stream-demo", "plain", rng)
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
