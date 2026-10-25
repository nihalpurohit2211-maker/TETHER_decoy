"""Demo CLI: `python -m tether.demo --scenario a1_pdf_injection --mode tether`

Prints a short colored step-by-step log (event, labels, score, ladder action)
and, in tether mode, the alert card. Colors are plain ANSI; `--no-color`
disables them (and older Windows consoles get a best-effort VT enable).
"""
from __future__ import annotations

import argparse
import json
import os
import random

from tether.alert import card_from_result
from tether.contract import load_contract
from tether.evaluate import make_config, seed_plan_replays
from tether.harness import run_session
from tether.ledger import Ledger
from tether.sim.scenarios import (
    BENIGN_STATEMENTS,
    a1_plan,
    a2_plan,
    a3_plan,
    a4_plan,
    a5_plan,
    a6_plan,
    benign_plan,
    legit_change_plan,
)

BUILDERS = {
    "benign": benign_plan,
    "legit_change": legit_change_plan,
    "a1_pdf_injection": a1_plan,
    "a2_tool_poisoning": a2_plan,
    "a3_mimicry": a3_plan,
    "a4_low_and_slow": a4_plan,
    "a5_stolen_token": a5_plan,
    "a6_delegation": a6_plan,
}

C = {"g": "\x1b[32m", "y": "\x1b[33m", "r": "\x1b[31m", "b": "\x1b[36m", "dim": "\x1b[2m", "x": "\x1b[0m"}


def paint(text: str, key: str, use_color: bool) -> str:
    return f"{C[key]}{text}{C['x']}" if use_color else text


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="a1_pdf_injection", choices=sorted(BUILDERS))
    ap.add_argument("--mode", default="tether", choices=["none", "textgate", "tether"])
    ap.add_argument("--tier", default="plain", choices=["plain", "mild", "mimic"])
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()
    use_color = not args.no_color
    if os.name == "nt":
        os.system("")  # best effort VT enable on Windows consoles

    contract = load_contract()
    rng = random.Random(args.seed)
    if args.scenario == "a1_pdf_injection":
        plan = a1_plan("demo-a1", args.tier, rng)
    else:
        plan = BUILDERS[args.scenario]("demo-session", rng)

    print(paint(f"Tether demo  scenario={args.scenario}  mode={args.mode}", "b", use_color))
    print(paint(f"contract role={contract.role} blueprint={contract.blueprint_version}", "dim", use_color))

    ledger = Ledger(":memory:")
    cfg = make_config(args.mode, True, BENIGN_STATEMENTS, contract, plan.change)
    seed_plan_replays(cfg.identity, plan)
    result = run_session(plan, args.mode, cfg, ledger)

    for ev, dec in result.decision_events:
        color = "g" if dec.rung == "log" else ("r" if dec.rung in ("enforcement", "quarantine", "isolate") else "y")
        labels = ",".join(ev.labels) or "-"
        line = f"  step {ev.step:>2}  {ev.tool:<22} labels[{labels}] -> "
        line += paint(dec.action.upper(), color, use_color)
        line += f"  score={dec.score:<7} rung={dec.rung:<11}"
        print(line)
        if dec.reasons and dec.rung != "log":
            print(paint(f"        reasons: {' | '.join(dec.reasons[:2])}", "dim", use_color))

    if args.mode == "tether" and result.decision_events:
        card = card_from_result(result, contract, plan.change)
        if card is not None:
            print()
            print(paint("alert card:", "b", use_color))
            print(json.dumps(card, indent=2, sort_keys=True))
        else:
            print()
            print("no alert above the log rung")

    print()
    print(paint(
        f"leak records={result.leak_records}  leak bytes={result.leak_bytes}  "
        f"utility={result.legit_executed}/{result.legit_total}  "
        f"injected-skipped={result.skipped_injected}", "dim", use_color))
    ledger.close()


if __name__ == "__main__":
    main()
