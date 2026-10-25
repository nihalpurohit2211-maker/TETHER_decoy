"""Documentation drift checks (M11, extended M12). Exit 0 = docs agree with measurement.

What is enforced
----------------
1. results/MANIFEST.json exists, its `results_sha256` matches results.json, and
   it states seed, units and a hypothesis table.
2. results/RESULTS_TABLE.md is byte-identical to the table re-rendered from
   results.json + the manifest verdicts (so it cannot be hand-edited).
3. The generated claims block embedded in HANDOFF.md / README.md is identical
   to the block re-rendered from results.json (so quoted numbers cannot drift).
   `--fix` rewrites the block instead of failing.
4. Every generated exhibit SVG and results/exhibits/INDEX.json is byte-identical
   to a fresh render of results.json (so a judge-facing number cannot be edited
   or go stale).
5. Every test-count claim in the current docs equals the number of collected
   tests. HISTORY.md is exempt: it is an append-only record of past states.
6. Every local markdown link in the core docs points at an existing file.
7. PREREG.md is unchanged since tag m8. If it changed, DECISIONS.md must carry
   a line containing "PREREG deviation:" (frozen-metric rule, D34).

Run:  python docs_check.py          # check
      python docs_check.py --fix    # rewrite generated blocks, then check
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import subprocess
import sys

from tether import exhibits
from tether.report import (
    CLAIMS_BEGIN,
    CLAIMS_END,
    render_claims_block,
    render_results_table,
    results_digest,
)

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "results")

CORE_DOCS = [
    "README.md",
    "HANDOFF.md",
    "EXHIBITS.md",
    "TRANSFER.md",
    "DECISIONS.md",
    "PLAN_V2.md",
    "PREREG.md",
    "THREAT_MODEL.md",
    "PROBLEM_STATEMENT.md",
    "TODO.md",
]
CLAIM_DOCS = ["HANDOFF.md", "README.md"]

failures: list[str] = []
passes: list[str] = []


def ok(msg: str) -> None:
    passes.append(msg)


def bad(msg: str) -> None:
    failures.append(msg)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def check_manifest() -> tuple[dict, dict]:
    results_path = os.path.join(RESULTS, "results.json")
    manifest_path = os.path.join(RESULTS, "MANIFEST.json")
    if not os.path.exists(results_path):
        bad("results/results.json missing; run `python -m tether.evaluate --seed 7 --ablation`")
        return {}, {}
    if not os.path.exists(manifest_path):
        bad("results/MANIFEST.json missing; run `python verify.py`")
        return {}, {}
    with open(results_path, "r", encoding="utf-8") as fh:
        result = json.load(fh)
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    digest = results_digest(result)
    if manifest.get("results_sha256") != digest:
        bad(f"MANIFEST results_sha256 {manifest.get('results_sha256')} != "
            f"recomputed {digest}")
    else:
        ok(f"MANIFEST digest matches results.json ({digest[:16]}…)")
    if manifest.get("seed") != result.get("meta", {}).get("seed"):
        bad("MANIFEST seed does not match results.json")
    if not manifest.get("units"):
        bad("MANIFEST has no units block")
    if not manifest.get("hypotheses"):
        bad("MANIFEST has no hypothesis verdicts; run verify.py")
    return result, manifest


def check_results_table(result: dict, manifest: dict) -> None:
    path = os.path.join(RESULTS, "RESULTS_TABLE.md")
    if not os.path.exists(path):
        bad("results/RESULTS_TABLE.md missing")
        return
    expected = render_results_table(result, manifest.get("hypotheses") or {})
    actual = _read(path)
    if actual.strip() != expected.strip():
        bad("RESULTS_TABLE.md differs from a fresh render of results.json "
            "(hand-edited or stale); regenerate with verify.py")
    else:
        ok("RESULTS_TABLE.md matches results.json exactly")


def check_exhibits() -> None:
    """Generated SVGs + captions must be a fresh render of results.json (D57)."""
    errors = exhibits.check()
    if errors:
        bad("generated exhibits are stale or hand-edited: "
            + "; ".join(errors)
            + " (run `python -m tether.exhibits --write`)")
    else:
        ok(f"{len(exhibits.EXHIBIT_ORDER)} generated exhibits + INDEX.json "
           f"match results.json byte-for-byte")


def _replace_block(text: str, block: str) -> str:
    pattern = re.compile(
        re.escape(CLAIMS_BEGIN) + r".*?" + re.escape(CLAIMS_END), re.S
    )
    if not pattern.search(text):
        return text
    return pattern.sub(block, text)


def check_claim_blocks(result: dict, manifest: dict, fix: bool) -> None:
    block = render_claims_block(result, manifest.get("hypotheses") or {})
    for name in CLAIM_DOCS:
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        text = _read(path)
        if CLAIMS_BEGIN not in text:
            bad(f"{name} has no generated claims block (markers missing)")
            continue
        expected = _replace_block(text, block)
        if expected.strip() != text.strip():
            if fix:
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(expected)
                ok(f"{name} claims block rewritten from results.json (--fix)")
            else:
                bad(f"{name} generated claims block is stale; run "
                    f"`python docs_check.py --fix`")
        else:
            ok(f"{name} claims block matches results.json")


def collected_test_count() -> int:
    count = 0
    for path in glob.glob(os.path.join(ROOT, "tests", "test_*.py")):
        with open(path, "r", encoding="utf-8") as fh:
            count += len(re.findall(r"^\s*def test_", fh.read(), re.M))
    return count


def check_test_counts() -> None:
    actual = collected_test_count()
    patterns = [r"Ran\s+(\d+)\s+tests", r"(\d+)\s*/\s*(\d+)\s+tests",
                r"(\d+)\s+tests\b"]
    checked = 0
    for name in ("HANDOFF.md", "README.md"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        text = _read(path)
        for pat in patterns:
            for m in re.finditer(pat, text):
                for g in m.groups():
                    if g and int(g) >= 20 and int(g) != actual:
                        bad(f"{name} claims {g} tests; collected={actual}")
                        return
                checked += 1
    ok(f"test-count claims agree with {actual} collected tests ({checked} claims)")


def check_links() -> None:
    missing = []
    for name in CORE_DOCS:
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        text = _read(path)
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
            t = target.strip()
            if t.startswith(("http://", "https://", "#", "mailto:")):
                continue
            t = t.split("#", 1)[0]
            if not t:
                continue
            if not os.path.exists(os.path.join(ROOT, t)):
                missing.append(f"{name} -> {t}")
    if missing:
        bad("broken local markdown links: " + "; ".join(sorted(set(missing))))
    else:
        ok("all local markdown links resolve")


def check_prereg_frozen() -> None:
    try:
        proc = subprocess.run(
            ["git", "diff", "--quiet", "m8", "--", "PREREG.md"],
            cwd=ROOT, capture_output=True, text=True,
        )
    except OSError:
        bad("git not available; cannot check PREREG freeze")
        return
    if proc.returncode == 0:
        ok("PREREG.md unchanged since tag m8")
        return
    decisions = _read(os.path.join(ROOT, "DECISIONS.md")) \
        if os.path.exists(os.path.join(ROOT, "DECISIONS.md")) else ""
    if "PREREG deviation:" in decisions:
        ok("PREREG.md changed since m8 with a recorded deviation")
    else:
        bad("PREREG.md changed since tag m8 without a 'PREREG deviation:' "
            "entry in DECISIONS.md (D34)")


def main() -> int:
    ap = argparse.ArgumentParser(description="check documentation drift")
    ap.add_argument("--fix", action="store_true",
                    help="rewrite generated claim blocks in HANDOFF/README")
    args = ap.parse_args()

    result, manifest = check_manifest()
    if result:
        check_results_table(result, manifest)
        check_claim_blocks(result, manifest, args.fix)
        check_exhibits()
    check_test_counts()
    check_links()
    check_prereg_frozen()

    for p in passes:
        print(f"PASS  {p}")
    for f in failures:
        print(f"FAIL  {f}")
    print(f"\n{len(passes)} passed, {len(failures)} failed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
