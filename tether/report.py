"""Deterministic results packaging: digest, MANIFEST.json, RESULTS_TABLE.md.

The digest exists so PREREG H6 is machine-checkable: two runs at the same seed
must hash the same. Anything measured with a stopwatch (wall_seconds, latency)
is excluded from the digest because it is real measurement but not
reproducible to the microsecond; it stays in results.json and is reported with
its own n and caveat.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import sys

VOLATILE_TOP_LEVEL = {"wall_seconds", "latency_ms"}


def _payload_for_digest(result: dict) -> dict:
    """Copy of the result without stopwatch-measured fields."""
    return {k: v for k, v in result.items() if k not in VOLATILE_TOP_LEVEL}


def canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def results_digest(result: dict) -> str:
    """sha256 of the deterministic subset of the result payload."""
    return hashlib.sha256(
        canonical_json(_payload_for_digest(result)).encode("utf-8")
    ).hexdigest()


def git_commit(root: str) -> str:
    """Best-effort HEAD sha without shelling out (no network, no subprocess).

    Returns "unknown" when the repo layout is not a plain .git directory.
    """
    try:
        head_path = os.path.join(root, ".git", "HEAD")
        with open(head_path, "r", encoding="utf-8") as fh:
            head = fh.read().strip()
        if head.startswith("ref:"):
            ref = head.split(":", 1)[1].strip()
            with open(os.path.join(root, ".git", ref), "r", encoding="utf-8") as fh:
                return fh.read().strip()
        return head
    except OSError:
        return "unknown"


def build_manifest(result: dict, hypotheses: dict | None = None,
                   root: str | None = None) -> dict:
    """The manifest is deterministic: no timestamps, no paths, no timings."""
    root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    meta = result.get("meta", {})
    payload = _payload_for_digest(result)
    return {
        "schema_version": 2,
        "results_sha256": results_digest(result),
        "payload_sha256_scope": sorted(payload.keys()),
        "seed": meta.get("seed"),
        "phase2": meta.get("phase2"),
        "counts": meta.get("counts"),
        "units": {
            "detection": meta.get("unit_detection", "session"),
            "leak": meta.get("unit_leak", "records"),
            "latency": meta.get("unit_latency", "ms per gateway decision"),
        },
        "python_version": platform.python_version(),
        "platform": sys.platform,
        "git_commit": git_commit(root),
        "hypotheses": hypotheses or {},
    }


def write_manifest(out_dir: str, result: dict, hypotheses: dict | None = None,
                   root: str | None = None) -> dict:
    manifest = build_manifest(result, hypotheses, root=root)
    path = os.path.join(out_dir, "MANIFEST.json")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest


def _ci(ci) -> str:
    if not ci:
        return "n/a"
    return f"[{ci[0]:.1f}, {ci[1]:.1f}]"


def render_results_table(result: dict, hypotheses: dict | None = None) -> str:
    meta = result.get("meta", {})
    seed = meta.get("seed")
    counts = meta.get("counts", {})
    attacks = result.get("attacks", [])
    benign = result.get("benign", {})
    lat = result.get("latency_ms", {})
    ladder = result.get("ladder_usage_total", {}).get("actions", {})
    idarm = {a["id"]: a for a in result.get("identity_arm", {}).get("attacks", [])}

    n_attack = attacks[0].get("n", counts.get("a1_pdf_injection", 0)) if attacks else 0
    lines: list[str] = []
    lines.append("# RESULTS_TABLE.md — generated, do not hand-edit")
    lines.append("")
    lines.append(
        f"Source: `results/results.json` · seed **{seed}** · "
        f"n = **{n_attack} sessions/attack**, "
        f"{benign.get('n_ordinary', counts.get('benign', 0))} benign, "
        f"{benign.get('n_incl_legit_change', 0) - benign.get('n_ordinary', 0)} "
        f"approved-change · unit = session (rates), records (leak), "
        f"ms (latency) · Wilson 95% CI."
    )
    lines.append("")
    lines.append("Regenerate with `python -m tether.evaluate --seed 7 --ablation`.")
    lines.append("")
    lines.append("## Detection and containment, full tether arm")
    lines.append("")
    lines.append("| id | attack | detected % | 95% CI | caught before harmful send % | 95% CI | leak median (none → tether) | leak p90 (tether) |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for a in attacks:
        lines.append(
            f"| {a['id']} | {a['name']} | {a['detected_pct']:.1f} | "
            f"{_ci(a.get('detected_ci95'))} | "
            f"{a['caught_before_harmful_send_pct']:.1f} | "
            f"{_ci(a.get('caught_ci95'))} | "
            f"{a['records_out_none']:.1f} → {a['records_out_tether_median']:.1f} | "
            f"{a.get('leak_p90_tether', 0.0):.1f} |"
        )
    lines.append("")
    lines.append("## Identity control arm (ablation: identity evidence only)")
    lines.append("")
    lines.append("| id | detected % | 95% CI |")
    lines.append("|---|---|---|")
    for a in attacks:
        row = idarm.get(a["id"])
        if row is None:
            continue
        lines.append(
            f"| {a['id']} | {row['detected_pct']:.1f} | {_ci(row.get('ci95'))} |"
        )
    lines.append("")
    lines.append(
        "Identity-only is a control, not the shipped configuration: 0% on "
        "content attacks by design, high on replay/delegation/impersonation. "
        "Key-compromise caveat: THREAT_MODEL.md §5.3."
    )
    lines.append("")
    lines.append("## False alerts and utility")
    lines.append("")
    lines.append("| metric | value | n | 95% CI |")
    lines.append("|---|---|---|---|")
    lines.append(
        f"| false alerts / 1000 ordinary | {benign.get('false_alerts_per_1000_ordinary', 0.0):.1f} | "
        f"{benign.get('n_ordinary', 0)} | {_ci(benign.get('false_alert_ci95_pct'))} |"
    )
    lines.append(
        f"| false alerts / 1000 incl. approved change | "
        f"{benign.get('false_alerts_per_1000_incl_legit_change', 0.0):.1f} | "
        f"{benign.get('n_incl_legit_change', 0)} | {_ci(benign.get('false_alert_ci95_pct'))} |"
    )
    lines.append(
        f"| utility preserved | {benign.get('utility_preserved_pct', 0.0):.1f}% | "
        f"{benign.get('legit_steps_planned', 0)} steps | "
        f"{_ci(benign.get('utility_ci95_pct'))} |"
    )
    lines.append(
        f"| attack-session utility | {result.get('attack_session_utility_pct', 0.0):.1f}% | "
        f"attack sessions, seed {seed} | n/a |"
    )
    lines.append("")
    lines.append("## Ladder usage (all attack corpora, full arm)")
    lines.append("")
    lines.append("| rung | count |")
    lines.append("|---|---|")
    for rung in ("allow", "hold", "narrow", "quarantine", "isolate", "block"):
        lines.append(f"| {rung} | {ladder.get(rung, 0)} |")
    lines.append("")
    lines.append("## Latency")
    lines.append("")
    lines.append(
        f"p50 {lat.get('p50', 0.0):.3f} ms · p95 {lat.get('p95', 0.0):.3f} ms · "
        f"p99 {lat.get('p99', 0.0):.3f} ms · max {lat.get('max', 0.0):.3f} ms "
        f"(n = {lat.get('n', 0)} decisions; max includes first-decision warm-up)."
    )
    lines.append("")
    if hypotheses:
        lines.append("## Pre-registered hypotheses")
        lines.append("")
        lines.append("| id | status | measured |")
        lines.append("|---|---|---|")
        for hid, v in hypotheses.items():
            lines.append(f"| {hid} | {v['status']} | {v['value']} |")
        lines.append("")
    lines.append("## Caveats")
    lines.append("")
    for c in result.get("caveats", []):
        lines.append(f"- {c}")
    lines.append("")
    return "\n".join(lines)


def write_results_table(out_dir: str, result: dict,
                        hypotheses: dict | None = None) -> str:
    text = render_results_table(result, hypotheses)
    path = os.path.join(out_dir, "RESULTS_TABLE.md")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


# --- generated claim block (embedded in HANDOFF.md / README.md) -------------
# docs_check.py regenerates this block from results.json and fails on any
# difference, so prose can quote numbers without them becoming hand-typed.

CLAIMS_BEGIN = "<!-- BEGIN GENERATED CLAIMS (docs_check.py --fix) -->"
CLAIMS_END = "<!-- END GENERATED CLAIMS -->"


def render_claims_block(result: dict, hypotheses: dict | None = None) -> str:
    meta = result.get("meta", {})
    benign = result.get("benign", {})
    lat = result.get("latency_ms", {})
    attacks = result.get("attacks", [])
    idarm = {a["id"]: a for a in result.get("identity_arm", {}).get("attacks", [])}
    n_attack = attacks[0].get("n", 0) if attacks else 0

    lines = [CLAIMS_BEGIN]
    lines.append(
        f"seed={meta.get('seed')} · n={n_attack} sessions/attack · "
        f"benign={benign.get('n_ordinary', 0)} · "
        f"approved_change={benign.get('n_incl_legit_change', 0) - benign.get('n_ordinary', 0)} · "
        f"unit=session (rates) / records (leak) / ms (latency)"
    )
    for a in attacks:
        det = a.get("detected_ci95") or [0.0, 0.0]
        cau = a.get("caught_ci95") or [0.0, 0.0]
        lines.append(
            f"{a['id']}: detected={a['detected_pct']:.1f}% "
            f"[{det[0]:.1f},{det[1]:.1f}] "
            f"caught={a['caught_before_harmful_send_pct']:.1f}% "
            f"[{cau[0]:.1f},{cau[1]:.1f}] "
            f"leak_median={a['records_out_tether_median']:.1f} "
            f"leak_p90={a.get('leak_p90_tether', 0.0):.1f}"
        )
    lines.append(
        f"clean: false_alerts_per_1000_incl_legit_change="
        f"{benign.get('false_alerts_per_1000_incl_legit_change', 0.0):.1f} "
        f"utility={benign.get('utility_preserved_pct', 0.0):.1f}% "
        f"attack_session_utility={result.get('attack_session_utility_pct', 0.0):.1f}%"
    )
    id_bits = " ".join(
        f"{aid}={row.get('detected_pct', 0.0):.1f}%"
        for aid, row in idarm.items()
    )
    lines.append(f"identity_arm: {id_bits}")
    ladder = result.get("ladder_usage_total", {}).get("actions", {})
    lines.append(
        "ladder_total: " + " ".join(
            f"{k}={ladder.get(k, 0)}"
            for k in ("allow", "hold", "narrow", "quarantine", "isolate", "block")
        )
    )
    lines.append(
        f"latency: p50={lat.get('p50', 0.0):.3f}ms p95={lat.get('p95', 0.0):.3f}ms "
        f"p99={lat.get('p99', 0.0):.3f}ms max={lat.get('max', 0.0):.3f}ms "
        f"n={lat.get('n', 0)}"
    )
    ablations = (result.get("ablation") or {}).get("rows") or []
    worst = (0.0, "none", "none")
    for row in ablations:
        for aid, cell in (row.get("attacks") or {}).items():
            delta = float(cell.get("delta_caught_pp", 0.0))
            if delta > worst[0]:
                worst = (delta, str(row.get("removed", "?")), aid)
    if ablations:
        lines.append(
            f"ablation: largest_caught_loss={worst[0]:.1f}pp "
            f"removed={worst[1]} attack={worst[2]} "
            f"(0 = no measured loss on that corpus)"
        )
    if hypotheses:
        lines.append(
            "hypotheses: " + " ".join(
                f"{hid}={v['status']}" for hid, v in hypotheses.items()
            )
        )
    lines.append(CLAIMS_END)
    return "\n".join(lines)

