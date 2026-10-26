"""Generated exhibits (M12).

Every SVG is rendered from `results/results.json`; nothing in this module is a
hand-copied measurement. `write_all()` produces:

    results/exhibits/<name>.svg     one deterministic SVG per exhibit
    results/exhibits/INDEX.json     captions + source paths + units + n

`check()` re-renders the same bytes and fails if any file was edited or if the
results changed without regenerating the exhibits. Captions are part of that
byte contract, so a stale caption number is a build failure, not a docs typo.

Run:
    python -m tether.exhibits --write
    python -m tether.exhibits --check
"""
from __future__ import annotations

import argparse
import html
import json
import math
import os
import re
import sys

from tether.report import results_digest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_PATH = os.path.join(ROOT, "results", "results.json")
EXHIBIT_DIR = os.path.join(ROOT, "results", "exhibits")

# D3COY theme tokens (PLAN_V2 section 4). No gradients, no glass, no emoji.
# Dark "Tactical Cyber-Brutalism" theme: obsidian canvas, slate panels, emerald
# nominal / cyan telemetry / crimson breach - matches dashboard.html, which
# embeds these exhibits as <img> (system fonts only, no network).
BG = "#090d14"
PANEL = "#0f172a"
PANEL2 = "#0b1120"
EDGE = "#1e293b"
ACCENT = "#06b6d4"
ACCENT_SOFT = "#22d3ee"
TEXT = "#dfe2ed"
DIM = "#64748b"
NUM = "#ef4444"
OK = "#10b981"
WARN = "#f59e0b"

FONT_TITLE = "ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Arial, sans-serif"
FONT_BODY = "'Segoe UI', Arial, sans-serif"
FONT_DATA = "Consolas, 'Courier New', monospace"

# name -> declared contract. The order of EXHIBIT_ORDER is the display order.
INDEX = {
    "detection": {
        "id": "E1",
        "title": "Detection by attack, with Wilson 95% CI",
        "source": "results.json -> attacks[].detected_pct, attacks[].phase2.detected_pct, attacks[].detected_ci95",
        "unit": "% of sessions detected",
        "renderer": "detection",
    },
    "leak": {
        "id": "E2",
        "title": "Leak distribution: none vs tether",
        "source": "results.json -> attacks[].leak_samples_none, attacks[].leak_samples_tether, attacks[].leak_p90_tether",
        "unit": "records leaked per session",
        "renderer": "leak",
    },
    "cusum": {
        "id": "E3",
        "title": "Cumulative drift (CUSUM) trajectory",
        "source": "results.json -> drift_trajectory",
        "unit": "standardized CUSUM units",
        "renderer": "cusum",
    },
    "ablation": {
        "id": "E4",
        "title": "Ablation: caught-before-send lost when a detector is removed",
        "source": "results.json -> ablation.rows[].attacks[].delta_caught_pp",
        "unit": "percentage points of caught-before-harmful-send lost",
        "renderer": "ablation",
    },
    "ladder": {
        "id": "E5",
        "title": "Ladder usage: every rung is reachable",
        "source": "results.json -> ladder_usage_total.actions",
        "unit": "decision count",
        "renderer": "ladder",
    },
    "latency": {
        "id": "E6",
        "title": "Latency CDF",
        "source": "results.json -> latency_ms.cdf, latency_ms.p50/p95/p99/max, latency_ms.n",
        "unit": "ms per gateway decision",
        "renderer": "latency",
    },
    "identity": {
        "id": "E7",
        "title": "Identity arm: what it does and does not see",
        "source": "results.json -> identity_arm.attacks[], identity_arm.false_alerts_per_1000_incl_legit_change",
        "unit": "% of sessions detected by identity evidence alone",
        "renderer": "identity",
    },
    "attackmap": {
        "id": "E8",
        "title": "Attack map: a1-a9 -> expected catcher -> expected rung",
        "source": "THREAT_MODEL.md section 4 + results.json -> attacks[].id/name",
        "unit": "categorical mapping (no measured rates)",
        "renderer": "attackmap",
    },
    "utility": {
        "id": "E9",
        "title": "Containment vs utility: the trade-off",
        "source": "results.json -> benign.utility_preserved_pct, attack_session_utility_pct, benign.false_alerts_per_1000_incl_legit_change, ladder_usage.benign",
        "unit": "percent; false alerts per 1,000",
        "renderer": "utility",
    },
}

EXHIBIT_ORDER = (
    "detection", "leak", "cusum", "ablation", "ladder",
    "latency", "identity", "attackmap", "utility",
)

# Categorical mapping only (THREAT_MODEL.md section 4). Names/ids come from
# results.json; this table carries no measured numbers.
ATTACK_MAP = {
    "a1_pdf_injection": ("contract + provenance", "narrow -> block"),
    "a2_tool_poisoning": ("contract + provenance", "narrow -> block"),
    "a3_mimicry": ("drift budget (phase 2)", "hold / narrow"),
    "a4_low_and_slow": ("drift budget (phase 2)", "hold / narrow"),
    "a5_stolen_token": ("identity nonce + context", "quarantine"),
    "a6_delegation": ("identity delegation cert", "quarantine"),
    "a7_persistent": ("escalation state machine", "all five rungs"),
    "a8_composition": ("provenance sequence", "narrow -> block"),
    "a9_impersonation": ("identity key->role binding", "quarantine"),
}

LADDER_ORDER = ("allow", "hold", "narrow", "quarantine", "isolate", "block")
RUNG_FOR_LABEL = {
    "allow": "log", "hold": "annotate", "narrow": "narrow",
    "quarantine": "quarantine", "isolate": "isolate", "block": "enforcement",
}
LADDER_COLOR = {
    "allow": OK, "hold": WARN, "narrow": WARN,
    "quarantine": WARN, "isolate": NUM, "block": NUM,
}
SERIES_COLOR = {"a3_mimicry": ACCENT, "a4_low_and_slow": WARN, "a7_persistent": NUM}


# ------------------------------------------------------------------ helpers

def load_results(path: str | None = None) -> dict:
    path = path or RESULTS_PATH
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"{path} is missing; run `python -m tether.evaluate --seed 7 --ablation`"
        )
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _f(value: float, digits: int = 1) -> str:
    return f"{float(value):.{digits}f}"


def _n(value: int) -> str:
    return f"{int(value):,}"


def _text(x: float, y: float, value: object, *, size: int = 12,
          fill: str = TEXT, anchor: str = "start", family: str = FONT_DATA,
          weight: int = 400, opacity: float | None = None,
          letter_spacing: float | None = None, extra: str = "") -> str:
    attrs = [
        f'x="{x:.2f}"', f'y="{y:.2f}"', f'font-size="{size}"',
        f'font-family="{family}"', f'fill="{fill}"', f'text-anchor="{anchor}"',
        f'font-weight="{weight}"',
    ]
    if opacity is not None:
        attrs.append(f'opacity="{opacity:.2f}"')
    if letter_spacing is not None:
        attrs.append(f'letter-spacing="{letter_spacing}"')
    if extra:
        attrs.append(extra)
    return f"<text {' '.join(attrs)}>{_esc(value)}</text>"


def _line(x1: float, y1: float, x2: float, y2: float, *,
          stroke: str = EDGE, width: float = 1.0,
          dash: str | None = None, opacity: float | None = None) -> str:
    attrs = [
        f'x1="{x1:.2f}"', f'y1="{y1:.2f}"', f'x2="{x2:.2f}"', f'y2="{y2:.2f}"',
        f'stroke="{stroke}"', f'stroke-width="{width}"',
    ]
    if dash:
        attrs.append(f'stroke-dasharray="{dash}"')
    if opacity is not None:
        attrs.append(f'opacity="{opacity:.2f}"')
    return f"<line {' '.join(attrs)} />"


def _rect(x: float, y: float, w: float, h: float, *,
          fill: str = PANEL, stroke: str | None = None, width: float = 1.0,
          opacity: float | None = None, rx: float = 0.0) -> str:
    attrs = [
        f'x="{x:.2f}"', f'y="{y:.2f}"', f'width="{max(0.0, w):.2f}"',
        f'height="{max(0.0, h):.2f}"', f'fill="{fill}"',
    ]
    if stroke:
        attrs.extend([f'stroke="{stroke}"', f'stroke-width="{width}"'])
    if opacity is not None:
        attrs.append(f'opacity="{opacity:.2f}"')
    if rx:
        attrs.append(f'rx="{rx}"')
    return f"<rect {' '.join(attrs)} />"


def _circle(cx: float, cy: float, r: float, *, fill: str = NUM,
            opacity: float | None = None) -> str:
    attr = [f'cx="{cx:.2f}"', f'cy="{cy:.2f}"', f'r="{r}"', f'fill="{fill}"']
    if opacity is not None:
        attr.append(f'opacity="{opacity:.2f}"')
    return f"<circle {' '.join(attr)} />"


def _polyline(points: list[tuple[float, float]], *, stroke: str,
              width: float = 1.8, fill: str = "none") -> str:
    if not points:
        return ""
    p = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return (f'<polyline points="{p}" fill="{fill}" stroke="{stroke}" '
            f'stroke-width="{width}" stroke-linejoin="round" />')


def _svg(width: int, height: int, title: str, body: list[str]) -> str:
    head = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="100%" role="img" aria-labelledby="exhibit-title" '
        f'preserveAspectRatio="xMidYMid meet">',
        f'<title id="exhibit-title">{_esc(title)}</title>',
        _rect(0, 0, width, height, fill=BG),
        _rect(0, 0, 3, height, fill=ACCENT),
        _rect(0.5, 0.5, width - 1, height - 1, fill="none", stroke=EDGE),
        _text(26, 27, "TETHER / D3COY 1.0", size=11, fill=ACCENT_SOFT,
              weight=700, letter_spacing=2.4),
        _text(width - 26, 27, "GENERATED FROM results/", size=10, fill=DIM,
              anchor="end", letter_spacing=1.2),
    ]
    return "\n".join(head + body + ["</svg>", ""])


def _caption_start(width: int, title: str, note: str | None = None) -> list[str]:
    out = [_text(26, 55, title, size=17, fill=TEXT, family=FONT_TITLE,
                 weight=700, letter_spacing=0.4)]
    if note:
        out.append(_text(26, 72, note, size=10, fill=DIM, letter_spacing=0.8))
    return out


def _by_id(result: dict) -> dict[str, dict]:
    return {a["id"]: a for a in result.get("attacks", [])}


def _phase2(row: dict) -> dict:
    return row.get("phase2") or {}


def _p2(row: dict) -> float:
    return float(_phase2(row).get("detected_pct", row.get("detected_pct", 0.0)))


def _ci(row: dict, p2: bool = False) -> list[float]:
    if p2:
        return _phase2(row).get("detected_ci95") or [0.0, 0.0]
    return row.get("detected_ci95") or [0.0, 0.0]


def _short_name(name: str, limit: int = 26) -> str:
    return name if len(name) <= limit else name[:limit - 1].rstrip() + "."


def _trajectory_curve(rows: list[list], max_sessions: int | None = None) -> list[tuple[float, int]]:
    """Max CUSUM per session, in first-seen order. Trajectory has two rows per
    session (one per destination), so a session is the unit, not a row."""
    by_session: dict[str, list[float]] = {}
    for session, _dest, _records, cusum, latched in rows:
        cur = by_session.setdefault(str(session), [0.0, 0])
        cur[0] = max(cur[0], float(cusum))
        cur[1] = max(cur[1], int(latched))
    vals = [(v[0], v[1]) for v in by_session.values()]
    return vals[:max_sessions] if max_sessions else vals


# --------------------------------------------------------------- renderers

def render_detection(result: dict) -> str:
    attacks = result.get("attacks", [])
    width = 920
    top, bottom, left, right = 92, 28, 196, 168
    row_h = 42
    height = top + row_h * max(1, len(attacks)) + bottom
    chart_w = width - left - right
    body = _caption_start(
        width, INDEX["detection"]["title"],
        "Phase 1 = primary per-session detectors; Phase 2 = + drift budget. "
        "Whiskers = Wilson 95% CI.",
    )
    # legend
    body.append(_rect(left, 78, 18, 8, fill=ACCENT))
    body.append(_text(left + 24, 86, "phase 1", size=10, fill=DIM))
    body.append(_rect(left + 98, 78, 18, 8, fill=WARN))
    body.append(_text(left + 122, 86, "phase 2 (+ drift)", size=10, fill=DIM))
    for tick in (0, 25, 50, 75, 100):
        x = left + chart_w * tick / 100.0
        body.append(_line(x, top, x, height - bottom, stroke=EDGE, width=0.6))
        body.append(_text(x, height - bottom + 16, f"{tick}%", size=9,
                          fill=DIM, anchor="middle"))

    for i, row in enumerate(attacks):
        cy = top + row_h * (i + 0.5)
        p1 = float(row.get("detected_pct", 0.0))
        p2 = _p2(row)
        if i:
            body.append(_line(20, top + row_h * i, width - 20, top + row_h * i,
                              stroke=EDGE, width=0.5, opacity=0.55))
        body.append(_text(26, cy - 1, row["id"].split("_")[0], size=12,
                          fill=ACCENT_SOFT, weight=700))
        body.append(_text(58, cy - 1, _short_name(row.get("name", ""), 22),
                          size=10, fill=TEXT))
        for val, ci, y, color in (
            (p1, _ci(row), cy - 13, ACCENT),
            (p2, _ci(row, p2=True), cy + 2, WARN),
        ):
            w = chart_w * max(0.0, min(100.0, val)) / 100.0
            body.append(_rect(left, y, max(1.5 if val > 0 else 0.0, w), 9,
                              fill=color, opacity=0.9))
            lo, hi = (float(ci[0]), float(ci[1])) if len(ci) == 2 else (val, val)
            xlo = left + chart_w * max(0.0, min(100.0, lo)) / 100.0
            xhi = left + chart_w * max(0.0, min(100.0, hi)) / 100.0
            body.append(_line(xlo, y + 4.5, xhi, y + 4.5, stroke=TEXT,
                              width=0.8, opacity=0.72))
            body.append(_line(xlo, y + 1.5, xlo, y + 7.5, stroke=TEXT,
                              width=0.8, opacity=0.72))
            body.append(_line(xhi, y + 1.5, xhi, y + 7.5, stroke=TEXT,
                              width=0.8, opacity=0.72))
        body.append(_text(width - right + 8, cy - 3, f"{p1:.1f}%", size=11,
                          fill=TEXT, weight=700))
        body.append(_text(width - right + 74, cy - 3, f"{p2:.1f}%", size=11,
                          fill=TEXT, weight=700))
        body.append(_text(width - right + 8, cy + 11,
                          f"[{_ci(row)[0]:.1f}, {_ci(row)[1]:.1f}]", size=9,
                          fill=DIM))
    body.append(_text(width - right + 8, top - 8, "P1      P2", size=9,
                      fill=DIM, letter_spacing=1.0))
    return _svg(width, height, INDEX["detection"]["title"], body)


def render_leak(result: dict) -> str:
    attacks = result.get("attacks", [])
    width = 920
    top, bottom, left, right = 92, 28, 200, 178
    row_h = 50
    height = top + row_h * max(1, len(attacks)) + bottom
    chart_w = width - left - right
    body = _caption_start(
        width, INDEX["leak"]["title"],
        "Every sample is drawn; each row has its own vertical scale (max printed). "
        "Upper strip = no defense, lower strip = full tether.",
    )
    body.append(_rect(left, 78, 18, 8, fill=NUM))
    body.append(_text(left + 24, 86, "none", size=10, fill=DIM))
    body.append(_rect(left + 98, 78, 18, 8, fill=OK))
    body.append(_text(left + 122, 86, "tether", size=10, fill=DIM))

    for i, row in enumerate(attacks):
        cy = top + row_h * (i + 0.5)
        if i:
            body.append(_line(20, top + row_h * i, width - 20, top + row_h * i,
                              stroke=EDGE, width=0.5, opacity=0.55))
        none_vals = [float(v) for v in row.get("leak_samples_none", [])]
        teth_vals = [float(v) for v in row.get("leak_samples_tether", [])]
        nmax = max(none_vals + teth_vals + [1.0])
        y0, y1, strip_h = cy - 17, cy + 2, 13
        body.append(_text(26, cy - 3, row["id"].split("_")[0], size=12,
                          fill=ACCENT_SOFT, weight=700))
        body.append(_text(58, cy - 3, _short_name(row.get("name", ""), 22),
                          size=10, fill=TEXT))
        for vals, y, color in ((none_vals, y0, NUM), (teth_vals, y1, OK)):
            body.append(_line(left, y + strip_h, left + chart_w, y + strip_h,
                              stroke=EDGE, width=0.7))
            if not vals:
                continue
            step = chart_w / max(1, len(vals) - 1)
            for idx, v in enumerate(vals):
                x = left + idx * step
                yy = y + strip_h - (v / nmax) * strip_h
                body.append(_circle(x, yy, 1.25, fill=color, opacity=0.9))
        body.append(_text(width - right + 8, y0 + 8,
                          f"med {row.get('records_out_none', 0.0):.1f} -> "
                          f"{row.get('records_out_tether_median', 0.0):.1f}",
                          size=9, fill=TEXT))
        body.append(_text(width - right + 8, y1 + 8,
                          f"p90 {row.get('leak_p90_none', 0.0):.1f} -> "
                          f"{row.get('leak_p90_tether', 0.0):.1f}",
                          size=9, fill=DIM))
        body.append(_text(width - 26, cy - 2, f"max {nmax:.0f}", size=10,
                          fill=TEXT, anchor="end"))
    body.append(_text(left, height - 8, "session index (0 -> n-1), one mark per session",
                      size=9, fill=DIM))
    return _svg(width, height, INDEX["leak"]["title"], body)


def render_cusum(result: dict) -> str:
    width, height = 920, 430
    top, bottom, left, right = 96, 48, 74, 52
    chart_w = width - left - right
    chart_h = height - top - bottom
    curves = {}
    for aid in ("a3_mimicry", "a4_low_and_slow", "a7_persistent"):
        rows = result.get("drift_trajectory", {}).get(aid) or []
        curves[aid] = _trajectory_curve(rows)
    ymax = max([v for c in curves.values() for v, _ in c] + [1.0])
    body = _caption_start(
        width, INDEX["cusum"]["title"],
        "Max per-session CUSUM for the drifting corpora. A latch is an escalation "
        "state, not a moved threshold.",
    )
    for tick in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = top + chart_h * (1.0 - tick)
        body.append(_line(left, y, left + chart_w, y, stroke=EDGE, width=0.6))
        body.append(_text(left - 10, y + 4, f"{ymax * tick:.1f}", size=9,
                          fill=DIM, anchor="end"))
    body.append(_text(22, top + chart_h / 2, "CUSUM", size=10, fill=DIM,
                      anchor="middle",
                      extra=f'transform="rotate(-90 22 {top + chart_h / 2:.1f})"'))
    body.append(_line(left, top + chart_h, left + chart_w, top + chart_h,
                      stroke=EDGE, width=1.0))

    for aid, curve in curves.items():
        if not curve:
            continue
        color = SERIES_COLOR[aid]
        n = len(curve)
        pts = [
            (left + (idx / max(1, n - 1)) * chart_w,
             top + chart_h - (v / ymax) * chart_h)
            for idx, (v, _latched) in enumerate(curve)
        ]
        body.append(_polyline(pts, stroke=color, width=1.7))
        first_latch = next((idx for idx, (_v, latched) in enumerate(curve) if latched), None)
        if first_latch is not None:
            x, y = pts[first_latch]
            body.append(_circle(x, y, 3.2, fill=color))
        max_v = max(v for v, _ in curve)
        body.append(_text(left + chart_w - 6, top + 16 + 16 * list(curves).index(aid),
                          f"{aid.split('_')[0]} max {max_v:.1f}", size=10,
                          fill=color, anchor="end", weight=700))
    body.append(_text(left, height - 18, "session order (each corpus has its own "
                      "200-session run)", size=9, fill=DIM))
    return _svg(width, height, INDEX["cusum"]["title"], body)


def render_ablation(result: dict) -> str:
    abl = result.get("ablation") or {}
    rows = abl.get("rows") or []
    attacks = result.get("attacks", [])
    width = 920
    top, bottom, left, right = 118, 38, 156, 22
    row_h = 32
    height = top + row_h * max(1, len(rows)) + bottom
    chart_w = width - left - right
    cell_w = chart_w / max(1, len(attacks))
    max_delta = max(
        [float(cell.get("delta_caught_pp", 0.0))
         for row in rows for cell in row.get("attacks", {}).values()] + [1.0]
    )
    body = _caption_start(
        width, INDEX["ablation"]["title"],
        "Leave-one-out: value = pp of caught-before-harmful-send lost when the row "
        "detector is removed. 0 = no measured loss on this corpus.",
    )
    for j, row in enumerate(attacks):
        x = left + cell_w * (j + 0.5)
        body.append(_text(x, top - 12, row["id"].split("_")[0], size=10,
                          fill=ACCENT_SOFT, anchor="middle", weight=700))
    for i, row in enumerate(rows):
        y = top + i * row_h
        body.append(_text(left - 10, y + row_h * 0.62, row.get("removed", ""),
                          size=10, fill=TEXT, anchor="end"))
        for j, attack in enumerate(attacks):
            cell = row.get("attacks", {}).get(attack["id"], {})
            val = float(cell.get("delta_caught_pp", 0.0))
            x = left + j * cell_w
            alpha = 0.10 + 0.85 * (val / max_delta if max_delta else 0.0)
            fill = ACCENT if val > 0 else PANEL2
            body.append(_rect(x + 1, y + 1, cell_w - 2, row_h - 2, fill=fill,
                              stroke=EDGE, width=0.5,
                              opacity=alpha if val > 0 else 1.0))
            label = "0" if val == 0 else f"+{val:.1f}"
            body.append(_text(x + cell_w / 2, y + row_h * 0.62, label, size=10,
                              fill=TEXT if val > 0 else DIM, anchor="middle",
                              weight=700 if val > 0 else 400))
    body.append(_text(width - 22, height - 12,
                      f"max measured loss {max_delta:.1f} pp", size=9,
                      fill=TEXT, anchor="end"))
    return _svg(width, height, INDEX["ablation"]["title"], body)


def render_ladder(result: dict) -> str:
    actions = (result.get("ladder_usage_total") or {}).get("actions") or {}
    total = sum(int(actions.get(k, 0)) for k in LADDER_ORDER)
    width = 920
    top, bottom, left, right = 96, 36, 196, 108
    row_h = 42
    height = top + row_h * len(LADDER_ORDER) + bottom
    chart_w = width - left - right
    body = _caption_start(
        width, INDEX["ladder"]["title"],
        f"Full tether arm, all attack corpora. n = {_n(total)} decisions; "
        "linear scale, so the small rungs stay visibly small.",
    )
    for i, rung in enumerate(LADDER_ORDER):
        count = int(actions.get(rung, 0))
        cy = top + row_h * (i + 0.5)
        if i:
            body.append(_line(20, top + row_h * i, width - 20, top + row_h * i,
                              stroke=EDGE, width=0.5, opacity=0.55))
        body.append(_text(26, cy + 4, rung, size=12,
                          fill=LADDER_COLOR[rung], weight=700))
        body.append(_text(92, cy + 4, f"/ {RUNG_FOR_LABEL[rung]}", size=10,
                          fill=DIM))
        w = chart_w * count / max(1, total)
        body.append(_rect(left, cy - 8, max(2.0 if count else 0.0, w), 16,
                          fill=LADDER_COLOR[rung], opacity=0.82))
        body.append(_text(width - 26, cy + 4, _n(count), size=12, fill=TEXT,
                          anchor="end", weight=700))
        pct = 100.0 * count / max(1, total)
        body.append(_text(width - right + 10, cy + 4, f"{pct:.1f}%", size=9,
                          fill=DIM, anchor="end"))
    body.append(_text(left, height - 10,
                      "counts are gateway decisions, not sessions", size=9,
                      fill=DIM))
    return _svg(width, height, INDEX["ladder"]["title"], body)


def render_latency(result: dict) -> str:
    lat = result.get("latency_ms") or {}
    cdf = [(float(v), float(p)) for v, p in (lat.get("cdf") or [])]
    width, height = 920, 430
    top, bottom, left, right = 96, 52, 76, 58
    chart_w = width - left - right
    chart_h = height - top - bottom
    positive = [v for v, _ in cdf if v > 0]
    xmin = min(positive) if positive else 0.001
    xmax = max([v for v, _ in cdf] + [xmin * 10])
    ymax = 100.0

    def sx(v: float) -> float:
        lo, hi = math.log10(xmin), math.log10(xmax)
        return left + (math.log10(max(v, xmin)) - lo) / max(1e-12, hi - lo) * chart_w

    def sy(p: float) -> float:
        return top + chart_h - (p / ymax) * chart_h

    body = _caption_start(
        width, INDEX["latency"]["title"],
        f"n = {_n(lat.get('n', 0))} decisions; p95 = {_f(lat.get('p95', 0.0), 3)} ms. "
        f"Max {_f(lat.get('max', 0.0), 3)} ms is first-decision warm-up and is plotted.",
    )
    for p in (0, 25, 50, 75, 100):
        y = sy(p)
        body.append(_line(left, y, left + chart_w, y, stroke=EDGE, width=0.6))
        body.append(_text(left - 10, y + 4, f"{p}%", size=9, fill=DIM,
                          anchor="end"))
    ticks = [t for t in (0.01, 0.1, 1.0, 10.0, 100.0) if xmin <= t <= xmax]
    if not ticks or math.log10(xmin) < math.log10(ticks[0]) - 0.12:
        ticks.insert(0, xmin)
    # The maximum is annotated at its point instead of becoming an axis tick:
    # 100 ms and the 130.682 ms max are only ~20 px apart on the log axis, so
    # a second label there would collide (D57).
    for t in sorted(set(ticks)):
        x = sx(t)
        body.append(_line(x, top, x, top + chart_h, stroke=EDGE, width=0.5,
                          opacity=0.7))
        label = f"{t:g}" if t >= 0.1 else f"{t:.3f}"
        body.append(_text(x, top + chart_h + 18, label, size=9, fill=DIM,
                          anchor="middle"))
    body.append(_text(left, height - 12, "latency (ms, log scale)", size=9,
                      fill=DIM))
    body.append(_polyline([(sx(v), sy(p)) for v, p in cdf], stroke=ACCENT, width=2.0))
    for key, label, color in (
        ("p50", "p50", ACCENT_SOFT), ("p95", "p95", WARN), ("p99", "p99", ACCENT),
    ):
        value = float(lat.get(key, 0.0))
        x = sx(value)
        body.append(_line(x, top, x, top + chart_h, stroke=color, width=0.9,
                          dash="4 4"))
        body.append(_text(x + 4, top + 12 + 15 * ("p50", "p95", "p99").index(key),
                          f"{label} {_f(value, 3)}", size=9, fill=color))
    body.append(_circle(sx(xmax), sy(100.0), 3.4, fill=NUM))
    body.append(_text(sx(xmax) - 6, sy(100.0) - 8, f"max {_f(xmax, 3)} ms",
                      size=9, fill=NUM, anchor="end"))
    return _svg(width, height, INDEX["latency"]["title"], body)


def render_identity(result: dict) -> str:
    rows = (result.get("identity_arm") or {}).get("attacks") or []
    width = 920
    top, bottom, left, right = 96, 32, 184, 184
    row_h = 42
    height = top + row_h * max(1, len(rows)) + bottom
    chart_w = width - left - right
    body = _caption_start(
        width, INDEX["identity"]["title"],
        "Identity evidence alone (canonical floors disabled, D36/D41). "
        "A 0% row is a blind spot by design, not a detector failure.",
    )
    for tick in (0, 25, 50, 75, 100):
        x = left + chart_w * tick / 100.0
        body.append(_line(x, top, x, top + row_h * len(rows), stroke=EDGE,
                          width=0.6))
        body.append(_text(x, top - 10, f"{tick}%", size=9, fill=DIM,
                          anchor="middle"))
    for i, row in enumerate(rows):
        cy = top + row_h * (i + 0.5)
        if i:
            body.append(_line(20, top + row_h * i, width - 20, top + row_h * i,
                              stroke=EDGE, width=0.5, opacity=0.55))
        val = float(row.get("detected_pct", 0.0))
        ci = row.get("ci95") or [0.0, 0.0]
        color = OK if val >= 50 else DIM
        body.append(_text(26, cy - 2, row["id"].split("_")[0], size=12,
                          fill=ACCENT_SOFT, weight=700))
        body.append(_text(58, cy - 2, _short_name(
            next((a.get("name", "") for a in result.get("attacks", [])
                  if a.get("id") == row["id"]), ""), 18), size=10, fill=TEXT))
        w = chart_w * max(0.0, min(100.0, val)) / 100.0
        if val > 0:
            body.append(_rect(left, cy - 8, max(1.5, w), 16, fill=color,
                              opacity=0.78))
        else:
            body.append(_rect(left, cy - 8, 2, 16, fill=ACCENT, opacity=0.9))
            body.append(_text(left + 8, cy + 4, "blind", size=9, fill=ACCENT_SOFT))
        xlo = left + chart_w * float(ci[0]) / 100.0
        xhi = left + chart_w * float(ci[1]) / 100.0
        body.append(_line(xlo, cy + 10, xhi, cy + 10, stroke=TEXT, width=0.7,
                          opacity=0.62))
        body.append(_text(width - 26, cy + 4,
                          f"{val:.1f}%  [{float(ci[0]):.1f}, {float(ci[1]):.1f}]",
                          size=10, fill=TEXT if val > 0 else DIM, anchor="end"))
    body.append(_text(left, height - 12,
                      "a1-a4/a7/a8: content or sequence; a5/a6/a9: identity evidence",
                      size=9, fill=DIM))
    return _svg(width, height, INDEX["identity"]["title"], body)


def render_attackmap(result: dict) -> str:
    attacks = result.get("attacks", [])
    width = 920
    top, bottom = 104, 30
    row_h = 37
    height = top + row_h * max(1, len(attacks)) + bottom
    cols = [24, 66, 350, 700]
    body = _caption_start(
        width, INDEX["attackmap"]["title"],
        "Categorical mapping only: no measured rates on this exhibit.",
    )
    headers = ("id", "attack", "expected catcher", "expected rung")
    for x, label in zip(cols, headers):
        body.append(_text(x, top - 12, label, size=9, fill=ACCENT_SOFT,
                          letter_spacing=1.1))
    for i, row in enumerate(attacks):
        y = top + i * row_h
        if i:
            body.append(_line(20, y, width - 20, y, stroke=EDGE, width=0.5,
                              opacity=0.62))
        catcher, rung = ATTACK_MAP.get(row["id"], ("(unmapped)", "(unmapped)"))
        body.append(_text(cols[0], y + row_h * 0.64, row["id"].split("_")[0],
                          size=12, fill=ACCENT_SOFT, weight=700))
        body.append(_text(cols[1], y + row_h * 0.64,
                          _short_name(row.get("name", ""), 34), size=10,
                          fill=TEXT))
        body.append(_text(cols[2], y + row_h * 0.64, catcher, size=10,
                          fill=DIM))
        body.append(_text(cols[3], y + row_h * 0.64, rung, size=10,
                          fill=NUM if "block" in rung or "isolate" in rung else OK))
    body.append(_text(24, height - 10,
                      "source: THREAT_MODEL.md section 4; attack ids/names from results.json",
                      size=9, fill=DIM))
    return _svg(width, height, INDEX["attackmap"]["title"], body)


def render_utility(result: dict) -> str:
    benign = result.get("benign") or {}
    attack_util = float(result.get("attack_session_utility_pct", 0.0))
    benign_util = float(benign.get("utility_preserved_pct", 0.0))
    n_legit = int(benign.get("n_incl_legit_change", 0))
    n_ordinary = int(benign.get("n_ordinary", 0))
    n_change = max(0, n_legit - n_ordinary)
    n_attack = sum(int(v) for k, v in (result.get("meta") or {}).get("counts", {}).items()
                   if str(k).startswith("a"))
    false_alerts = float(benign.get("false_alerts_per_1000_incl_legit_change", 0.0))
    benign_isolates = int(((result.get("ladder_usage") or {})
                           .get("benign", {}).get("actions", {})).get("isolate", 0))
    width, height = 920, 340
    top, bottom, left, right = 96, 44, 268, 196
    chart_w = width - left - right
    body = _caption_start(
        width, INDEX["utility"]["title"],
        "Utility and containment are reported separately. Attack-session utility is "
        "the containment cost (D55), not a false-positive rate.",
    )
    rows = [
        ("legitimate utility preserved", benign_util,
         float((benign.get("utility_ci95_pct") or [0.0, 0.0])[0]),
         float((benign.get("utility_ci95_pct") or [0.0, 0.0])[1]),
         OK, f"n = {_n(n_legit)} legitimate sessions ({_n(n_ordinary)} ordinary + {_n(n_change)} approved change)"),
        ("attack-session utility", attack_util, attack_util, attack_util, WARN,
         f"n = {_n(n_attack)} attack sessions"),
    ]
    for i, (label, val, lo, hi, color, ntext) in enumerate(rows):
        cy = top + i * 92
        body.append(_text(26, cy + 3, label, size=11, fill=TEXT))
        body.append(_text(26, cy + 21, ntext, size=9, fill=DIM))
        body.append(_rect(left, cy - 9, chart_w, 18, fill=PANEL2, stroke=EDGE,
                          width=0.7))
        body.append(_rect(left, cy - 9, chart_w * max(0.0, min(100.0, val)) / 100.0,
                          18, fill=color, opacity=0.84))
        body.append(_text(width - 26, cy + 4, f"{val:.1f}%", size=16, fill=NUM,
                          anchor="end", weight=700))
        if lo != hi:
            xlo = left + chart_w * max(0.0, min(100.0, lo)) / 100.0
            xhi = left + chart_w * max(0.0, min(100.0, hi)) / 100.0
            body.append(_line(xlo, cy + 13, xhi, cy + 13, stroke=TEXT, width=0.8,
                              opacity=0.7))
            body.append(_text(left, cy + 33,
                              f"95% CI [{lo:.2f}, {hi:.2f}]", size=9, fill=DIM))
    # third stat row: zero false alerts and zero benign isolations
    cy = top + 2 * 92
    body.append(_text(26, cy + 3, "false alerts (incl. approved change)", size=11,
                      fill=TEXT))
    body.append(_text(26, cy + 21, f"n = {_n(n_legit)} sessions; unit = per 1,000",
                      size=9, fill=DIM))
    body.append(_text(left, cy + 8, f"{false_alerts:.1f}", size=26, fill=OK,
                      weight=700))
    body.append(_text(left + 74, cy + 8, "per 1,000 sessions", size=10, fill=DIM))
    body.append(_text(width - 26, cy + 4, f"benign isolates {benign_isolates}",
                      size=11, fill=NUM, anchor="end", weight=700))
    return _svg(width, height, INDEX["utility"]["title"], body)


RENDERERS = {
    "detection": render_detection,
    "leak": render_leak,
    "cusum": render_cusum,
    "ablation": render_ablation,
    "ladder": render_ladder,
    "latency": render_latency,
    "identity": render_identity,
    "attackmap": render_attackmap,
    "utility": render_utility,
}


def render(name: str, result: dict) -> str:
    if name not in RENDERERS:
        raise KeyError(f"unknown exhibit {name!r}")
    return RENDERERS[name](result)


# --------------------------------------------------------------- captions

def _n_label(name: str, result: dict) -> str:
    attacks = result.get("attacks", [])
    n = attacks[0].get("n", 0) if attacks else 0
    if name in ("detection", "leak", "cusum", "ablation", "identity"):
        return f"{_n(n)} sessions/attack"
    if name == "ladder":
        actions = (result.get("ladder_usage_total") or {}).get("actions") or {}
        return f"{_n(sum(int(actions.get(k, 0)) for k in LADDER_ORDER))} attack-corpus decisions"
    if name == "latency":
        return f"{_n((result.get('latency_ms') or {}).get('n', 0))} gateway decisions"
    if name == "attackmap":
        return f"{len(attacks)} attacks (a1-a9)"
    if name == "utility":
        benign = result.get("benign") or {}
        n_legit = int(benign.get("n_incl_legit_change", 0))
        n_attack = sum(int(v) for k, v in (result.get("meta") or {}).get("counts", {}).items()
                       if str(k).startswith("a"))
        return f"{_n(n_legit)} legitimate sessions + {_n(n_attack)} attack sessions"
    return "n/a"


def _caption(name: str, result: dict) -> str:
    seed = (result.get("meta") or {}).get("seed")
    nlabel = _n_label(name, result)
    unit = INDEX[name]["unit"]
    by_id = _by_id(result)
    if name == "detection":
        a3, a4 = by_id.get("a3_mimicry", {}), by_id.get("a4_low_and_slow", {})
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Phase 1 (solid) and "
            f"Phase 2 (+ drift budget, light) bars with Wilson 95% CI. "
            f"a3/a4 Phase 1 = {a3.get('detected_pct', 0.0):.1f}%/"
            f"{a4.get('detected_pct', 0.0):.1f}%; Phase 2 = {_p2(a3):.1f}%/"
            f"{_p2(a4):.1f}%. The Phase-1 misses are shown, not hidden."
        )
    if name == "leak":
        a7 = by_id.get("a7_persistent", {})
        a7_samples = [float(v) for v in a7.get("leak_samples_tether", [])]
        leaking = [v for v in a7_samples if v > 0]
        tail = (f"{len(leaking)}/{len(a7_samples)} sessions leak, max "
                f"{max(leaking):.0f} records" if leaking else "no session leaks")
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Every sample in both "
            f"arms is drawn; each row uses its own vertical scale (max printed). "
            f"a7 residual tail: {tail}; median "
            f"{a7.get('records_out_tether_median', 0.0):.1f}, "
            f"p90 {a7.get('leak_p90_tether', 0.0):.1f} records/session."
        )
    if name == "cusum":
        maxima = []
        for aid in ("a3_mimicry", "a4_low_and_slow", "a7_persistent"):
            curve = _trajectory_curve((result.get("drift_trajectory") or {}).get(aid) or [])
            maxima.append(f"{aid.split('_')[0]} {max([v for v, _ in curve] + [0.0]):.1f}")
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Max per-session CUSUM; "
            f"maxima: {', '.join(maxima)}. A filled dot is the first latched "
            f"session; the latch is a policy state, not a moved threshold."
        )
    if name == "ablation":
        best = max(
            [(float(cell.get("delta_caught_pp", 0.0)), row.get("removed", ""),
              aid)
             for row in (result.get("ablation") or {}).get("rows", [])
             for aid, cell in row.get("attacks", {}).items()] + [(0.0, "none", "")],
        )
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Leave-one-out over the "
            f"detectors; largest measured loss = {best[0]:.1f} pp "
            f"({best[1]} removed, {best[2]}). 0 means no loss on this corpus, "
            f"not 'unnecessary'."
        )
    if name == "ladder":
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. All six rungs are "
            f"reachable. Linear scale: the small rungs stay visibly small. "
            f"enforcement (block) is counted separately from policy rungs."
        )
    if name == "latency":
        lat = result.get("latency_ms") or {}
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. p50 = "
            f"{float(lat.get('p50', 0.0)):.3f} ms, p95 = "
            f"{float(lat.get('p95', 0.0)):.3f} ms, p99 = "
            f"{float(lat.get('p99', 0.0)):.3f} ms, max = "
            f"{float(lat.get('max', 0.0)):.3f} ms. The maximum is first-decision "
            f"warm-up; the CDF plots it rather than trimming it."
        )
    if name == "identity":
        rows = (result.get("identity_arm") or {}).get("attacks") or []
        lows = [float(r.get("detected_pct", 0.0)) for r in rows
                if r.get("id") in ("a1_pdf_injection", "a2_tool_poisoning",
                                    "a3_mimicry", "a4_low_and_slow")]
        highs = [float(r.get("detected_pct", 0.0)) for r in rows
                 if r.get("id") in ("a5_stolen_token", "a6_delegation",
                                     "a9_impersonation")]
        low_min = min(lows) if lows else 0.0
        low_max = max(lows) if lows else 0.0
        high_min = min(highs) if highs else 0.0
        high_max = max(highs) if highs else 0.0
        low_txt = (f"all {low_min:.1f}%" if low_min == low_max
                   else f"{low_min:.1f}-{low_max:.1f}%")
        high_txt = (f"all {high_min:.1f}%" if high_min == high_max
                    else f"{high_min:.1f}-{high_max:.1f}%")
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Content attacks a1-a4 = "
            f"{low_txt}; identity attacks a5/a6/a9 = {high_txt}. "
            f"Key-compromise limitation (THREAT_MODEL section 5.3): a stolen "
            f"signing key is not detectable by this layer; a5 models replay, not "
            f"key compromise."
        )
    if name == "attackmap":
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Expected catcher and "
            f"expected rung from THREAT_MODEL section 4; ids and names from "
            f"results.json. No measured rate is claimed here."
        )
    if name == "utility":
        benign = result.get("benign") or {}
        n_attack = sum(int(v) for k, v in (result.get("meta") or {}).get("counts", {}).items()
                       if str(k).startswith("a"))
        benign_isolates = int(((result.get("ladder_usage") or {})
                               .get("benign", {}).get("actions", {})).get("isolate", 0))
        return (
            f"Seed {seed} - n = {nlabel} - unit = {unit}. Legitimate utility = "
            f"{float(benign.get('utility_preserved_pct', 0.0)):.1f}%; attack-session "
            f"utility = {float(result.get('attack_session_utility_pct', 0.0)):.1f}% "
            f"across {_n(n_attack)} attack sessions. False alerts = "
            f"{float(benign.get('false_alerts_per_1000_incl_legit_change', 0.0)):.1f} "
            f"per 1,000; benign isolates = {benign_isolates}. The attack-session gap "
            f"is the containment cost (D55), not a false-positive rate."
        )
    return f"Seed {seed} - n = {nlabel} - unit = {unit}."


# --------------------------------------------------------------- packaging

def build_index(result: dict) -> dict:
    meta = result.get("meta") or {}
    counts = meta.get("counts") or {}
    attacks = result.get("attacks") or []
    summary = {
        "seed": meta.get("seed"),
        "attack_n": attacks[0].get("n", 0) if attacks else 0,
        "benign": counts.get("benign", 0),
        "approved_change": counts.get("legit_change", 0),
        "unit": "session (rates), records (leak), ms (latency)",
    }
    exhibits = []
    for name in EXHIBIT_ORDER:
        spec = INDEX[name]
        exhibits.append({
            "id": spec["id"],
            "name": name,
            "title": spec["title"],
            "renderer": spec["renderer"],
            "svg": f"{name}.svg",
            "source": spec["source"],
            "unit": spec["unit"],
            "n": _n_label(name, result),
            "caption": _caption(name, result),
        })
    return {
        "schema_version": 1,
        "generated_from": "results/results.json",
        "results_sha256": results_digest(result),
        "summary": summary,
        "counts": counts,
        "exhibits": exhibits,
        "note": "Deterministic artifacts. Captions contain seed, n and unit; "
                "tampering with either SVG or INDEX is a --check failure.",
    }


def _index_text(index: dict) -> str:
    return json.dumps(index, indent=2, ensure_ascii=False) + "\n"


def write_all(out_dir: str | None = None, result: dict | None = None) -> dict:
    result = result or load_results()
    out_dir = out_dir or EXHIBIT_DIR
    os.makedirs(out_dir, exist_ok=True)
    index = build_index(result)
    for name in EXHIBIT_ORDER:
        path = os.path.join(out_dir, f"{name}.svg")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render(name, result))
    with open(os.path.join(out_dir, "INDEX.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write(_index_text(index))
    return index


def check(out_dir: str | None = None, result: dict | None = None) -> list[str]:
    """Re-render in memory and byte-compare. A caption edit is a failure."""
    try:
        result = result or load_results()
    except FileNotFoundError as exc:
        return [str(exc)]
    out_dir = out_dir or EXHIBIT_DIR
    errors: list[str] = []
    if not os.path.isdir(out_dir):
        return [f"{out_dir} is missing; run `python -m tether.exhibits --write`"]
    for name in EXHIBIT_ORDER:
        path = os.path.join(out_dir, f"{name}.svg")
        if not os.path.exists(path):
            errors.append(f"{path} missing")
            continue
        expected = render(name, result).encode("utf-8")
        with open(path, "rb") as fh:
            actual = fh.read()
        if actual != expected:
            errors.append(f"{path} is stale or hand-edited; regenerate exhibits")
    index_path = os.path.join(out_dir, "INDEX.json")
    if not os.path.exists(index_path):
        errors.append(f"{index_path} missing")
    else:
        with open(index_path, "rb") as fh:
            actual = fh.read()
        if actual != _index_text(build_index(result)).encode("utf-8"):
            errors.append(f"{index_path} is stale or hand-edited; regenerate exhibits")
    return errors


def main() -> int:
    ap = argparse.ArgumentParser(description="generate D3COY exhibits from results/")
    ap.add_argument("--check", action="store_true",
                    help="verify generated SVGs + captions without writing")
    ap.add_argument("--write", action="store_true",
                    help="write results/exhibits/ (the default)")
    ap.add_argument("--out", default=EXHIBIT_DIR,
                    help="output directory (default results/exhibits)")
    args = ap.parse_args()

    if args.check:
        errors = check(args.out)
        if errors:
            for error in errors:
                print(f"FAIL  {error}")
            print(f"\n{len(errors)} exhibit problem(s); run "
                  f"`python -m tether.exhibits --write`")
            return 1
        print(f"PASS  {len(EXHIBIT_ORDER)} exhibits + INDEX.json match "
              f"results.json byte-for-byte")
        return 0

    try:
        index = write_all(args.out)
    except FileNotFoundError as exc:
        print(f"FAIL  {exc}")
        return 1
    print(f"wrote {len(EXHIBIT_ORDER)} SVGs + INDEX.json -> {args.out}")
    print(f"seed {index['summary']['seed']} - results {index['results_sha256'][:16]}...")
    return 0


if __name__ == "__main__":
    sys.exit(main())
