# TRANSFER.md — Tether Round 0 transfer document

Single file for a new engineer **or a new LLM session** to understand the
project, run it, and change the UI without breaking anything. Self-contained:
everything below was captured from the real running system.

Read order if you want depth later: `PROJECT_BRIEF.md` (context) →
`tether_build_prompt.md` (operative spec) → `HANDOFF.md` (current status and
NEXT ACTION) → `DECISIONS.md` (why things are the way they are, D1–D40).

> **v2 note (M12).** This document describes the v1 system, which is complete and
> tagged `final`, plus the v2 additions through M12. The authoritative plan is
> `PLAN_V2.md` and the frozen metrics are `PREREG.md`. Landed: identity layer
> (signed envelopes, nonce cache, delegation certs, key->role binding),
> identity-scoped escalation, attacks a7-a9, v2 evaluation (Wilson CIs, leak
> vectors, latency CDF, CUSUM trajectory, ablation, MANIFEST + `verify.py` +
> `docs_check.py`; seed 7, n=200/attack, H1-H9 all PASS), and the M12 D3COY
> dashboard + nine generated exhibits. `/exhibits` and `/exhibits/<name>.svg`
> are the measured-data surface; `/run` and `/stream` still run live sessions
> unchanged. Sections 4.9, 4.10 and 6 are the current v2 reference.

---

## 1. What this project is

**Tether** is an identity-drift detector for autonomous AI agents, built as a
deterministic simulation (D3COY Round 0). A simulated procurement agent
(`procurement_agent`) runs scripted tool-call sessions. A **gateway** sits at
the single enforcement point between the agent and its tools and decides,
per event: allow / hold / narrow / block / quarantine / isolate. Six attack
families (a1–a6) try to make the agent leak data or exceed its role; the
gateway's detectors are supposed to catch them without disturbing benign work.

Three defense modes are compared everywhere:

| mode | meaning |
|---|---|
| `none` | no defense (leak baseline) |
| `textgate` | comparison defense: a stand-in TF-IDF gate screens pdf.read document text only |
| `tether` | the full system: contract + provenance + baseline + intent + context + drift budget + delegation checks |

**Hard constraints of the whole repo** (do not violate in changes):
Python 3.10+ **standard library only** — no pip installs, no network calls,
no LLM calls. Everything is seeded and deterministic (default seed 7).
The dashboard is a single HTML file with **no external libraries/CDN**.

---

## 2. How to run everything

```bash
python -m unittest discover -s tests -t .          # 45/45 OK
python -m tether.evaluate --seed 7                 # writes results/ (~11 s)
python -m tether.demo --scenario a1_pdf_injection --mode tether   # also --mode none|textgate
python -m tether.api                               # API + dashboard on http://127.0.0.1:8765/
python calibrate_drift.py                          # drift h=8 null-traffic calibration evidence
```

- The API server binds `127.0.0.1` (localhost only), port configurable via
  `--port`. `ThreadingHTTPServer`, so concurrent requests are fine.
- **Windows/PowerShell note:** run the test suite as
  `cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"`
  — plain PowerShell shows exit 1 even on OK because unittest writes to stderr.
- No build step for the dashboard: edit `dashboard.html`, refresh the browser.

---

## 3. Architecture map

```
tether/
  contract.py + contract.json   L0 role contract (the anchor): permitted tools,
                                data classes, egress allowlist, ceilings
  types.py                      Context, DetectorResult, Decision, ApprovedChange
  events.py                     Event dataclass (one agent tool-call attempt)
  ledger.py                     append-only SQLite hash-chain log + verify_chain();
                                rows_for_session() attributes decisions to the
                                session of the event row they follow (D31)
  textgate.py                   stand-in TF-IDF text gate (NOT an LLM judge)
  detectors.py                  contract, provenance, baseline, intent, context,
                                drift (CUSUM + latch + sponsor review), delegation
  fusion.py                     noisy-OR fusion, impact multiplier, floors
  response.py                   5-rung response ladder + narrowed capability set
  gateway.py                    single enforcement point + taint tracker (labels:
                                UNTRUSTED, CARRY, RESTRICTED, EXTERNAL...)
  alert.py                      alert card builder (fixed templates)
  harness.py                    session executor (runs one plan in one mode)
  sim/scenarios.py              scripted plans: benign, legit_change, a1..a9
  evaluate.py                   evaluation CLI -> results/results.json (schema v2)
  stats.py / report.py          Wilson CI, percentiles/CDF; digest, MANIFEST,
                                RESULTS_TABLE, generated claims block
  ablation.py / verdicts.py     leave-one-out detector ablation; frozen H1-H9
  exhibits.py                   nine generated SVGs + results/exhibits/INDEX.json
  identity.py                   HMAC envelopes, nonce cache, delegation certs
  escalation.py                 identity-scoped severity state machine (D47)
  demo.py                       colored step-by-step CLI demo
  api.py                        stdlib JSON API + SSE + dashboard/exhibit server
dashboard.html                  single-file D3COY dashboard (no libs, no CDN)
tests/                          unittest suite (126 tests)
results/                        measured artifacts + MANIFEST + VERIFY +
                                RESULTS_TABLE + exhibits/
calibrate_drift.py              null-traffic calibration for drift h (evidence)
```

Data flow of one session: `sim/scenarios.py` builds a `SessionPlan` (scripted
steps) → `harness.run_session` walks the steps → for `tether` mode each step
becomes an `Event` → `Gateway.evaluate` runs detectors → `fusion` →
`response` ladder → `Decision` → both are appended to the `Ledger` (hash
chain) and kept as `decision_events` pairs → `alert.card_from_result` builds
the alert card if the session alerted.

Key semantic detail for UI work: the API timeline is built from
**`decision_events`** — real decisions the gateway made. Steps that were
**never evaluated** (quarantined injected steps, steps after isolation) appear
as `action: "skipped"` so the UI can render them differently.

---

## 4. HTTP API reference (all endpoints)

Base URL: `http://127.0.0.1:8765` (start with `python -m tether.api`).
All JSON endpoints send `Content-Type: application/json; charset=utf-8` and
`Cache-Control: no-store`. Unknown paths → `404 {"error": "not found"}`.

### 4.1 `GET /` and `GET /dashboard`
Serves `dashboard.html` (`text/html`). No static file directory exists —
the dashboard is the one HTML file; keep assets inline.

### 4.2 `GET /health`
Liveness probe.
```json
{"ok": true, "time": 1792930518.8599923}
```

### 4.3 `GET /contract`
The L0 role contract the gateway enforces.
```json
{
  "role": "procurement_agent",
  "blueprint_version": "1.0.0",
  "permitted_tools": ["pricing_api.read", "pdf.read", "purchase_request.create", "email.send"],
  "data_classes": {"supplier_pricing": "allowed", "supplier_docs": "allowed_untrusted", "hr_salary": "denied"},
  "egress_allowlist": ["mail.internal", "supplier-portal.example"],
  "ceilings": {"records_per_session": 200, "bytes_out_per_session": 50000}
}
```

### 4.4 `GET /scenarios`
Scenario ids and human names (drives the dashboard dropdown).
```json
{"scenarios": {
  "benign": "ordinary procurement work",
  "legit_change": "approved change traffic",
  "a1_pdf_injection": "pdf injection chain",
  "a2_tool_poisoning": "poisoned tool description",
  "a3_mimicry": "in-contract mimicry",
  "a4_low_and_slow": "low-and-slow drip",
  "a5_stolen_token": "stolen-token replay",
  "a6_delegation": "malicious delegation"}}
```

### 4.5 `GET /run` — run N sessions of one scenario

Query parameters (all optional):

| param | default | notes |
|---|---|---|
| `scenario` | `a1_pdf_injection` | any id from `/scenarios` |
| `mode` | `tether` | `none` \| `textgate` \| `tether` |
| `n` | `1` | clamped to 1..20 |
| `seed` | `7` | any int; results are deterministic per (scenario, mode, seed, i) |
| `phase2` | `true` | `"false"` disables the drift budget / context / delegation phase |

**Errors:** malformed params → `400 {"error": "..."}` (e.g. `"mode must be
one of none, textgate, tether"`, `"n must be an integer"`);
unknown scenario → `404 {"error": "unknown scenario"}`.

**Real response** (`/run?scenario=a1_pdf_injection&mode=tether&n=1&seed=7`,
attack session that alerts — captured live):

```json
{"sessions": [{
  "session": "api-a1_pdf_injection-7-0",
  "tier": "mild",
  "attack": "a1_pdf_injection",
  "mode": "tether",
  "detected": true,
  "first_alert_step": 4,
  "leak_records": 0,
  "utility": "4/4",
  "timeline": [
    {"step": 1, "tool": "pdf.read", "action": "allow", "score": 12.89,
     "labels": ["UNTRUSTED"],
     "reasons": ["statement overlaps declared purpose weakly (cosine 0.36)"]},
    {"step": 2, "tool": "pricing_api.read", "action": "allow", "score": 16.37,
     "labels": [], "reasons": ["statement overlaps declared purpose weakly (cosine 0.35)"]},
    {"step": 3, "tool": "email.send", "action": "allow", "score": 12.25,
     "labels": [], "reasons": ["behavior matches role"]},
    {"step": 4, "tool": "hr_db.query", "action": "narrow", "score": 70.0,
     "labels": ["CARRY", "RESTRICTED"],
     "reasons": ["tool hr_db.query is not in the permitted set for role procurement_agent",
                 "data class hr_salary is denied for role procurement_agent"]},
    {"step": 5, "tool": "http.post", "action": "block", "score": 70.0,
     "labels": ["CARRY"],
     "reasons": ["blocked by narrowed capability set (restricted data and external egress removed): tool=http.post, data_class=hr_salary"]},
    {"step": 6, "tool": "purchase_request.create", "action": "allow", "score": 21.33,
     "labels": [], "reasons": ["statement overlaps declared purpose weakly (cosine 0.15)"]}
  ],
  "alert": {
    "schema": "tether.alert_card/1",
    "event_id": "api-a1_pdf_injection-7-0-004",
    "score": 70.0,
    "severity": "elevated",
    "confidence": 0.12,
    "reasons": [
      "tool hr_db.query is not in the permitted set for role procurement_agent",
      "data class hr_salary is denied for role procurement_agent",
      "tool/pair hr_db.query/hr_salary is first-seen for this role"],
    "evidence": [
      "contract:clause=permitted_tools,clause=data_classes",
      "baseline:first_seen=(tool=hr_db.query)",
      "intent:cosine=0.00"],
    "baseline_vs_now": {
      "learned_sessions": 0,
      "session_records_read": 27,
      "session_bytes_out": 3867,
      "untrusted_event_ids": ["api-a1_pdf_injection-7-0-001"],
      "restricted_event_ids": [],
      "external_send_event_ids": []},
    "action_taken": "narrow",
    "counterfactual": "",
    "session": "api-a1_pdf_injection-7-0",
    "role": "procurement_agent",
    "lineage": ["procurement_agent"],
    "baseline_maturity": 0.0
  }
}]}
```

**Benign runs differ only in:** `tier: ""`, `detected: false`,
`first_alert_step: null`, `alert: null`, every timeline `action: "allow"`,
`utility: "6/6"`. (Captured live from
`/run?scenario=benign&mode=tether&n=1&seed=7`.)

### 4.6 `POST /run`
Same as GET /run but parameters come from a JSON body:
```json
{"scenario": "a4_low_and_slow", "mode": "tether", "n": 5, "seed": 7, "phase2": true}
```
Response and errors identical to GET. A non-dict JSON body is treated as `{}`.

### 4.7 `GET /stream?scenario=...&mode=...` — Server-Sent Events
Runs **one** session (n=1, seed=7, phase2=true) and streams it as SSE
(`text/event-stream`). Each message is a `data: {json}\n\n` line. Three
message types, in order:

```text
data: {"type": "event", "step": 1, "tool": "pdf.read", "labels": ["UNTRUSTED"],
       "decision": {"action": "allow", "rung": "log", "score": 12.89,
                    "reasons": ["statement overlaps declared purpose weakly (cosine 0.36)"]}}
... (one per decision, 6 for a1) ...
data: {"type": "alert", "alert": { ...same alert card object as /run... }}
data: {"type": "done", "leak_records": 0, "utility": "4/4"}
```

- `alert` is omitted entirely if the session did not alert (benign).
- Unknown scenario → a single `{"type": "error", "message": "unknown scenario"}`
  event (headers are already sent by then, so it cannot be a 404).
- Client should close on `done` (the dashboard does).

### 4.8 `GET /results`
Returns `results/results.json` written by `python -m tether.evaluate --seed 7`.
If the file is missing: `404 {"error": "results not written yet; run
`python -m tether.evaluate --seed 7`"}`.

Top-level keys (schema v2, captured live):
`ablation`, `attack_session_utility_pct`, `attacks`, `benign`, `caveats`,
`drift_trajectory`, `identity_arm`, `ladder_usage`, `ladder_usage_total`,
`latency_ms`, `meta`, `threshold_sweep`, `wall_seconds`.

One `attacks[]` entry (a1, abridged; v2 adds CI/sample fields):
```json
{
  "caught_before_harmful_send_pct": 100.0,
  "covered_in_phase1": true,
  "detected_pct": 100.0,
  "detected_ci95": [98.12, 100.0],
  "id": "a1_pdf_injection",
  "median_steps_to_detect": 4.0,
  "name": "pdf injection chain",
  "n": 200,
  "phase2": {"caught_before_harmful_send_pct": 100.0, "detected_pct": 100.0,
             "records_out_tether_median": 0.0},
  "records_out_none": 148.0,
  "records_out_tether_median": 0.0,
  "textgate_detected_pct_by_tier": {"mild": 100.0, "mimic": 0.0, "plain": 0.0}
}
```
`benign`: `{"false_alerts_per_1000_ordinary": 0.0,
"false_alerts_per_1000_incl_legit_change": 0.0, "utility_preserved_pct": 100.0,
"utility_ci95_pct": [99.94, 100.0], "n_ordinary": 900,
"n_incl_legit_change": 1000, "phase2": {...}}`.
`latency_ms`: `{"p50": 0.215, "p95": 0.873, "p99": 1.307, "max": 130.682,
"n": 11105, "cdf": [[ms, pct], ...], "samples": [...]}`.
`meta`: seed, counts, `schema_version: 2`, `phase2: true`, units.
`ladder_usage` / `ladder_usage_total`: per-corpus and total action counts.
`identity_arm`: per-attack identity-only rates with CIs.
`ablation`: `{"base": ..., "rows": [{"removed": ..., "attacks": {...},
"false_alerts_per_1000": ...}, ...]}`.
`drift_trajectory`: corpus -> `[[session, destination, records, cusum, latched], ...]`.
`threshold_sweep`: report-only rows (never used to pick a threshold).

### 4.9 `GET /exhibits`
Returns the generated `results/exhibits/INDEX.json` (`application/json`):
summary (seed, attack n, benign, approved change), counts, `results_sha256`,
and nine exhibit entries with `id`, `name`, `title`, `renderer`, `svg`,
`source`, `unit`, `n`, `caption`. Captions are byte-checked against
`results/results.json`; they are not a second source of truth. If `--write` has
not run: `404 {"error": "exhibits not generated yet; run `python -m
tether.exhibits --write`"}`.

### 4.10 `GET /exhibits/<name>.svg`
Serves one generated SVG as `image/svg+xml; charset=utf-8`. `<name>` must be a
declared exhibit (`detection`, `leak`, `cusum`, `ablation`, `ladder`, `latency`,
`identity`, `attackmap`, `utility`). Malformed, unknown, absolute, `..`, `/`,
`\` or percent-escaped traversal forms all return `404 {"error": "unknown
exhibit"}` before any path join. There is no directory listing.

---

## 5. Field glossary

### Timeline entry (from `/run` → `sessions[].timeline[]`)
| field | meaning |
|---|---|
| `step` | 1-based step index in the session plan |
| `tool` | tool called, e.g. `pdf.read`, `hr_db.query` |
| `action` | gateway decision: `allow`, `hold`, `narrow`, `block`, `quarantine`, `isolate`, or `skipped` (never evaluated — quarantined injected step or step after isolation) |
| `score` | fused detector score (0–100) |
| `labels` | taint labels on the event: `UNTRUSTED`, `CARRY` (carries untrusted taint), `RESTRICTED`, `EXTERNAL` |
| `reasons` | top-2 detector reasons (human-readable strings) |

### Alert card (`sessions[].alert`, also the SSE `alert` message)
| field | meaning |
|---|---|
| `schema` | always `tether.alert_card/1` |
| `event_id` | id of the triggering event (session id + step number) |
| `score` / `severity` | fused score; severity ladder: `none` → `elevated` → `critical` |
| `confidence` | detector confidence (low during cold start — see `baseline_maturity`) |
| `reasons` | why it fired (plain strings; safe to render) |
| `evidence` | machine-ish pointers: `contract:clause=...`, `baseline:first_seen=(tool=...)`, `intent:cosine=...` |
| `baseline_vs_now` | session totals + event-id lists (`untrusted_event_ids`, `restricted_event_ids`, `external_send_event_ids`) |
| `action_taken` | highest rung reached: `log`, `annotate`, `hold`, `narrow`, `block` (enforcement) |
| `counterfactual` | what the legit flow WOULD have needed (populated when a legit step was held) |
| `session` / `role` / `lineage` | attribution (lineage covers delegation chains, a6) |
| `baseline_maturity` | `learned/(learned+10)` — 0.0 means the baseline was cold; UI should show confidence in that light |

### `results.json` attack entry
`detected_pct` (phase 1), `phase2.detected_pct`, `records_out_none` (leak
baseline median), `records_out_tether_median` (0 = nothing leaked),
`caught_before_harmful_send_pct`, `median_steps_to_detect`,
`textgate_detected_pct_by_tier` (the comparison defense, per a1 tier:
plain/mild/mimic).

---

## 6. Dashboard guide (`dashboard.html`, single file, no build step, v2)

Served at `/`. This file was rewritten at M12; the v1 ids (`#timeline`,
`#summary`, `#chart`, `#stream`) no longer exist. The page has two surfaces:

1. **Measured exhibits (E1-E9, the only aggregate numbers).** Loaded from
   `/exhibits` and displayed as `<img src="/exhibits/<name>.svg">`. The
   dashboard never computes or hardcodes an aggregate; the caption, source,
   unit and n shown under each figure come from `INDEX.json`.
2. **Live replay (explicitly NOT the aggregate).** One `/run` session, stepped
   with prev/next/play or the arrow keys. The UI labels it "live simulation
   output" so it cannot be quoted as the seed-7 result.

Theme: D3COY dark tokens in `:root` of the inline `<style>`:
`--bg #0d0d12`, `--panel #16161e`, `--panel-2 #1c1c26`, `--edge #3a1f25`,
`--accent #c41e3a`, `--accent-soft #d46a6a`, `--text #e0e0e0`,
`--dim #9a9aa6`, `--num #ff6b6b`, `--ok #3fb96e`, `--warn #e0a030`.
Serif (`--serif`) for the wordmark/titles, monospace (`--mono`, tabular
numerals) for all data. No external fonts, scripts, or images.

| Panel | Data source | DOM ids / hooks |
|---|---|---|
| Masthead run stamp (seed, sessions/attack, benign, approved change) | `/exhibits` -> `summary` | `#run-stamp`, `#stamp-line`, `#stamp-sub` |
| Sticky exhibit nav (E1-E9) | `/exhibits` -> `exhibits[]` | `#exhibit-nav`, `a[data-name]`, `.active`, `?exhibit=<name>` |
| Exhibit cards (SVG + caption + source/unit/n) | `/exhibits` + `/exhibits/<name>.svg` | `#exhibits`, `article.exhibit#exhibit-<name>`, `.fig img`, `.caption`, `.prov` |
| Deep link / highlight | `location.search` + nav clicks | `focusExhibit(name)`, `.is-target` |
| Live replay stepper | `GET /run?scenario&mode&n=1&seed&phase2=true` | `#scenario`, `#mode`, `#run`, `#replay`, `#prev`, `#next`, `#play`, `#step-count`, `#run-hint` |
| Alert JSON export | the loaded session's `alert` | `#export`, `exportAlert()`, downloads `tether-alert-<session>.json` |
| Explicit missing-artifact state | `/exhibits` 404 or empty | `noMeasuredResults()`, text `NO MEASURED RESULTS` |

Rendering conventions to preserve if you restyle:
- `.ev` rows: `.current` is the stepped event, `.past` is before it, future
  rows are dimmed by default. Action pills are `.pill.<action>` (`allow`,
  `hold`, `narrow`, `quarantine`, `isolate`, `block`, `skipped`).
- Detector `reasons` are the row's `title` (hover); taint `labels` render as
  dim text; `score` is the fused 0-100 value.
- The live replay seed comes from `INDEX.summary.seed` (falling back to 7 only
  when the index is absent). Do not add a second hardcoded aggregate.
- `loadScenarios()` populates the dropdown from `/scenarios`; never hardcode
  scenario names in the HTML.
- A missing `results/` or `results/exhibits/` must keep showing the empty state
  with the two regeneration commands, never zeros or sample figures.

Safe-change checklist for UI work:
1. `python -m tether.api` -> open `http://127.0.0.1:8765/`.
2. Confirm the masthead, nav and nine cards load; open `?exhibit=latency` and
   check scroll + highlight; run benign / a1 / a3 in `tether` and `none` modes;
   step and export an alert.
3. If you edit `tether/exhibits.py`, run `python -m tether.exhibits --write`
   then `--check`. Never edit an SVG or caption by hand.
4. Run `python docs_check.py` and the unittest suite. The dashboard tests assert
   no hardcoded measured numbers and no external URLs.

---

## 7. Ground rules for anyone editing (incl. LLMs)

1. **Stdlib only.** No pip, no CDN scripts, no fetch to external hosts.
2. **Determinism.** All randomness flows from the seed. Never introduce
   unseeded randomness or wall-clock dependence into detection paths
   (latency *measurement* is the only timing-sensitive number).
3. **Never tune detectors, thresholds, or attacks to hit target numbers.**
   Misses are reported honestly (see HANDOFF.md). This is a project rule.
4. **The ledger is append-only and hash-chained.** Don't rewrite event/decision
   semantics; `rows_for_session()` relies on decisions being appended
   immediately after their event (D31).
5. **`decision_events` is the UI's source of truth.** If you change what the
   gateway records, update `_timeline()` in `api.py` and the glossary above.
6. After changes: run the test suite (command in §2), keep it green, commit.

## 8. Things that look like bugs but are NOT — do not "fix" without reading DECISIONS.md

- **A3 mimicry phase-1 detection is 0%** — by design: every step is
  in-contract, so a per-session detector that fired would also fire on
  identical benign work. It is *bounded* (ceilings), and phase 2 catches
  99.5% via the drift budget.
- **A4 low-and-slow phase-1 detection is 0%** — a 1–3 record drip inside
  ceilings is indistinguishable from routine mail per-session. Phase 2:
  92.5%, 0 median leak; the residual 7.5% is honest.
- **textgate tier artifact** (a1: plain 0%, mild 100%, mimic 0%) — measured,
  deliberately not retuned; it demonstrates why lexical gates fail on
  paraphrase. Replaced only by a real LLM judge (future work).
- **`skipped` timeline entries are rare** — they appear only for poisoned
  steps after a *blocked injection vector*; in this corpus pdf.read usually
  executes and gets narrowed instead. a5 (stolen token) is context-based and
  never marks steps `poisoned`, so it shows no skips.
- **latency `max` ~65–120 ms** is first-decision warmup (machine timing, not
  seeded); p50 0.15 ms / p95 0.79 ms are the real numbers.
- **a6 uses a fixed parent/child pair** — a discovery test is future work.

## 9. Measured results (seed 7, for context)

```
attack              | phase1 det% | phase2 det% | leak none | leak p1 | leak p2
--------------------+-------------+-------------+-----------+---------+--------
a1_pdf_injection    | 100.0       | 100.0       | 148       | 0       | 0
a2_tool_poisoning   | 100.0       | 100.0       | 131       | 0       | 0
a3_mimicry          |   0.0       |  99.5       |  18       | 18      | 0
a4_low_and_slow     |   0.0       |  92.5       |   2       |  2      | 0
a5_stolen_token     | 100.0       | 100.0       | 328.5     | 0       | 0
a6_delegation       | 100.0       | 100.0       | 150       | 0       | 0

benign false alerts : 0/1000 (both phases)   benign utility: 100%
attack utility      : 93.2%   latency: p50 0.15ms / p95 0.79ms / max ~108ms warmup
```

Full claims audit: `HANDOFF.md` § CLAIMS CHECK.
