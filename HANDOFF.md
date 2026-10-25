# HANDOFF.md — Tether v2 (M8 done)

## Status

v1 is complete and tagged `final` (45/45 tests, measured seed-7 results, API,
dashboard, TRANSFER.md). v2 is in progress. **M8 (framing) is complete and
committed**: `PLAN_V2.md` (authoritative plan), `PREREG.md` (frozen metrics,
H1-H9), `THREAT_MODEL.md` (adversaries P1-P9, attacks a1-a9),
`PROBLEM_STATEMENT.md` (three drift classes), `EXHIBITS.md` (E1-E9 list).
No production code has changed in v2 yet; the suite is still 45/45 green.

Remaining order is strict: M9 identity -> M10 ladder+attacks -> M11 evaluation
v2 -> M12 UI v2 -> M13a judge docs -> M14 final. M13b (slides) is optional and
only after M12+M13a.

## NEXT ACTION

Create `tether/identity.py` and wire it into the gateway as a detector (M9).

1. New file `tether/identity.py`:
   - `class Scope` (frozen dataclass: `role: str`, `blueprint_version: str`)
   - `class IdentityRegistry` with `register(identity_id, role, blueprint,
     secret)` and `public_binding(identity_id) -> Scope`
   - `sign(envelope: dict, identity_id) -> dict` -> `{"payload": {...},
     "alg": "HS256", "key_id": ..., "sig": hexdigest}` over
     `json.dumps(payload, sort_keys=True, separators=(",",":")).encode()`
   - `verify(signed) -> VerifyResult(ok, code, detail)` with codes:
     `bad_signature`, `unknown_key`, `role_mismatch`, `blueprint_mismatch`,
     `nonce_replay`, `expired`, `delegation_grant_exceeded`
   - `NonceCache.accept(nonce, ttl_sessions) -> bool` (deterministic counter,
     not wall clock, so results stay reproducible)
   - `DelegationCert(parent, child, grant_tools, grant_classes, issued_at,
     expires_at)` + `check_cert(cert, claimed)` returning an intersection
2. New function `identity_check(ev, registry, certs, nonces) -> DetectorResult`
   in `tether/identity.py` (not detectors.py, to keep the module self-contained),
   weight `W_IDENTITY = 0.95` added to `tether/fusion.py:BASE_WEIGHTS`.
3. `tether/events.py`: add `envelope: dict | None = None` (additive) and
   `claimed_role: str = ""`; `tether/harness.py:_event_for` attaches a signed
   envelope per step when `RunConfig.identity` is set.
4. `tether/evaluate.py`: add `identity` arm (identity detector ONLY, per D36)
   and an `identity_arm` block in results.json.
5. Tests in `tests/test_identity.py`: tamper -> bad_signature; replay ->
   nonce_replay; expired cert -> expired; forged grant -> delegation_grant_exceeded;
   legit delegation -> score 0 (no FP); a5/a6/a9 caught, a1-a4 not.

Do not change `choose_action` or the fusion floors in M9; the ladder work is M10.

## How to run and test

```
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
python -m tether.evaluate --seed 7
python -m tether.demo --scenario a1_pdf_injection --mode tether
python -m tether.api            # http://127.0.0.1:8765/
```

Windows: run unittest through `cmd /c` (PowerShell reports exit 1 on OK because
unittest writes to stderr).

## Last test result

2026-10-25 21:43 — `Ran 45 tests ... OK`, EXIT=0 (unchanged since v1; M8 touched
docs only).

## Known bugs / watch items

- None open. v1 caveats still apply and are restated in PREREG/THREAT_MODEL:
  a3/a4 Phase-1 misses by design; textgate tier artifact is measured, not tuned;
  a6 uses a fixed parent/child pair; latency max includes first-decision warm-up.
- Ladder top-heaviness (isolate unreachable, quarantine pre-empted by narrowing)
  is a **known defect to fix in M10**, not a caveat to live with (a7/H4).
- HMAC stand-in has no public-key verification and no non-repudiation (D33);
  a5 models replay, not key compromise (D37).

## File map

- PLAN_V2.md — authoritative v2 plan (theme §4, milestones §6, docs §7)
- PREREG.md — FROZEN metrics, corpus, seeds, arms, H1-H9 (do not edit silently)
- THREAT_MODEL.md — assets, trust boundaries, P1-P9, a1-a9, out of scope
- PROBLEM_STATEMENT.md — three drift classes, 5 PS demands -> mechanism
- EXHIBITS.md — E1-E9 judge exhibits with results/ sources
- HANDOFF.md — this file (rewrite each checkpoint)
- HISTORY.md — append-only checkpoint log
- DECISIONS.md — numbered decisions D1-D40
- TODO.md — M8-M14 checklist
- RESUME_PROMPT.md — paste-into-another-model resume prompt
- TRANSFER.md — endpoints, payloads, dashboard map (for team/LLM handoff)
- PROJECT_BRIEF.md / tether_build_prompt.md — original brief + operative spec
- tether/types.py — Context, DetectorResult, Decision, ApprovedChange
- tether/contract.py + contract.json — L0 role contract (anchor)
- tether/events.py — Event dataclass
- tether/ledger.py — append-only SQLite hash chain + verify_chain()
- tether/textgate.py — stand-in TF-IDF gate (not an LLM judge)
- tether/detectors.py — contract, provenance, baseline, intent, context, drift,
  delegation detectors (+ BaselineTracker, DriftBudget)
- tether/fusion.py — noisy-OR, impact multiplier, floors, confidence
- tether/response.py — 5-rung ladder + narrowing capsule
- tether/gateway.py — single enforcement point + taint tracker
- tether/alert.py — alert card builder (fixed templates)
- tether/harness.py — session executor (none / textgate / tether)
- tether/sim/scenarios.py — scripted plans (benign, legit_change, a1..a6)
- tether/evaluate.py — evaluation CLI writing results/
- tether/demo.py — step-by-step demo CLI
- tether/api.py — stdlib JSON API + SSE + static dashboard
- dashboard.html — single-file dashboard (v1 light-on-dark canvas charts)
- tests/ — unittest suite, 45 tests (3 files)
- results/ — v1 measured artifacts (will be regenerated once at M11, D39)
- calibrate_drift.py — null-traffic evidence for CUSUM h=8
