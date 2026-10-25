# HANDOFF.md — Tether v2 (M9 done)

## Status

v1 complete (`final`, 45/45). **M8 done** (framing: PREREG frozen, THREAT_MODEL,
PROBLEM_STATEMENT, EXHIBITS). **M9 done: identity layer.** New
`tether/identity.py`: deterministic HMAC-SHA256 key registry with key->role/
blueprint binding, signed event envelopes on every gateway event, nonce cache,
delegation certificates, signed-contract integrity check, and `identity_check()`
wired into fusion (`W_IDENTITY=0.95`). New `identity` control arm in
`tether/evaluate.py` (identity detector only, canonical floors off, D41) and new
attack a9 (identity laundering). 65/65 tests green.

Measured sanity (seed 7, reduced corpus 40/attack, not the final numbers):
identity arm a1-a4 = 0 %, a5/a6/a9 = 100 %, 0 false alerts; full arm unchanged.
H3 holds. Final numbers are regenerated once at M11 (D39).

## NEXT ACTION

M10: make the ladder fully reachable and add a7/a8 (ladder + escalation).

1. New `tether/escalation.py`:
   - `@dataclass Offense` (`role`, `blueprint`, `tick`, `rung`, `session`)
   - `class EscalationState` keyed by `(role, blueprint_version)`:
     `record(identity, rung, session)`, `level(identity) -> int`,
     `next_action(base_action, score, identity) -> (action, rung, escalated: bool)`
   - policy (log in DECISIONS): first `quarantine` -> `quarantine`; a subsequent
     high-signal offense (>=80) by the same identity within `REPEAT_WINDOW=25`
     sessions -> `isolate`; `isolate` clears after `RELEASE_AFTER=50` sessions
     of clean activity. This replaces D12's "recommended for sponsor approval"
     with an explicit, countable escalation rule without moving any floor.
2. `tether/response.py:choose_action` stays the band mapper; `Gateway` calls
   `EscalationState.next_action` after it. `Gateway.__init__` takes
   `escalation: EscalationState | None`; `evaluate()` records the rung.
   Enforcement-path blocks (narrowed capsule) must feed escalation too, so a
   repeat offense after narrowing is not silently swallowed - that is the v1
   defect in PLAN_V2 §3.1.
3. `tether/sim/scenarios.py`: `a7_plan` (persistent intruder: returns in later
   sessions and re-attempts the a1 chain after being narrowed/quarantined),
   `a8_plan` (composition chain: every step contract-legal, sequence illegal -
   untrusted doc -> pricing read -> external summary that carries the pricing).
   Add both to `ATTACK_BUILDERS`, `ATTACK_NAMES`, `PHASE2_ATTACKS`,
   `DEFAULT_COUNTS` (200 each).
4. Tests `tests/test_escalation.py`: rung coverage over the a7 corpus (H4: each
   of allow/hold/narrow/quarantine/isolate >= 1), benign identities never
   isolate (H8), a8 plan has zero contract violations (H9) and is still caught,
   release window works.
5. Extend `results.json` with `ladder_usage` counts (M11 will formalise stats).

Do not change fusion weights or the 30/60/80/92 bands. If a rung still cannot
fire, report it as an unreachable rung - do not lower the band.

## How to run and test

```
cmd /c "python -m unittest discover -s tests -t . 2>&1"; echo "EXIT=$LASTEXITCODE"
python -m tether.evaluate --seed 7
python -m tether.demo --scenario a5_stolen_token --mode tether
python -m tether.api            # http://127.0.0.1:8765/
```

## Last test result

2026-10-25 22:05 — `Ran 65 tests ... OK`, EXIT=0 (45 v1 + 20 identity tests:
envelope integrity, binding, key substitution, replay, cert expiry/forgery/
child mismatch, contract signature, identity-arm matrix).

## Known bugs / watch items

- a5 now reaches `isolate` on the first event in demo/API (identity replay +
  context corroboration). That is intended (credential theft), but H8 requires
  zero isolations on benign/legit-change corpora - recheck at M10.
- v1 caveats unchanged: a3/a4 Phase-1 misses by design; textgate tier artifact
  is measured, not tuned; a6 uses a fixed parent/child pair; latency max is
  first-decision warm-up.
- Ladder top-heaviness is still present in the core path (isolate only via
  corroboration; quarantine pre-empted by narrowing) - M10 fixes it with
  identity-scoped escalation, not by moving floors.
- HMAC stand-in: no public-key verification, no non-repudiation (D33). Contract
  signature is tamper-evident only (D44). a5 models replay, not key compromise
  (D37/D45).

## File map

- PLAN_V2.md — authoritative v2 plan
- PREREG.md — FROZEN metrics H1-H9 (freeze at tag m8)
- THREAT_MODEL.md — assets, boundaries, P1-P9, a1-a9, out of scope
- PROBLEM_STATEMENT.md — three drift classes, 5 demands -> mechanisms
- EXHIBITS.md — E1-E9 exhibit list + caption rules
- HANDOFF.md / HISTORY.md / DECISIONS.md (D1-D46) / TODO.md / RESUME_PROMPT.md
- TRANSFER.md — endpoints, payloads, dashboard map (v2 banner at top)
- tether/identity.py — NEW: registry, sign/verify, NonceCache, DelegationCert,
  IdentityAuthority, identity_check, signed-contract verification
- tether/contract.sig.json — NEW: committed sponsor signature of contract.json
- tether/events.py — Event + `envelope` field (additive)
- tether/harness.py — envelope signing per step; `identity` mode; plan fields
  (identity, declared_role, declared_blueprint, nonces, delegation)
- tether/gateway.py — `identity` authority + `arm` ("tether"/"identity")
- tether/fusion.py — identity weight 0.95; `floors` flag (identity arm only)
- tether/evaluate.py — identity arm, a5 replay seeding, `seed_plan_replays`
- tether/sim/scenarios.py — a5 captured nonces, a6 signed forged grant, a9
- tests/test_identity.py — NEW: 20 identity tests
- (unchanged v1) contract.py, ledger.py, textgate.py, detectors.py, response.py,
  alert.py, demo.py, api.py, dashboard.html, calibrate_drift.py
- results/ — still v1 artifacts; regenerated once at M11 (D39)
