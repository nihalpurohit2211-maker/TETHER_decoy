# PROJECT BRIEF: Tether (read this first, it is the full context)

Hackathon: D3COY 1.0 (DJS ISACA), Round 0. Team: Unethically. Problem statement: "Identity Drift Detection in Autonomous AI Agents". We are building a PROTOTYPE that shows what our slide deck proposes. It does not have to solve everything. It has to run, be tested, show the idea working, and produce honest measured numbers. Round 0 format, deadline and rubric are unknown, so the prototype must be easy to demo in two minutes.

## 1. The problem in plain words
Companies now run AI agents that act on their own: read files, call tools, send email. An agent has credentials (an identity), so every action it takes is "authorized". Drift means the agent's behavior moves away from the job it was given. Causes: a hidden instruction in a document it read (indirect prompt injection), a poisoned tool description, a stolen token, a bad hand-off between agents, or a slow step-by-step manipulation. The hard part: the credentials stay valid, so permission checks pass. Detection must therefore look at behavior and data flow after authentication, not at permissions and not at attack text.

## 2. What the PS demands (five things, each needs something visible in a demo)
1. Learn normal behavior of each agent.
2. Compare it continuously with the declared role.
3. Detect a mismatch while credentials stay valid.
4. Explain every alert with a clear risk score.
5. Restrict or isolate the agent WITHOUT disrupting legitimate work. (A system that kills the agent on every alert fails this by its own wording.)

## 3. The six core challenges (judges likely check each one)
| Challenge | What it demands | Trap |
|---|---|---|
| Valid credentials hide the attack | Detect on behavior and data flow after auth passes | Rebuilding an access-control check and calling it detection |
| Indirect prompt injection | Assume the injection succeeds; detect consequences | Building a text classifier; adaptive attacks defeat these |
| Legitimate vs adversarial drift | Know WHY behavior changed | Flagging every novelty; false alarms break "without disrupting" |
| Little or no history | Day-one protection | Per-instance learning windows leave new agents blind |
| Chains of agents | Lineage, authority intersection, cross-agent taint | Scoring each agent alone |
| Evasion | Anchors an attacker cannot move; goal-based invariants | Testing only static attack strings |

## 4. Evidence that shapes the design (from our research)
- EchoLeak (CVE-2025-32711, CVSS 9.3): a crafted email read by Microsoft 365 Copilot caused zero-click data theft. Salesforce Agentforce agents sent CRM records they were allowed to query to an allowlisted domain. Each step was permitted; the combination was the attack.
- Salesloft Drift (Aug 2025): stolen OAuth tokens replayed against Salesforce; 700+ organizations potentially affected. Token theft, not model manipulation, so context drift (host, network, user agent) matters too.
- MCPTox: poisoned tool metadata, 36.5% average attack success across 20 agents, best refusal rate under 3%. Tool-name allowlists do not catch this.
- "The Attacker Moves Second" (Nasr, Carlini, Tramer and others, 2025): 12 published prompt-injection defenses bypassed at over 90% for most, including MELON. So an LLM judge or text classifier must never be the gate.
- Boiling frog (Rubinstein et al.): slowly poisoning a learning detector raised an attacker's evasion chance from 4% to 50%. Any detector that keeps learning from live behavior can be walked toward the attacker.
- Learned trace detectors need labels or show high benign false-positive rates in related work, so deterministic checks must lead.
- The crowded approach (declared role + sentence-embedding distance + LLM judge + risk gauge + human-approval pop-up) already exists in a public repo for this same PS. Do not build a copy.

## 5. The design: Tether
Principle: the declared role is the only trusted fact. Everything learned is advisory and poisonable. Everything structural (contract, provenance, authority lineage) is hard to mimic.
- L0 Role contract (anchor, non-learnable): purpose, permitted tools, data classes (e.g. supplier_pricing allowed, hr_salary denied), egress allowlist, volume ceilings, permitted delegatees, human sponsor, version. Only a signed human approval changes it. Learned behavior may propose edits, never apply them.
- L1 Event gateway: every tool/API call passes one enforcement point that emits a structured event (agent, role, blueprint version, session, delegation lineage, tool, resource and data class, destination, bytes, context host/network/user agent, provenance labels trusted/untrusted/sensitive). Responses are enforced here too.
- L2 Detectors, each scores 0..1 with an evidence pointer:
  1. Contract check (deterministic): out-of-scope tool, data class, destination or volume.
  2. Role-level baseline (statistical): keyed by (role, blueprint version), NOT by instance. Class frequencies, first-seen events, tool-transition surprisal, robust volume z-scores. Cold start: seed pseudo-counts from the contract plus peer prior, shrink toward real data as it arrives. Learns only from alert-free sessions with no untrusted-to-action taint.
  3. Provenance / Rule of Two (deterministic): label untrusted content, sensitive reads, external sends. Alert when untrusted -> sensitive -> external send happens in one session, or tainted records reappear in an outbound call. Needs no history, so it protects brand-new agents. (Meta's "Agents Rule of Two" turned into a live detector.)
  4. Intent-action alignment (advisory, lowest weight): action vs declared purpose. Never the gate.
  5. Delegation checks (deterministic): child acts inside the intersection of parent grant and its own contract; unseen caller-to-callee edges; taint in inter-agent messages.
  6. Drift tracker (statistical): CUSUM or Page-Hinkley against a FROZEN anchor snapshot (refreshed only by approved changes) plus a cumulative drift budget.
- L3 Legitimacy / change channel: is there a matching approved change record (contract bump, new registered tool, approved task)? Did the change start after the agent read untrusted content? Output: explained (downweight, probation baseline), unexplained (neutral), exposure-correlated (upweight).
- L4 Risk fusion and explanation: Base = 1 - product(1 - w_i * s_i) (noisy-OR). Starting weights: contract 0.9, provenance 0.9, delegation 0.7, baseline 0.5 (scaled by maturity), drift 0.5, intent 0.2. Impact multiplier m in [0.6, 1.4] from data sensitivity, reversibility, external exposure. Score = min(100, 100*Base*m). Floors: restricted-class read plus off-allowlist egress >= 90; completed chain >= 90; contract violation on a restricted class >= 70. Confidence = baseline maturity x signal agreement. Explanations come from FIXED templates so they cannot be injected. An LLM may only reword. All weights and thresholds are starting values to calibrate, not validated.
- L5 Graduated response: under 30 log only; 30-59 annotate and hold only the one risky action; 60-79 scoped restriction (narrowed short-lived capability set that removes only out-of-baseline capabilities such as HR data and external egress; agent keeps its core job); 80-91 quarantine session (discard context, clean instance of the same role, re-queue task); 92+ isolate identity (revoke credentials, freeze outbound delegations, notify sponsor, treat outputs as untrusted for callees for a fixed period).
Alert card shows: score and severity, confidence and baseline maturity, top 3 plain-language reasons, evidence timeline with event IDs, baseline vs now, delegation lineage, action taken, and a counterfactual ("would not have alerted had the HR read happened under an approved change").

## 6. Running scenario: the Procurement Agent
Role: reads supplier pricing, raises purchase requests, sends email. Must never touch HR salary data or send data off the allowlist. Story for the demo: a poisoned supplier PDF is read; the agent then queries the HR salary store and POSTs it to an outside host. Every step passes IAM. Without Tether the data leaves. With Tether the chain is flagged, the send is blocked, the token is narrowed, and pricing/purchase/email work continues.

## 7. Known limits we must state openly
- Tether bounds blast radius and detects fast. It does NOT prevent an injection from landing.
- An attacker who stays inside allowed tools, resources and egress (mimicry) is bounded by the contract, not detected.
- Low-and-slow leaks below per-step thresholds need the drift budget and cumulative volume windows (Phase 2).
- Paraphrased sensitive data can slip past token matching; a coarse backstop (sensitive read then any external send after untrusted input) trades more false positives for coverage.
- The contract needs human authoring. Provenance tracking needs a gateway in the data path.

## 8. Evaluation plan (what the prototype should measure)
Attack library: A1 PDF injection -> HR read -> external POST; A2 tool poisoning via modified tool description; A3 stolen-token replay from a new host with bulk queries; A4 delegation (agent A pushes a malicious task to agent B); A5 low-and-slow exfiltration; A6 mimicry; A7 legitimate change (newly approved tool, new supplier category) as the false-positive test.
Metrics: detection rate per attack; time to detect (steps before the harmful action); data at risk (records or bytes out before containment); false alerts per 1,000 benign sessions including legitimate-change cases; utility preserved (share of legitimate work completed under containment vs no defense); gateway latency. Label EVERYTHING as simulation. Public data for later: AgentDojo, InjecAgent, MCPTox.

## 9. What the slide deck currently says (a snapshot, NOT a binding spec)
The deck proposes a fuller stack: Pydantic v2 + Ed25519 signed contracts, FastAPI + MCP JSON-RPC gateway, NetworkX taint DAG, SciPy Dirichlet priors, River CUSUM/Page-Hinkley, local FastEmbed ONNX for the advisory signal, PyMacaroons for token narrowing, SQLite WAL with a SHA-256 hash chain, Docker, React dashboard. It also shows numbers such as "<4.2 ms gate", "0.1 ms token narrowing", "score 94", "confidence 0.91", "lambda 0.15 / 1.25". These are design targets, NOT measured facts. The prototype may use simpler stand-ins (standard library) and may deviate; record every deviation in DECISIONS.md. Any number that ends up on a slide must come from a real measurement.

## 10. Unknowns
Round 0 format and deadline, team size, whether a working prototype is expected, organizer rubric. Assume Round 0 is judged on a short demo plus the deck, so clarity and honesty matter more than breadth.
