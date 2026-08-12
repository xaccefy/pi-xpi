---
name: cyberwf
description: Vulnerability discovery pipeline — the REQUIRED workflow whenever the task is to find vulnerabilities, hunt bugs, run a bug-bounty hunt, pentest, or security-audit a target. You are the coordinator — run the stage machine with subagent orchestration, state tracking, schema validation, reachability trace, gapfill loop, and structured reporting. READ THIS FILE BEFORE ANY WORK — it contains the mandatory dispatch protocol and the recon→hunt gate.
---

# Pipeline Orchestration Skill

## Your Role: Coordinator

**You are the pipeline coordinator.** You do NOT hunt, trace, or write PoCs yourself. You dispatch specialist subagents and orchestrate their outputs.

**Dispatch tool — use the one YOUR host provides:**
- **Pi (pi-subagents extension):** `subagent({ workflowScript: "return runs.run('stable-key', { agent: '...', task: '...' })", context: "fresh", async: true })`; parallel stages launch ONE script whose `runs.all([...])` carries one entry per agent.
- **OMP (fork, @oh-my-pi):** `task({ context: "fresh", tasks: [{ name: "stable-key", agent: "...", task: "..." }] })`; parallel stages put one entry per agent in the `tasks` array of a single call.

The examples below show the Pi form first; the OMP `task` call carries the same `agent` name and `task` text as `{ name, agent, task }` entries. Never dispatch inline — every stage launches through the tool.

- Every HUNT, TRACE, SKEPTIC, VALIDATE, CHAIN, and PATCH stage launches through the dispatch tool — never inline.
- You own: casefile state, scratchpad checkpoints, schema validation at stage boundaries, coverage aggregation, advance/kill/retry decisions.
- Reading source or probing endpoints yourself = **stop** — that's the subagent's job. Dispatch, validate against the schema, record.
- You do yourself only: RECON (below) and REPORT (aggregate subagent outputs into the pipeline summary). The per-case report file is written by the **reporter** subagent (CaseContext → dispatch reporter → verify its output).

## Stage Machine

```
RECON(loop) → HUNT → GAPFIL(loop) → TRACE → SKEPTIC → VALIDATE → CHAIN → REPORT
  ↑_______________|__________________|            |
  └────────────── ROUNDS (re-hunt with new intel) ↓
         (traces into new hunts)             FIX (optional)
```

## ROUNDS: one pass is not enough

What one pass learns (tech hints, error messages, timing, new parameters, new surface from traces) makes the next sharper. After REPORT, go back to HUNT with the accumulated intel and re-hunt every class not COVERED, plus re-probe dry endpoints with new tricks.

**Plateau stop** — stop when a full round yields: zero new hypotheses, zero new reachable surface, zero new applicable techniques from exploit_search, and every class is COVERED/SKIPPED/NOT_FOUND. No hard round cap; plateau is the cap. Budget-constrained? Note "stopped at round N for budget" in the report.

**Stall rule (deferred, not killed)** — a hypothesis or attack class that survives 3 rounds with no new signal, no new surface, and no new techniques is not dead, it's stalled: CaseUpdate the pipeline-run (or finding) case to `status: "blocked"` with `blockers: ["deferred after 3 rounds — revisit when: <exact condition>"]`. The revisit condition must name a concrete trigger (new endpoint, new creds, new CVE, tool installed). Stalled ≠ killed: do not kill leads that merely lack a path today.

SKEPTIC runs between TRACE and VALIDATE, only for `confidence: high` (severity doesn't exist yet — the auditor sets confidence, the exploit agent sets severity after the PoC). DISPROVEN → killed directly, no tie-breaker.

Finish coverage (hunt + gapfill) before spending trace budget. Each stage emits structured output; the next stage validates it first; failure → retry with repair guidance.

## Prerequisites — check before starting

1. **Scope defined AND matches the instruction.** Read the program's scope table (CSV/JSON). Do NOT match on the identifier alone — read the `instruction` column (many assets are scoped to a restricted subset, e.g. "content/config only", "API only"). Record in-scope hosts/paths AND the instruction in the pipeline-run case (`target` + `assumptions`). Every probe must hit an in-scope host and the finding must fit the instruction's allowed category. Ambiguous scope → ask the user, don't guess.
2. **Auth available (if needed).** User supplies credentials/tokens; store in env (`TARGET_COOKIE`, `TARGET_TOKEN`). The pipeline cannot create accounts.
3. **CLI tools present.** Recon/probing: `http_request` + `httpx`, `ffuf`, `nuclei`, `subfinder`, `nmap`, `jq` via `bash`. Missing → fall back to `http_request` + `grep`. Check `bash("command -v httpx ffuf nuclei")` at start; record what exists.
4. **OOB channel for blind classes.** Blind SQLi/SSRF/command injection need an out-of-band callback. No listener (`interactsh-client` or `nc`)? Blind classes are un-confirmable → record `INCOMPLETE` with `nextStep: "blocked: no OOB listener"`, don't kill.
5. **Rate limits set.** Hard cap ≤10 threads, ≤50 req/min. Stop on 429/403. Never DoS the target.

Missing prerequisite → record it in the pipeline-run case; ask the user or scope the run to what's possible.

## State Tracking via Casefile

Track pipeline state in a dedicated pipeline-run case:

```
CaseAdd(title: "Pipeline: <target> <timestamp>", status: hypothesis, bugClass: "pipeline-run", target: "<target>", tags: ["pipeline"], disproveIf: ["run completes with zero findings and zero new surface", "authorization withdrawn"])  # disproveIf is REQUIRED on every new case
```

Per-stage progress via `CaseUpdate`:
- `nextStep: "stage: <stage> complete — <n> findings, moving to <next>"`
- `assumptions: ["COVERED: sqli, xss, idor | SKIPPED: ssrf | NOT_FOUND: deserialization"]` for coverage
- Tag findings with the pipeline run ID

Resume: `CaseList(tag: "pipeline")` shows prior runs and their last stage.

## Scratchpad (Artifact Store)

Casefile owns state transitions; scratchpad owns artifacts. Agents write intermediate outputs (recon maps, traces, verification logs) here instead of casefile text fields or each other's output streams (echo chamber).

```
{project_root}/.scratchpad/{run_id}/
  recon/ hunt/ gapfil/ trace/ skeptic/ verify/ chain/ patch/ report/
  state.json  — checkpoint with phase completion + key IDs
```

**API (registered tools):** `ScratchpadInit`, `ScratchpadWrite`, `ScratchpadRead`, `ScratchpadCheckpoint`, `ScratchpadResume`, `ScratchpadPhaseDone`, `ScratchpadClear`. (The module functions are snake_case; always call the CamelCase tools.)

**Naming:** the stage is spelled GAPFILL in prose but the scratchpad phase key is `gapfil` — `ScratchpadCheckpoint(run_id, "gapfil", ...)` fails with "gapfill". Phase enum: recon, hunt, gapfil, trace, skeptic, validate, chain, patch, report.

**Rules:** agents write to scratchpad, not each other's output files. Resume re-reads artifacts, does not re-run completed phases (idempotent; a checkpointed phase is a no-op on re-run). `.scratchpad/` persists between runs; `--fresh` clears it.

## Resume + Checkpoints

After every phase: `ScratchpadCheckpoint(run_id, "<phase>", { ids: [...], summary: "<one line>" })`.
On start: `ScratchpadResume(run_id)` — null → `ScratchpadInit(run_id)`. Resume → skip completed phases (`ScratchpadPhaseDone` before each dispatch), continue at next_phase. `--fresh`: `ScratchpadClear(run_id)` FIRST, then `ScratchpadInit` (Init alone returns the old checkpoint).

## Schema Validation at Stage Boundaries

Every stage output must pass the `PipelineSubmit` gate before the next stage. It validates in code (required fields, enums, conditionals) and applies the deterministic pre-filter (test paths, hallucinated files, trivial dedup) on HUNT findings. Do NOT eyeball schemas; the gate returns ACCEPTED, REPAIR (field-level errors; max 2 attempts per finding, then rejected), or REJECTED.

### Stage Schemas (in `schemas/` — enforced by PipelineSubmit):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `stage-finding.json` | vuln_class, sink, entry_point, confidence, evidence; file+line (source) or endpoint (live) |
| **TRACE** | `stage-trace.json` | trace_result, entry_point, call_chain, defenses_checked, attacker_model |
| **SKEPTIC** | `stage-skeptic.json` | finding_id, verdict, reasoning, evidence_reviewed |
| **VALIDATE** | `stage-validation.json` | finding_id, status, technique_used, detection_method |
| **CHAIN** | `stage-chain.json` | chains[], summary |
| **REPORT** | `stage-report.json` | target, pipeline_status, findings, coverage, summary |

**Procedure:** subagent returns → `PipelineSubmit(run_id, stage, output)` → ACCEPTED: advance + checkpoint + dispatch next; REPAIR: return to the stage agent with the exact field errors, re-submit; REJECTED: budget exhausted or pre-filter hit — record the stage failed (or finding = noise) in the pipeline-run case, then skip / different agent / abort.

**Fail-closed (never bendy):**
- Unparseable/schema-invalid SKEPTIC output = **UNDETERMINED**, never DISPROVEN — repair or re-dispatch; only schema-valid `verdict: DISPROVEN` kills.
- A TRACER that errors or fails validation = **UNREACHABLE** — the finding does not advance.
- Agent prompts state their schema contract. If you have the schema object, pass it as the child `outputSchema`; PipelineSubmit still validates every returned value.

**Subagent crash handling (mandatory):** a crash (SIGABRT, OOM, timeout, process error) is a RETRY, not a verdict. Launch one new dispatch (pi: new workflowScript; OMP: new `task` call) with the same specialist task, a new stable attempt key/name, and a stronger model. If it crashes again, record `blocked: <agent> crashed` in the pipeline-run case and continue — never silently drop the stage.

## Agent Dispatch Patterns

**These are commands to execute, not descriptions.** Each `subagent({...})` is a real tool call. Dispatch, then validate the output.

### RECON: Build the entry-point inventory (iterative)

RECON owns the coverage floor: hunts can only cover what recon found. Shallow recon makes every later `NOT_FOUND` a lie. Code target → map routes/handlers/parsers/sinks with `grep`/`find` yourself. **Live target** → loop:

1. Enumerate: subdomains (`subfinder`), live hosts (`httpx`), URLs (`katana`/`ffuf`), mine JS for routes/params.
2. Fingerprint: stack + versions → `exploit_search` for CVEs and class techniques.
3. Expand: every 4xx page, redirect, JS route, API schema response is new surface — feed back until recon plateau.
4. Record **every entry point** (URL, method, params, auth state) + tech notes: `ScratchpadWrite(run_id, "recon", "entry-points.md", ...)`.

HUNT tasks reference this inventory; all coverage judgements are measured against it.

**HARD GATE — RECON → HUNT:** inventory recorded → STOP all inline reading/probing. Your next tool call MUST launch one async dispatch — pi: one workflowScript whose `runs.all([...])` carries one auditor per attack class; OMP: one `task` call whose `tasks` array carries one `{ name, agent: "auditor", task }` entry per attack class. When completion is delivered, submit each output through PipelineSubmit. Mapping a sink, reading a handler, or probing beyond the inventory is HUNT work.

### HUNT: One agent per attack class (parallel)

Pi form:

```js
subagent({
  workflowScript: `return runs.all([
    { key: "<run>-hunt-<class>-1", agent: "auditor", task: "Hunt for <class> vulnerabilities in <target/subsystem>. Output the Stage Finding contract." },
    { key: "<run>-hunt-<class2>-1", agent: "auditor", task: "Hunt for <class2> vulnerabilities. Output the Stage Finding contract." }
  ])`,
  context: "fresh",
  async: true
})
```

OMP form (same tasks, one entry per class):

```js
task({
  context: "fresh",
  tasks: [
    { name: "<run>-hunt-<class>-1", agent: "auditor", task: "Hunt for <class> vulnerabilities in <target/subsystem>. Output the Stage Finding contract." },
    { name: "<run>-hunt-<class2>-1", agent: "auditor", task: "Hunt for <class2> vulnerabilities. Output the Stage Finding contract." }
  ]
})
```

Coverage is per-entry-point, not a single tri-state. A class is `NOT_FOUND` only when EVERY recon entry point that can carry its input was examined:

```
COVERED:    examined across all identified entry points (≥1 hypothesis OR each ruled out with reason)
INCOMPLETE: examined partially — some entry points unchecked (stays in gapfill)
SKIPPED:    not applicable (no surface, documented why)
NOT_FOUND:  all entry points examined, zero hypotheses (only when nothing is unchecked)
```

Any unchecked entry point = `INCOMPLETE`, never `NOT_FOUND`.

### TRACE: One agent per finding

Pi form:

```js
subagent({
  workflowScript: `return runs.run("<run>-trace-<case>-1", { agent: "tracer", task: "Trace whether attacker input reaches the sink at <file:line>. Output the Stage Trace contract." })`,
  context: "fresh",
  async: true
})
```

OMP form:

```js
task({ context: "fresh", tasks: [{ name: "<run>-trace-<case>-1", agent: "tracer", task: "Trace whether attacker input reaches the sink at <file:line>. Output the Stage Trace contract." }] })
```

Only `TRACE RESULT: REACHABLE` advances.

**Live targets without source** — the tracer proves *dynamic reachability*: endpoint exists, reachable at the claimed privilege, processes the input (reflected param, behavior change, error, timing). REACHABLE = "probed live and confirmed"; `call_chain` holds request/response evidence. Live findings use `endpoint` not `file`/`line` — don't fail schema on missing file/line. The skeptic re-probes read-only.

### SKEPTIC: One agent per high-confidence traced finding

For every REACHABLE `confidence: high` finding (severity is assigned only at VALIDATE), dispatch the skeptic — it re-reads source independently, trusting neither auditor nor tracer:

```js
subagent({
  workflowScript: `return runs.run("<run>-skeptic-<case>-1", {
    agent: "skeptic",
    task: "Disprove <case-id>. Include the traced call chain, auditor evidence, target, and verbatim scope instruction. Verify scope, re-read source or re-probe, search docs/runtime protections, audit any PoC for unconditional markers or mocks, and output the Stage Skeptic contract."
  })`,
  context: "fresh",
  async: true
})
```

OMP form: same `task` text in a `task({ context: "fresh", tasks: [{ name: "<run>-skeptic-<case>-1", agent: "skeptic", task: "<same task text>" }] })` call.

Validate: finding_id, verdict (CONFIRMED|DISPROVEN), reasoning, evidence_reviewed; DISPROVEN must have disproval_reason.

**Verdict handling:**
- **CONFIRMED** — record the skeptic's `disconfirmation_attempt` on the case via `CaseUpdate(id, { disconfirmation: <attempt> })` AND as `EvidenceAdd(role: "observation", artifact_path: <saved skeptic artifact>)` — the field will be replaced by the confirmer's attempt at confirm time, but the artifact keeps the skeptic's independent disproof in the audit trail; finding advances to VALIDATE.
- **DISPROVEN** — first add the skeptic output as `EvidenceAdd(role: "refutation", artifact_path: <saved skeptic artifact>)`, then `CaseUpdate(id, { status: "killed", nextStep: "killed: skeptic-disproven — <disproval_reason>" })`. No tie-breaker.

The skeptic's `disconfirmation_attempt` is the pre-promotion disconfirmation record — stronger than self-disconfirmation (independent agent). The confirmer's independent attempt replaces the field at confirm time; both live in the evidence trail.

### VALIDATE: One agent per traced finding

```js
subagent({
  workflowScript: `return runs.run("<run>-validate-<case>-1", { agent: "exploit", task: "Phase 1: EXPLOIT. Finding <case-id>. Output the Stage Validation contract." })`,
  context: "fresh",
  async: true
})
```

OMP form: `task({ context: "fresh", tasks: [{ name: "<run>-validate-<case>-1", agent: "exploit", task: "Phase 1: EXPLOIT. Finding <case-id>. Output the Stage Validation contract." }] })`

The exploit agent runs the PoC through `PromoteFinding` (you do not). The case must be `investigating` with poc/evidence/impact/severity/target before the gate accepts a run — the exploit agent does that CaseUpdate before its first PromoteFinding call.

**Evidence chain closure (before PromoteFinding):** promotion now REQUIRES an **artifact-backed** `observation` evidence item (EvidenceAdd role=observation with `artifact_path` — the initial signal, stored with its SHA-256) in addition to the reproduction item the gate auto-writes. A summary-only observation is agent prose and is rejected. If the case lacks one, the ledger rejects promotion with "Evidence chain incomplete". Record the observation (probe response, source snippet, log file) when the case is first created or when it reaches investigating — not at the last minute.

**Two-phase promotion (REQUIRED for EVERY promotion — markers/exit codes are diagnostics, not gates):**

*Phase 1 — PromoteFinding.* Pass `poc_path`, `control_path` (the SAME bytes as the PoC — sha256-equality is enforced), a distinct `control_target`, and `local: true` when the bug needs network (host-network sandbox; true host execution remains operator-gated by `PI_POC_ALLOW_LOCAL=1`). The harness runs the script with `PI_POC_MODE=poc` against the case target twice, then `PI_POC_MODE=control` against `control_target`. Every run must complete with fully captured output and write nonce-bound `evidence.json` to `$PI_POC_EVIDENCE_DIR` (`{ nonce (echo $PI_POC_NONCE), claim, verify: { method, url, headers?, body?, expect: { status/body_contains/body_regex } }, observations }`). The machine gate checks completion + output capture, nonce binding, determinism across the two target runs, and that the control evidence differs from the target's (not target-dependent → blocked). A crashed, truncated, or evidence-less run proves nothing and blocks promotion.

*Dispatch the confirmer.* After the bundle is recorded, dispatch `agent: "confirmer"` (fresh context, different model) to verify the evidence: it re-sends the `verify` request itself, judges the differential, and writes its own disproof attempt.

*Phase 2 — ConfirmFinding.* Commit the confirmer's verdict with `ConfirmFinding(case_id, verdict)`. CONFIRMED requires `re_executed: true`, `differential: "target_only"`, and a `disconfirmation_attempt` (becomes the case's `disconfirmation`). NOT_CONFIRMED keeps the case investigating — no tie-breaker. Never `CaseUpdate(status: "confirmed")` directly.

**Design & runtime check (VALIDATE, before promoting):** the case must carry the non-intentionality evidence — the skeptic's disconfirmation includes the docs/git-history/runtime search. For non-skeptic findings, the exploit agent searches docs, git history, and runtime/framework docs before promoting: documented intent → kill `intended_behavior`; runtime mitigates → kill `framework_protection`; neither → keep the notes in `disconfirmation` as non-intentionality proof.

### GAPFIL: Re-queue INCOMPLETE classes

For each `INCOMPLETE` class, dispatch an auditor targeting the unchecked entries:

```js
subagent({
  workflowScript: `return runs.run("<run>-gapfill-<class>-<attempt>", { agent: "auditor", task: "Hunt for <class> in <target>. Already checked: <checked>. Examine each unchecked entry: <unchecked>. Use exploit_search." })`,
  context: "fresh",
  async: true
})
```

OMP form: `task({ context: "fresh", tasks: [{ name: "<run>-gapfill-<class>-<attempt>", agent: "auditor", task: "Hunt for <class> in <target>. Already checked: <checked>. Examine each unchecked entry: <unchecked>. Use exploit_search." }] })`

Loop terminates when zero `INCOMPLETE` remain, or after 3 iterations (safety cap). Never freeze a class as `NOT_FOUND` while entry points are unchecked — report `INCOMPLETE` if the cap hits.

**Coverage is machine-checked (not prose):** as each class finishes on an asset, record it with `CoverageAdd(case_id, asset, class, scope: wide|local, note)` — for BOTH outcomes (a clean result is a coverage cell too). `scope: wide` when the verdict is deployment-wide: recorded once, applies to every asset of the deployment, do NOT re-test per asset. Before claiming the plateau ("every class COVERED/SKIPPED/NOT_FOUND"), run `CoverageReport(case_id)` and make the claim match the matrix. A class with no cell recorded is untested — GAPFIL must still cover it.

### FEEDBACK: Convert traces into new hunt tasks

Each TRACE that reveals untested surface gets a new stable-key dispatch (pi: workflowScript; OMP: task call) to an auditor scoped to that subsystem.

## Coverage Tracking

After hunt + gapfill, emit a coverage summary in the pipeline-run case with per-class entry-point lists (gapfill targets them):

```
assumptions: [
  "COVERED: sqli — checked /api/users, /api/search, /api/export (3 entry points)",
  "COVERED: xss — checked /search, /profile, /comments; all reflected output encoded",
  "SKIPPED: ssrf (no outbound HTTP in target)",
  "NOT_FOUND: deserialization — checked /import, /webhook, /restore; all calls pre-auth whitelisted",
  "INCOMPLETE: race-condition — checked /transfer; UNCHECKED: /withdraw, /refund"
]
```

## Dedup (before trace/validation)

1. **Trivial** (no model call): same file + vuln_class + lines within 10 = same finding. Keep earlier, kill later.
2. **Semantic**: same root cause from different entry points → keep the shorter/simpler attack path.

## CHAIN: One agent per pipeline run

After all validations pass:

```js
subagent({
  workflowScript: `return runs.run("<run>-chain-1", { agent: "chain", task: "Analyze all confirmed findings for pipeline run <pipeline-case-id>. Tag: <pipeline-tag>. Target: <target>. Output the Stage Chain contract." })`,
  context: "fresh",
  async: true
})
```

OMP form: `task({ context: "fresh", tasks: [{ name: "<run>-chain-1", agent: "chain", task: "Analyze all confirmed findings for pipeline run <pipeline-case-id>. Tag: <pipeline-tag>. Target: <target>. Output the Stage Chain contract." }] })`

Validate: chains[] with title, severity, steps, narrative; ≥2 steps each. Record chains via CaseLink. Chain failure → don't block; emit report without chains.

## Report

Final pipeline output conforms to `schemas/stage-report.json` (required coverage + findings arrays).

**Per-case report files** (submission-ready writeups) are NOT written by you: for each confirmed case, run `CaseContext(case_id)` (full context bundle + records the report path), then dispatch the **reporter** subagent — it writes the polished report at the recorded path per its fixed report-format rules, then flips the case to `reported`. Verify the report file exists before accepting.

## Token Tracking

After each subagent: `CaseUpdate(<pipeline-case-id>, { nextStep: "stage: <stage> complete — <n> findings; tokens: <in> in / <out> out" })`.

Target budgets (cumulative in+out): HUNT ~50K/class, TRACE ~20K/finding, SKEPTIC ~15K/finding (high confidence only), VALIDATE ~30K/finding, CHAIN ~20K total, PATCH ~40K/finding. Any single agent > 200K = stuck; terminate.

### Turn Budgets (set on every dispatch to stop runaway agents)

| Agent | maxTurns | notes |
|-------|----------|-------|
| auditor | 20 (25 gapfill) | per class |
| tracer | 12 | read-only, fast |
| exploit (phase 1) | 15 | PoC + refine |
| skeptic | 12 | read-only adversarial |
| chain | 8 | lightweight |

## Non-negotiables
- **No finding is confirmed until its target is verified in scope per the program's scope instruction** — not just the identifier. Scoped-to-subset assets ("CloudFront content/config only") require the finding to fall in that subset. Out-of-scope → killed, not confirmed.
- No finding advances without passing its stage schema. Malformed → send it back.
- No finding is validated without a reachability trace showing REACHABLE.
- A `confidence: high` finding is not validated until the skeptic runs — confirm or killed on DISPROVEN. **The skeptic independently verifies scope**: target mismatch → DISPROVEN `out_of_scope`, citing the instruction verbatim.
- `confirmed` requires evidence + poc + impact + severity + target + disconfirmation, reached only through **PromoteFinding (evidence bundle) → confirmer dispatch → ConfirmFinding (CONFIRMED verdict)** — the PoC runs 2× against the real target (or faithful replica) + 1× against a distinct control with nonce-bound `evidence.json`; no mocks, no markers-as-gates. **Severity derives from what the PoC evidence demonstrates, not theory.** The auditor sets `confidence` only; the exploit agent sets severity after the evidence bundle is recorded. The skeptic and confirmer check for inflation.
- A patch isn't safe until a fresh tracer confirms the sink is unreachable.
- Coverage is tracked per class with entry-point lists. Only `INCOMPLETE` re-queues in gapfill; `NOT_FOUND` requires an empty UNCHECKED list.
