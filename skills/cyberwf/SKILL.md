---
name: cyberwf
description: Bounded swarm vulnerability discovery pipeline for broad bug-bounty or security-audit sweeps. Use when the user explicitly asks for the full pipeline, enables /xp or /xp swarm, or wants parallel specialist review. Prefer /xp lite or the casefile skill for CTFs, focused one-target work, and single suspected bugs.
---

# Pipeline Orchestration Skill

## Your Role: Coordinator

**You are the full-pipeline coordinator.** Use this workflow only for `/xp`, `/xp swarm`, or an explicitly broad multi-agent audit. For CTFs, focused reviews, and one-target work, use `/xp lite` and work inline.

When this workflow is active, only four roles run as subagents: **auditor**, **tracer**, **skeptic**, and **chain**. You, the main coordinator, keep RECON, VALIDATE/PoC writing, ConfirmFinding, patching, final reports, state decisions, and all orchestration.

**Dispatch tool — use the one YOUR host provides:**
- **Pi (pi-subagents extension):** `subagent({ workflowScript: "return runs.run('stable-key', { agent: '...', task: '...' })", context: "fresh", async: true })`; parallel stages launch ONE script whose `runs.all([...])` carries one entry per agent.
- **OMP (fork, @oh-my-pi):** `task({ context: "fresh", tasks: [{ name: "stable-key", agent: "...", task: "..." }] })`; parallel stages put one entry per agent in the `tasks` array of a single call.

The examples below show the Pi form first; the OMP `task` call carries the same `agent` name and `task` text as `{ name, agent, task }` entries. Only the delegated stages launch through these tools.

- HUNT rounds, TRACE, SKEPTIC, and CHAIN launch through the dispatch tool.
- VALIDATE, ConfirmFinding, PATCH, REPORT, and all final decisions stay with the main coordinator — never hand those phases to workers in swarm mode.
- You own: casefile state, scratchpad checkpoints, schema validation at stage boundaries, coverage aggregation, advance/kill/retry decisions.
- After RECON, source reading/probing for HUNT or TRACE belongs to the relevant subagent. Validation and reporting evidence checks are yours.
- You aggregate subagent outputs into the pipeline summary and write the per-case reports yourself after CaseContext.

## Stage Machine

```
RECON(you) → HUNT rounds(auditor) → TRACE(tracer) → SKEPTIC(skeptic) → VALIDATE(you) → CHAIN(chain) → REPORT(you)
  ↑_______________________|___________________|
  └──── re-hunt with new intel / traces ─────↓
                         FIX (optional)
```

## ROUNDS: one pass is not enough

What one pass learns (tech hints, error messages, timing, new parameters, new surface from traces) makes the next sharper. After REPORT, go back to HUNT with the accumulated intel and re-hunt every class not COVERED, plus re-probe dry endpoints with new tricks.

**Plateau stop** — stop when a full round yields: zero new hypotheses, zero new reachable surface, zero new applicable techniques from exploit_search, and every class is COVERED/SKIPPED/NOT_FOUND. No hard round cap; plateau is the cap. Budget-constrained? Note "stopped at round N for budget" in the report.

**Stall rule (deferred, not killed)** — a hypothesis or attack class that survives 3 rounds with no new signal, no new surface, and no new techniques is not dead, it's stalled: CaseUpdate the pipeline-run (or finding) case to `status: "blocked"` with `blockers: ["deferred after 3 rounds — revisit when: <exact condition>"]`. The revisit condition must name a concrete trigger (new endpoint, new creds, new CVE, tool installed). Stalled ≠ killed: do not kill leads that merely lack a path today.

SKEPTIC runs between TRACE and VALIDATE, only for `confidence: high` (severity doesn't exist yet — the auditor sets confidence, the main agent sets severity after the PoC). DISPROVEN → killed directly, no tie-breaker.

Finish enough HUNT coverage before spending trace budget. Each stage emits structured output; the next stage validates it first; failure → retry with repair guidance.

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
  recon/ hunt/ trace/ skeptic/ validate/ chain/ report/
  legacy/manual buckets: gapfil/ patch/
  state.json  — checkpoint with phase completion + key IDs
```

**API (registered tools):** `ScratchpadInit`, `ScratchpadWrite`, `ScratchpadRead`, `ScratchpadCheckpoint`, `ScratchpadResume`, `ScratchpadPhaseDone`, `ScratchpadClear`. (The module functions are snake_case; always call the CamelCase tools.)

**Naming:** use `hunt` for initial and follow-up audit rounds. The legacy scratchpad phase key `gapfil` and manual `patch` bucket remain accepted, but ScratchpadResume does not schedule them for new swarm runs.

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

**Procedure:** delegated stage returns (or you produce VALIDATE/REPORT output) → `PipelineSubmit(run_id, stage, output)` → ACCEPTED: advance + checkpoint + dispatch/run next; REPAIR: fix the listed fields or return them to the delegated stage agent, then re-submit; REJECTED: budget exhausted or pre-filter hit — record the stage failed (or finding = noise) in the pipeline-run case, then skip / different agent / abort.

HUNT `vuln_class` is agent-chosen, not a fixed taxonomy. Use the most precise stable label for the target/technique and reuse it consistently for coverage and dedup.

**Fail-closed (never bendy):**
- Unparseable/schema-invalid SKEPTIC output = no verdict — repair or re-dispatch; only schema-valid `verdict: DISPROVEN` kills. Schema-valid `UNDETERMINED` blocks validation until resolved.
- Tracer crash, timeout, unparseable output, or schema failure = no trace verdict — repair/re-dispatch.
  Schema-valid `trace_result: "UNREACHABLE"` blocks advancement as a proven unreachable path; schema-valid `UNDETERMINED` blocks validation until resolved.
- Agent prompts state their schema contract. If you have the schema object, pass it as the child `outputSchema`; PipelineSubmit still validates every returned value.

**Subagent failure handling (mandatory):** a crash, timeout, process error, unparseable output, or schema-invalid output is a RETRY, not a verdict. Launch one new dispatch (pi: new workflowScript; OMP: new `task` call) with the same specialist task, a new stable attempt key/name, and a stronger model. If it fails again, record `blocked: <agent> failed` in the pipeline-run case and continue — never silently drop the stage.

## Agent Dispatch Patterns

**These are commands to execute for delegated stages, not descriptions.** Each `subagent({...})` is a real tool call. Dispatch, then validate the output.

### RECON: Attack-surface mapping (agent-selected)

RECON owns the coverage basis: hunts can only cover what recon found. It aggressively gathers high-signal intel and turns it into an entry-point inventory, attacker model, auth/role boundaries, trust boundaries, likely vuln-class batches, and known gaps. Aim for the richest useful map, not the largest raw crawl. Choose target-specific probes that answer: what entry points exist, what auth states/roles can reach them, what stack/version signals are credible, and which vuln classes are worth assigning to HUNT. Code target → map routes/handlers/parsers/sinks with `grep`/`find` yourself. **Live target** → plan:

1. Enumerate enough surface for coverage: subdomains (`subfinder`), live hosts (`httpx`), URLs (`katana`/`ffuf`) when in scope; JS bundles/source maps for SPA/API-heavy apps or hidden routes; public metadata/schemas/passive archives/backups only when they answer a concrete unknown.
2. Fingerprint for decisions: stack + version confidence → `exploit_search` for CVEs and class techniques; record uncertainty instead of forcing a version guess.
3. Observe behavior: 4xx/redirect/error/timing/schema responses can reveal auth boundaries and new surfaces; feed high-signal anomalies into HUNT tasks.
4. Record discovered entry points (URL, method, params, auth state), selected HUNT class batches, tech notes, and gaps: `ScratchpadWrite(run_id, "recon", "entry-points.md", ...)`.

HUNT tasks reference this inventory; all coverage judgements are measured against it.

**HARD GATE — RECON → HUNT:** inventory recorded → STOP all inline reading/probing. Your next tool call MUST launch one async dispatch — pi: one workflowScript whose `runs.all([...])` carries at most 3 batched auditor tasks; OMP: one `task` call whose `tasks` array carries at most 3 `{ name, agent: "auditor", task }` entries. Batch related classes by surface/family instead of spawning one agent per bug class. When completion is delivered, submit each output through PipelineSubmit. Mapping a sink, reading a handler, or probing beyond the inventory is HUNT work.

### HUNT: 2-3 batched auditor agents (parallel)

Pi form:

```js
subagent({
  workflowScript: `return runs.all([
    { key: "<run>-hunt-batch1-1", agent: "auditor", task: "Hunt related classes <class,class2> in <target/subsystem>. Output the Stage Finding contract and coverage log." },
    { key: "<run>-hunt-batch2-1", agent: "auditor", task: "Hunt related classes <class3,class4> in <target/subsystem>. Output the Stage Finding contract and coverage log." }
  ])`,
  context: "fresh",
  async: true
})
```

OMP form (same tasks, one entry per batch):

```js
task({
  context: "fresh",
  tasks: [
    { name: "<run>-hunt-batch1-1", agent: "auditor", task: "Hunt related classes <class,class2> in <target/subsystem>. Output the Stage Finding contract and coverage log." },
    { name: "<run>-hunt-batch2-1", agent: "auditor", task: "Hunt related classes <class3,class4> in <target/subsystem>. Output the Stage Finding contract and coverage log." }
  ]
})
```

Coverage is per-entry-point, not a single tri-state. A class is `NOT_FOUND` only when EVERY recon entry point that can carry its input was examined:

```
COVERED:    examined across all identified entry points (≥1 hypothesis OR each ruled out with reason)
INCOMPLETE: examined partially — some entry points unchecked (re-queue as a HUNT follow-up)
SKIPPED:    not applicable (no surface, documented why)
NOT_FOUND:  all entry points examined, zero hypotheses (only when nothing is unchecked)
```

Any unchecked entry point = `INCOMPLETE`, never `NOT_FOUND`.

### TRACE: Tracer agents for prioritized findings

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

Only `TRACE RESULT: REACHABLE` advances. `UNREACHABLE` requires a concrete blocker; `UNDETERMINED` records missing context/auth/WAF/source ambiguity and must be re-dispatched or resolved before validation.

**Live targets without source** — the tracer proves *dynamic reachability*: endpoint exists, reachable at the claimed privilege, processes the input (reflected param, behavior change, server message, timing). REACHABLE = "probed live and confirmed"; `call_chain` holds request/response evidence. Blocked auth/WAF or missing test credentials is UNDETERMINED unless the attacker model itself is impossible. Live findings use `endpoint` not `file`/`line` — don't fail schema on missing file/line. The skeptic re-probes read-only.

### SKEPTIC: Bounded high-confidence challenge

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

Validate: finding_id, verdict (CONFIRMED|DISPROVEN|UNDETERMINED), reasoning, evidence_reviewed; DISPROVEN must have disproval_reason; UNDETERMINED must have uncertainty_reason.

**Verdict handling:**
- **CONFIRMED** — record the skeptic's `disconfirmation_attempt` on the case via `CaseUpdate(id, { disconfirmation: <attempt> })` AND as `EvidenceAdd(role: "observation", artifact_path: <saved skeptic artifact>)` — the field will be replaced by the main agent's phase-2 attempt, while the artifact keeps the skeptic's independent challenge in the audit trail; finding advances to VALIDATE.
- **DISPROVEN** — first add the skeptic output as `EvidenceAdd(role: "refutation", artifact_path: <saved skeptic artifact>)`, then `CaseUpdate(id, { status: "killed", nextStep: "killed: skeptic-disproven — <disproval_reason>" })`. No tie-breaker.
- **UNDETERMINED** — do not validate. Record the blocker on the case (`status: "blocked"` or `nextStep: "blocked: skeptic-undetermined — <uncertainty_reason>"`) and re-dispatch once with the missing context, or keep investigating until the blocker is resolved.

The skeptic's `disconfirmation_attempt` is the pre-promotion challenge. The main agent performs the final disconfirmation itself at ConfirmFinding time; both attempts remain in the evidence trail.

### VALIDATE: Main agent only

Do this stage inline. Do not dispatch validation.

Write the smallest reliable PoC that demonstrates the **maximum reachable impact** of the vulnerability, then run it through `PromoteFinding`, derive severity from that proven impact, and submit your own Stage Validation output. "Smallest" means no fragile ceremony, mocks, or unrelated exploit steps — not a weaker impact demonstration. Do not stop at a benign marker if a stronger in-scope, non-destructive primitive is reachable (read/write, privilege change, account takeover path, data exposure, etc.). The case must be `investigating` with poc/evidence/impact/severity/target before the gate accepts a run; fill missing fields with `CaseUpdate` before your first `PromoteFinding` call.

**Evidence chain closure (before PromoteFinding):** promotion now REQUIRES an **artifact-backed** `observation` evidence item (EvidenceAdd role=observation with `artifact_path` — the initial signal, stored with its SHA-256) in addition to the reproduction item the gate auto-writes. A summary-only observation is agent prose and is rejected. If the case lacks one, the ledger rejects promotion with "Evidence chain incomplete". Record the observation (probe response, source snippet, log file) when the case is first created or when it reaches investigating — not at the last minute.

**Two-phase promotion (REQUIRED for EVERY promotion — zero exit is necessary run integrity, never proof; markers are diagnostic only):**

*Phase 1 — PromoteFinding.* Pass `poc_path`, an operator-approved `control_target` from `PI_POC_CONTROL_TARGETS`, optional same-byte `control_path` only when overriding the default `poc_path`, and `local: true` when needed. Every run must complete with captured output and nonce-bound `evidence.json` containing a response-body predicate; status-only evidence is rejected. The harness pins DNS, locks redirects to the bound host, applies one request to target/control, and requires two conclusive responses with `target_only`. Crashed, truncated, evidence-less, or transport-inconclusive runs block promotion.

*Phase 2 — ConfirmFinding (main agent only).* Do not dispatch confirmation. The main/coordinator reads the exact PoC and preserved evidence, hunts trivial predicates or fabrication, performs a concrete disconfirmation attempt, and calls `ConfirmFinding` itself. A CONFIRMED call performs and stores a fresh harness-owned target/control replay; there is no caller-supplied re-execution checkbox. CONFIRMED requires `re_execution_note`, `differential: "target_only"`, and the main agent's `disconfirmation_attempt`. Worker processes are rejected. Never `CaseUpdate(status: "confirmed")` directly.

**Design & runtime check (VALIDATE, before promoting):** the case must carry the non-intentionality evidence — the skeptic's disconfirmation includes the docs/git-history/runtime search. For non-skeptic findings, you search docs, git history, and runtime/framework docs before promoting: documented intent → kill `intended_behavior`; runtime mitigates → kill `framework_protection`; neither → keep the notes in `disconfirmation` as non-intentionality proof.

### HUNT follow-up: Re-queue INCOMPLETE classes

For each `INCOMPLETE` class, dispatch an auditor targeting the unchecked entries:

```js
subagent({
  workflowScript: `return runs.run("<run>-hunt-followup-<class>-<attempt>", { agent: "auditor", task: "Hunt for <class> in <target>. Already checked: <checked>. Examine each unchecked entry: <unchecked>. Use exploit_search." })`,
  context: "fresh",
  async: true
})
```

OMP form: `task({ context: "fresh", tasks: [{ name: "<run>-hunt-followup-<class>-<attempt>", agent: "auditor", task: "Hunt for <class> in <target>. Already checked: <checked>. Examine each unchecked entry: <unchecked>. Use exploit_search." }] })`

Loop terminates when zero `INCOMPLETE` remain, or after 3 iterations (safety cap). Never freeze a class as `NOT_FOUND` while entry points are unchecked — report `INCOMPLETE` if the cap hits.

**Coverage is machine-checked (not prose):** as each class finishes on an asset, record it with `CoverageAdd(case_id, asset, class, scope: wide|local, note)` — for BOTH outcomes (a clean result is a coverage cell too). `scope: wide` when the verdict is deployment-wide: recorded once, applies to every asset of the deployment, do NOT re-test per asset. Before claiming the plateau ("every class COVERED/SKIPPED/NOT_FOUND"), run `CoverageReport(case_id)` and make the claim match the matrix. A class with no cell recorded is untested — send it through a HUNT follow-up.

### FEEDBACK: Convert traces into new hunt tasks

Each TRACE that reveals untested surface gets a new stable-key dispatch (pi: workflowScript; OMP: task call) to an auditor scoped to that subsystem.

## Coverage Tracking

After HUNT rounds, emit a coverage summary in the pipeline-run case with per-class entry-point lists:

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

**Per-case report files** (submission-ready writeups) are written by you: for each confirmed case, run `CaseContext(case_id)` (full context bundle + records the report path), write the polished report at the recorded path, then flip the case to `reported`. Verify the report file exists before accepting.

## Non-negotiables
- **No finding is confirmed until its target is verified in scope per the program's scope instruction** — not just the identifier. Scoped-to-subset assets ("CloudFront content/config only") require the finding to fall in that subset. Out-of-scope → killed, not confirmed.
- No finding advances without passing its stage schema. Malformed → send it back.
- No finding is validated without a reachability trace showing REACHABLE.
- A `confidence: high` finding is not validated until the skeptic returns CONFIRMED. DISPROVEN kills; UNDETERMINED blocks/retries. **The skeptic independently verifies scope**: target mismatch → DISPROVEN `out_of_scope`, citing the instruction verbatim.
- `confirmed` requires evidence + poc + impact + severity + target + disconfirmation, reached only through **PromoteFinding machine bundle → main-agent review → ConfirmFinding**. The main agent produces phase-1 evidence, checks severity, and commits; no mocks, markers, or exit-code-only proof.
- A patch isn't safe until a fresh tracer confirms the sink is unreachable.
- Coverage is tracked per class with entry-point lists. Only `INCOMPLETE` re-queues into a HUNT follow-up; `NOT_FOUND` requires an empty UNCHECKED list.
