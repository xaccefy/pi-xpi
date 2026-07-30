---
name: pipeline
description: Full pipeline orchestration skill for vulnerability discovery. Teaches the harness agent how to run stages with state tracking, schema validation, reachability trace, gapfill, and structured reporting.
---

# Pipeline Orchestration Skill

## Stage Machine

```
RECON → HUNT → GAPFIL(loop) → TRACE → SKEPTIC → VALIDATE → CHAIN → REPORT
  ↑___________________|                    |
  └────── FEEDBACK ────┘                    ↓
         (traces into new hunts)      FIX (optional)
```

SKEPTIC runs between TRACE and VALIDATE, but only for findings at severity >= high. The skeptic independently re-reads source to disprove the finding. If the skeptic says DISPROVEN, the finding is killed directly — no tie-breaker.

Finish coverage (hunt + gapfill) before spending trace budget. Trace only the hypotheses that survived a complete hunt, then validate the reachable ones.

Each stage produces a structured output. The next stage validates it before starting. If validation fails, the stage retries with repair guidance.

## Prerequisites — check before starting a run

The pipeline assumes the target is **in scope** and the agent has the tools to probe it. Before dispatching the first auditor, verify:

1. **Scope is defined.** Record the in-scope hosts/paths in the pipeline-run case `target` + `assumptions`. Every probe must hit a host in scope. If scope is ambiguous, ask the user — do not guess.
2. **Auth is available (if needed).** If the target requires auth, the user must supply credentials/tokens. Store them in env vars (`TARGET_COOKIE`, `TARGET_TOKEN`). The pipeline cannot create accounts.
3. **CLI tools are present.** Recon and probing rely on `http_request` (stateful HTTP, cookie persistence) plus CLI tools `httpx`, `ffuf`, `nuclei`, `subfinder`, `nmap`, `jq` via `bash`. If a CLI tool is missing, fall back to `http_request` + `grep` (slower). Check with `bash("command -v httpx ffuf nuclei")` at run start and record what's available.
4. **OOB channel for blind classes.** Blind SQLi / blind SSRF / blind command injection can only be confirmed via an out-of-band callback. If no listener is running (`interactsh-client` or a `nc` listener), blind classes will be **un-confirmable** — record them as `INCOMPLETE` with `nextStep: "blocked: no OOB listener"`, don't kill them.
5. **Rate limits are set.** Hard cap: ≤10 threads, ≤50 req/min. Stop on 429/403. The pipeline must not DoS the target.

If any prerequisite is missing, record it in the pipeline-run case and either ask the user or scope the run to what's possible.

## Stage Config

Each stage has:
- **model** — which model class to dispatch on (hunt = standard, trace = strong, skeptic = strong [deliberate disagreement with auditor], validate = different than hunt for deliberate disagreement)
- **tools** — what tools the agent gets (trace/skeptic have no write tools)
- **output schema** — what shape the stage must emit
- **max_turns** — when to terminate a stuck agent

## State Tracking via Casefile

Track pipeline state in the casefile ledger. Use a dedicated pipeline-run case:

```
CaseAdd(
  title: "Pipeline: <target> <timestamp>",
  status: hypothesis,
  bugClass: "pipeline-run",
  target: "<target>",
  tags: ["pipeline"]
)
```

Record per-stage progress with `CaseUpdate`:
- Add `nextStep: "stage: recon complete, findings: 3, moving to validate"` after each stage
- Add `assumptions: ["COVERED: sqli, xss, idor | SKIPPED: ssrf | NOT_FOUND: deserialization"]` for coverage
- Tag findings with the pipeline run ID for cross-referencing

This gives you resume capability: on restart, `CaseList(tag: "pipeline")` shows previous runs and their last recorded stage.

## Scratchpad (Artifact Store)

The casefile owns state transitions; the scratchpad owns artifacts. Agents write their intermediate outputs (recon maps, trace outputs, verification logs) to the scratchpad instead of stuffing everything into casefile text fields or relying on each other's output streams.

**Directory layout** (created by `scratchpad_init`):
```
{project_root}/.scratchpad/{run_id}/
  recon/      — fingerprints, tech detection, surface maps
  hunt/       — per-class coverage logs, finding candidates
  gapfil/     — gapfill re-queue artifacts
  trace/      — per-finding reachability traces
  skeptic/    — per-finding disconfirmation verdicts
  verify/     — PoC logs, run outputs
  chain/      — chain analysis artifacts
  patch/      — patch diffs, re-attack results
  report/     — final report drafts
  state.json  — checkpoint file with phase completion + key IDs
```

**API:** see `packages/pi-casefile/src/scratchpad.ts` for the full API. Key functions: `scratchpad_init`, `scratchpad_write`, `scratchpad_read`, `scratchpad_checkpoint`, `scratchpad_resume`, `scratchpad_phase_done`, `scratchpad_clear`.

**Rules:**
- Agents write artifacts to scratchpad, not to each other's output files (prevents echo chamber).
- Casefile still owns state transitions; scratchpad owns artifacts.
- Resume re-reads scratchpad artifacts, does not re-run completed phases (idempotent). A completed phase with a checkpoint artifact is a no-op on re-run.
- The `.scratchpad/` directory is preserved between runs; `--fresh` clears it.

## Resume + Checkpoints

After every phase: `scratchpad_checkpoint(run_id, "<phase>", { ids: [<case-ids>], summary: "<one-line>" })`.

On pipeline start: `scratchpad_resume(run_id) ?? scratchpad_init(run_id)`. If resume returns a checkpoint, skip completed phases (check `scratchpad_phase_done` before each dispatch) and continue from `resume.next_phase`. `--fresh` clears the scratchpad via `scratchpad_clear(run_id)`.

## Schema Validation at Stage Boundaries

Every stage output must conform to its schema before the next stage begins. Validate by reading the schema file and checking each required field.

### Stage Schemas (in `schemas/`):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `schemas/stage-finding.json` | vuln_class, file, line, sink, entry_point, confidence, evidence |
| **TRACE** | `schemas/stage-trace.json` | trace_result, entry_point, call_chain, defenses_checked, attacker_model |
| **SKEPTIC** | `schemas/stage-skeptic.json` | finding_id, verdict, reasoning, evidence_reviewed |
| **VALIDATE** | `schemas/stage-validation.json` | finding_id, status, technique_used, detection_method |
| **CHAIN** | `schemas/stage-chain.json` | chains[], summary |
| **REPORT** | `schemas/stage-report.json` | target, pipeline_status, findings, coverage, summary |

**Validation procedure:**
```
1. Read the schema file: read("schemas/stage-finding.json")
2. For each output, check every required field exists and has non-null content
3. If missing or malformed → return to the stage agent with "Your output is missing: <fields>. Please fix."
4. Re-validate after repair. Max 2 repair attempts per stage.
```

If the agent cannot produce valid output after 2 repair attempts:
- Record the stage state as `failed` in the pipeline-run case
- Log the failure reason
- Decide: skip to next stage? retry with different agent? abort?

## Agent Dispatch Patterns

### HUNT: One agent per attack class

```
Spawn multiple auditor agents concurrently, one per attack class:
  subagent({agent: "auditor",
    task: "Hunt for <class> vulnerabilities in <target/subsystem>. ..."})
```

Coverage rule: check at least 3 entry points per class. After all auditors return, aggregate coverage. Coverage is per-entry-point, not a single tri-state — a class is only `NOT_FOUND` when every entry point identified in recon was actually examined:
```
COVERED:    class examined across all identified entry points (≥1 hypothesis OR each entry point ruled out with reason)
INCOMPLETE: class examined partially — some entry points never checked (stays in gapfill)
SKIPPED:    class not applicable (no surface, documented why)
NOT_FOUND:  class examined across ALL entry points and produced zero hypotheses (only when no entry point is unchecked)
```
A class with any unchecked entry point is `INCOMPLETE`, never `NOT_FOUND`. `INCOMPLETE` classes stay in the gapfill loop until every entry point is checked or explicitly ruled out.

### TRACE: One agent per finding

```
For each hypothesis that passed validation:
  subagent({agent: "tracer",
    task: "Trace whether attacker input reaches the sink at <file:line>. ..."})
```

Only findings with `TRACE RESULT: REACHABLE` advance to exploit.

### SKEPTIC: One agent per high-severity traced finding (adversarial disconfirmation)

Runs for every REACHABLE finding with severity >= high. The skeptic independently re-reads source to disprove the finding — it does not trust the auditor's or tracer's summary.

```
For each REACHABLE finding with severity >= high:
  subagent({agent: "skeptic",
    task: "Disprove finding <case-id>. vuln_class=<class>, sink=<file:line>, entry_point=<entry>.
           Trace result: REACHABLE via <call_chain>. Auditor evidence: <evidence>.
           Read the source yourself. Try to disprove it. Output conforming to schemas/stage-skeptic.json.",
    turnBudget: {maxTurns: 12, graceTurns: 2}})
```

Validate skeptic output against `schemas/stage-skeptic.json`:
- Must have finding_id, verdict (CONFIRMED|DISPROVEN), reasoning, evidence_reviewed
- If DISPROVEN: must have disproval_reason

**Skeptic verdict handling:**
- **CONFIRMED** — the skeptic agrees the finding is real. Write the skeptic's `disconfirmation_attempt` into the case's `disconfirmation` field via `CaseUpdate(id, { disconfirmation: <skeptic's attempt> })`. The finding advances to VALIDATE.
- **DISPROVEN** — the skeptic found a concrete reason the finding is false. Kill directly: `CaseUpdate(id, { status: "killed", nextStep: "killed: skeptic-disproven — <disproval_reason>" })`. No tie-breaker — a read-only re-read of source that found no path is the answer.

The skeptic's `disconfirmation_attempt` IS the case's disconfirmation record — it satisfies the disconfirmation gate before CONFIRMED. This is stronger than self-disconfirmation because a different agent produced it.

### VALIDATE: One agent per traced finding

```
For each reachable finding:
  subagent({agent: "exploit", task: "Phase 1: EXPLOIT"})
  Run through PromoteFinding.
```

### GAPFIL: Re-queue INCOMPLETE classes (targeted at the gap)

```
For each attack class with "INCOMPLETE" coverage:
  Read the class's checked/unchecked entry-point list from the pipeline-run case.
  subagent({agent: "auditor",
    task: "Hunt for <class> in <target>. Previous hunts found nothing.
             These entry points are ALREADY CHECKED — do not re-tread them: <checked list>.
             These entry points are UNCHECKED — examine each one: <unchecked list>.
             Use exploit_search for this specific class."})
```

The loop terminates when every class is COVERED, SKIPPED, or NOT_FOUND (i.e. zero `INCOMPLETE` remain), or after 2 iterations as a safety cap. Do NOT freeze a class as `NOT_FOUND` while unchecked entry points remain — if the cap hits with `INCOMPLETE` classes, report them as `INCOMPLETE` in coverage, not `NOT_FOUND`.

### FEEDBACK: Convert traces into new hunt tasks

```
For each TRACE that revealed a new attack surface (a subsystem touched by the call chain
that wasn't previously audited):
  subagent({agent: "auditor", task: "Audit this subsystem: <subsystem>. The trace revealed it as untested attack surface."})
```

## Coverage Tracking

Coverage is the pipeline's self-check. It answers: "what did we actually test vs what did we skip or miss?"

After the hunt + gapfill stages, emit a coverage summary in the pipeline-run case. Each class line must list the entry points checked so gapfill can target the gaps:

```
assumptions: [
  "COVERED: sqli — checked /api/users, /api/search, /api/export (3 entry points)",
  "COVERED: xss — checked /search, /profile, /comments; all reflected output encoded",
  "SKIPPED: ssrf (no outbound HTTP in target)",
  "NOT_FOUND: deserialization — checked /import, /webhook, /restore; all deserialization calls are pre-auth whitelisted",
  "INCOMPLETE: race-condition — checked /transfer; UNCHECKED: /withdraw, /refund"
]
```

This feeds the gapfill loop. `INCOMPLETE` classes get re-queued with their unchecked list. `NOT_FOUND` is only valid when no entry point is unchecked.

## Dedup

Before running trace or validation, deduplicate hypotheses:

1. **Trivial dedup** (no model call): same file + vuln_class + lines within 10 = same finding. Keep the earlier one, kill the later.
2. **Semantic dedup**: if two findings describe the same root cause from different entry points, keep the one with the shorter/simpler attack path.

### CHAIN: One agent per pipeline run

After all validations pass, spawn the chain analyst:

```
subagent({agent: "chain",
  task: "Analyze confirmed findings for pipeline run <pipeline-case-id>.
           Tag: <pipeline-tag>. Target: <target>.
           Find exploit chains across ALL confirmed findings."})
```

Validate chain output against `schemas/stage-chain.json`:
- Must have chains[] with title, severity, steps, narrative
- Each chain must have ≥2 steps
- Record chains in casefile via CaseLink

If chain analysis fails, don't block the pipeline — emit report without chains.

## Report

Final output must conform to `schemas/stage-report.json`. Required coverage and findings arrays.

## Token Tracking

After each subagent completes, record token usage in the pipeline-run case:

```
CaseUpdate(<pipeline-case-id>, {
  nextStep: "stage: <stage> complete — <n> findings
             tokens: <input> in / <output> out"
})
```

Target token budgets per stage (cumulative input+output):
- HUNT: ~50K tokens per class
- TRACE: ~20K per finding
- SKEPTIC: ~15K per finding (only severity >= high)
- VALIDATE: ~30K per finding (exploit phase)
- CHAIN: ~20K total
- PATCH: ~40K per finding

If any single agent exceeds 200K tokens, consider it stuck and terminate.

### Turn Budgets

Set turn budgets on subagent calls to prevent runaway agents:

```
subagent({agent: "auditor",
  task: "...",
  turnBudget: {maxTurns: 20, graceTurns: 2}})
```

| Agent | maxTurns | notes |
|-------|----------|-------|
| auditor | 20 | 25 with gapfill |
| tracer | 12 | read-only, should be fast |
| exploit (phase 1) | 15 | PoC writing + refine |
| skeptic | 12 | read-only adversarial review |
| chain | 8 | lightweight analysis |

## Non-negotiables
- No finding advances without passing its stage schema. If the output is malformed, send it back.
- No finding is validated without a reachability trace showing REACHABLE.
- A High/Critical finding is not validated until the skeptic stage runs — either the skeptic confirms it, or it's killed on DISPROVEN.
- A finding is only `confirmed` with evidence + poc + impact + severity and a PoC that exited 0.
- A patch isn't safe until a fresh tracer confirms the sink is no longer reachable.
- Coverage must be tracked per class with entry-point lists. Only `INCOMPLETE` classes re-queue in gapfill; `NOT_FOUND` requires an empty UNCHECKED list.
