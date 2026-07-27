---
name: pipeline
description: Full pipeline orchestration skill for vulnerability discovery. Teaches the harness agent how to run stages with state tracking, schema validation, reachability trace, gapfill, and structured reporting.
---

# Pipeline Orchestration Skill

## Stage Machine

```
RECON → HUNT → GAPFIL(loop) → TRACE → VALIDATE → CHAIN → REPORT
  ↑___________________|                    |
  └────── FEEDBACK ────┘                    |
         (traces into new hunts)            |
                                            ↓
                                      FIX (optional)
```

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
- **model** — which model class to dispatch on (hunt = standard, trace = strong, validate = different than hunt for deliberate disagreement)
- **tools** — what tools the agent gets (trace has no write tools)
- **output schema** — what shape the stage must emit
- **max_turns** — when to terminate a stuck agent
- **concurrency** — how many parallel agents to run

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

## Schema Validation at Stage Boundaries

Every stage output must conform to its schema before the next stage begins. Validate by reading the schema file and checking each required field.

### Stage Schemas (in `schemas/`):

| Stage | Schema | Required Fields |
|-------|--------|-----------------|
| **HUNT** | `schemas/stage-finding.json` | vuln_class, file, line, sink, entry_point, confidence, evidence |
| **TRACE** | `schemas/stage-trace.json` | trace_result, entry_point, call_chain, defenses_checked, attacker_model |
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
| exploit (phase 2) | 20 | patch + verify + re-attack |
| chain | 8 | lightweight analysis |
