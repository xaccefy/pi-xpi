---
name: pipeline
description: Full pipeline orchestration skill for vulnerability discovery. Teaches the harness agent how to run stages with state tracking, schema validation, reachability trace, gapfill, and structured reporting.
---

# Pipeline Orchestration Skill

## Stage Machine

```
RECON → HUNT → VALIDATE → GAPFIL(loop) → TRACE → CHAIN → REPORT
  ↑________________________|                    |
  └────── FEEDBACK ────────┘                    |
         (traces into new hunts)                |
                                                ↓
                                          FIX (optional)
```

Each stage produces a structured output. The next stage validates it before starting. If validation fails, the stage retries with repair guidance.

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

Coverage rule: check at least 3 entry points per class. After all auditors return, aggregate coverage:
```
COVERED:   classes that produced ≥1 hypothesis
SKIPPED:   classes not applicable (no surface)
NOT_FOUND: classes checked but produced zero hypotheses
```

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

### GAPFIL: Re-queue NOT_FOUND classes

```
If any attack classes have "NOT_FOUND" coverage:
  For each such class:
    subagent({agent: "auditor",
      task: "Hunt for <class> in <target>. The previous hunt found nothing.
               Try different entry points, different techniques.
               Use ExploitSearch for this specific class."})
```

Max 2 gapfill iterations.

### FEEDBACK: Convert traces into new hunt tasks

```
For each TRACE that revealed a new attack surface (a subsystem touched by the call chain
that wasn't previously audited):
  subagent({agent: "auditor", task: "Audit this subsystem: <subsystem>. The trace revealed it as untested attack surface."})
```

## Coverage Tracking

Coverage is the pipeline's self-check. It answers: "what did we actually test vs what did we skip or miss?"

After the hunt + gapfill stages, emit a coverage summary in the pipeline-run case:

```
assumptions: [
  "COVERED: sqli, xss, idor, auth-bypass",
  "SKIPPED: ssrf (no outbound HTTP in target)",
  "NOT_FOUND: deserialization (all deserialization calls are pre-auth whitelisted)",
  "COVERED: path-traversal, command-injection (second gapfill iteration)",
  "NOT_FOUND: race-condition (all state mutations use serial transactions)"
]
```

This feeds the gapfill loop. NOT_FOUND classes with surface potential get re-queued.

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
